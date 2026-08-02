/**
 * MuSig2 (BIP327) — firma Schnorr agregada n-de-n, implementada desde cero.
 *
 * MuSig2 permite que N personas produzcan UNA sola firma Schnorr de 64 bytes,
 * indistinguible de la de un único firmante. En la cadena solo se ve tr(P_agg):
 * una clave pública normal y un gasto key-path normal. Nadie sabe que detrás
 * había varios firmantes → privacidad total y coste en fees mínimo.
 *
 * Esto SOLO es posible con Schnorr, por su linealidad:
 *
 *     s·G = R + e·P        (ecuación de verificación BIP340)
 *
 * Como todo es lineal, sumar las s de cada firmante, sus R y sus P mantiene
 * la ecuación. Con ECDSA es imposible (la inversa modular s⁻¹ lo rompe).
 *
 * ── Ojo con el matiz ────────────────────────────────────────────────────
 * MuSig2 es n-de-n (TODOS firman). El m-de-n con clave agregada sería FROST.
 * El m-de-n de este proyecto es el del árbol Taproot con sortedmulti_a — esa
 * es ruta de SCRIPT. MuSig2 es ruta de CLAVE (key-path).
 *
 * ── Las dos trampas que MuSig2 resuelve ─────────────────────────────────
 *
 * 1) Ataque de clave falsa (rogue key). Agregar ingenuamente P_agg = ΣPᵢ es
 *    inseguro: un firmante malicioso publica P₂' = P₂ − P₁ y logra P_agg = P₂,
 *    firmando él solo por todos. Se neutraliza con COEFICIENTES de agregación:
 *
 *        L    = H(P₁ ‖ P₂ ‖ … ‖ Pₙ)     (compromiso con todas las claves)
 *        aᵢ   = H_agg(L, Pᵢ)             (coeficiente de la clave i)
 *        P_agg = Σ aᵢ · Pᵢ
 *
 *    Ahora no puedes cancelar P₁: cambiar tu clave cambia L y con él todos los aᵢ.
 *
 * 2) Los nonces (el corazón del "2" de MuSig2). Agregar R = ΣRᵢ es vulnerable
 *    a un ataque de Wagner en sesiones concurrentes. MuSig clásico lo evitaba
 *    con una 3ª ronda de compromiso. MuSig2 la elimina: cada firmante manda DOS
 *    nonces y se combinan con un coeficiente b derivado de todos los nonces + m:
 *
 *        R₁ = ΣR_{i,1}   R₂ = ΣR_{i,2}
 *        b  = H_nonce(R₁ ‖ R₂ ‖ P_agg ‖ m)
 *        R  = R₁ + b·R₂
 *
 *    El b impide "pre-cocinar" combinaciones de nonces → bastan 2 rondas.
 *
 * ── Flujo completo ──────────────────────────────────────────────────────
 *   Ronda 1: cada i genera k_{i,1},k_{i,2} y publica R_{i,1},R_{i,2}
 *   Ronda 2: e = H_sig(R.x ‖ P_agg.x ‖ m)
 *            sᵢ = kᵢ + e·aᵢ·dᵢ   con  kᵢ = k_{i,1} + b·k_{i,2}
 *            s  = Σ sᵢ
 *   Firma:   (R.x, s)  →  verifica con schnorrVerify normal contra P_agg.x ✨
 *
 * NOTA didáctica: omitimos la optimización "second key" de BIP327 (poner aᵢ=1
 * para la segunda clave única). Es solo una optimización; no afecta la seguridad
 * ni la corrección. Aquí calculamos aᵢ = H_agg(L, Pᵢ) para TODAS las claves,
 * por claridad. Por eso esto no reproduce los vectores de test de BIP327, pero
 * sí produce firmas válidas verificables por nuestro schnorrVerify.
 */

import {
  G, N, mod,
  scalarMultiply, pointAdd, compressPublicKey,
  type Point,
} from './secp256k1';
import { taggedHash, liftX, type SchnorrSignature } from './schnorr';
import { bigintToBytes, bytesToBigint, bytesToHex } from './hmac';

// ─── Tipos ──────────────────────────────────────────────────

/** El material público que un firmante aporta en la ronda 1 (los dos nonces). */
export interface PublicNonce {
  R1: Point;  // R_{i,1} = k_{i,1}·G
  R2: Point;  // R_{i,2} = k_{i,2}·G
}

/** El material secreto de nonce que cada firmante guarda para la ronda 2. */
export interface SecretNonce {
  k1: bigint; // k_{i,1}
  k2: bigint; // k_{i,2}
}

/** Un firmante completo (para la simulación local de las 2 rondas). */
export interface Signer {
  privateKey: bigint;
  publicKey: Point;      // Pᵢ = dᵢ·G (punto completo, 33 bytes comprimidos)
}

/** Resultado de la agregación de claves, con pasos intermedios. */
export interface KeyAggResult {
  publicKeys: Point[];         // las claves individuales (ya ordenadas)
  L: string;                   // hash del conjunto de claves (hex)
  coefficients: bigint[];      // aᵢ = H_agg(L, Pᵢ)
  aggregatePoint: Point;       // Q = Σ aᵢ·Pᵢ (punto completo)
  aggregateXOnly: bigint;      // Q.x — la x-only pubkey final (lo que va en tr())
  parityNegated: boolean;      // ¿hubo que negar Q para tener y par? (BIP340)
}

/** Resultado de la agregación de nonces + cálculo de b y R. */
export interface NonceAggResult {
  R1: Point;                   // Σ R_{i,1}
  R2: Point;                   // Σ R_{i,2}
  b: bigint;                   // coeficiente de nonce H_nonce(R₁‖R₂‖P_agg‖m)
  bHash: string;
  R: Point;                    // R = R₁ + b·R₂ (nonce efectivo agregado)
  finalNonceX: bigint;         // R.x (lo que va en la firma)
  parityNegated: boolean;      // ¿hubo que negar R para tener y par?
}

/** Una firma parcial de un firmante concreto. */
export interface PartialSignature {
  index: number;
  s: bigint;                   // sᵢ = kᵢ + e·aᵢ·dᵢ  (con ajustes de paridad)
  effectiveNonce: bigint;      // kᵢ = k_{i,1} + b·k_{i,2}  (tras paridad de R)
  coefficient: bigint;         // aᵢ usado
}

/** Resultado completo de una sesión MuSig2 end-to-end (para el explorer). */
export interface MuSig2SessionResult {
  keyAgg: KeyAggResult;
  publicNonces: PublicNonce[];
  nonceAgg: NonceAggResult;
  challenge: bigint;           // e = H_sig(R.x ‖ Q.x ‖ m)
  challengeHash: string;
  partialSignatures: PartialSignature[];
  s: bigint;                   // s = Σ sᵢ
  signature: SchnorrSignature; // (R.x, s)
  signatureHex: string;        // 64 bytes hex
  message: string;             // mensaje (hex)
}

// ─── Paso 1: Agregación de claves (con defensa rogue-key) ────

/**
 * Ordena las claves públicas lexicográficamente por su serialización comprimida.
 * BIP327 exige un orden canónico (KeySort) para que todos los firmantes calculen
 * el MISMO conjunto L independientemente del orden en que las reciban.
 */
export function sortPublicKeys(keys: Point[]): Point[] {
  return [...keys].sort((a, b) =>
    compressPublicKey(a).localeCompare(compressPublicKey(b))
  );
}

/**
 * Calcula L = H_list(P₁ ‖ P₂ ‖ … ‖ Pₙ): el compromiso con TODO el conjunto de
 * claves. Es lo que ata cada coeficiente al grupo entero y bloquea el rogue-key.
 */
function hashKeyList(keys: Point[]): Uint8Array {
  const serialized = keys.map((k) => hexToBytes(compressPublicKey(k)));
  const total = serialized.reduce((n, s) => n + s.length, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const s of serialized) { buf.set(s, off); off += s.length; }
  return taggedHash('KeyAgg list', buf);
}

/**
 * Coeficiente de agregación de la clave Pᵢ: aᵢ = H_agg(L ‖ Pᵢ) mod n.
 * Depende de L (todas las claves), por eso no se puede cancelar una clave ajena.
 */
export function keyAggCoefficient(L: Uint8Array, key: Point): bigint {
  const input = concat(L, hexToBytes(compressPublicKey(key)));
  return mod(bytesToBigint(taggedHash('KeyAgg coefficient', input)), N);
}

/**
 * Agrega n claves públicas en una sola: Q = Σ aᵢ·Pᵢ.
 *
 * El resultado Q.x es la x-only pubkey que iría en un output tr(Q). Como BIP340
 * asume y par, si Q tiene y impar marcamos parityNegated (se compensa negando
 * las claves privadas al firmar).
 */
export function aggregateKeys(publicKeys: Point[]): KeyAggResult {
  const sorted = sortPublicKeys(publicKeys);
  const L = hashKeyList(sorted);
  const coefficients = sorted.map((k) => keyAggCoefficient(L, k));

  // Q = Σ aᵢ·Pᵢ
  let Q: Point = null;
  for (let i = 0; i < sorted.length; i++) {
    Q = pointAdd(Q, scalarMultiply(coefficients[i], sorted[i]));
  }
  if (Q === null) throw new Error('Agregación degenerada: Q es el punto en el infinito');

  const parityNegated = Q.y % 2n !== 0n;

  return {
    publicKeys: sorted,
    L: bytesToHex(L),
    coefficients,
    aggregatePoint: Q,
    aggregateXOnly: Q.x,
    parityNegated,
  };
}

// ─── Paso 2: Nonces (ronda 1) ───────────────────────────────

/**
 * Genera el par de nonces de un firmante (la esencia del "2" en MuSig2).
 *
 * Cada firmante produce DOS nonces secretos k1,k2 y publica R1=k1·G, R2=k2·G.
 * En producción se derivan determinísticamente (BIP327 nonce_gen) mezclando
 * clave secreta, mensaje, aggpk y aleatoriedad. Aquí aceptamos los escalares
 * directamente para poder hacer sesiones reproducibles en tests y en el explorer.
 */
export function generateNonce(k1: bigint, k2: bigint): { secret: SecretNonce; pub: PublicNonce } {
  const R1 = scalarMultiply(mod(k1, N), G);
  const R2 = scalarMultiply(mod(k2, N), G);
  if (R1 === null || R2 === null) throw new Error('Nonce nulo: elige otros k');
  return { secret: { k1: mod(k1, N), k2: mod(k2, N) }, pub: { R1, R2 } };
}

/**
 * Agrega los nonces de todos los firmantes y calcula el nonce efectivo R.
 *
 *   R₁ = Σ R_{i,1}      R₂ = Σ R_{i,2}
 *   b  = H_nonce(R₁ ‖ R₂ ‖ Q.x ‖ m)
 *   R  = R₁ + b·R₂
 *
 * Si R queda con y impar, marcamos parityNegated (se compensa negando todos los
 * nonces secretos al firmar), para que la firma final cumpla la convención BIP340.
 */
export function aggregateNonces(
  publicNonces: PublicNonce[],
  aggregateXOnly: bigint,
  message: Uint8Array,
): NonceAggResult {
  let R1: Point = null;
  let R2: Point = null;
  for (const pn of publicNonces) {
    R1 = pointAdd(R1, pn.R1);
    R2 = pointAdd(R2, pn.R2);
  }
  if (R1 === null || R2 === null) throw new Error('Suma de nonces degenerada');

  // b = H_nonce(R₁ ‖ R₂ ‖ Q.x ‖ m)
  const bInput = concat(
    hexToBytes(compressPublicKey(R1)),
    hexToBytes(compressPublicKey(R2)),
    bigintToBytes(aggregateXOnly, 32),
    message,
  );
  const bHashBytes = taggedHash('MuSig/noncecoef', bInput);
  const b = mod(bytesToBigint(bHashBytes), N);

  // R = R₁ + b·R₂
  const R = pointAdd(R1, scalarMultiply(b, R2));
  if (R === null) throw new Error('Nonce efectivo degenerado (R en el infinito)');

  const parityNegated = R.y % 2n !== 0n;

  return {
    R1, R2, b, bHash: bytesToHex(bHashBytes),
    R, finalNonceX: R.x, parityNegated,
  };
}

// ─── Paso 3: Challenge y firmas parciales (ronda 2) ──────────

/**
 * Challenge BIP340: e = H_sig(R.x ‖ Q.x ‖ m) mod n.
 * Idéntico al de una firma Schnorr normal — por eso la firma agregada es
 * indistinguible de una individual.
 */
export function computeChallenge(
  finalNonceX: bigint,
  aggregateXOnly: bigint,
  message: Uint8Array,
): { e: bigint; hash: string } {
  const input = concat(bigintToBytes(finalNonceX, 32), bigintToBytes(aggregateXOnly, 32), message);
  const hashBytes = taggedHash('BIP0340/challenge', input);
  return { e: mod(bytesToBigint(hashBytes), N), hash: bytesToHex(hashBytes) };
}

/**
 * Firma parcial de un firmante:
 *
 *   kᵢ = k_{i,1} + b·k_{i,2}          (combina sus dos nonces con b)
 *   sᵢ = kᵢ + e·aᵢ·dᵢ                 (contribución a la s final)
 *
 * Ajustes de paridad BIP340:
 *   - si R quedó con y impar, se niega kᵢ  (para que R final tenga y par)
 *   - si Q quedó con y impar, se niega dᵢ  (para firmar bajo -Q, de y par)
 * Estos dos negados se cancelan en la ecuación de verificación y dejan una
 * firma válida contra la x-only Q.x.
 */
export function partialSign(
  signer: Signer,
  secretNonce: SecretNonce,
  coefficient: bigint,       // aᵢ de este firmante
  nonceAgg: NonceAggResult,
  keyAgg: KeyAggResult,
  challenge: bigint,         // e
  index: number,
): PartialSignature {
  // kᵢ = k1 + b·k2, negado si R tiene y impar
  let ki = mod(secretNonce.k1 + nonceAgg.b * secretNonce.k2, N);
  if (nonceAgg.parityNegated) ki = mod(N - ki, N);

  // dᵢ negado si Q tiene y impar (firmamos bajo -Q, que tiene y par)
  let di = signer.privateKey;
  if (keyAgg.parityNegated) di = mod(N - di, N);

  // sᵢ = kᵢ + e·aᵢ·dᵢ
  const s = mod(ki + mod(challenge * mod(coefficient * di, N), N), N);

  return { index, s, effectiveNonce: ki, coefficient };
}

/**
 * Verifica una firma PARCIAL sin conocer la secreta del firmante:
 *
 *   sᵢ·G  ==  Rᵢ,eff  +  e·aᵢ·(g·Pᵢ)
 *
 * donde Rᵢ,eff = ±(R_{i,1} + b·R_{i,2}) según la paridad de R, y g=±1 según la
 * paridad de Q. Esto permite detectar QUIÉN mandó una firma parcial inválida
 * antes de agregar (útil para no arruinar toda la sesión por un firmante).
 */
export function partialVerify(
  partial: PartialSignature,
  publicNonce: PublicNonce,
  signerPublicKey: Point,
  nonceAgg: NonceAggResult,
  keyAgg: KeyAggResult,
  challenge: bigint,
): boolean {
  // lado izquierdo: sᵢ·G
  const lhs = scalarMultiply(partial.s, G);

  // Rᵢ,eff = R_{i,1} + b·R_{i,2}, negado si R tiene y impar
  let Reff = pointAdd(publicNonce.R1, scalarMultiply(nonceAgg.b, publicNonce.R2));
  if (nonceAgg.parityNegated) Reff = negate(Reff);

  // g·Pᵢ  (Pᵢ negada si Q tiene y impar)
  const Pi = keyAgg.parityNegated ? negate(signerPublicKey) : signerPublicKey;

  // e·aᵢ·Pᵢ
  const term = scalarMultiply(mod(challenge * partial.coefficient, N), Pi);

  const rhs = pointAdd(Reff, term);
  return pointsEqual(lhs, rhs);
}

// ─── Paso 4: Agregación de firmas parciales ─────────────────

/**
 * Agrega las firmas parciales en la s final: s = Σ sᵢ mod n.
 * Combinada con R.x da la firma Schnorr (R.x, s) verificable con BIP340.
 */
export function aggregatePartialSignatures(
  partials: PartialSignature[],
  finalNonceX: bigint,
): SchnorrSignature {
  const s = partials.reduce((acc, p) => mod(acc + p.s, N), 0n);
  return { r: finalNonceX, s };
}

// ─── Sesión completa (para el explorer / tests) ─────────────

/**
 * Ejecuta una sesión MuSig2 completa localmente (simulamos a todos los firmantes)
 * y devuelve TODOS los pasos intermedios. La firma resultante se puede verificar
 * con schnorrVerify(message, signature, keyAgg.aggregateXOnly).
 */
export function runMuSig2Session(
  signers: Signer[],
  secretNonces: SecretNonce[],
  message: Uint8Array,
): MuSig2SessionResult {
  if (message.length !== 32) throw new Error('El mensaje debe ser de 32 bytes');
  if (signers.length !== secretNonces.length) throw new Error('Nº de firmantes ≠ nº de nonces');

  // Paso 1: agregar claves
  const keyAgg = aggregateKeys(signers.map((s) => s.publicKey));

  // Reordenar firmantes y nonces para que coincidan con el orden canónico de keyAgg
  const order = keyAgg.publicKeys.map((pk) => {
    const idx = signers.findIndex((s) => pointsEqual(s.publicKey, pk));
    if (idx === -1) throw new Error('Clave agregada no corresponde a ningún firmante');
    return idx;
  });
  const orderedSigners = order.map((i) => signers[i]);
  const orderedSecretNonces = order.map((i) => secretNonces[i]);

  // Paso 2 (ronda 1): nonces públicos
  const publicNonces = orderedSecretNonces.map((sn) => generateNonce(sn.k1, sn.k2).pub);
  const nonceAgg = aggregateNonces(publicNonces, keyAgg.aggregateXOnly, message);

  // Paso 3 (ronda 2): challenge + firmas parciales
  const { e, hash } = computeChallenge(nonceAgg.finalNonceX, keyAgg.aggregateXOnly, message);
  const partialSignatures = orderedSigners.map((signer, i) =>
    partialSign(signer, orderedSecretNonces[i], keyAgg.coefficients[i], nonceAgg, keyAgg, e, i)
  );

  // Paso 4: agregar
  const signature = aggregatePartialSignatures(partialSignatures, nonceAgg.finalNonceX);
  const signatureHex = bytesToHex(bigintToBytes(signature.r, 32)) + bytesToHex(bigintToBytes(signature.s, 32));

  return {
    keyAgg,
    publicNonces,
    nonceAgg,
    challenge: e,
    challengeHash: hash,
    partialSignatures,
    s: signature.s,
    signature,
    signatureHex,
    message: bytesToHex(message),
  };
}

// ─── Utilidades ─────────────────────────────────────────────

/** -P : el inverso aditivo de un punto (misma x, y = p - y). */
function negate(point: Point): Point {
  if (point === null) return null;
  return { x: point.x, y: mod(-point.y) };
}

/** Igualdad de puntos (incluye el punto en el infinito). */
function pointsEqual(a: Point, b: Point): boolean {
  if (a === null || b === null) return a === b;
  return a.x === b.x && a.y === b.y;
}

/** Reconstruye el punto de aggregación par desde su x-only (útil para verificar). */
export function aggregatePointFromXOnly(x: bigint): Point {
  return liftX(x);
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
