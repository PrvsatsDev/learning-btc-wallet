/**
 * Taproot (BIP341) — el "tweak" de la clave de salida.
 *
 * Taproot (SegWit v1, activado en 2021) es el mayor cambio de Bitcoin desde SegWit.
 * Su idea central es sorprendentemente elegante:
 *
 *   Toda salida Taproot es UNA sola clave pública Schnorr (x-only, 32 bytes).
 *   Pero esa clave no es cualquiera: es una clave INTERNA P "ajustada" (tweaked)
 *   con un compromiso criptográfico:
 *
 *       Q = P + t·G        con   t = taggedHash("TapTweak", P.x ‖ merkleRoot)
 *
 *   - P  = "internal key" — la clave que controla el gasto por KEY-PATH.
 *   - merkleRoot = raíz de un árbol de scripts alternativos (vacío si no hay).
 *   - Q  = "output key" — lo que aparece en la dirección `bc1p…` (el scriptPubKey
 *          es `OP_1 <Q.x>`).
 *
 * ¿Por qué sumar t·G en vez de usar P a secas? Porque así Q "esconde" un árbol de
 * condiciones de gasto SIN revelarlas hasta que se usan. Hay DOS formas de gastar:
 *
 *   1. KEY-PATH  — firmas con la privada ajustada  q = p + t  (mod n). En la
 *      cadena se ve una única firma Schnorr: indistinguible de un single-sig
 *      normal. Máxima privacidad y el caso más barato. (Es lo de este módulo.)
 *
 *   2. SCRIPT-PATH — revelas una hoja del árbol (un script) + una prueba Merkle
 *      de que estaba comprometida en Q. Solo se revela la rama que usas; el resto
 *      del árbol nunca se ve. (Vendrá en el módulo siguiente: TapLeaf, TapBranch,
 *      control block, OP_CHECKSIGADD.)
 *
 * Detalle clave (BIP341): incluso una salida "solo key-path" SE AJUSTA igualmente,
 * con merkleRoot VACÍO. Así se prueba que NO hay ningún script escondido (si se
 * usara P directamente, nadie podría descartar que P ocultaba un tweak con scripts).
 *
 * Todo es x-only con convención de Y par (como en BIP340/Schnorr): una clave de
 * 32 bytes representa el punto cuya coordenada Y es par.
 *
 * Verificado contra los vectores oficiales de BIP341 (ver taproot.test.ts).
 */

import {
  G, N, mod, scalarMultiply, pointAdd, getPublicKey,
  type Point,
} from './secp256k1';
import { taggedHash, liftX, schnorrSign, type SchnorrSignResult } from './schnorr';
import { bigintToBytes, bytesToBigint, bytesToHex } from './hmac';
import { createP2TR, addressP2TR } from './script';

// ─── El tweak BIP341 ────────────────────────────────────────

export interface TapTweakResult {
  tweak: Uint8Array;   // los 32 bytes de taggedHash("TapTweak", P.x ‖ merkleRoot)
  t: bigint;           // el mismo valor como escalar (debe ser < n)
}

/**
 * Calcula el tweak de Taproot: t = taggedHash("TapTweak", P.x ‖ merkleRoot).
 *
 * @param internalX  - coordenada x de la clave interna P (x-only, 32 bytes)
 * @param merkleRoot - raíz del árbol de scripts (32 bytes) u omitido si no hay árbol
 */
export function tapTweak(internalX: bigint, merkleRoot?: Uint8Array): TapTweakResult {
  const px = bigintToBytes(internalX, 32);
  // Sin árbol de scripts, el mensaje del hash es SOLO P.x (merkleRoot vacío).
  const data = merkleRoot && merkleRoot.length > 0 ? concat(px, merkleRoot) : px;
  const tweak = taggedHash('TapTweak', data);
  const t = bytesToBigint(tweak);
  if (t >= N) throw new Error('tweak ≥ n (probabilidad ínfima): clave interna inválida');
  return { tweak, t };
}

// ─── Ajuste de la clave PÚBLICA (para direcciones / recibir) ─

export interface TweakedPubKey {
  outputKey: bigint;   // Q.x — la x-only que va en el scriptPubKey `OP_1 <Q.x>`
  parity: number;      // 0 si Q.y es par, 1 si impar (se necesita en script-path)
  point: Point;        // el punto Q completo
  tweak: Uint8Array;   // el tweak usado (didáctico)
}

/**
 * Ajusta una clave interna x-only y devuelve la OUTPUT KEY Q = P + t·G.
 *
 * La clave interna x-only se "levanta" (liftX) al punto de Y par, como manda la
 * convención x-only. La paridad de Q sí importa: se necesita luego para el
 * "control block" del gasto por script-path.
 */
export function tweakPublicKey(internalX: bigint, merkleRoot?: Uint8Array): TweakedPubKey {
  const P = liftX(internalX);
  if (P === null) throw new Error('internalX no está en la curva');
  const { tweak, t } = tapTweak(internalX, merkleRoot);
  const Q = pointAdd(P, scalarMultiply(t, G));
  if (Q === null) throw new Error('Q es el punto en el infinito (imposible en la práctica)');
  return { outputKey: Q.x, parity: Number(Q.y & 1n), point: Q, tweak };
}

// ─── Ajuste de la clave PRIVADA (para gastar por key-path) ──

/**
 * Ajusta una clave privada para gastar por key-path: q = (d' + t) mod n.
 *
 * Sutileza x-only: la clave interna representa el punto de Y PAR. Si d·G tiene Y
 * impar, primero se niega (d' = n − d) para que d'·G sea justo el punto par cuya
 * x es la clave interna. Luego se le suma el tweak. El resultado q es la privada
 * que firma como la output key Q.
 */
export function tweakPrivateKey(privateKey: bigint, merkleRoot?: Uint8Array): bigint {
  const P = getPublicKey(privateKey);
  if (P === null) throw new Error('clave privada inválida');
  const dEven = P.y % 2n === 0n ? privateKey : N - privateKey;
  const internalX = P.x;
  const { t } = tapTweak(internalX, merkleRoot);
  return mod(dEven + t, N);
}

// ─── Dirección y scriptPubKey ───────────────────────────────

/** scriptPubKey P2TR: `OP_1 <32B output key>`. */
export function p2trScriptPubKey(internalX: bigint, merkleRoot?: Uint8Array): Uint8Array {
  const { outputKey } = tweakPublicKey(internalX, merkleRoot);
  return createP2TR(bigintToBytes(outputKey, 32));
}

/** Dirección Taproot `bc1p…` (bech32m) a partir de una clave interna x-only. */
export function p2trAddress(internalX: bigint, mainnet = true, merkleRoot?: Uint8Array): string {
  const { outputKey } = tweakPublicKey(internalX, merkleRoot);
  return addressP2TR(bigintToBytes(outputKey, 32), mainnet);
}

// ─── Firma key-path (didáctica: gasto + verificación) ───────

export interface KeyPathSignResult {
  outputKey: bigint;             // Q.x — la clave contra la que se verifica
  tweakedPrivateKey: bigint;     // q = d' + t
  schnorr: SchnorrSignResult;    // pasos internos de la firma (Schnorr BIP340)
  signatureHex: string;          // 64 bytes: R.x ‖ s
}

/**
 * Firma un mensaje (normalmente el sighash BIP341) por key-path.
 *
 * Ajusta la clave privada y firma con Schnorr. La firma resultante es válida
 * contra la OUTPUT KEY Q — es decir, contra lo que hay en el scriptPubKey. En la
 * cadena solo se ve esa firma de 64 bytes: nadie puede saber si había o no un
 * árbol de scripts detrás. El sighash de Taproot (BIP341) es otro algoritmo (no
 * BIP143); se implementa aparte. Aquí `message` es cualquier hash de 32 bytes.
 */
export function keyPathSign(
  message: Uint8Array,
  privateKey: bigint,
  merkleRoot?: Uint8Array,
  auxRand: Uint8Array = new Uint8Array(32),
): KeyPathSignResult {
  const q = tweakPrivateKey(privateKey, merkleRoot);
  const schnorr = schnorrSign(message, q, auxRand);
  const Q = getPublicKey(q)!;
  return {
    outputKey: Q.x,
    tweakedPrivateKey: q,
    schnorr,
    signatureHex: schnorr.signatureHex,
  };
}

// ─── Utilidades ─────────────────────────────────────────────

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

export { bytesToHex };
