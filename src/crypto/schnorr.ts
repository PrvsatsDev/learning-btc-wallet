/**
 * Firmas Schnorr (BIP340) — implementadas desde cero.
 *
 * Schnorr es el esquema de firma que Bitcoin adoptó con Taproot (2021).
 * Es matemáticamente más simple que ECDSA y tiene propiedades superiores:
 *
 *   1. Linealidad: permite agregar firmas (multisig nativo, MuSig2)
 *   2. Sin inversa modular: la verificación es más eficiente
 *   3. Verificación por lotes (batch verification): N firmas casi tan rápido como 1
 *   4. Formato compacto: 64 bytes fijos (vs DER variable en ECDSA)
 *
 * ¿Por qué Bitcoin no usó Schnorr desde el principio?
 * Claus Schnorr tenía una patente que expiró en 2008 — justo antes de Bitcoin (2009).
 * Satoshi eligió ECDSA porque era libre de patentes y estándar.
 *
 * El flujo de firma (BIP340):
 *   1. Generar nonce auxiliar → derivar k (nonce) mediante tagged hash
 *   2. R = k × G (solo se usa R.x — "x-only public key")
 *   3. e = tagged_hash("BIP0340/challenge", R.x || P.x || message)
 *   4. s = k + e·d mod n
 *   5. La firma es (R.x, s) — 64 bytes
 *
 * Para verificar: s·G == R + e·P
 *   (porque s·G = (k + e·d)·G = k·G + e·d·G = R + e·P ✓)
 */

import {
  G, N, P, mod,
  scalarMultiply, pointAdd,
  type Point,
} from './secp256k1';
import { sha256 } from './sha256';
import { bigintToBytes, bytesToBigint, bytesToHex } from './hmac';

// ─── Tipos ──────────────────────────────────────────────────

export interface SchnorrSignature {
  r: bigint;  // coordenada x del punto R (32 bytes)
  s: bigint;  // escalar s (32 bytes)
}

/** Pasos intermedios de la firma Schnorr */
export interface SchnorrSignResult {
  privateKey: bigint;
  publicKeyX: bigint;          // x-only public key (32 bytes)
  message: string;             // mensaje original hex
  auxRand: string;             // randomness auxiliar hex
  t: string;                   // d XOR tagged_hash("BIP0340/aux", aux) hex
  nonceHash: string;           // tagged_hash("BIP0340/nonce", t || P.x || m) hex
  k: bigint;                   // nonce final
  R: Point;                    // punto R = k × G
  rX: bigint;                  // R.x (lo que va en la firma)
  e: bigint;                   // challenge: tagged_hash("BIP0340/challenge", R.x || P.x || m)
  eHash: string;               // challenge hash hex
  s: bigint;                   // s = k + e·d mod n
  signature: SchnorrSignature;
  signatureHex: string;        // 64 bytes hex: R.x (32) || s (32)
}

/** Pasos intermedios de la verificación */
export interface SchnorrVerifyResult {
  valid: boolean;
  e: bigint;                   // challenge recalculado
  eHash: string;
  sG: Point;                   // s × G
  eP: Point;                   // e × P
  R: Point;                    // punto R reconstruido
  rExpected: bigint;           // R.x esperado de la firma
  rRecovered: bigint;          // R.x recuperado
}

// ─── Tagged Hash ────────────────────────────────────────────
/**
 * Tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)
 *
 * BIP340 usa "tagged hashes" para separación de dominios (domain separation).
 * Esto evita que un hash calculado para un propósito (ej: nonce) pueda
 * ser reutilizado en otro contexto (ej: challenge).
 *
 * El SHA256(tag) se calcula una vez y se usa como prefijo.
 * Es como un "namespace" para hashes.
 */
export function taggedHash(tag: string, data: Uint8Array): Uint8Array {
  const tagHash = hexToBytes(sha256(new TextEncoder().encode(tag)).hash);
  // El prefijo es SHA256(tag) || SHA256(tag) (repetido dos veces)
  const prefixed = new Uint8Array(tagHash.length * 2 + data.length);
  prefixed.set(tagHash, 0);
  prefixed.set(tagHash, tagHash.length);
  prefixed.set(data, tagHash.length * 2);
  return hexToBytes(sha256(prefixed).hash);
}

// ─── Firma Schnorr ──────────────────────────────────────────

/**
 * Firma un mensaje de 32 bytes con Schnorr (BIP340).
 *
 * @param message    - 32 bytes del mensaje (normalmente un hash)
 * @param privateKey - Clave privada
 * @param auxRand    - 32 bytes de aleatoriedad auxiliar (para protección contra side-channels)
 */
export function schnorrSign(
  message: Uint8Array,
  privateKey: bigint,
  auxRand: Uint8Array = new Uint8Array(32)
): SchnorrSignResult {
  if (message.length !== 32) throw new Error('El mensaje debe ser de 32 bytes');

  // Paso 1: Asegurar que la clave pública tiene y par
  // BIP340 usa "x-only public keys" — siempre se asume y par.
  // Si y es impar, negamos d (usamos n - d).
  const pubKey = scalarMultiply(privateKey, G);
  if (pubKey === null) throw new Error('Clave pública inválida');

  let d = privateKey;
  if (pubKey.y % 2n !== 0n) {
    d = N - d; // negar la clave para que y sea par
  }
  const publicKeyX = pubKey.x;

  // Paso 2: t = d XOR tagged_hash("BIP0340/aux", auxRand)
  // El XOR con aleatoriedad auxiliar protege contra ataques de canal lateral
  // (side-channel attacks que midan timing o consumo eléctrico)
  const auxHash = taggedHash('BIP0340/aux', auxRand);
  const dBytes = bigintToBytes(d, 32);
  const tBytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    tBytes[i] = dBytes[i] ^ auxHash[i];
  }

  // Paso 3: Derivar nonce k = tagged_hash("BIP0340/nonce", t || P.x || m)
  const pxBytes = bigintToBytes(publicKeyX, 32);
  const nonceInput = concat(tBytes, pxBytes, message);
  const nonceHashBytes = taggedHash('BIP0340/nonce', nonceInput);
  let k = mod(bytesToBigint(nonceHashBytes), N);
  if (k === 0n) throw new Error('k = 0, cambiar auxRand');

  // Paso 4: R = k × G
  let R = scalarMultiply(k, G);
  if (R === null) throw new Error('R es el punto en el infinito');

  // Asegurar que R.y es par (si no, negar k)
  if (R.y % 2n !== 0n) {
    k = N - k;
    R = scalarMultiply(k, G)!;
  }

  const rX = R.x;

  // Paso 5: e = tagged_hash("BIP0340/challenge", R.x || P.x || m) mod n
  const challengeInput = concat(bigintToBytes(rX, 32), pxBytes, message);
  const eHashBytes = taggedHash('BIP0340/challenge', challengeInput);
  const e = mod(bytesToBigint(eHashBytes), N);

  // Paso 6: s = (k + e·d) mod n
  const s = mod(k + e * d, N);

  const signature: SchnorrSignature = { r: rX, s };
  const signatureHex = bigintToBytes(rX, 32).reduce((h, b) => h + b.toString(16).padStart(2, '0'), '')
    + bigintToBytes(s, 32).reduce((h, b) => h + b.toString(16).padStart(2, '0'), '');

  return {
    privateKey: d,
    publicKeyX,
    message: bytesToHex(message),
    auxRand: bytesToHex(auxRand),
    t: bytesToHex(tBytes),
    nonceHash: bytesToHex(nonceHashBytes),
    k,
    R,
    rX,
    e,
    eHash: bytesToHex(eHashBytes),
    s,
    signature,
    signatureHex,
  };
}

// ─── Verificación Schnorr ───────────────────────────────────

/**
 * Verifica una firma Schnorr (BIP340).
 *
 * La verificación es elegantemente simple:
 *   s·G = R + e·P
 *
 * Porque: s = k + e·d, así que
 *   s·G = (k + e·d)·G = k·G + e·(d·G) = R + e·P ✓
 *
 * Comparado con ECDSA que necesita calcular s⁻¹ (inversa modular),
 * Schnorr solo necesita sumas y multiplicaciones escalares.
 */
export function schnorrVerify(
  message: Uint8Array,
  signature: SchnorrSignature,
  publicKeyX: bigint,
): SchnorrVerifyResult {
  const { r, s } = signature;

  // Reconstruir el punto P desde x-only (asumiendo y par)
  const P_point = liftX(publicKeyX);
  if (P_point === null) {
    return { valid: false, e: 0n, eHash: '', sG: null, eP: null, R: null, rExpected: r, rRecovered: 0n };
  }

  // Recalcular el challenge e
  const challengeInput = concat(bigintToBytes(r, 32), bigintToBytes(publicKeyX, 32), message);
  const eHashBytes = taggedHash('BIP0340/challenge', challengeInput);
  const e = mod(bytesToBigint(eHashBytes), N);

  // Verificar: s·G == R + e·P
  // Equivalente a: R = s·G - e·P
  const sG = scalarMultiply(s, G);
  const eP = scalarMultiply(e, P_point);

  // Negar eP para hacer R = sG + (-eP) = sG - eP
  const ePneg: Point = eP ? { x: eP.x, y: mod(P - eP.y) } : null;
  const R = pointAdd(sG, ePneg);

  if (R === null) {
    return { valid: false, e, eHash: bytesToHex(eHashBytes), sG, eP, R: null, rExpected: r, rRecovered: 0n };
  }

  // R debe tener y par y R.x debe coincidir con r
  const rRecovered = R.x;
  const valid = R.y % 2n === 0n && rRecovered === r;

  return { valid, e, eHash: bytesToHex(eHashBytes), sG, eP, R, rExpected: r, rRecovered };
}

// ─── Utilidades ─────────────────────────────────────────────

/**
 * "Lift x" — reconstruir un punto de la curva desde solo la coordenada x.
 * Asume y par (convención BIP340 para x-only public keys).
 *
 * Calcula y = sqrt(x³ + 7) mod p
 * La raíz cuadrada en un campo primo se calcula como: y = (x³+7)^((p+1)/4) mod p
 * (funciona porque p ≡ 3 mod 4 para secp256k1)
 */
export function liftX(x: bigint): Point {
  if (x >= P) return null;
  const c = mod(x * x * x + 7n); // x³ + 7 mod p
  // sqrt via exponenciación: c^((p+1)/4) mod p
  const y = modPow(c, (P + 1n) / 4n, P);
  if (mod(y * y) !== c) return null; // no es un punto válido

  // Elegir y par
  return { x, y: y % 2n === 0n ? y : P - y };
}

/** Exponenciación modular rápida */
function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let result = 1n;
  base = mod(base, m);
  while (exp > 0n) {
    if (exp & 1n) result = mod(result * base, m);
    exp >>= 1n;
    base = mod(base * base, m);
  }
  return result;
}

/** Concatenar arrays de bytes */
function concat(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/** Convierte hex string a bytes */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
