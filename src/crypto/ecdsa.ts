/**
 * Firmas ECDSA (Elliptic Curve Digital Signature Algorithm) — desde cero.
 *
 * ECDSA es el esquema de firma digital que Bitcoin usó desde el principio.
 * Permite demostrar que conoces una clave privada sin revelarla.
 *
 * El flujo es:
 *   1. Hashear el mensaje → z (un número de 256 bits)
 *   2. Generar un nonce k (RFC 6979 para determinismo)
 *   3. Calcular R = k × G, tomar r = R.x mod n
 *   4. Calcular s = k⁻¹ · (z + r·d) mod n
 *   5. La firma es (r, s)
 *
 * Para verificar (sin conocer d):
 *   1. Calcular u1 = z · s⁻¹ mod n, u2 = r · s⁻¹ mod n
 *   2. Calcular R' = u1·G + u2·PubKey
 *   3. Si R'.x === r → firma válida
 *
 * ¿Por qué funciona? Porque s = k⁻¹(z + rd), así que:
 *   u1·G + u2·P = (z·s⁻¹)·G + (r·s⁻¹)·(d·G) = s⁻¹·(z + rd)·G = k·G = R ✓
 */

import {
  G, N, mod, modInverse,
  scalarMultiply, pointAdd,
  type Point,
} from './secp256k1';
import { hmacSha256, bigintToBytes, bytesToBigint, bytesToHex } from './hmac';

// ─── Tipos ──────────────────────────────────────────────────

export interface EcdsaSignature {
  r: bigint;
  s: bigint;
}

/** Pasos intermedios de la firma (para visualización) */
export interface EcdsaSignResult {
  messageHash: string;      // hash z del mensaje
  z: bigint;                // z como número
  k: bigint;                // nonce usado
  R: Point;                 // punto R = k × G
  r: bigint;                // R.x mod n
  s: bigint;                // k⁻¹(z + rd) mod n
  sLow: bigint;             // s normalizado (low-s)
  der: Uint8Array;          // firma en formato DER
  derFields: DerField[];    // campos DER desglosados
  signature: EcdsaSignature;
}

/** Pasos intermedios de la verificación */
export interface EcdsaVerifyResult {
  valid: boolean;
  z: bigint;
  sInv: bigint;             // s⁻¹ mod n
  u1: bigint;               // z · s⁻¹ mod n
  u2: bigint;               // r · s⁻¹ mod n
  R1: Point;                // u1 · G
  R2: Point;                // u2 · PubKey
  Rprime: Point;            // R1 + R2
  rRecovered: bigint;       // R'.x mod n
}

/** Campo individual en la codificación DER */
export interface DerField {
  name: string;
  bytes: number[];
  description: string;
  color: string;
}

// ─── RFC 6979: nonce determinístico ─────────────────────────
/**
 * Genera un nonce k determinístico según RFC 6979.
 *
 * ¿Por qué no usar Math.random()? Porque un k malo es CATASTRÓFICO:
 * - Si reutilizas k en dos firmas diferentes, se puede calcular tu clave privada
 *   (esto le pasó a Sony con PlayStation 3 en 2010)
 * - Si k es predecible, también se filtra la clave
 *
 * RFC 6979 resuelve esto derivando k de forma determinística a partir de
 * la clave privada + el mensaje. Mismo input → mismo k → misma firma.
 * Diferente mensaje → diferente k → seguro.
 */
export function rfc6979(messageHash: Uint8Array, privateKey: bigint): bigint {
  const x = bigintToBytes(privateKey, 32);
  const h1 = messageHash;

  // Inicializar V y K
  let v: Uint8Array = new Uint8Array(32).fill(0x01); // V = 0x01 0x01 ... 0x01
  let kHmac: Uint8Array = new Uint8Array(32).fill(0x00); // K = 0x00 0x00 ... 0x00

  // K = HMAC_K(V || 0x00 || x || h1)
  kHmac = hmacSha256(kHmac, concat(v, [0x00], x, h1));
  // V = HMAC_K(V)
  v = hmacSha256(kHmac, v);

  // K = HMAC_K(V || 0x01 || x || h1)
  kHmac = hmacSha256(kHmac, concat(v, [0x01], x, h1));
  // V = HMAC_K(V)
  v = hmacSha256(kHmac, v);

  // Generar candidatos hasta encontrar uno válido
  while (true) {
    v = hmacSha256(kHmac, v);
    const candidate = bytesToBigint(v);

    if (candidate >= 1n && candidate < N) {
      return candidate;
    }

    // Si no es válido, seguir iterando
    kHmac = hmacSha256(kHmac, concat(v, [0x00]));
    v = hmacSha256(kHmac, v);
  }
}

// ─── Firma ──────────────────────────────────────────────────

/**
 * Firma un mensaje con ECDSA.
 *
 * @param messageHash - Hash SHA-256 del mensaje (32 bytes)
 * @param privateKey  - Clave privada (bigint entre 1 y N-1)
 * @param customK     - Nonce manual (SOLO para demostración educativa, nunca en producción)
 */
export function ecdsaSign(
  messageHash: Uint8Array,
  privateKey: bigint,
  customK?: bigint
): EcdsaSignResult {
  const z = bytesToBigint(messageHash);

  // Paso 1: Obtener nonce k
  const k = customK ?? rfc6979(messageHash, privateKey);

  // Paso 2: R = k × G
  const R = scalarMultiply(k, G);
  if (R === null) throw new Error('R es el punto en el infinito');

  // Paso 3: r = R.x mod n
  const r = mod(R.x, N);
  if (r === 0n) throw new Error('r = 0, elegir otro k');

  // Paso 4: s = k⁻¹ · (z + r·d) mod n
  const kInv = modInverse(k, N);
  let s = mod(kInv * (z + r * privateKey), N);
  if (s === 0n) throw new Error('s = 0, elegir otro k');

  // Paso 5: Normalizar s (low-s rule, BIP-62)
  // Bitcoin requiere s ≤ n/2 para evitar maleabilidad de firma.
  // Si s > n/2, usar n - s (que es igualmente válido matemáticamente).
  const sLow = s > N / 2n ? N - s : s;

  const signature: EcdsaSignature = { r, s: sLow };
  const { der, fields: derFields } = derEncode(signature);

  return {
    messageHash: bytesToHex(messageHash),
    z,
    k,
    R,
    r,
    s,
    sLow,
    der,
    derFields,
    signature,
  };
}

// ─── Verificación ───────────────────────────────────────────

/**
 * Verifica una firma ECDSA.
 *
 * La magia: podemos verificar que alguien conoce la clave privada
 * sin que la revele, usando solo la firma (r, s) y la clave pública.
 */
export function ecdsaVerify(
  messageHash: Uint8Array,
  signature: EcdsaSignature,
  publicKey: Point,
): EcdsaVerifyResult {
  const { r, s } = signature;
  const z = bytesToBigint(messageHash);

  if (publicKey === null) {
    return { valid: false, z, sInv: 0n, u1: 0n, u2: 0n, R1: null, R2: null, Rprime: null, rRecovered: 0n };
  }

  // Paso 1: s⁻¹ mod n
  const sInv = modInverse(s, N);

  // Paso 2: u1 = z · s⁻¹ mod n
  const u1 = mod(z * sInv, N);

  // Paso 3: u2 = r · s⁻¹ mod n
  const u2 = mod(r * sInv, N);

  // Paso 4: R' = u1·G + u2·PubKey
  const R1 = scalarMultiply(u1, G);
  const R2 = scalarMultiply(u2, publicKey);
  const Rprime = pointAdd(R1, R2);

  if (Rprime === null) {
    return { valid: false, z, sInv, u1, u2, R1, R2, Rprime, rRecovered: 0n };
  }

  // Paso 5: ¿R'.x mod n === r?
  const rRecovered = mod(Rprime.x, N);
  const valid = rRecovered === r;

  return { valid, z, sInv, u1, u2, R1, R2, Rprime, rRecovered };
}

// ─── Codificación DER ───────────────────────────────────────
/**
 * DER (Distinguished Encoding Rules) es el formato que Bitcoin usa
 * para codificar firmas ECDSA dentro de las transacciones.
 *
 * Estructura:
 *   30 [longitud total]
 *     02 [longitud r] [bytes de r]
 *     02 [longitud s] [bytes de s]
 *
 * Reglas:
 * - r y s son enteros big-endian con signo
 * - Si el byte más significativo tiene el bit 7 = 1, se añade 0x00 al inicio
 *   (para que no se interprete como negativo)
 * - No se permiten ceros iniciales innecesarios
 */
export function derEncode(sig: EcdsaSignature): { der: Uint8Array; fields: DerField[] } {
  const rBytes = bigintToMinBytes(sig.r);
  const sBytes = bigintToMinBytes(sig.s);

  const fields: DerField[] = [
    { name: 'Tipo SEQUENCE', bytes: [0x30], description: 'Indica que es una secuencia DER', color: '#a78bfa' },
    { name: 'Longitud total', bytes: [rBytes.length + sBytes.length + 4], description: `${rBytes.length + sBytes.length + 4} bytes de contenido`, color: '#a78bfa' },
    { name: 'Tipo INTEGER', bytes: [0x02], description: 'r es un entero', color: '#60a5fa' },
    { name: 'Longitud r', bytes: [rBytes.length], description: `r ocupa ${rBytes.length} bytes`, color: '#60a5fa' },
    { name: 'Valor r', bytes: Array.from(rBytes), description: 'R.x mod n — primera mitad de la firma', color: '#60a5fa' },
    { name: 'Tipo INTEGER', bytes: [0x02], description: 's es un entero', color: '#4ade80' },
    { name: 'Longitud s', bytes: [sBytes.length], description: `s ocupa ${sBytes.length} bytes`, color: '#4ade80' },
    { name: 'Valor s', bytes: Array.from(sBytes), description: 'k⁻¹(z + rd) mod n — segunda mitad', color: '#4ade80' },
  ];

  const allBytes: number[] = [];
  for (const field of fields) {
    allBytes.push(...field.bytes);
  }

  return { der: new Uint8Array(allBytes), fields };
}

/** Decodifica una firma DER a (r, s) */
export function derDecode(der: Uint8Array): EcdsaSignature {
  if (der[0] !== 0x30) throw new Error('No es una secuencia DER');
  if (der[2] !== 0x02) throw new Error('r no es INTEGER');

  const rLen = der[3];
  const rBytes = der.slice(4, 4 + rLen);
  const r = bytesToBigint(rBytes);

  const sStart = 4 + rLen;
  if (der[sStart] !== 0x02) throw new Error('s no es INTEGER');
  const sLen = der[sStart + 1];
  const sBytes = der.slice(sStart + 2, sStart + 2 + sLen);
  const s = bytesToBigint(sBytes);

  return { r, s };
}

// ─── Demostración: ataque por reutilización de k ────────────
/**
 * Si se firma dos mensajes diferentes con el MISMO k,
 * cualquiera puede calcular la clave privada.
 *
 * Dados (r, s1) para m1 y (r, s2) para m2 con el mismo k:
 *   s1 = k⁻¹(z1 + r·d)
 *   s2 = k⁻¹(z2 + r·d)
 *   s1 - s2 = k⁻¹(z1 - z2)
 *   k = (z1 - z2) / (s1 - s2) mod n
 *   d = (s1·k - z1) / r mod n
 *
 * Esto es exactamente lo que pasó con PlayStation 3:
 * Sony usó un k fijo para todas las firmas.
 */
export function recoverPrivateKeyFromReusedK(
  z1: bigint, s1: bigint,
  z2: bigint, s2: bigint,
  r: bigint
): { k: bigint; privateKey: bigint } {
  // k = (z1 - z2) · (s1 - s2)⁻¹ mod n
  const k = mod((z1 - z2) * modInverse(mod(s1 - s2, N), N), N);

  // d = (s1 · k - z1) · r⁻¹ mod n
  const privateKey = mod((s1 * k - z1) * modInverse(r, N), N);

  return { k, privateKey };
}

// ─── Utilidades internas ────────────────────────────────────

/** Convierte bigint a bytes mínimos con prefijo 0x00 si el MSB es 1 (DER signed integer) */
function bigintToMinBytes(n: bigint): Uint8Array {
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;

  // Si el bit más significativo es 1, añadir 0x00 para que sea positivo en DER
  if (parseInt(hex[0], 16) >= 8) {
    hex = '00' + hex;
  }

  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Concatena múltiples arrays de bytes */
function concat(...arrays: (Uint8Array | number[])[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr instanceof Uint8Array ? arr : new Uint8Array(arr), offset);
    offset += arr.length;
  }
  return result;
}

/** Convierte hex string a bytes */
export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
