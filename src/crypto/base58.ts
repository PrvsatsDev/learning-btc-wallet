/**
 * Base58 y Base58Check — la codificación de las direcciones Bitcoin clásicas.
 *
 * ¿Por qué Base58 y no Base64 o hexadecimal?
 * - Hex (Base16): demasiado largo (40 caracteres para 20 bytes)
 * - Base64: incluye caracteres confusos y problemáticos (+, /, 0, O, I, l)
 * - Base58: compacto y legible. Satoshi eliminó:
 *     0 (cero) y O (o mayúscula) — se confunden
 *     I (i mayúscula) y l (ele minúscula) — se confunden
 *     + y / — causan problemas en URLs y al hacer doble clic para seleccionar
 *
 * Base58Check añade un checksum de 4 bytes (primeros 4 bytes de SHA-256(SHA-256(payload)))
 * para que si copias mal una dirección, se detecte el error antes de enviar bitcoins.
 */

import { sha256Hex } from './sha256';

// ─── Alfabeto Base58 ─────────────────────────────────────────
// 58 caracteres: 1-9, A-H, J-N, P-Z, a-k, m-z
// (sin 0, O, I, l)
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE = BigInt(ALPHABET.length); // 58n

// ─── Utilidades ──────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** SHA-256 de bytes crudos */
function sha256Bytes(data: Uint8Array): string {
  return sha256Hex(data);
}

// ─── Base58 Encode ───────────────────────────────────────────
/**
 * Codifica un array de bytes en Base58.
 *
 * El algoritmo es esencialmente una conversión de base numérica:
 * interpretar los bytes como un número grande y dividir repetidamente por 58.
 *
 * Detalle importante: los bytes 0x00 al inicio se convierten en '1' (el primer
 * carácter del alfabeto). Esto preserva los ceros iniciales, que en Bitcoin
 * indican el tipo de red (mainnet = 0x00 → dirección empieza con '1').
 */
export function base58Encode(bytes: Uint8Array): string {
  // Contar ceros iniciales (se convierten en '1')
  let leadingZeros = 0;
  for (const byte of bytes) {
    if (byte !== 0) break;
    leadingZeros++;
  }

  // Convertir bytes a un número grande (big-endian)
  let num = BigInt('0x' + bytesToHex(bytes) || '0');

  // Dividir repetidamente por 58 y tomar el resto
  const chars: string[] = [];
  while (num > 0n) {
    const remainder = num % BASE;
    chars.push(ALPHABET[Number(remainder)]);
    num = num / BASE;
  }

  // Los restos se generaron en orden inverso
  chars.reverse();

  // Añadir '1' por cada byte 0x00 inicial
  return '1'.repeat(leadingZeros) + chars.join('');
}

// ─── Base58 Decode ───────────────────────────────────────────
/**
 * Decodifica un string Base58 a bytes.
 */
export function base58Decode(str: string): Uint8Array {
  // Contar '1' iniciales (representan bytes 0x00)
  let leadingOnes = 0;
  for (const char of str) {
    if (char !== '1') break;
    leadingOnes++;
  }

  // Convertir de Base58 a número
  let num = 0n;
  for (const char of str) {
    const index = ALPHABET.indexOf(char);
    if (index === -1) throw new Error(`Carácter inválido en Base58: ${char}`);
    num = num * BASE + BigInt(index);
  }

  // Convertir número a bytes
  const hex = num === 0n ? '' : num.toString(16).padStart(2, '0');
  const paddedHex = hex.length % 2 ? '0' + hex : hex;
  const dataBytes = hexToBytes(paddedHex);

  // Preponer los bytes 0x00
  const result = new Uint8Array(leadingOnes + dataBytes.length);
  result.set(dataBytes, leadingOnes);

  return result;
}

// ─── Base58Check ─────────────────────────────────────────────

export interface Base58CheckResult {
  address: string;
  version: number;
  payload: string;      // hash160 en hex
  checksum: string;     // 4 bytes de checksum en hex
  fullPayload: string;  // version + hash160 + checksum en hex
}

/**
 * Codifica con Base58Check: añade versión + checksum.
 *
 * Formato: Base58(version [1 byte] + payload [N bytes] + checksum [4 bytes])
 *
 * El checksum son los primeros 4 bytes de SHA256(SHA256(version + payload)).
 * Esto permite detectar errores: si copias mal una dirección, el checksum no cuadra.
 */
export function base58CheckEncode(version: number, payload: Uint8Array): Base58CheckResult {
  // Paso 1: Preponer el byte de versión
  const versionedPayload = new Uint8Array(1 + payload.length);
  versionedPayload[0] = version;
  versionedPayload.set(payload, 1);

  // Paso 2: Doble SHA-256 para el checksum
  const firstHash = sha256Bytes(versionedPayload);
  const secondHash = sha256Hex(hexToBytes(firstHash));
  const checksum = secondHash.slice(0, 8); // primeros 4 bytes (8 hex chars)

  // Paso 3: Concatenar version + payload + checksum
  const checksumBytes = hexToBytes(checksum);
  const fullPayload = new Uint8Array(versionedPayload.length + 4);
  fullPayload.set(versionedPayload);
  fullPayload.set(checksumBytes, versionedPayload.length);

  // Paso 4: Codificar en Base58
  const address = base58Encode(fullPayload);

  return {
    address,
    version,
    payload: bytesToHex(payload),
    checksum,
    fullPayload: bytesToHex(fullPayload),
  };
}

/**
 * Verifica que una dirección Base58Check sea válida.
 * Decodifica y comprueba que el checksum coincida.
 */
export function base58CheckValidate(address: string): {
  valid: boolean;
  version?: number;
  payload?: string;
  error?: string;
} {
  try {
    const decoded = base58Decode(address);
    if (decoded.length < 5) {
      return { valid: false, error: 'Demasiado corta' };
    }

    const version = decoded[0];
    const payload = decoded.slice(1, -4);
    const checksum = decoded.slice(-4);

    // Recalcular el checksum
    const versionedPayload = decoded.slice(0, -4);
    const firstHash = sha256Bytes(versionedPayload);
    const secondHash = sha256Hex(hexToBytes(firstHash));
    const expectedChecksum = secondHash.slice(0, 8);
    const actualChecksum = bytesToHex(checksum);

    if (actualChecksum !== expectedChecksum) {
      return { valid: false, error: `Checksum inválido: esperado ${expectedChecksum}, recibido ${actualChecksum}` };
    }

    return { valid: true, version, payload: bytesToHex(payload) };
  } catch (e) {
    return { valid: false, error: (e as Error).message };
  }
}

// ─── Dirección Bitcoin completa ──────────────────────────────

export interface BitcoinAddressResult {
  privateKeyHex: string;
  publicKeyHex: string;
  publicKeyCompressed: string;
  sha256Hash: string;
  hash160: string;
  address: string;
  addressTestnet: string;
  base58Details: Base58CheckResult;
}
