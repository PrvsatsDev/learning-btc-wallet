/**
 * HMAC (Hash-based Message Authentication Code) — implementado desde cero.
 *
 * HMAC combina una función hash con una clave secreta para producir
 * un código de autenticación. Se usa en Bitcoin para:
 *   - RFC 6979: generar nonces determinísticos para firmas ECDSA
 *   - BIP32: derivar claves hijas en HD wallets (HMAC-SHA512)
 *   - BIP39: PBKDF2 para convertir mnemónico en seed
 *
 * La construcción es:
 *   HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
 *
 * Donde:
 *   K' = clave ajustada al tamaño del bloque (64 bytes para SHA-256)
 *   ipad = 0x36 repetido (inner padding)
 *   opad = 0x5c repetido (outer padding)
 *
 * ¿Por qué dos pasadas de hash? Una sola H(K || m) sería vulnerable
 * a ataques de extensión de longitud. La doble estructura lo evita.
 */

import { sha256 } from './sha256';
import { sha512 } from './sha512';

// SHA-256 usa bloques de 64 bytes (512 bits)
const BLOCK_SIZE_256 = 64;
// SHA-512 usa bloques de 128 bytes (1024 bits)
const BLOCK_SIZE_512 = 128;

/**
 * HMAC-SHA256: calcula el código de autenticación de un mensaje con una clave.
 *
 * @param key - La clave secreta (cualquier longitud)
 * @param message - El mensaje a autenticar
 * @returns 32 bytes (256 bits) del HMAC
 */
export function hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array {
  // Paso 1: Ajustar la clave al tamaño del bloque
  // Si es más larga que el bloque, hashearla primero
  // Si es más corta, rellenar con ceros a la derecha
  let keyPrime: Uint8Array;

  if (key.length > BLOCK_SIZE_256) {
    keyPrime = hexToBytes(sha256(key).hash);
  } else {
    keyPrime = new Uint8Array(BLOCK_SIZE_256);
    keyPrime.set(key);
  }

  if (keyPrime.length < BLOCK_SIZE_256) {
    const padded = new Uint8Array(BLOCK_SIZE_256);
    padded.set(keyPrime);
    keyPrime = padded;
  }

  const ipad = new Uint8Array(BLOCK_SIZE_256);
  const opad = new Uint8Array(BLOCK_SIZE_256);

  for (let i = 0; i < BLOCK_SIZE_256; i++) {
    ipad[i] = keyPrime[i] ^ 0x36;
    opad[i] = keyPrime[i] ^ 0x5c;
  }

  const innerData = new Uint8Array(BLOCK_SIZE_256 + message.length);
  innerData.set(ipad);
  innerData.set(message, BLOCK_SIZE_256);
  const innerHash = hexToBytes(sha256(innerData).hash);

  const outerData = new Uint8Array(BLOCK_SIZE_256 + innerHash.length);
  outerData.set(opad);
  outerData.set(innerHash, BLOCK_SIZE_256);
  const outerHash = hexToBytes(sha256(outerData).hash);

  return outerHash;
}

// ─── HMAC-SHA512 ────────────────────────────────────────────
/**
 * HMAC-SHA512: igual que HMAC-SHA256 pero con SHA-512.
 * Bloque de 128 bytes, produce 64 bytes.
 * Usado en BIP32 (derivación de claves) y BIP39 (PBKDF2).
 */
export function hmacSha512(key: Uint8Array, message: Uint8Array): Uint8Array {
  let keyPrime: Uint8Array;

  if (key.length > BLOCK_SIZE_512) {
    keyPrime = hexToBytes(sha512(key));
  } else {
    keyPrime = new Uint8Array(BLOCK_SIZE_512);
    keyPrime.set(key);
  }

  if (keyPrime.length < BLOCK_SIZE_512) {
    const padded = new Uint8Array(BLOCK_SIZE_512);
    padded.set(keyPrime);
    keyPrime = padded;
  }

  const ipad = new Uint8Array(BLOCK_SIZE_512);
  const opad = new Uint8Array(BLOCK_SIZE_512);

  for (let i = 0; i < BLOCK_SIZE_512; i++) {
    ipad[i] = keyPrime[i] ^ 0x36;
    opad[i] = keyPrime[i] ^ 0x5c;
  }

  const innerData = new Uint8Array(BLOCK_SIZE_512 + message.length);
  innerData.set(ipad);
  innerData.set(message, BLOCK_SIZE_512);
  const innerHash = hexToBytes(sha512(innerData));

  const outerData = new Uint8Array(BLOCK_SIZE_512 + innerHash.length);
  outerData.set(opad);
  outerData.set(innerHash, BLOCK_SIZE_512);
  const outerHash = hexToBytes(sha512(outerData));

  return outerHash;
}

// ─── Utilidades ─────────────────────────────────────────────

/** Convierte hex string a bytes */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Convierte bytes a hex string */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Convierte un bigint a Uint8Array de longitud fija (big-endian) */
export function bigintToBytes(n: bigint, length: number): Uint8Array {
  const hex = n.toString(16).padStart(length * 2, '0');
  return hexToBytes(hex);
}

/** Convierte Uint8Array a bigint (big-endian) */
export function bytesToBigint(bytes: Uint8Array): bigint {
  return BigInt('0x' + bytesToHex(bytes));
}
