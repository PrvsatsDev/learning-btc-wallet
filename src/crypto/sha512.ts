/**
 * SHA-512 implementado desde cero — sin librerías externas.
 *
 * SHA-512 es el hermano mayor de SHA-256. Misma estructura (Merkle-Damgård),
 * pero con palabras de 64 bits, 80 rondas y bloques de 1024 bits.
 *
 * Bitcoin lo usa indirectamente a través de HMAC-SHA512 para:
 *   - BIP32: derivar claves hijas en HD wallets
 *   - BIP39: PBKDF2 para convertir mnemónico en seed
 *
 * La diferencia principal con SHA-256:
 *   - Palabras de 64 bits (BigInt en JS, porque no hay uint64 nativo)
 *   - 80 rondas en vez de 64
 *   - Bloques de 128 bytes (1024 bits) en vez de 64
 *   - Produce 64 bytes (512 bits) de hash
 */

// ─── Constantes ──────────────────────────────────────────────
// Primeros 64 bits de las partes fraccionarias de las raíces cúbicas
// de los primeros 80 primos (2, 3, 5, 7, 11, ..., 409).
// Se split en high/low 32-bit para evitar issues con bigint literals.
function k64(hi: number, lo: number): bigint {
  return (BigInt(hi >>> 0) << 32n) | BigInt(lo >>> 0);
}

const K: bigint[] = [
  k64(0x428a2f98, 0xd728ae22), k64(0x71374491, 0x23ef65cd), k64(0xb5c0fbcf, 0xec4d3b2f), k64(0xe9b5dba5, 0x8189dbbc),
  k64(0x3956c25b, 0xf348b538), k64(0x59f111f1, 0xb605d019), k64(0x923f82a4, 0xaf194f9b), k64(0xab1c5ed5, 0xda6d8118),
  k64(0xd807aa98, 0xa3030242), k64(0x12835b01, 0x45706fbe), k64(0x243185be, 0x4ee4b28c), k64(0x550c7dc3, 0xd5ffb4e2),
  k64(0x72be5d74, 0xf27b896f), k64(0x80deb1fe, 0x3b1696b1), k64(0x9bdc06a7, 0x25c71235), k64(0xc19bf174, 0xcf692694),
  k64(0xe49b69c1, 0x9ef14ad2), k64(0xefbe4786, 0x384f25e3), k64(0x0fc19dc6, 0x8b8cd5b5), k64(0x240ca1cc, 0x77ac9c65),
  k64(0x2de92c6f, 0x592b0275), k64(0x4a7484aa, 0x6ea6e483), k64(0x5cb0a9dc, 0xbd41fbd4), k64(0x76f988da, 0x831153b5),
  k64(0x983e5152, 0xee66dfab), k64(0xa831c66d, 0x2db43210), k64(0xb00327c8, 0x98fb213f), k64(0xbf597fc7, 0xbeef0ee4),
  k64(0xc6e00bf3, 0x3da88fc2), k64(0xd5a79147, 0x930aa725), k64(0x06ca6351, 0xe003826f), k64(0x14292967, 0x0a0e6e70),
  k64(0x27b70a85, 0x46d22ffc), k64(0x2e1b2138, 0x5c26c926), k64(0x4d2c6dfc, 0x5ac42aed), k64(0x53380d13, 0x9d95b3df),
  k64(0x650a7354, 0x8baf63de), k64(0x766a0abb, 0x3c77b2a8), k64(0x81c2c92e, 0x47edaee6), k64(0x92722c85, 0x1482353b),
  k64(0xa2bfe8a1, 0x4cf10364), k64(0xa81a664b, 0xbc423001), k64(0xc24b8b70, 0xd0f89791), k64(0xc76c51a3, 0x0654be30),
  k64(0xd192e819, 0xd6ef5218), k64(0xd6990624, 0x5565a910), k64(0xf40e3585, 0x5771202a), k64(0x106aa070, 0x32bbd1b8),
  k64(0x19a4c116, 0xb8d2d0c8), k64(0x1e376c08, 0x5141ab53), k64(0x2748774c, 0xdf8eeb99), k64(0x34b0bcb5, 0xe19b48a8),
  k64(0x391c0cb3, 0xc5c95a63), k64(0x4ed8aa4a, 0xe3418acb), k64(0x5b9cca4f, 0x7763e373), k64(0x682e6ff3, 0xd6b2b8a3),
  k64(0x748f82ee, 0x5defb2fc), k64(0x78a5636f, 0x43172f60), k64(0x84c87814, 0xa1f0ab72), k64(0x8cc70208, 0x1a6439ec),
  k64(0x90befffa, 0x23631e28), k64(0xa4506ceb, 0xde82bde9), k64(0xbef9a3f7, 0xb2c67915), k64(0xc67178f2, 0xe372532b),
  k64(0xca273ece, 0xea26619c), k64(0xd186b8c7, 0x21c0c207), k64(0xeada7dd6, 0xcde0eb1e), k64(0xf57d4f7f, 0xee6ed178),
  k64(0x06f067aa, 0x72176fba), k64(0x0a637dc5, 0xa2c898a6), k64(0x113f9804, 0xbef90dae), k64(0x1b710b35, 0x131c471b),
  k64(0x28db77f5, 0x23047d84), k64(0x32caab7b, 0x40c72493), k64(0x3c9ebe0a, 0x15c9bebc), k64(0x431d67c4, 0x9c100d4c),
  k64(0x4cc5d4be, 0xcb3e42b6), k64(0x597f299c, 0xfc657e2a), k64(0x5fcb6fab, 0x3ad6faec), k64(0x6c44198c, 0x4a475817),
];

// Valores iniciales: primeros 64 bits de las raíces cuadradas de los primeros 8 primos.
const H_INITIAL: bigint[] = [
  k64(0x6a09e667, 0xf3bcc908), k64(0xbb67ae85, 0x84caa73b),
  k64(0x3c6ef372, 0xfe94f82b), k64(0xa54ff53a, 0x5f1d36f1),
  k64(0x510e527f, 0xade682d1), k64(0x9b05688c, 0x2b3e6c1f),
  k64(0x1f83d9ab, 0xfb41bd6b), k64(0x5be0cd19, 0x137e2179),
];

const MASK64 = (1n << 64n) - 1n;

// ─── Operaciones bit a bit (64 bits) ────────────────────────

function rotr64(n: bigint, bits: number): bigint {
  return ((n >> BigInt(bits)) | (n << BigInt(64 - bits))) & MASK64;
}

function shr64(n: bigint, bits: number): bigint {
  return n >> BigInt(bits);
}

function sigma0(x: bigint): bigint {
  return rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39);
}

function sigma1(x: bigint): bigint {
  return rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41);
}

function lowerSigma0(x: bigint): bigint {
  return rotr64(x, 1) ^ rotr64(x, 8) ^ shr64(x, 7);
}

function lowerSigma1(x: bigint): bigint {
  return rotr64(x, 19) ^ rotr64(x, 61) ^ shr64(x, 6);
}

function ch(x: bigint, y: bigint, z: bigint): bigint {
  return (x & y) ^ (~x & MASK64 & z);
}

function maj(x: bigint, y: bigint, z: bigint): bigint {
  return (x & y) ^ (x & z) ^ (y & z);
}

// ─── Padding ────────────────────────────────────────────────
function padMessage(message: Uint8Array): Uint8Array {
  const msgLen = message.length;
  const bitLength = BigInt(msgLen) * 8n;

  // Bloque = 128 bytes. Espacio: msg + 1 byte (0x80) + padding + 16 bytes (longitud 128-bit)
  let totalLength = msgLen + 1 + 16;
  const remainder = totalLength % 128;
  if (remainder > 0) totalLength += 128 - remainder;

  const padded = new Uint8Array(totalLength);
  padded.set(message);
  padded[msgLen] = 0x80;

  // Longitud en los últimos 16 bytes (big-endian, 128-bit)
  // Para mensajes < 2^64 bits, los primeros 8 bytes son 0
  for (let i = 0; i < 8; i++) {
    padded[totalLength - 1 - i] = Number((bitLength >> BigInt(i * 8)) & 0xffn);
  }

  return padded;
}

// ─── Función principal ──────────────────────────────────────

/**
 * Calcula SHA-512 de bytes crudos o string UTF-8.
 * Devuelve el hash como string hexadecimal de 128 caracteres (64 bytes).
 */
export function sha512(input: string | Uint8Array): string {
  const messageBytes = typeof input === 'string'
    ? new TextEncoder().encode(input)
    : input;

  const padded = padMessage(messageBytes);
  const hash = [...H_INITIAL];
  const numBlocks = padded.length / 128;

  for (let block = 0; block < numBlocks; block++) {
    const offset = block * 128;

    // Message schedule: 16 words → 80 words (64-bit)
    const w = new Array<bigint>(80);
    for (let t = 0; t < 16; t++) {
      const i = offset + t * 8;
      w[t] = 0n;
      for (let j = 0; j < 8; j++) {
        w[t] = (w[t] << 8n) | BigInt(padded[i + j]);
      }
    }
    for (let t = 16; t < 80; t++) {
      w[t] = (lowerSigma1(w[t - 2]) + w[t - 7] + lowerSigma0(w[t - 15]) + w[t - 16]) & MASK64;
    }

    // Compresión: 80 rondas
    let [a, b, c, d, e, f, g, h] = hash;

    for (let t = 0; t < 80; t++) {
      const t1 = (h + sigma1(e) + ch(e, f, g) + K[t] + w[t]) & MASK64;
      const t2 = (sigma0(a) + maj(a, b, c)) & MASK64;

      h = g;
      g = f;
      f = e;
      e = (d + t1) & MASK64;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) & MASK64;
    }

    hash[0] = (hash[0] + a) & MASK64;
    hash[1] = (hash[1] + b) & MASK64;
    hash[2] = (hash[2] + c) & MASK64;
    hash[3] = (hash[3] + d) & MASK64;
    hash[4] = (hash[4] + e) & MASK64;
    hash[5] = (hash[5] + f) & MASK64;
    hash[6] = (hash[6] + g) & MASK64;
    hash[7] = (hash[7] + h) & MASK64;
  }

  return hash.map(h => h.toString(16).padStart(16, '0')).join('');
}

/** Convierte el hash hex a Uint8Array de 64 bytes */
export function sha512Bytes(input: string | Uint8Array): Uint8Array {
  const hex = sha512(input);
  const bytes = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
