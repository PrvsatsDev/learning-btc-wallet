/**
 * SHA-256 implementado desde cero — sin librerías externas.
 *
 * Este archivo existe para APRENDER cómo funciona SHA-256 por dentro.
 * En producción usarías SubtleCrypto o una librería auditada.
 *
 * El algoritmo procesa datos en bloques de 512 bits (64 bytes):
 *   1. Padding: rellena el mensaje para que sea múltiplo de 512 bits
 *   2. Message Schedule: expande 16 words → 64 words por bloque
 *   3. Compresión: 64 rondas de mezcla bit a bit por bloque
 *   4. Resultado: 8 words de 32 bits = 256 bits = 32 bytes
 */

// ─── Constantes ──────────────────────────────────────────────
// Las primeras 32 bits de las raíces cúbicas de los primeros 64 primos.
// No hay nada mágico aquí — se eligieron para que nadie pudiera
// meter una "puerta trasera" en las constantes (nothing-up-my-sleeve numbers).
const K: number[] = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// Valores iniciales del hash: las primeras 32 bits de las
// raíces cuadradas de los primeros 8 primos (2, 3, 5, 7, 11, 13, 17, 19).
const H_INITIAL: number[] = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// ─── Operaciones bit a bit ───────────────────────────────────
// SHA-256 trabaja con enteros de 32 bits sin signo.
// JavaScript usa 64-bit floats, así que usamos >>> 0 para forzar uint32.

/** Rotación a la derecha: mueve bits hacia la derecha, los que "caen" vuelven por la izquierda */
function rotr(n: number, bits: number): number {
  return ((n >>> bits) | (n << (32 - bits))) >>> 0;
}

/** Shift a la derecha: como rotr pero los bits que caen se pierden (se rellenan con 0) */
function shr(n: number, bits: number): number {
  return n >>> bits;
}

// Las funciones Σ y σ combinan rotaciones y shifts.
// Son el corazón de la "difusión" — hacen que cada bit de entrada
// afecte a muchos bits de salida (efecto avalancha).

function sigma0(x: number): number {
  return (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)) >>> 0;
}

function sigma1(x: number): number {
  return (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)) >>> 0;
}

function lowerSigma0(x: number): number {
  return (rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)) >>> 0;
}

function lowerSigma1(x: number): number {
  return (rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)) >>> 0;
}

/** Choice: para cada bit, si x=1 elige y, si x=0 elige z */
function ch(x: number, y: number, z: number): number {
  return ((x & y) ^ (~x & z)) >>> 0;
}

/** Majority: para cada bit, elige el valor que tenga mayoría entre x, y, z */
function maj(x: number, y: number, z: number): number {
  return ((x & y) ^ (x & z) ^ (y & z)) >>> 0;
}

// ─── Padding ─────────────────────────────────────────────────
/**
 * Rellena el mensaje para que su longitud sea múltiplo de 512 bits.
 *
 * Formato: [mensaje] [1] [ceros...] [longitud en 64 bits big-endian]
 *
 * ¿Por qué? SHA-256 procesa bloques de tamaño fijo (512 bits).
 * El padding asegura que el último bloque esté completo y que
 * la longitud original del mensaje quede codificada al final.
 */
function padMessage(message: Uint8Array): Uint8Array {
  const bitLength = message.length * 8;
  // Necesitamos espacio para: mensaje + 1 byte (0x80) + longitud (8 bytes)
  // Total debe ser múltiplo de 64 bytes (512 bits)
  const paddingLength = 64 - ((message.length + 1 + 8) % 64);
  const totalLength = message.length + 1 + paddingLength + 8;

  const padded = new Uint8Array(totalLength);
  padded.set(message);

  // Añadir bit "1" seguido de ceros (0x80 = 10000000 en binario)
  padded[message.length] = 0x80;

  // Los últimos 8 bytes son la longitud del mensaje en bits (big-endian)
  // Usamos solo los últimos 4 bytes porque nuestros mensajes son < 2^32 bits
  const view = new DataView(padded.buffer);
  view.setUint32(totalLength - 4, bitLength, false);

  return padded;
}

// ─── Función principal ───────────────────────────────────────

/** Estado intermedio de cada ronda de compresión (para visualización) */
export interface RoundState {
  round: number;
  a: number;
  b: number;
  c: number;
  d: number;
  e: number;
  f: number;
  g: number;
  h: number;
  w: number;  // word del message schedule para esta ronda
  k: number;  // constante K para esta ronda
}

export interface Sha256Result {
  hash: string;               // el hash final en hexadecimal
  inputBytes: Uint8Array;     // los bytes de entrada originales
  paddedBytes: Uint8Array;    // el mensaje después del padding
  rounds: RoundState[];       // estado de cada una de las 64 rondas
}

/**
 * Calcula SHA-256 de un string UTF-8.
 * Devuelve el hash y todos los estados intermedios para visualización.
 */
export function sha256(input: string): Sha256Result {
  // Convertir string a bytes UTF-8
  const encoder = new TextEncoder();
  const messageBytes = encoder.encode(input);

  // Paso 1: Padding
  const padded = padMessage(messageBytes);

  // Inicializar el hash con los valores de las raíces cuadradas
  const hash = [...H_INITIAL];

  const allRounds: RoundState[] = [];

  // Procesar cada bloque de 512 bits (64 bytes)
  const numBlocks = padded.length / 64;

  for (let block = 0; block < numBlocks; block++) {
    const offset = block * 64;

    // Paso 2: Message Schedule — expandir 16 words a 64 words
    // Los primeros 16 words vienen directamente del bloque
    const w = new Array<number>(64);
    const view = new DataView(padded.buffer);
    for (let t = 0; t < 16; t++) {
      w[t] = view.getUint32(offset + t * 4, false);
    }
    // Los words 16-63 se calculan mezclando words anteriores
    for (let t = 16; t < 64; t++) {
      w[t] = (lowerSigma1(w[t - 2]) + w[t - 7] + lowerSigma0(w[t - 15]) + w[t - 16]) >>> 0;
    }

    // Paso 3: Compresión — 64 rondas
    // Las 8 variables de trabajo (a-h) empiezan con el hash actual
    let [a, b, c, d, e, f, g, h] = hash;

    for (let t = 0; t < 64; t++) {
      // T1 y T2 combinan todo: el word, la constante, y las funciones de mezcla
      const t1 = (h + sigma1(e) + ch(e, f, g) + K[t] + w[t]) >>> 0;
      const t2 = (sigma0(a) + maj(a, b, c)) >>> 0;

      // Los valores "bajan" una posición (h←g←f←e←d←c←b←a)
      // con dos inyecciones de los valores calculados
      h = g;
      g = f;
      f = e;
      e = (d + t1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) >>> 0;

      allRounds.push({ round: t, a, b, c, d, e, f, g, h, w: w[t], k: K[t] });
    }

    // Sumar el resultado de la compresión al hash acumulado
    hash[0] = (hash[0] + a) >>> 0;
    hash[1] = (hash[1] + b) >>> 0;
    hash[2] = (hash[2] + c) >>> 0;
    hash[3] = (hash[3] + d) >>> 0;
    hash[4] = (hash[4] + e) >>> 0;
    hash[5] = (hash[5] + f) >>> 0;
    hash[6] = (hash[6] + g) >>> 0;
    hash[7] = (hash[7] + h) >>> 0;
  }

  // Convertir los 8 words de 32 bits a string hexadecimal
  const hashHex = hash.map(h => h.toString(16).padStart(8, '0')).join('');

  return {
    hash: hashHex,
    inputBytes: messageBytes,
    paddedBytes: padded,
    rounds: allRounds,
  };
}

/**
 * Versión simple que solo devuelve el hash hex.
 * Útil para verificar contra la Web Crypto API.
 */
export function sha256Hex(input: string): string {
  return sha256(input).hash;
}

/** Convierte un número uint32 a string binario de 32 bits */
export function toBinary(n: number): string {
  return (n >>> 0).toString(2).padStart(32, '0');
}

/** Convierte un número uint32 a string hex de 8 caracteres */
export function toHex(n: number): string {
  return (n >>> 0).toString(16).padStart(8, '0');
}
