/**
 * RIPEMD-160 implementado desde cero — sin librerías externas.
 *
 * RIPEMD-160 fue diseñado en 1996 por Hans Dobbertin, Antoon Bosselaers
 * y Bart Preneel en la KU Leuven (Bélgica). A diferencia de SHA-256
 * (diseñado por la NSA), RIPEMD viene del mundo académico europeo.
 *
 * Característica única: dos líneas paralelas de compresión (izquierda y derecha)
 * que procesan el mismo bloque con funciones y constantes distintas.
 * Al final, los resultados de ambas líneas se combinan.
 *
 * En Bitcoin: address = Base58Check(0x00 + RIPEMD160(SHA256(pubkey)))
 */

// ─── Constantes ──────────────────────────────────────────────

// Constantes aditivas para la línea izquierda
const KL = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];

// Constantes aditivas para la línea derecha (diferentes!)
const KR = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];

// Orden de selección de words del mensaje — línea izquierda
// Cada grupo de 16 rondas usa los 16 words en un orden distinto
const RL = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,  // rondas 0-15
  7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,   // rondas 16-31
  3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,   // rondas 32-47
  1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,   // rondas 48-63
  4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,   // rondas 64-79
];

// Orden de selección de words — línea derecha (totalmente diferente)
const RR = [
  5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
  6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
  15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
  8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
  12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];

// Cantidades de rotación — línea izquierda
const SL = [
  11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
  7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
  11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
  11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
  9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];

// Cantidades de rotación — línea derecha
const SR = [
  8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
  9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
  9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
  15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
  8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];

// Valores iniciales del hash (los mismos que MD4/MD5 — estándar)
const H_INITIAL = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

// ─── Operaciones bit a bit ───────────────────────────────────

/** Rotación a la izquierda (RIPEMD usa rotl, SHA-256 usa rotr) */
function rotl(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

/**
 * 5 funciones booleanas, una por grupo de 16 rondas.
 * Cada una combina tres registros de forma diferente.
 * La línea izquierda las usa en orden 0→4,
 * la línea derecha las usa en orden inverso 4→0.
 */
function f(j: number, x: number, y: number, z: number): number {
  if (j < 16) return (x ^ y ^ z) >>> 0;                     // XOR puro
  if (j < 32) return ((x & y) | (~x & z)) >>> 0;            // como Ch de SHA-256
  if (j < 48) return ((x | ~y) ^ z) >>> 0;                  // OR-NOT-XOR
  if (j < 64) return ((x & z) | (y & ~z)) >>> 0;            // intercambiado
  return (x ^ (y | ~z)) >>> 0;                               // XOR con OR-NOT
}

// ─── Padding ─────────────────────────────────────────────────
/**
 * Mismo esquema de padding que SHA-256, pero la longitud
 * se codifica en little-endian (vs big-endian en SHA-256).
 * RIPEMD-160 sigue la convención MD4/MD5.
 */
function padMessage(message: Uint8Array): Uint8Array {
  const bitLength = message.length * 8;
  const paddingLength = 64 - ((message.length + 1 + 8) % 64);
  const totalLength = message.length + 1 + paddingLength + 8;

  const padded = new Uint8Array(totalLength);
  padded.set(message);
  padded[message.length] = 0x80;

  // Longitud en bits, little-endian (diferente a SHA-256!)
  const view = new DataView(padded.buffer);
  view.setUint32(totalLength - 8, bitLength, true);       // true = little-endian
  view.setUint32(totalLength - 4, 0, true);               // bits altos (0 para mensajes cortos)

  return padded;
}

// ─── Tipos para visualización ────────────────────────────────

export interface RipemdRoundState {
  round: number;
  // Línea izquierda
  al: number; bl: number; cl: number; dl: number; el: number;
  // Línea derecha
  ar: number; br: number; cr: number; dr: number; er: number;
  // Metadata
  wl: number;  // word usado (izquierda)
  wr: number;  // word usado (derecha)
}

export interface Ripemd160Result {
  hash: string;
  inputBytes: Uint8Array;
  paddedBytes: Uint8Array;
  rounds: RipemdRoundState[];
}

// ─── Función principal ───────────────────────────────────────

export function ripemd160(input: string | Uint8Array): Ripemd160Result {
  const messageBytes = typeof input === 'string'
    ? new TextEncoder().encode(input)
    : input;

  const padded = padMessage(messageBytes);
  const hash = [...H_INITIAL];
  const allRounds: RipemdRoundState[] = [];

  const numBlocks = padded.length / 64;

  for (let block = 0; block < numBlocks; block++) {
    const offset = block * 64;

    // Leer los 16 words del bloque (little-endian!)
    const w = new Array<number>(16);
    const view = new DataView(padded.buffer);
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4, true);  // little-endian
    }

    // Inicializar las dos líneas con el hash actual
    let [al, bl, cl, dl, el] = hash;  // línea izquierda
    let [ar, br, cr, dr, er] = hash;  // línea derecha

    // 80 rondas: ambas líneas procesan en paralelo
    for (let j = 0; j < 80; j++) {
      const group = Math.floor(j / 16);

      // ─── Línea izquierda ───
      // Usa funciones f en orden 0,1,2,3,4
      let t = (al + f(j, bl, cl, dl) + w[RL[j]] + KL[group]) >>> 0;
      t = (rotl(t, SL[j]) + el) >>> 0;
      al = el;
      el = dl;
      dl = rotl(cl, 10);
      cl = bl;
      bl = t;

      // ─── Línea derecha ───
      // Usa funciones f en orden INVERSO: 4,3,2,1,0
      const jr = 79 - j;  // índice invertido para seleccionar la función
      t = (ar + f(jr, br, cr, dr) + w[RR[j]] + KR[group]) >>> 0;
      t = (rotl(t, SR[j]) + er) >>> 0;
      ar = er;
      er = dr;
      dr = rotl(cr, 10);
      cr = br;
      br = t;

      allRounds.push({
        round: j,
        al, bl, cl, dl, el,
        ar, br, cr, dr, er,
        wl: w[RL[j]],
        wr: w[RR[j]],
      });
    }

    // Combinar ambas líneas con el hash acumulado
    // Esta es la parte clave: mezcla izquierda + derecha + hash anterior
    const t = (hash[1] + cl + dr) >>> 0;
    hash[1] = (hash[2] + dl + er) >>> 0;
    hash[2] = (hash[3] + el + ar) >>> 0;
    hash[3] = (hash[4] + al + br) >>> 0;
    hash[4] = (hash[0] + bl + cr) >>> 0;
    hash[0] = t;
  }

  // Convertir a hex (little-endian: cada word se escribe byte a byte)
  const hashHex = hash.map(h => {
    const bytes = [
      h & 0xff,
      (h >>> 8) & 0xff,
      (h >>> 16) & 0xff,
      (h >>> 24) & 0xff,
    ];
    return bytes.map(b => b.toString(16).padStart(2, '0')).join('');
  }).join('');

  return {
    hash: hashHex,
    inputBytes: messageBytes,
    paddedBytes: padded,
    rounds: allRounds,
  };
}

export function ripemd160Hex(input: string | Uint8Array): string {
  return ripemd160(input).hash;
}
