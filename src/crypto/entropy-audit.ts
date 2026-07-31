/**
 * Entropy Auditor — comprobación "a ojo" de la aleatoriedad de un mnemónico
 *
 * Motivación: el caso ColdCard (2026). Coinkite avisó de que semillas
 * generadas en Mk3/Mk4/Q/Mk5 tenían MUCHA menos entropía de la esperada
 * ("~72 bits en vez de 128"). Eso NO significa que las palabras tengan
 * menos bits — una semilla de 12 palabras SIEMPRE codifica 128 bits.
 * Significa que el *conjunto de semillas que el aparato podía producir*
 * era mucho más pequeño de lo debido.
 *
 * ⚠️  IDEA CLAVE — leer antes de usar:
 * La entropía es una propiedad del PROCESO que generó la semilla, no de la
 * semilla en sí. Un único valor de 128 bits es indistinguible venga de un
 * RNG perfecto o de uno roto. Por eso NINGÚN análisis de una sola semilla
 * puede "medir" cuántos bits de entropía tenía el generador.
 *
 * Lo que SÍ puede hacer esta herramienta:
 *   - Reconstruir los 128/256 bits crudos a partir de las palabras (offline).
 *   - Verificar el checksum BIP39 con nuestro propio SHA-256.
 *   - Aplicar tests estadísticos que detectan DEFECTOS GROSEROS: patrones
 *     fijos, mitades repetidas, sesgo de bits extremo... la clase de "firma"
 *     que un generador roto podría dejar.
 *
 * Lo que NO puede hacer:
 *   - Certificar que una semilla es segura. Pasar todos los tests NO prueba
 *     buena entropía; solo significa "no se ve ningún patrón obvio".
 *   - Detectar la reducción sutil tipo ColdCard (72 bits con bytes de aspecto
 *     aleatorio) — para eso hace falta conocer el algoritmo exacto del bug.
 *
 * Todo es 100% local: nada sale de esta máquina.
 */

import { sha256 } from './sha256';
import { BIP39_WORDLIST } from './bip39-wordlist';

// ─── Reconstrucción palabras → bits → entropía ───────────────

const VALID_WORD_COUNTS = [12, 15, 18, 21, 24];

/** Convierte un hex string a su representación en bits ('0'/'1'). */
function hexToBits(hex: string): string {
  return hex
    .split('')
    .map(c => parseInt(c, 16).toString(2).padStart(4, '0'))
    .join('');
}

export interface EntropyDecode {
  words: string[];
  wordIndices: number[];   // índice 0-2047 de cada palabra
  allBits: string;         // entropía + checksum (words*11 bits)
  entropyBits: string;     // los ENT bits de entropía
  checksumBits: string;    // los CS bits de checksum leídos de las palabras
  entropy: Uint8Array;     // la entropía cruda
  entropyHex: string;
  checksumValid: boolean;  // ¿coincide con SHA-256(entropía)?
  expectedChecksum: string;
}

/**
 * Reconstruye la entropía cruda a partir de las palabras y verifica el
 * checksum. Es el mismo procedimiento que harías a mano con la hoja BIP39:
 *   1. cada palabra → su índice (0-2047) → 11 bits
 *   2. concatenar → ENT bits de entropía + CS bits de checksum
 *   3. checksum esperado = primeros CS bits de SHA-256(entropía)
 */
export function decodeMnemonic(words: string[]): EntropyDecode {
  const wordIndices = words.map(w => BIP39_WORDLIST.indexOf(w));

  const allBits = wordIndices
    .map(i => i.toString(2).padStart(11, '0'))
    .join('');

  // 12→4, 15→5, 18→6, 21→7, 24→8 bits de checksum
  const checksumLength = words.length / 3;
  const entropyLength = allBits.length - checksumLength;

  const entropyBits = allBits.slice(0, entropyLength);
  const checksumBits = allBits.slice(entropyLength);

  const entropy = new Uint8Array(entropyLength / 8);
  for (let i = 0; i < entropy.length; i++) {
    entropy[i] = parseInt(entropyBits.slice(i * 8, i * 8 + 8), 2);
  }

  const entropyHex = Array.from(entropy)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

  const expectedChecksum = hexToBits(sha256(entropy).hash).slice(0, checksumLength);

  return {
    words,
    wordIndices,
    allBits,
    entropyBits,
    checksumBits,
    entropy,
    entropyHex,
    checksumValid: checksumBits === expectedChecksum,
    expectedChecksum,
  };
}

// ─── Validación de entrada ───────────────────────────────────

export interface MnemonicParse {
  words: string[];
  valid: boolean;
  error: string | null;
}

/** Parsea texto libre a palabras y comprueba longitud + pertenencia a la lista. */
export function parseMnemonic(input: string): MnemonicParse {
  const words = input
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter(w => w.length > 0);

  if (words.length === 0) {
    return { words, valid: false, error: null };
  }
  if (!VALID_WORD_COUNTS.includes(words.length)) {
    return {
      words,
      valid: false,
      error: `Un mnemónico BIP39 tiene 12, 15, 18, 21 o 24 palabras (tienes ${words.length}).`,
    };
  }
  const unknown = words.filter(w => BIP39_WORDLIST.indexOf(w) === -1);
  if (unknown.length > 0) {
    return {
      words,
      valid: false,
      error: `Palabras que no están en la lista BIP39: ${unknown.join(', ')}`,
    };
  }
  return { words, valid: true, error: null };
}

// ─── Tests estadísticos de aleatoriedad ──────────────────────

export type CheckStatus = 'ok' | 'warn' | 'alert';

export interface RandomnessCheck {
  name: string;
  status: CheckStatus;
  observed: string;   // qué se ha medido
  expected: string;   // qué se esperaría de una fuente aleatoria
  explanation: string;
}

/** Cuenta bits a 1 en un byte. */
function popcount(byte: number): number {
  let c = 0;
  for (let b = byte; b > 0; b >>= 1) c += b & 1;
  return c;
}

/**
 * Batería de tests sobre la entropía cruda. Cada uno detecta una clase de
 * defecto que un generador roto podría dejar. Son *descriptivos*: sirven para
 * levantar banderas, no para certificar. Con solo 16-32 bytes, incluso una
 * fuente perfecta produce alguna fluctuación, por eso los umbrales son laxos
 * y la mayoría de avisos son 'warn' (mirar), no 'alert' (patrón claro).
 */
export function runRandomnessChecks(entropy: Uint8Array): RandomnessCheck[] {
  const n = entropy.length;           // bytes
  const totalBits = n * 8;
  const checks: RandomnessCheck[] = [];

  // 1) Balance de bits (test monobit) ────────────────────────
  // Nº esperado de unos = totalBits/2, desviación típica = sqrt(totalBits)/2.
  const ones = Array.from(entropy).reduce((s, b) => s + popcount(b), 0);
  const meanOnes = totalBits / 2;
  const sdOnes = Math.sqrt(totalBits) / 2;
  const zOnes = Math.abs(ones - meanOnes) / sdOnes;
  checks.push({
    name: 'Balance de bits',
    status: zOnes > 3 ? 'alert' : zOnes > 2 ? 'warn' : 'ok',
    observed: `${ones} unos / ${totalBits - ones} ceros (${((ones / totalBits) * 100).toFixed(1)}%, z=${zOnes.toFixed(2)})`,
    expected: `≈${meanOnes} unos (50%), desviación típica ±${sdOnes.toFixed(1)}`,
    explanation:
      'Una fuente aleatoria produce tantos 1 como 0. Un sesgo fuerte (z>3) delata ' +
      'un generador con bits fijos o pegados a un valor.',
  });

  // 2) Bytes distintos (diversidad de símbolos) ──────────────
  // Esperado ≈ 256·(1-(255/256)^n) para n extracciones de 256 valores.
  const distinct = new Set(entropy).size;
  const expectedDistinct = 256 * (1 - Math.pow(255 / 256, n));
  checks.push({
    name: 'Diversidad de bytes',
    status: distinct <= n * 0.55 ? 'alert' : distinct <= n * 0.8 ? 'warn' : 'ok',
    observed: `${distinct} valores distintos de ${n} bytes`,
    expected: `≈${expectedDistinct.toFixed(1)} distintos (casi todos únicos)`,
    explanation:
      'Con pocos bytes casi todos deberían ser diferentes. Muchos bytes repetidos ' +
      'sugieren un rango de valores artificialmente pequeño.',
  });

  // 3) Byte más frecuente ────────────────────────────────────
  const freq = new Map<number, number>();
  for (const b of entropy) freq.set(b, (freq.get(b) ?? 0) + 1);
  const maxFreq = Math.max(...freq.values());
  checks.push({
    name: 'Repetición de un byte',
    status: maxFreq >= 4 ? 'alert' : maxFreq === 3 ? 'warn' : 'ok',
    observed: `el byte más repetido aparece ${maxFreq} ${maxFreq === 1 ? 'vez' : 'veces'}`,
    expected: `1-2 veces como mucho en ${n} bytes`,
    explanation:
      'Que un mismo valor aparezca 3+ veces en tan pocos bytes es raro en una ' +
      'fuente sana y puede indicar relleno con un valor constante.',
  });

  // 4) Racha más larga de bits iguales ───────────────────────
  const bitStr = Array.from(entropy).map(b => b.toString(2).padStart(8, '0')).join('');
  let longestRun = 0;
  let currentRun = 0;
  let prev = '';
  for (const bit of bitStr) {
    currentRun = bit === prev ? currentRun + 1 : 1;
    prev = bit;
    if (currentRun > longestRun) longestRun = currentRun;
  }
  // La racha más larga esperada en N bits ronda log2(N) (~7-8 para 128 bits).
  const expectedRun = Math.log2(totalBits);
  checks.push({
    name: 'Racha de bits iguales',
    status: longestRun >= expectedRun + 6 ? 'alert' : longestRun >= expectedRun + 4 ? 'warn' : 'ok',
    observed: `racha más larga: ${longestRun} bits iguales seguidos`,
    expected: `≈${expectedRun.toFixed(0)} bits (rachas largas son improbables)`,
    explanation:
      'Muchos 0 (o 1) seguidos apuntan a zonas de la semilla que no fueron ' +
      'realmente aleatorizadas (p. ej. bytes altos siempre a cero).',
  });

  // 5) Mitades / cuartos idénticos ───────────────────────────
  const half = n / 2;
  const firstHalf = entropy.slice(0, half);
  const secondHalf = entropy.slice(half);
  const halvesEqual = firstHalf.every((b, i) => b === secondHalf[i]);
  checks.push({
    name: 'Mitades repetidas',
    status: halvesEqual ? 'alert' : 'ok',
    observed: halvesEqual
      ? 'la segunda mitad es idéntica a la primera'
      : 'las dos mitades son diferentes',
    expected: 'las dos mitades deben ser independientes',
    explanation:
      'Duplicar media semilla es un patrón clásico de un bug que solo genera ' +
      'la mitad de los bytes y copia el resto — reduce la entropía a la mitad.',
  });

  // 6) Valores constantes evidentes ──────────────────────────
  const allZero = entropy.every(b => b === 0x00);
  const allOnes = entropy.every(b => b === 0xff);
  const allSame = distinct === 1;
  checks.push({
    name: 'Constantes evidentes',
    status: allZero || allOnes || allSame ? 'alert' : 'ok',
    observed: allZero
      ? 'toda la entropía es 0x00'
      : allOnes
        ? 'toda la entropía es 0xff'
        : allSame
          ? 'todos los bytes son idénticos'
          : 'sin constantes triviales',
    expected: 'ningún patrón trivial',
    explanation:
      'Semillas como "abandon abandon … about" (todo ceros) son válidas y tienen ' +
      'checksum correcto, pero jamás las produciría un RNG sano.',
  });

  return checks;
}

// ─── Veredicto global ────────────────────────────────────────

export interface AuditResult {
  decode: EntropyDecode;
  checks: RandomnessCheck[];
  worst: CheckStatus;      // peor estado entre los tests
}

export function auditMnemonic(words: string[]): AuditResult {
  const decode = decodeMnemonic(words);
  const checks = runRandomnessChecks(decode.entropy);
  const worst: CheckStatus = checks.some(c => c.status === 'alert')
    ? 'alert'
    : checks.some(c => c.status === 'warn')
      ? 'warn'
      : 'ok';
  return { decode, checks, worst };
}
