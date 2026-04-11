/**
 * Curva elíptica secp256k1 — implementada desde cero.
 *
 * secp256k1 es la curva que usa Bitcoin para toda su criptografía
 * de clave pública. La ecuación es: y² = x³ + 7 (mod p)
 *
 * "sec" = Standards for Efficient Cryptography
 * "p"   = sobre campo primo (vs campo binario)
 * "256" = el primo p tiene 256 bits
 * "k"   = variante Koblitz (a=0, eficiente)
 * "1"   = primera curva de este tipo
 *
 * En producción usarías una librería optimizada (noble-secp256k1, etc).
 * Esto es para APRENDER cómo funciona por dentro.
 */

// ─── Parámetros de la curva ──────────────────────────────────
// Todos son públicos y fijos — definidos en el estándar.

/** El primo que define el campo finito: p = 2²⁵⁶ - 2³² - 977 */
export const P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;

/** Coeficientes de la curva y² = x³ + ax + b */
export const A = 0n;
export const B = 7n;

/** Orden del grupo: cuántos puntos tiene la curva.
 *  Si multiplicás G por n, volvés al punto en el infinito (identidad). */
export const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;

/** Punto generador G — un punto fijo en la curva elegido por el estándar.
 *  Todos los usuarios de Bitcoin usan este mismo G. */
export const Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
export const Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;

// ─── Aritmética modular ──────────────────────────────────────

/** Módulo que siempre da resultado positivo (a diferencia de %, que puede dar negativo) */
export function mod(a: bigint, m: bigint = P): bigint {
  const result = a % m;
  return result >= 0n ? result : result + m;
}

/**
 * Inverso modular: encuentra b tal que (a * b) mod m = 1
 *
 * Usa el teorema de Fermat: a^(p-1) ≡ 1 (mod p) cuando p es primo
 * Por lo tanto: a^(-1) ≡ a^(p-2) (mod p)
 *
 * Esto funciona porque el campo Zp es un grupo multiplicativo de orden p-1
 */
export function modInverse(a: bigint, m: bigint = P): bigint {
  return modPow(mod(a, m), m - 2n, m);
}

/**
 * Exponenciación modular rápida: calcula (base^exp) mod m
 *
 * Usa el método de "cuadrar y multiplicar" (square-and-multiply):
 * En vez de multiplicar `exp` veces, recorre los bits de exp
 * y cuadra en cada paso. Complejidad: O(log exp) en vez de O(exp).
 */
function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let result = 1n;
  base = mod(base, m);
  while (exp > 0n) {
    // Si el bit actual es 1, multiplicar
    if (exp & 1n) {
      result = mod(result * base, m);
    }
    // Cuadrar la base y pasar al siguiente bit
    exp >>= 1n;
    base = mod(base * base, m);
  }
  return result;
}

// ─── Puntos en la curva ──────────────────────────────────────

/** Un punto en la curva, o null para el "punto en el infinito" (elemento neutro) */
export type Point = { x: bigint; y: bigint } | null;

/** El punto generador como objeto */
export const G: Point = { x: Gx, y: Gy };

/** Verifica si un punto está realmente sobre la curva y² = x³ + 7 (mod p) */
export function isOnCurve(point: Point): boolean {
  if (point === null) return true; // el punto en el infinito está "en la curva" por convención
  const { x, y } = point;
  const left = mod(y * y);          // y²
  const right = mod(x * x * x + B); // x³ + 7
  return left === right;
}

/**
 * Suma de dos puntos P + Q en la curva elíptica.
 *
 * Hay 4 casos:
 * 1. P o Q es el punto en el infinito → devolver el otro
 * 2. P = -Q (misma x, y opuesta) → punto en el infinito
 * 3. P = Q → "point doubling" (tangente a la curva)
 * 4. P ≠ Q → caso general (línea secante)
 *
 * En ambos casos (3 y 4), la fórmula es:
 *   λ (lambda) = pendiente de la línea
 *   x₃ = λ² - x₁ - x₂
 *   y₃ = λ(x₁ - x₃) - y₁
 */
export function pointAdd(p1: Point, p2: Point): Point {
  // Caso 1: punto en el infinito (elemento neutro de la suma)
  if (p1 === null) return p2;
  if (p2 === null) return p1;

  const { x: x1, y: y1 } = p1;
  const { x: x2, y: y2 } = p2;

  // Caso 2: P + (-P) = infinito
  if (x1 === x2 && mod(y1 + y2) === 0n) {
    return null;
  }

  let lambda: bigint;

  if (x1 === x2 && y1 === y2) {
    // Caso 3: Point doubling (P + P)
    // La pendiente es la derivada de la curva en ese punto:
    // λ = (3x² + a) / (2y)  — donde a=0 en secp256k1
    lambda = mod(3n * x1 * x1 * modInverse(2n * y1));
  } else {
    // Caso 4: Suma general (P + Q)
    // λ = (y₂ - y₁) / (x₂ - x₁)
    lambda = mod((y2 - y1) * modInverse(x2 - x1));
  }

  // Calcular el nuevo punto
  const x3 = mod(lambda * lambda - x1 - x2);
  const y3 = mod(lambda * (x1 - x3) - y1);

  return { x: x3, y: y3 };
}

/**
 * Multiplicación escalar: k × P
 *
 * Calcula P + P + P + ... (k veces), pero de forma eficiente
 * usando el algoritmo "double-and-add" (análogo al square-and-multiply):
 *
 * Para cada bit de k (de izquierda a derecha):
 *   - Siempre: duplicar el acumulador
 *   - Si el bit es 1: sumar P al acumulador
 *
 * Esto convierte O(k) sumas en O(log k) operaciones.
 * Para k de 256 bits: ~256 operaciones en vez de ~2²⁵⁶.
 */
export function scalarMultiply(k: bigint, point: Point): Point {
  // Reducir k módulo N (el orden del grupo)
  k = mod(k, N);
  if (k === 0n) return null;

  let result: Point = null;    // acumulador (empieza en el infinito = identidad)
  let current: Point = point;  // potencia actual de 2 × P

  while (k > 0n) {
    if (k & 1n) {
      result = pointAdd(result, current);
    }
    current = pointAdd(current, current); // doubling
    k >>= 1n;
  }

  return result;
}

// ─── Funciones Bitcoin ───────────────────────────────────────

/**
 * Deriva la clave pública desde una clave privada.
 *
 * publicKey = privateKey × G
 *
 * La clave privada es un número entre 1 y N-1.
 * La clave pública es un punto (x, y) en la curva.
 */
export function getPublicKey(privateKey: bigint): Point {
  if (privateKey <= 0n || privateKey >= N) {
    throw new Error('Clave privada debe estar entre 1 y N-1');
  }
  return scalarMultiply(privateKey, G);
}

/**
 * Serializa una clave pública en formato comprimido (33 bytes).
 *
 * Formato: [prefijo 1 byte] [coordenada x 32 bytes]
 * - Prefijo 02 si y es par
 * - Prefijo 03 si y es impar
 *
 * ¿Por qué funciona? Porque dada x, la ecuación y² = x³ + 7
 * tiene exactamente dos soluciones: y y p-y (una par y otra impar).
 * Así que basta con guardar x + 1 bit para saber cuál y es.
 */
export function compressPublicKey(point: Point): string {
  if (point === null) throw new Error('No se puede comprimir el punto en el infinito');
  const prefix = point.y % 2n === 0n ? '02' : '03';
  return prefix + point.x.toString(16).padStart(64, '0');
}

/**
 * Serializa una clave pública sin comprimir (65 bytes).
 *
 * Formato: [04] [x 32 bytes] [y 32 bytes]
 */
export function uncompressPublicKey(point: Point): string {
  if (point === null) throw new Error('No se puede serializar el punto en el infinito');
  return '04' + point.x.toString(16).padStart(64, '0') + point.y.toString(16).padStart(64, '0');
}

// ─── Para visualización ──────────────────────────────────────

/** Pasos intermedios de la multiplicación escalar (para el explorador visual) */
export interface ScalarMultiplyStep {
  bit: number;         // valor del bit actual (0 o 1)
  bitIndex: number;    // posición del bit
  doubled: Point;      // resultado después del doubling
  added: Point | null; // resultado después de sumar (solo si bit=1)
  accumulator: Point;  // estado del acumulador
}

/** Versión de scalarMultiply que registra cada paso */
export function scalarMultiplyWithSteps(k: bigint, point: Point): {
  result: Point;
  steps: ScalarMultiplyStep[];
} {
  k = mod(k, N);
  const steps: ScalarMultiplyStep[] = [];

  let result: Point = null;
  let current: Point = point;
  let bitIndex = 0;

  while (k > 0n) {
    const bit = Number(k & 1n);
    const doubled = pointAdd(current, current);

    if (bit) {
      result = pointAdd(result, current);
    }

    steps.push({
      bit,
      bitIndex,
      doubled,
      added: bit ? result : null,
      accumulator: result,
    });

    current = doubled;
    k >>= 1n;
    bitIndex++;
  }

  return { result, steps };
}

/** Formatea un bigint como hex truncado para mostrar en UI */
export function formatBigInt(n: bigint, chars: number = 16): string {
  const hex = n.toString(16).padStart(64, '0');
  if (hex.length <= chars) return hex;
  return hex.slice(0, chars / 2) + '...' + hex.slice(-chars / 2);
}
