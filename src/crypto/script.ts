/**
 * Bitcoin Script — intérprete desde cero.
 *
 * Bitcoin Script es un lenguaje de pila (stack-based), parecido a Forth.
 * Es intencionalmente NO Turing-completo: no tiene bucles.
 *
 * Cada UTXO tiene un "scriptPubKey" (condiciones de gasto).
 * Para gastarlo, proporcionas un "scriptSig" (prueba de que cumples las condiciones).
 * El nodo ejecuta scriptSig + scriptPubKey y si el resultado es true, la tx es válida.
 *
 * Tipos de script implementados:
 *   P2PKH  — Pay to Public Key Hash (dirección 1xxx, el clásico)
 *   P2WPKH — Pay to Witness Public Key Hash (dirección bc1qxxx, SegWit v0)
 *   P2TR   — Pay to Taproot (dirección bc1pxxx, SegWit v1)
 *   Multisig m-of-n (OP_CHECKMULTISIG) y su envoltorio P2WSH (bc1q..., 32 bytes)
 */

import { sha256 } from './sha256';
import { ripemd160Hex } from './ripemd160';

// ─── Opcodes ────────────────────────────────────────────────

export const OP = {
  // Constantes
  OP_0: 0x00,
  OP_PUSHBYTES_20: 0x14,
  OP_PUSHBYTES_32: 0x20,
  OP_PUSHBYTES_33: 0x21,
  OP_PUSHBYTES_65: 0x41,
  OP_PUSHDATA1: 0x4c,

  // Números pequeños: OP_1..OP_16 apilan el entero 1..16 (OP_n = 0x50 + n).
  // Se usan como umbral (m) y total (n) en los scripts multisig.
  OP_1: 0x51,
  OP_2: 0x52,
  OP_3: 0x53,
  OP_4: 0x54,
  OP_5: 0x55,
  OP_6: 0x56,
  OP_7: 0x57,
  OP_8: 0x58,
  OP_9: 0x59,
  OP_10: 0x5a,
  OP_11: 0x5b,
  OP_12: 0x5c,
  OP_13: 0x5d,
  OP_14: 0x5e,
  OP_15: 0x5f,
  OP_16: 0x60,

  // Flow
  OP_NOP: 0x61,
  OP_VERIFY: 0x69,
  OP_RETURN: 0x6a,

  // Stack
  OP_DUP: 0x76,

  // Crypto
  OP_HASH160: 0xa9,
  OP_CHECKSIG: 0xac,
  OP_CHECKMULTISIG: 0xae,
  // Taproot (BIP342): reemplaza a OP_CHECKMULTISIG. En lugar de verificar todas
  // las firmas de golpe (con el bug del dummy), suma 1 a un contador por cada
  // firma válida. El multisig k-of-n queda:
  //   <pk1> CHECKSIG <pk2> CHECKSIGADD … <pkn> CHECKSIGADD <k> NUMEQUAL
  OP_CHECKSIGADD: 0xba,

  // Comparison
  OP_EQUAL: 0x87,
  OP_EQUALVERIFY: 0x88,
  OP_NUMEQUAL: 0x9c,   // ¿dos números son iguales? (para el umbral k del multisig Taproot)
} as const;

// Mapeo inverso para mostrar nombres
const OPCODE_NAMES: Record<number, string> = {};
for (const [name, code] of Object.entries(OP)) {
  OPCODE_NAMES[code] = name;
}

/** Paso de ejecución del script (para visualización) */
export interface ScriptStep {
  opcode: number;
  opcodeName: string;
  description: string;
  stack: string[];        // stack después de esta operación (hex strings)
  consumed: string[];     // items consumidos del stack
  produced: string[];     // items añadidos al stack
}

/** Resultado de ejecutar un script */
export interface ScriptExecutionResult {
  steps: ScriptStep[];
  success: boolean;
  finalStack: string[];
  error?: string;
}

// ─── Intérprete ─────────────────────────────────────────────

/**
 * Ejecuta un script Bitcoin (scriptSig + scriptPubKey concatenados).
 * Solo soporta los opcodes necesarios para P2PKH.
 */
export function executeScript(
  script: Uint8Array,
  checkSigFn?: (sig: Uint8Array, pubKey: Uint8Array) => boolean
): ScriptExecutionResult {
  const stack: Uint8Array[] = [];
  const steps: ScriptStep[] = [];
  let offset = 0;

  function stackToHex(): string[] {
    return stack.map(item => bytesToHex(item));
  }

  try {
    while (offset < script.length) {
      const opcode = script[offset];
      offset++;

      // Push data: opcodes 0x01-0x4b push that many bytes
      if (opcode >= 0x01 && opcode <= 0x4b) {
        const data = script.slice(offset, offset + opcode);
        offset += opcode;
        stack.push(data);
        steps.push({
          opcode,
          opcodeName: `PUSH_${opcode}`,
          description: `Apilar ${opcode} bytes de datos`,
          stack: stackToHex(),
          consumed: [],
          produced: [bytesToHex(data)],
        });
        continue;
      }

      // OP_1..OP_16: apilan el entero 1..16 (small ints). En multisig son el
      // umbral m (OP_2 = "hacen falta 2 firmas") y el total n (OP_3 = "de 3 claves").
      if (opcode >= OP.OP_1 && opcode <= OP.OP_16) {
        const num = opcode - 0x50;
        stack.push(new Uint8Array([num]));
        steps.push({
          opcode, opcodeName: `OP_${num}`,
          description: `Apilar el número ${num}`,
          stack: stackToHex(), consumed: [],
          produced: [num.toString(16).padStart(2, '0')],
        });
        continue;
      }

      switch (opcode) {
        case OP.OP_0: {
          stack.push(new Uint8Array(0));
          steps.push({
            opcode, opcodeName: 'OP_0', description: 'Apilar valor vacío (false/cero)',
            stack: stackToHex(), consumed: [], produced: ['(empty)'],
          });
          break;
        }

        case OP.OP_DUP: {
          const top = stack[stack.length - 1];
          const dup = new Uint8Array(top);
          stack.push(dup);
          steps.push({
            opcode, opcodeName: 'OP_DUP', description: 'Duplicar el tope de la pila',
            stack: stackToHex(), consumed: [], produced: [bytesToHex(dup)],
          });
          break;
        }

        case OP.OP_HASH160: {
          const item = stack.pop()!;
          const shaHash = sha256(item).hash;
          const h160 = ripemd160Hex(hexToBytes(shaHash));
          const result = hexToBytes(h160);
          stack.push(result);
          steps.push({
            opcode, opcodeName: 'OP_HASH160',
            description: 'RIPEMD-160(SHA-256(tope)) — Hash160',
            stack: stackToHex(),
            consumed: [bytesToHex(item)],
            produced: [h160],
          });
          break;
        }

        case OP.OP_EQUAL: {
          const b = stack.pop()!;
          const a = stack.pop()!;
          const equal = a.length === b.length && a.every((v, i) => v === b[i]);
          stack.push(new Uint8Array([equal ? 1 : 0]));
          steps.push({
            opcode, opcodeName: 'OP_EQUAL',
            description: `¿Son iguales? → ${equal ? 'Sí' : 'No'}`,
            stack: stackToHex(),
            consumed: [bytesToHex(a), bytesToHex(b)],
            produced: [equal ? '01' : '00'],
          });
          break;
        }

        case OP.OP_EQUALVERIFY: {
          const b = stack.pop()!;
          const a = stack.pop()!;
          const equal = a.length === b.length && a.every((v, i) => v === b[i]);
          if (!equal) {
            steps.push({
              opcode, opcodeName: 'OP_EQUALVERIFY',
              description: '¿Son iguales? → No — ¡FALLO!',
              stack: stackToHex(),
              consumed: [bytesToHex(a), bytesToHex(b)],
              produced: [],
            });
            return { steps, success: false, finalStack: stackToHex(), error: 'OP_EQUALVERIFY falló' };
          }
          steps.push({
            opcode, opcodeName: 'OP_EQUALVERIFY',
            description: '¿Son iguales? → Sí ✓ (no deja nada en la pila)',
            stack: stackToHex(),
            consumed: [bytesToHex(a), bytesToHex(b)],
            produced: [],
          });
          break;
        }

        case OP.OP_CHECKSIG: {
          const pubKey = stack.pop()!;
          const sig = stack.pop()!;
          const valid = checkSigFn ? checkSigFn(sig, pubKey) : true;
          stack.push(new Uint8Array([valid ? 1 : 0]));
          steps.push({
            opcode, opcodeName: 'OP_CHECKSIG',
            description: `Verificar firma ECDSA → ${valid ? 'Válida ✓' : 'Inválida ✗'}`,
            stack: stackToHex(),
            consumed: [bytesToHex(sig), bytesToHex(pubKey)],
            produced: [valid ? '01' : '00'],
          });
          break;
        }

        case OP.OP_CHECKMULTISIG: {
          // Pila esperada (de abajo a arriba):
          //   <dummy> <sig1..sigM> <M> <pk1..pkN> <N>
          // Se desapila de arriba abajo: primero N, luego las N claves, luego M,
          // luego las M firmas, y por último el <dummy>.
          if (stack.length < 1) throw new Error('OP_CHECKMULTISIG: falta N');
          const n = readScriptNum(stack.pop()!);
          if (n < 0 || n > 20) throw new Error(`OP_CHECKMULTISIG: N inválido (${n})`);
          if (stack.length < n) throw new Error('OP_CHECKMULTISIG: faltan claves públicas');
          const pubKeys: Uint8Array[] = [];
          for (let i = 0; i < n; i++) pubKeys.unshift(stack.pop()!);

          if (stack.length < 1) throw new Error('OP_CHECKMULTISIG: falta M');
          const m = readScriptNum(stack.pop()!);
          if (m < 0 || m > n) throw new Error(`OP_CHECKMULTISIG: M inválido (${m} de ${n})`);
          if (stack.length < m) throw new Error('OP_CHECKMULTISIG: faltan firmas');
          const sigs: Uint8Array[] = [];
          for (let i = 0; i < m; i++) sigs.unshift(stack.pop()!);

          // EL BUG HISTÓRICO: OP_CHECKMULTISIG desapila un elemento de más. Es un
          // fallo de la implementación original que quedó fijado en las reglas de
          // consenso. Por eso el scriptSig/witness DEBE empezar con un elemento
          // basura (normalmente OP_0). Si falta, aquí se subdesborda la pila.
          if (stack.length < 1) {
            throw new Error('OP_CHECKMULTISIG: falta el elemento dummy (el bug del off-by-one)');
          }
          const dummy = stack.pop()!;

          // Emparejado: las firmas deben ir en el MISMO orden que las claves.
          // Se recorre buscando, para cada firma, la siguiente clave que la valide.
          let ok = true;
          let keyIdx = 0;
          for (let s = 0; s < sigs.length; s++) {
            let matched = false;
            while (keyIdx < pubKeys.length) {
              const valid = checkSigFn ? checkSigFn(sigs[s], pubKeys[keyIdx]) : true;
              keyIdx++;
              if (valid) { matched = true; break; }
            }
            if (!matched) { ok = false; break; }
          }

          stack.push(new Uint8Array([ok ? 1 : 0]));
          steps.push({
            opcode, opcodeName: 'OP_CHECKMULTISIG',
            description: `Verificar ${m}-of-${n} (consume un dummy extra) → ${ok ? 'Válido ✓' : 'Inválido ✗'}`,
            stack: stackToHex(),
            consumed: [
              bytesToHex(dummy),
              ...sigs.map(bytesToHex),
              m.toString(16).padStart(2, '0'),
              ...pubKeys.map(bytesToHex),
              n.toString(16).padStart(2, '0'),
            ],
            produced: [ok ? '01' : '00'],
          });
          break;
        }

        case OP.OP_CHECKSIGADD: {
          // Pila esperada (de abajo a arriba): <sig> <n> <pubkey>.
          // Desapila pubkey, luego el contador n, luego la firma.
          //   - firma VACÍA → no verifica, deja n igual (esa clave no firmó).
          //   - firma no vacía y válida → deja n+1.
          //   - firma no vacía e inválida → el script FALLA (regla de Tapscript).
          const pubKey = stack.pop()!;
          const n = readScriptNum(stack.pop()!);
          const sig = stack.pop()!;
          let result = n;
          if (sig.length === 0) {
            result = n; // clave no firmada: se salta sin verificar
          } else {
            const valid = checkSigFn ? checkSigFn(sig, pubKey) : true;
            if (!valid) {
              steps.push({
                opcode, opcodeName: 'OP_CHECKSIGADD',
                description: 'Firma no vacía INVÁLIDA → ¡FALLO! (Tapscript no la tolera)',
                stack: stackToHex(), consumed: [bytesToHex(sig), bytesToHex(pubKey)], produced: [],
              });
              return { steps, success: false, finalStack: stackToHex(), error: 'OP_CHECKSIGADD: firma no vacía inválida' };
            }
            result = n + 1;
          }
          stack.push(encodeScriptNum(result));
          steps.push({
            opcode, opcodeName: 'OP_CHECKSIGADD',
            description: sig.length === 0
              ? `Firma vacía → contador sigue en ${n}`
              : `Firma válida ✓ → contador ${n} → ${result}`,
            stack: stackToHex(),
            consumed: [bytesToHex(sig), n.toString(16).padStart(2, '0'), bytesToHex(pubKey)],
            produced: [result.toString(16).padStart(2, '0')],
          });
          break;
        }

        case OP.OP_NUMEQUAL: {
          const b = readScriptNum(stack.pop()!);
          const a = readScriptNum(stack.pop()!);
          const eq = a === b;
          stack.push(new Uint8Array(eq ? [1] : []));
          steps.push({
            opcode, opcodeName: 'OP_NUMEQUAL',
            description: `¿${a} = ${b}? → ${eq ? 'Sí ✓' : 'No'}`,
            stack: stackToHex(),
            consumed: [a.toString(16).padStart(2, '0'), b.toString(16).padStart(2, '0')],
            produced: [eq ? '01' : '(empty)'],
          });
          break;
        }

        case OP.OP_VERIFY: {
          const top = stack.pop()!;
          const isTrue = top.length > 0 && top.some(b => b !== 0);
          if (!isTrue) {
            steps.push({
              opcode, opcodeName: 'OP_VERIFY', description: 'Verificar tope → false — ¡FALLO!',
              stack: stackToHex(), consumed: [bytesToHex(top)], produced: [],
            });
            return { steps, success: false, finalStack: stackToHex(), error: 'OP_VERIFY falló' };
          }
          steps.push({
            opcode, opcodeName: 'OP_VERIFY', description: 'Verificar tope → true ✓',
            stack: stackToHex(), consumed: [bytesToHex(top)], produced: [],
          });
          break;
        }

        default: {
          steps.push({
            opcode, opcodeName: OPCODE_NAMES[opcode] || `0x${opcode.toString(16)}`,
            description: `Opcode desconocido: 0x${opcode.toString(16)}`,
            stack: stackToHex(), consumed: [], produced: [],
          });
        }
      }
    }

    const finalStack = stackToHex();
    const top = stack[stack.length - 1];
    const success = top !== undefined && top.length > 0 && top.some(b => b !== 0);
    return { steps, success, finalStack };

  } catch (e) {
    return { steps, success: false, finalStack: stackToHex(), error: (e as Error).message };
  }
}

// ─── Creación de scripts ────────────────────────────────────

/**
 * P2PKH scriptPubKey: OP_DUP OP_HASH160 <20 bytes pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
 * Es el script "clásico" de Bitcoin. Direcciones que empiezan por 1.
 */
export function createP2PKH(pubKeyHash: Uint8Array): Uint8Array {
  return new Uint8Array([
    OP.OP_DUP,           // duplicar la pubKey del scriptSig
    OP.OP_HASH160,       // hashear: SHA-256 → RIPEMD-160
    0x14,                // push 20 bytes
    ...pubKeyHash,       // el hash esperado de la pubKey
    OP.OP_EQUALVERIFY,   // ¿coinciden los hashes?
    OP.OP_CHECKSIG,      // ¿la firma es válida para esta pubKey?
  ]);
}

/**
 * P2WPKH scriptPubKey: OP_0 <20 bytes pubKeyHash>
 * SegWit v0 nativo. Direcciones bc1q...
 * La firma va en el witness, no en scriptSig.
 */
export function createP2WPKH(pubKeyHash: Uint8Array): Uint8Array {
  return new Uint8Array([
    OP.OP_0,    // witness version 0
    0x14,       // push 20 bytes
    ...pubKeyHash,
  ]);
}

/**
 * P2TR scriptPubKey: OP_1 <32 bytes tweaked pubkey x>
 * Taproot (SegWit v1). Direcciones bc1p...
 * Usa firma Schnorr con x-only public keys.
 */
export function createP2TR(tweakedPubKeyX: Uint8Array): Uint8Array {
  return new Uint8Array([
    OP.OP_1,    // witness version 1
    0x20,       // push 32 bytes
    ...tweakedPubKeyX,
  ]);
}

/**
 * witnessScript multisig m-of-n:
 *   OP_m <pubkey1> <pubkey2> ... <pubkeyN> OP_n OP_CHECKMULTISIG
 *
 * Es el script que hay que cumplir para gastar. En P2WSH este script NO va en la
 * dirección: solo va su SHA-256 (ver createP2WSH). Se revela al gastar, en el witness.
 *
 * Las claves suelen ser comprimidas (33 bytes). El orden importa para el gasto;
 * para descriptores reproducibles se ordenan lexicográficamente (sortedmulti / BIP67),
 * pero eso es cosa de la capa de descriptor, no de este script.
 */
export function createMultisig(m: number, pubKeys: Uint8Array[]): Uint8Array {
  const n = pubKeys.length;
  if (n < 1 || n > 16) throw new Error('n (número de claves) debe estar entre 1 y 16');
  if (m < 1 || m > n) throw new Error(`m (umbral) debe estar entre 1 y ${n}`);

  const script: number[] = [];
  script.push(0x50 + m);           // OP_m
  for (const pk of pubKeys) {
    if (pk.length > 0x4b) throw new Error('clave demasiado larga para un push simple');
    script.push(pk.length);        // push de la clave (0x21 = 33 bytes si es comprimida)
    script.push(...pk);
  }
  script.push(0x50 + n);           // OP_n
  script.push(OP.OP_CHECKMULTISIG);
  return new Uint8Array(script);
}

/**
 * P2WSH scriptPubKey: OP_0 <32 bytes SHA-256(witnessScript)>
 * SegWit v0 nativo, pero para SCRIPTS arbitrarios (multisig, timelocks…), no para
 * una sola clave. Direcciones bc1q... más largas que P2WPKH (32 bytes vs 20).
 *
 * Diferencia clave con P2WPKH: aquí se usa SHA-256 «a secas» (32 bytes), no HASH160
 * (RIPEMD160(SHA256), 20 bytes). Con scripts, 20 bytes darían poca resistencia a
 * colisiones para un atacante que elige el script.
 */
export function createP2WSH(witnessScript: Uint8Array): Uint8Array {
  const hash = hexToBytes(sha256(witnessScript).hash);   // SHA-256, 32 bytes
  return new Uint8Array([
    OP.OP_0,    // witness version 0
    0x20,       // push 32 bytes
    ...hash,
  ]);
}

/** Desensambla un script a texto legible */
export function disassemble(script: Uint8Array): string[] {
  const result: string[] = [];
  let offset = 0;

  while (offset < script.length) {
    const opcode = script[offset];
    offset++;

    if (opcode >= 0x01 && opcode <= 0x4b) {
      const data = script.slice(offset, offset + opcode);
      offset += opcode;
      result.push(`PUSH(${bytesToHex(data)})`);
    } else if (OPCODE_NAMES[opcode]) {
      result.push(OPCODE_NAMES[opcode]);
    } else {
      result.push(`0x${opcode.toString(16)}`);
    }
  }

  return result;
}

// ─── Bech32 / Bech32m ───────────────────────────────────────
/**
 * Bech32 es la codificación de direcciones para SegWit (BIP173).
 * Bech32m es la versión mejorada para Taproot y futuras versiones (BIP350).
 *
 * Formato: hrp + "1" + data_part
 * Ejemplo: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
 *          ^^ ^                                    ^^^^^^^
 *          hrp separator                           checksum
 *
 * Ventajas sobre Base58Check:
 *   - Solo minúsculas (sin confusión 0/O, l/I)
 *   - Detección de errores más potente (BCH code)
 *   - Más eficiente en QR codes
 */

const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

const BECH32_CONST = 1;   // Bech32 (SegWit v0)
const BECH32M_CONST = 0x2bc830a3; // Bech32m (SegWit v1+)

function bech32Polymod(values: number[]): number {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((top >> i) & 1) chk ^= GEN[i];
    }
  }
  return chk;
}

function bech32HrpExpand(hrp: string): number[] {
  const result: number[] = [];
  for (let i = 0; i < hrp.length; i++) result.push(hrp.charCodeAt(i) >> 5);
  result.push(0);
  for (let i = 0; i < hrp.length; i++) result.push(hrp.charCodeAt(i) & 31);
  return result;
}

function bech32CreateChecksum(hrp: string, data: number[], spec: number): number[] {
  const values = [...bech32HrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
  const polymod = bech32Polymod(values) ^ spec;
  const checksum: number[] = [];
  for (let i = 0; i < 6; i++) {
    checksum.push((polymod >> (5 * (5 - i))) & 31);
  }
  return checksum;
}

function bech32VerifyChecksum(hrp: string, data: number[]): number {
  return bech32Polymod([...bech32HrpExpand(hrp), ...data]);
}

/** Convierte bytes (8-bit) a grupos de 5 bits (para bech32) */
function convertBits(data: Uint8Array, fromBits: number, toBits: number, pad: boolean): number[] {
  let acc = 0;
  let bits = 0;
  const result: number[] = [];
  const maxv = (1 << toBits) - 1;

  for (const value of data) {
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      result.push((acc >> bits) & maxv);
    }
  }

  if (pad && bits > 0) {
    result.push((acc << (toBits - bits)) & maxv);
  }

  return result;
}

/**
 * Codifica una dirección SegWit en bech32/bech32m.
 * @param hrp - "bc" para mainnet, "tb" para testnet
 * @param witnessVersion - 0 para P2WPKH, 1 para P2TR
 * @param witnessProgram - 20 bytes (P2WPKH) o 32 bytes (P2TR)
 */
export function bech32Encode(hrp: string, witnessVersion: number, witnessProgram: Uint8Array): string {
  const spec = witnessVersion === 0 ? BECH32_CONST : BECH32M_CONST;
  const data5bit = convertBits(witnessProgram, 8, 5, true);
  const allData = [witnessVersion, ...data5bit];
  const checksum = bech32CreateChecksum(hrp, allData, spec);
  const combined = [...allData, ...checksum];
  return hrp + '1' + combined.map(d => BECH32_CHARSET[d]).join('');
}

/**
 * Decodifica una dirección bech32/bech32m.
 * Devuelve el witness version y el witness program.
 */
export function bech32Decode(address: string): { hrp: string; version: number; program: Uint8Array } | null {
  const lower = address.toLowerCase();
  const pos = lower.lastIndexOf('1');
  if (pos < 1 || pos + 7 > lower.length) return null;

  const hrp = lower.slice(0, pos);
  const dataStr = lower.slice(pos + 1);
  const data: number[] = [];
  for (const ch of dataStr) {
    const idx = BECH32_CHARSET.indexOf(ch);
    if (idx === -1) return null;
    data.push(idx);
  }

  const check = bech32VerifyChecksum(hrp, data);
  if (check !== BECH32_CONST && check !== BECH32M_CONST) return null;

  const version = data[0];
  // v0 = bech32, v1+ = bech32m
  if (version === 0 && check !== BECH32_CONST) return null;
  if (version > 0 && check !== BECH32M_CONST) return null;

  const payload = data.slice(1, -6);
  const programBits = convertBits(new Uint8Array(payload), 5, 8, false);
  const program = new Uint8Array(programBits);

  return { hrp, version, program };
}

// ─── Generación de direcciones ──────────────────────────────

/** Genera una dirección P2PKH (1xxx) desde un hash160 de clave pública */
export function addressP2PKH(pubKeyHash: Uint8Array, mainnet = true): string {
  // Este import circular se evita porque base58 solo exporta funciones puras
  // En la práctica, para P2PKH usamos Base58Check (implementada en base58.ts)
  // Aquí devolvemos el scriptPubKey y el hash para referencia
  return (mainnet ? '00' : '6f') + bytesToHex(pubKeyHash);
}

/** Genera una dirección P2WPKH (bc1qxxx) desde un hash160 */
export function addressP2WPKH(pubKeyHash: Uint8Array, mainnet = true): string {
  return bech32Encode(mainnet ? 'bc' : 'tb', 0, pubKeyHash);
}

/** Genera una dirección P2TR (bc1pxxx) desde una x-only pubkey (32 bytes) */
export function addressP2TR(tweakedPubKeyX: Uint8Array, mainnet = true): string {
  return bech32Encode(mainnet ? 'bc' : 'tb', 1, tweakedPubKeyX);
}

/**
 * Genera una dirección P2WSH (bc1q..., 32 bytes) desde un witnessScript.
 * El programa testigo es SHA-256(witnessScript). Sirve para multisig y otros scripts.
 */
export function addressP2WSH(witnessScript: Uint8Array, mainnet = true): string {
  const hash = hexToBytes(sha256(witnessScript).hash);
  return bech32Encode(mainnet ? 'bc' : 'tb', 0, hash);
}

// ─── Utilidades ─────────────────────────────────────────────

/**
 * Lee un "script number" de la pila. Bitcoin los guarda en little-endian con signo
 * (complemento a uno en el bit alto). Aquí solo manejamos enteros pequeños y
 * positivos (0..20: los umbrales/totales de multisig), así que basta con leer los
 * bytes en little-endian. Un item vacío representa el 0.
 */
function readScriptNum(item: Uint8Array): number {
  let value = 0;
  for (let i = 0; i < item.length; i++) value |= item[i] << (8 * i);
  return value;
}

/**
 * Codifica un entero pequeño y no negativo como "script number" (LE, sin signo).
 * El 0 es el item VACÍO; para 1..127 basta un byte. Suficiente para los contadores
 * de OP_CHECKSIGADD (0..n con n ≤ 20).
 */
function encodeScriptNum(value: number): Uint8Array {
  if (value === 0) return new Uint8Array(0);
  if (value < 0 || value > 0x7f) throw new Error('encodeScriptNum solo maneja 0..127');
  return new Uint8Array([value]);
}

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
