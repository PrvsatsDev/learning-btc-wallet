/**
 * BIP143 — Sighash para SegWit v0 (P2WPKH / P2WSH)
 *
 * El "sighash" es el hash que firmas en una transacción: el compromiso
 * criptográfico de "yo autorizo esta tx exactamente como está". Firmar el
 * hash evita tener que firmar toda la tx (mucho más barato) y sobre todo
 * evita el problema clásico de "¿cómo firmas una tx que contiene tu firma?".
 *
 * Antes de SegWit, el algoritmo de sighash (legacy) tenía dos problemas graves:
 *   1. Era O(n²) — para cada input, re-serializabas la tx entera con ese
 *      scriptCode insertado. Con muchos inputs, verificar una tx era lentísimo.
 *   2. NO incluía la cantidad del UTXO gastado. Una wallet hardware que recibía
 *      la tx a firmar no podía saber cuánto iba a la comisión sin ver la tx
 *      previa entera. Esto permitía ataques tipo "fee alto inesperado".
 *
 * BIP143 reescribe el algoritmo para SegWit:
 *   - Precalcula TRES hashes compartidos entre todos los inputs:
 *       hashPrevouts  — compromiso con qué UTXOs se gastan
 *       hashSequence  — compromiso con los sequence numbers
 *       hashOutputs   — compromiso con todos los outputs
 *     Así, firmar N inputs es O(N) en lugar de O(N²).
 *   - INCLUYE la cantidad del UTXO gastado (amount). Ahora una hardware wallet
 *     puede verificar la fee con seguridad antes de firmar. Esta fue la mejora
 *     práctica más importante de SegWit para wallets hardware.
 *
 * El preimage (lo que hasheas con dSHA256 para obtener el sighash) es:
 *
 *   1. nVersion         (4 B LE)
 *   2. hashPrevouts     (32 B) = dSHA256 de todos los (txid-rev || vout-LE)
 *   3. hashSequence     (32 B) = dSHA256 de todos los sequence
 *   4. outpoint         (36 B) = txid-rev || vout-LE  DEL INPUT QUE FIRMAS
 *   5. scriptCode       (varint-prefixed)  DEL INPUT QUE FIRMAS
 *   6. amount           (8 B LE)  DEL INPUT QUE FIRMAS
 *   7. nSequence        (4 B LE)  DEL INPUT QUE FIRMAS
 *   8. hashOutputs      (32 B) = dSHA256 de todos los outputs serializados
 *   9. nLocktime        (4 B LE)
 *  10. sighashType      (4 B LE, normalmente 0x00000001 = SIGHASH_ALL)
 *
 *   sighash = dSHA256(preimage)
 *
 * Para P2WPKH, el scriptCode es el P2PKH "equivalente" del pubkey hash:
 *   76 a9 14 {hash160(pubkey) 20B} 88 ac   — 25 bytes
 * (Curiosidad: BIP143 reutiliza la forma de P2PKH para mantener compatibilidad
 *  conceptual con el sistema legacy. Firmas "como si" estuvieras gastando un P2PKH
 *  de la misma pubkey, pero con el algoritmo nuevo).
 */

import { sha256 } from './sha256';
import type { Transaction, TxField } from './transaction';
import { ecdsaSign, type EcdsaSignResult } from './ecdsa';

// ─── SIGHASH types ──────────────────────────────────────────

export const SIGHASH = {
  ALL: 0x01,
  NONE: 0x02,
  SINGLE: 0x03,
  ANYONECANPAY: 0x80,
} as const;

// ─── Utilidades internas ────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function reverseBytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array([...bytes].reverse());
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

function uint32LE(n: number): Uint8Array {
  const b = new Uint8Array(4);
  b[0] = n & 0xff; b[1] = (n >> 8) & 0xff;
  b[2] = (n >> 16) & 0xff; b[3] = (n >> 24) & 0xff;
  return b;
}

function int64LE(n: bigint): Uint8Array {
  const b = new Uint8Array(8);
  for (let i = 0; i < 8; i++) b[i] = Number((n >> BigInt(i * 8)) & 0xffn);
  return b;
}

function varInt(n: number): Uint8Array {
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) return new Uint8Array([0xfd, n & 0xff, (n >> 8) & 0xff]);
  if (n <= 0xffffffff) {
    return new Uint8Array([
      0xfe,
      n & 0xff, (n >> 8) & 0xff,
      (n >> 16) & 0xff, (n >> 24) & 0xff,
    ]);
  }
  throw new Error('varInt > 32 bits no soportado');
}

/** Doble SHA-256. Devuelve 32 bytes. */
function dSHA256(data: Uint8Array): Uint8Array {
  const h1 = hexToBytes(sha256(data).hash);
  return hexToBytes(sha256(h1).hash);
}

// ─── Hashes precalculados (BIP143) ──────────────────────────

/**
 * hashPrevouts = dSHA256(serialize(input.prevout) para todos los inputs).
 * Cada outpoint son 36 bytes: txid-reversed (32) || vout-LE (4).
 *
 * ¿Por qué se precalcula? Porque es idéntico para todos los inputs de esta tx.
 * En lugar de rehacer el trabajo N veces (como hacía el sighash legacy),
 * BIP143 lo hace una vez y lo reutiliza → firma O(N) en lugar de O(N²).
 */
export function computeHashPrevouts(tx: Transaction): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const input of tx.inputs) {
    parts.push(reverseBytes(hexToBytes(input.prevTxId)));
    parts.push(uint32LE(input.prevVout));
  }
  return dSHA256(concat(...parts));
}

/**
 * hashSequence = dSHA256(sequence LE de todos los inputs).
 *
 * Compromiso con los sequence numbers de todos los inputs. Importante para
 * timelocks relativos (BIP68) y RBF (BIP125): al firmar, aseguras que nadie
 * puede cambiar estos valores sin invalidar la firma.
 */
export function computeHashSequence(tx: Transaction): Uint8Array {
  const parts = tx.inputs.map(i => uint32LE(i.sequence));
  return dSHA256(concat(...parts));
}

/**
 * hashOutputs = dSHA256(todos los outputs serializados).
 *
 * Cada output serializado = value (8B LE) || varint(scriptLen) || script.
 * Esto es lo que fija "a dónde va el dinero" — si alguien cambia un output,
 * este hash cambia y la firma deja de ser válida.
 */
export function computeHashOutputs(tx: Transaction): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const out of tx.outputs) {
    parts.push(int64LE(out.value));
    parts.push(varInt(out.scriptPubKey.length));
    parts.push(out.scriptPubKey);
  }
  return dSHA256(concat(...parts));
}

// ─── scriptCode P2WPKH ──────────────────────────────────────

/**
 * scriptCode de P2WPKH = 76 a9 14 {hash160(pubkey)} 88 ac
 *
 *   OP_DUP OP_HASH160 <20B> OP_EQUALVERIFY OP_CHECKSIG
 *
 * Es literalmente el scriptPubKey de un P2PKH con la misma pubkey.
 * La idea detrás: firmas "como si" estuvieras desbloqueando un P2PKH
 * tradicional. Esto mantiene compatibilidad conceptual y simplifica
 * la implementación de validadores SegWit.
 */
export function p2wpkhScriptCode(pubKeyHash20: Uint8Array): Uint8Array {
  if (pubKeyHash20.length !== 20) {
    throw new Error('pubKeyHash debe ser 20 bytes');
  }
  const out = new Uint8Array(25);
  out[0] = 0x76; // OP_DUP
  out[1] = 0xa9; // OP_HASH160
  out[2] = 0x14; // push 20 bytes
  out.set(pubKeyHash20, 3);
  out[23] = 0x88; // OP_EQUALVERIFY
  out[24] = 0xac; // OP_CHECKSIG
  return out;
}

// ─── Sighash BIP143 ─────────────────────────────────────────

export interface SighashBIP143Result {
  preimage: Uint8Array;       // los bytes exactos que se hashean
  preimageFields: TxField[];  // desglose anotado (para visualizar)
  sighash: Uint8Array;        // dSHA256(preimage) — lo que se firma
  hashPrevouts: Uint8Array;
  hashSequence: Uint8Array;
  hashOutputs: Uint8Array;
  scriptCode: Uint8Array;
}

/** Alias histórico: el resultado es el mismo para P2WPKH y P2WSH. */
export type SighashP2WPKHResult = SighashBIP143Result;

/**
 * Calcula el sighash BIP143 GENÉRICO para un input SegWit v0.
 *
 * Es el corazón común de P2WPKH y P2WSH: el preimage y el algoritmo son
 * idénticos, lo ÚNICO que cambia es el `scriptCode`:
 *   - P2WPKH: el P2PKH-equivalente de la pubkey (ver p2wpkhScriptCode).
 *   - P2WSH:  el witnessScript ENTERO (p. ej. el script multisig m-of-n).
 * Por eso este núcleo recibe el scriptCode ya montado y no sabe (ni le importa)
 * de qué tipo de output viene. El multisig firma "sobre" su propio witnessScript.
 *
 * @param tx          - Transacción (con witness opcional; los witness NO se incluyen)
 * @param inputIndex  - Qué input estamos firmando
 * @param scriptCode  - El scriptCode a comprometer (varint-prefijado dentro del preimage)
 * @param amount      - Valor del UTXO gastado, en satoshis (BIP143 obliga a incluirlo)
 * @param sighashType - Tipo de sighash (por defecto SIGHASH_ALL = 0x01)
 */
export function computeSighashBIP143(
  tx: Transaction,
  inputIndex: number,
  scriptCode: Uint8Array,
  amount: bigint,
  sighashType: number = SIGHASH.ALL,
): SighashBIP143Result {
  const input = tx.inputs[inputIndex];
  if (!input) throw new Error(`Input ${inputIndex} no existe`);

  const hashPrevouts = computeHashPrevouts(tx);
  const hashSequence = computeHashSequence(tx);
  const hashOutputs = computeHashOutputs(tx);

  // Campos anotados — se muestran en orden de aparición en el preimage
  const fields: TxField[] = [
    {
      name: '1. nVersion',
      bytes: uint32LE(tx.version),
      description: `Versión de la tx (${tx.version}) — compromete a qué reglas aplican`,
      color: '#a78bfa',
    },
    {
      name: '2. hashPrevouts',
      bytes: hashPrevouts,
      description: 'dSHA256 de todos los (txid,vout) concatenados — qué UTXOs se gastan',
      color: '#f87171',
    },
    {
      name: '3. hashSequence',
      bytes: hashSequence,
      description: 'dSHA256 de los sequence numbers — RBF/timelocks',
      color: '#94a3b8',
    },
    {
      name: `4. outpoint (input #${inputIndex})`,
      bytes: concat(reverseBytes(hexToBytes(input.prevTxId)), uint32LE(input.prevVout)),
      description: 'UTXO concreto que estamos firmando ahora',
      color: '#fb923c',
    },
    {
      name: '5. scriptCode (len)',
      bytes: varInt(scriptCode.length),
      description: `varint con la longitud del scriptCode (${scriptCode.length} bytes)`,
      color: '#38bdf8',
    },
    {
      name: '5. scriptCode',
      bytes: scriptCode,
      description: 'Script que se compromete al firmar (P2PKH-equiv. en P2WPKH, witnessScript en P2WSH)',
      color: '#38bdf8',
    },
    {
      name: '6. amount',
      bytes: int64LE(amount),
      description: `Valor del UTXO gastado: ${amount.toString()} sats (solo SegWit incluye esto)`,
      color: '#4ade80',
    },
    {
      name: '7. nSequence',
      bytes: uint32LE(input.sequence),
      description: `Sequence del input: 0x${input.sequence.toString(16).padStart(8, '0')}`,
      color: '#94a3b8',
    },
    {
      name: '8. hashOutputs',
      bytes: hashOutputs,
      description: 'dSHA256 de todos los outputs — fija a dónde va el dinero',
      color: '#2dd4bf',
    },
    {
      name: '9. nLocktime',
      bytes: uint32LE(tx.locktime),
      description: `Locktime de la tx: ${tx.locktime}`,
      color: '#c084fc',
    },
    {
      name: '10. sighashType',
      bytes: uint32LE(sighashType),
      description: sighashType === SIGHASH.ALL
        ? 'SIGHASH_ALL (0x01) — firmas todos los inputs y outputs'
        : `Sighash type 0x${sighashType.toString(16)}`,
      color: '#e879f9',
    },
  ];

  const preimage = concat(...fields.map(f => f.bytes));
  const sighash = dSHA256(preimage);

  return {
    preimage,
    preimageFields: fields,
    sighash,
    hashPrevouts,
    hashSequence,
    hashOutputs,
    scriptCode,
  };
}

/**
 * Sighash BIP143 para un input P2WPKH. Envoltorio fino sobre
 * `computeSighashBIP143`: solo construye el scriptCode P2PKH-equivalente.
 *
 * @param pubKeyHash  - hash160 de la pubkey del propietario del UTXO (20 B)
 */
export function computeSighashP2WPKH(
  tx: Transaction,
  inputIndex: number,
  pubKeyHash: Uint8Array,
  amount: bigint,
  sighashType: number = SIGHASH.ALL,
): SighashP2WPKHResult {
  return computeSighashBIP143(tx, inputIndex, p2wpkhScriptCode(pubKeyHash), amount, sighashType);
}

/**
 * Sighash BIP143 para un input P2WSH. Envoltorio fino sobre
 * `computeSighashBIP143`: el scriptCode ES el witnessScript entero.
 *
 * @param witnessScript - El script que se revela al gastar (p. ej. multisig m-of-n)
 */
export function computeSighashP2WSH(
  tx: Transaction,
  inputIndex: number,
  witnessScript: Uint8Array,
  amount: bigint,
  sighashType: number = SIGHASH.ALL,
): SighashBIP143Result {
  return computeSighashBIP143(tx, inputIndex, witnessScript, amount, sighashType);
}

// ─── Firma completa de un input P2WPKH ──────────────────────

export interface SignP2WPKHResult {
  sighashInfo: SighashP2WPKHResult;   // preimage + sighash (para visualizar)
  ecdsa: EcdsaSignResult;             // firma ECDSA (r, s, k, DER...) — didáctico
  signatureWithHashType: Uint8Array;  // DER || sighashType — lo que va al witness
  witness: Uint8Array[];              // [signature+type, pubkey] — 2 elementos
}

/**
 * Firma un input P2WPKH completo.
 *
 * El witness final para P2WPKH son SIEMPRE dos elementos:
 *   witness[0] = DER(signature) || sighashType (1 byte)
 *   witness[1] = pubkey comprimida (33 bytes)
 *
 * ¿Por qué el sighash type se pega al final de la firma? Porque el verificador
 * necesita saber qué sighash rehacer (ALL / NONE / SINGLE / ANYONECANPAY).
 * Por convención Bitcoin mete ese byte al final de cada firma serializada.
 *
 * @param tx                   - Transacción a firmar
 * @param inputIndex           - Qué input firmamos
 * @param privateKey           - Clave privada del UTXO (bigint)
 * @param compressedPubKey     - Pubkey comprimida (33 B) — va al witness
 * @param pubKeyHash           - hash160(pubkey) (20 B) — va al scriptCode
 * @param amount               - Valor del UTXO (BIP143 lo exige)
 * @param sighashType          - SIGHASH_ALL por defecto
 */
export function signP2WPKHInput(
  tx: Transaction,
  inputIndex: number,
  privateKey: bigint,
  compressedPubKey: Uint8Array,
  pubKeyHash: Uint8Array,
  amount: bigint,
  sighashType: number = SIGHASH.ALL,
): SignP2WPKHResult {
  // 1) Calcular sighash BIP143
  const sighashInfo = computeSighashP2WPKH(tx, inputIndex, pubKeyHash, amount, sighashType);

  // 2) Firmar el sighash con ECDSA (RFC 6979, low-s, DER)
  const ecdsa = ecdsaSign(sighashInfo.sighash, privateKey);

  // 3) Pegarle el sighash type como byte final a la firma DER
  const signatureWithHashType = new Uint8Array(ecdsa.der.length + 1);
  signatureWithHashType.set(ecdsa.der, 0);
  signatureWithHashType[ecdsa.der.length] = sighashType;

  // 4) Witness P2WPKH = [firma+type, pubkey]
  const witness: Uint8Array[] = [signatureWithHashType, compressedPubKey];

  return { sighashInfo, ecdsa, signatureWithHashType, witness };
}

