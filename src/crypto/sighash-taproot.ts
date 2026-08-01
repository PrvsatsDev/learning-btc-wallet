/**
 * Sighash de Taproot (BIP341) — el mensaje que se firma en un gasto SegWit v1.
 *
 * Taproot reescribe otra vez el algoritmo de sighash (ya lo hizo BIP143 para
 * SegWit v0). Los cambios respecto a BIP143 son importantes:
 *
 *   1. Compromete el UTXO de TODOS los inputs, no solo el que se firma:
 *      sha_amounts (importes) y sha_scriptpubkeys (scripts) de todos. Así una
 *      hardware wallet ve TODO lo que se gasta y no puede ser engañada sobre
 *      inputs que no controla.
 *   2. Usa SHA256 SIMPLE (no doble) y un tagged hash final "TapSighash".
 *   3. Añade un byte `spend_type` (key-path vs script-path, y si hay annex) y,
 *      para script-path, el hash de la hoja (ext).
 *   4. Un `epoch` 0x00 al principio, reservado para futuras versiones.
 *
 * El mensaje (SigMsg), en orden:
 *
 *   epoch (1)  = 0x00
 *   hash_type (1)
 *   nVersion (4 LE)
 *   nLockTime (4 LE)
 *   si NO es ANYONECANPAY:
 *     sha_prevouts     = SHA256( outpoints de todos los inputs )
 *     sha_amounts      = SHA256( importes (8 LE) de todos los UTXOs gastados )
 *     sha_scriptpubkeys= SHA256( scriptPubKeys (con longitud) de todos )
 *     sha_sequences    = SHA256( nSequence (4 LE) de todos )
 *   si NO es NONE ni SINGLE:
 *     sha_outputs      = SHA256( todos los outputs serializados )
 *   spend_type (1)     = ext_flag*2 + (annex ? 1 : 0)
 *   si ANYONECANPAY:  outpoint(36) ‖ amount(8) ‖ scriptPubKey(len‖…) ‖ nSequence(4)  DEL input
 *   si NO ANYONECANPAY: input_index (4 LE)
 *   si hay annex: sha_annex
 *   si SINGLE: sha_single_output = SHA256( el output con el mismo índice )
 *   si script-path (ext): tapLeafHash(32) ‖ keyVersion(1) ‖ codeSepPos(4 LE)
 *
 *   sighash = taggedHash("TapSighash", epoch ‖ SigMsg)   ← ¡hash simple + tag!
 *
 * hash_type: 0x00 = DEFAULT (se comporta como ALL). También ALL(1)/NONE(2)/
 * SINGLE(3), combinables con ANYONECANPAY(0x80).
 *
 * Verificado contra los vectores oficiales BIP341 keyPathSpending (ver test).
 */

import type { Transaction, TxOutput, TxField } from './transaction';
import { serializeVarInt } from './transaction';
import { taggedHash } from './schnorr';
import { sha256 } from './sha256';
import { SIGHASH } from './sighash';

export const SIGHASH_DEFAULT = 0x00;

// ─── Utilidades ─────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  return b;
}

function reverseBytes(b: Uint8Array): Uint8Array {
  return new Uint8Array([...b].reverse());
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
  b[0] = n & 0xff; b[1] = (n >> 8) & 0xff; b[2] = (n >> 16) & 0xff; b[3] = (n >> 24) & 0xff;
  return b;
}

function int64LE(n: bigint): Uint8Array {
  const b = new Uint8Array(8);
  for (let i = 0; i < 8; i++) b[i] = Number((n >> BigInt(i * 8)) & 0xffn);
  return b;
}

/** SHA256 SIMPLE (a diferencia de BIP143, que usa doble). Devuelve 32 bytes. */
function sha256Bytes(data: Uint8Array): Uint8Array {
  return hexToBytes(sha256(data).hash);
}

/** Serializa un output: value(8 LE) ‖ compactSize(len) ‖ scriptPubKey. */
function serializeOutput(out: TxOutput): Uint8Array {
  return concat(int64LE(out.value), serializeVarInt(out.scriptPubKey.length), out.scriptPubKey);
}

// ─── Hashes precalculados (SHA256 simple, BIP341) ───────────

export function shaPrevouts(tx: Transaction): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const i of tx.inputs) parts.push(reverseBytes(hexToBytes(i.prevTxId)), uint32LE(i.prevVout));
  return sha256Bytes(concat(...parts));
}

export function shaAmounts(prevouts: TxOutput[]): Uint8Array {
  return sha256Bytes(concat(...prevouts.map(o => int64LE(o.value))));
}

export function shaScriptPubkeys(prevouts: TxOutput[]): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const o of prevouts) parts.push(serializeVarInt(o.scriptPubKey.length), o.scriptPubKey);
  return sha256Bytes(concat(...parts));
}

export function shaSequences(tx: Transaction): Uint8Array {
  return sha256Bytes(concat(...tx.inputs.map(i => uint32LE(i.sequence))));
}

export function shaOutputs(tx: Transaction): Uint8Array {
  return sha256Bytes(concat(...tx.outputs.map(serializeOutput)));
}

// ─── Sighash BIP341 ─────────────────────────────────────────

export interface TaprootSighashOptions {
  hashType?: number;              // por defecto SIGHASH_DEFAULT (0x00)
  annex?: Uint8Array;             // annex opcional (BIP341) sin el prefijo 0x50
  /** Para gasto por SCRIPT-PATH (ext_flag = 1). */
  ext?: { tapLeafHash: Uint8Array; keyVersion?: number; codeSepPos?: number };
}

export interface TaprootSighashResult {
  sigMsg: Uint8Array;         // epoch ‖ SigMsg (lo que va dentro del tagged hash)
  sigHash: Uint8Array;        // taggedHash("TapSighash", sigMsg) — lo que se firma
  fields: TxField[];          // desglose anotado (para visualizar)
}

const ALLOWED = new Set([0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83]);

/**
 * Calcula el sighash BIP341 para un input.
 *
 * @param tx         - la transacción
 * @param inputIndex - qué input se firma
 * @param prevouts   - los UTXOs gastados por CADA input (importe + scriptPubKey), en orden
 * @param opts       - hashType, annex y datos de script-path
 */
export function computeSighashTaproot(
  tx: Transaction,
  inputIndex: number,
  prevouts: TxOutput[],
  opts: TaprootSighashOptions = {},
): TaprootSighashResult {
  const hashType = opts.hashType ?? SIGHASH_DEFAULT;
  if (!ALLOWED.has(hashType)) throw new Error(`hashType no soportado: 0x${hashType.toString(16)}`);
  if (prevouts.length !== tx.inputs.length) throw new Error('prevouts debe tener un UTXO por input');
  const input = tx.inputs[inputIndex];
  if (!input) throw new Error(`Input ${inputIndex} no existe`);

  const anyonecanpay = (hashType & SIGHASH.ANYONECANPAY) !== 0;
  const outputMode = hashType & 0x03; // 0=DEFAULT(≈ALL), 1=ALL, 2=NONE, 3=SINGLE
  const isSingle = outputMode === SIGHASH.SINGLE;
  const isNone = outputMode === SIGHASH.NONE;
  const includeOutputs = !isSingle && !isNone;
  const ext = opts.ext;
  const extFlag = ext ? 1 : 0;
  const spendType = extFlag * 2 + (opts.annex ? 1 : 0);

  const fields: TxField[] = [];
  const add = (name: string, bytes: Uint8Array, description: string, color: string) => {
    fields.push({ name, bytes, description, color });
    return bytes;
  };

  add('epoch', new Uint8Array([0x00]), 'Reservado para futuras versiones (siempre 0x00)', '#64748b');
  add('hash_type', new Uint8Array([hashType]), sighashLabel(hashType), '#e879f9');
  add('nVersion', uint32LE(tx.version), `Versión ${tx.version}`, '#a78bfa');
  add('nLockTime', uint32LE(tx.locktime), `Locktime ${tx.locktime}`, '#c084fc');

  if (!anyonecanpay) {
    add('sha_prevouts', shaPrevouts(tx), 'SHA256 de los outpoints de TODOS los inputs', '#f87171');
    add('sha_amounts', shaAmounts(prevouts), 'SHA256 de los importes de TODOS los UTXOs gastados', '#4ade80');
    add('sha_scriptpubkeys', shaScriptPubkeys(prevouts), 'SHA256 de los scriptPubKeys de TODOS los UTXOs', '#38bdf8');
    add('sha_sequences', shaSequences(tx), 'SHA256 de los nSequence de TODOS los inputs', '#94a3b8');
  }
  if (includeOutputs) {
    add('sha_outputs', shaOutputs(tx), 'SHA256 de TODOS los outputs', '#2dd4bf');
  }

  add('spend_type', new Uint8Array([spendType]), `ext_flag=${extFlag}, annex=${opts.annex ? 1 : 0}`, '#fbbf24');

  if (anyonecanpay) {
    const po = prevouts[inputIndex];
    add('outpoint', concat(reverseBytes(hexToBytes(input.prevTxId)), uint32LE(input.prevVout)), 'El UTXO concreto (solo ANYONECANPAY)', '#fb923c');
    add('amount', int64LE(po.value), `Importe del UTXO: ${po.value} sats`, '#4ade80');
    add('scriptPubKey', concat(serializeVarInt(po.scriptPubKey.length), po.scriptPubKey), 'scriptPubKey del UTXO gastado', '#38bdf8');
    add('nSequence', uint32LE(input.sequence), `Sequence 0x${input.sequence.toString(16).padStart(8, '0')}`, '#94a3b8');
  } else {
    add('input_index', uint32LE(inputIndex), `Índice del input firmado: ${inputIndex}`, '#fb923c');
  }

  if (opts.annex) {
    add('sha_annex', sha256Bytes(concat(serializeVarInt(opts.annex.length), opts.annex)), 'SHA256 del annex', '#a3a3a3');
  }

  if (isSingle) {
    const out = tx.outputs[inputIndex];
    if (!out) throw new Error(`SIGHASH_SINGLE sin output ${inputIndex}`);
    add('sha_single_output', sha256Bytes(serializeOutput(out)), `SHA256 del output ${inputIndex} (solo SINGLE)`, '#2dd4bf');
  }

  if (ext) {
    add('tapleaf_hash', ext.tapLeafHash, 'Hash de la hoja de script que se ejecuta', '#38bdf8');
    add('key_version', new Uint8Array([ext.keyVersion ?? 0]), 'Versión de clave (0)', '#64748b');
    add('codesep_pos', uint32LE(ext.codeSepPos ?? 0xffffffff), 'Posición del último OP_CODESEPARATOR (0xffffffff = ninguno)', '#64748b');
  }

  const sigMsg = concat(...fields.map(f => f.bytes));
  const sigHash = taggedHash('TapSighash', sigMsg);

  return { sigMsg, sigHash, fields };
}

function sighashLabel(hashType: number): string {
  const base = ({ 0: 'DEFAULT', 1: 'ALL', 2: 'NONE', 3: 'SINGLE' } as Record<number, string>)[hashType & 3];
  const acp = (hashType & SIGHASH.ANYONECANPAY) ? ' | ANYONECANPAY' : '';
  return `SIGHASH_${base}${acp} (0x${hashType.toString(16).padStart(2, '0')})`;
}
