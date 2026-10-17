/**
 * Visor de transacciones (inputs → outputs) — Fase 4, estilo Sparrow.
 *
 * Una transacción en crudo NO dice cuánto dinero gasta: cada input sólo es un
 * puntero (outpoint = txid:vout) a un output de una tx anterior. Los importes de
 * entrada, el tipo de script que se desbloquea y por tanto la COMISIÓN sólo se
 * conocen mirando esas transacciones previas:
 *
 *   fee = Σ importes de entrada (de las tx previas) − Σ importes de salida
 *
 * Por eso aquí no nos fiamos de lo que diga un explorador: para cada input se
 * hashea la tx previa y se comprueba que da el txid del outpoint. Si cuadra, el
 * importe está VERIFICADO (cambiar un solo satoshi cambiaría el hash).
 *
 * Además del dibujo, el módulo interpreta lo que una wallet como Sparrow enseña:
 *   - peso / vsize y el descuento SegWit (weight = base·3 + total)
 *   - txid vs wtxid
 *   - nSequence: RBF (BIP125) y timelocks relativos (BIP68)
 *   - nLockTime: altura/fecha y el truco anti fee-sniping
 *   - cómo se gastó cada input (P2PKH, P2SH anidado, multisig, Taproot key/script-path…)
 *   - pistas heurísticas de cuál es el cambio (privacidad)
 *
 * Verificado contra transacciones reales de mainnet en tx-view.test.ts.
 */

import {
  parseTxHex,
  serializeLegacy,
  serializeWitness,
  type Transaction,
} from './transaction';
import { sha256 } from './sha256';
import { base58CheckEncode } from './base58';
import { bech32Encode, disassemble } from './script';

// ─── Tipos ──────────────────────────────────────────────────

export type ScriptType =
  | 'p2pk' | 'p2pkh' | 'p2sh' | 'p2wpkh' | 'p2wsh' | 'p2tr'
  | 'op_return' | 'witness_unknown' | 'unknown';

export interface ScriptInfo {
  type: ScriptType;
  /** null para scripts sin dirección (OP_RETURN, P2PK, raros) */
  address: string | null;
  /** Nombre corto para la UI */
  label: string;
}

export type PrevoutStatus = 'verified' | 'mismatch' | 'missing' | 'coinbase';

export interface Prevout {
  value: bigint;
  scriptPubKey: Uint8Array;
}

export interface InputView {
  index: number;
  prevTxId: string;
  prevVout: number;
  status: PrevoutStatus;
  /** Sólo si la tx previa está disponible y verificada */
  value: bigint | null;
  script: ScriptInfo | null;
  /** Cómo se desbloquea, deducido del scriptSig/witness */
  spend: string;
  sequence: number;
  sequenceInfo: string;
  signalsRbf: boolean;
  scriptSig: Uint8Array;
  witness: Uint8Array[];
  /** Tipos de sighash de las firmas encontradas (ALL, DEFAULT, …) */
  sighashes: string[];
}

export interface OutputView {
  index: number;
  value: bigint;
  script: ScriptInfo;
  scriptPubKey: Uint8Array;
  /** Texto del OP_RETURN si es legible */
  opReturnText?: string;
  /** Pistas heurísticas (no certezas) sobre si es pago o cambio */
  hints: string[];
}

export interface TxView {
  tx: Transaction;
  txid: string;
  wtxid: string;
  segwit: boolean;
  version: number;
  /** Bytes totales (con witness) */
  size: number;
  /** Bytes sin witness: lo que cuenta ×4 */
  baseSize: number;
  weight: number;
  vsize: number;
  inputs: InputView[];
  outputs: OutputView[];
  totalIn: bigint | null;
  totalOut: bigint;
  fee: bigint | null;
  /** sat/vB */
  feeRate: number | null;
  signalsRbf: boolean;
  locktime: number;
  locktimeInfo: string;
}

// ─── Utilidades de bytes ────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Doble SHA-256, mostrado al revés (convención de txid) */
function hash256Reversed(bytes: Uint8Array): string {
  const h = hexToBytes(sha256(hexToBytes(sha256(bytes).hash)).hash);
  return bytesToHex(h.reverse());
}

// ─── Parseo estricto ────────────────────────────────────────

/**
 * Parsea y VALIDA el hex: lo vuelve a serializar y exige los mismos bytes.
 * El parser de transaction.ts es permisivo (no comprueba longitudes), así que el
 * round-trip es lo que detecta hex truncado o basura.
 */
export function parseTxStrict(hexInput: string): Transaction {
  const hex = hexInput.trim().toLowerCase().replace(/\s+/g, '');
  if (!/^[0-9a-f]*$/.test(hex) || hex.length % 2 !== 0) throw new Error('No es hex válido');
  if (hex.length < 120) throw new Error('Demasiado corto para ser una transacción');
  let tx: Transaction;
  try {
    tx = parseTxHex(hex);
  } catch (e) {
    throw new Error(`No se pudo parsear: ${(e as Error).message}`);
  }
  if (rawHex(tx) !== hex) throw new Error('El hex no es una transacción bien formada (no hace round-trip)');
  return tx;
}

function hasWitness(tx: Transaction): boolean {
  return !!tx.witnesses && tx.witnesses.some(w => w.length > 0);
}

function rawHex(tx: Transaction): string {
  return hasWitness(tx) ? serializeWitness(tx).hex : serializeLegacy(tx).hex;
}

export function txidOf(tx: Transaction): string {
  return serializeLegacy(tx).txid;
}

// ─── Scripts y direcciones ──────────────────────────────────

/**
 * Reconoce las plantillas estándar de scriptPubKey y deriva su dirección.
 * La dirección NO está en la cadena: es sólo una forma de escribir el script.
 */
export function classifyScript(spk: Uint8Array, mainnet = true): ScriptInfo {
  const n = spk.length;
  const hrp = mainnet ? 'bc' : 'tb';

  // P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
  if (n === 25 && spk[0] === 0x76 && spk[1] === 0xa9 && spk[2] === 0x14 && spk[23] === 0x88 && spk[24] === 0xac) {
    return { type: 'p2pkh', label: 'P2PKH', address: base58CheckEncode(mainnet ? 0x00 : 0x6f, spk.slice(3, 23)).address };
  }
  // P2SH: OP_HASH160 <20> OP_EQUAL
  if (n === 23 && spk[0] === 0xa9 && spk[1] === 0x14 && spk[22] === 0x87) {
    return { type: 'p2sh', label: 'P2SH', address: base58CheckEncode(mainnet ? 0x05 : 0xc4, spk.slice(2, 22)).address };
  }
  // SegWit: OP_n <2..40 bytes de programa>
  const isVersionOp = spk[0] === 0x00 || (spk[0] >= 0x51 && spk[0] <= 0x60);
  if (n >= 4 && n <= 42 && isVersionOp && spk[1] === n - 2) {
    const version = spk[0] === 0x00 ? 0 : spk[0] - 0x50;
    const program = spk.slice(2);
    const address = bech32Encode(hrp, version, program);
    if (version === 0 && program.length === 20) return { type: 'p2wpkh', label: 'P2WPKH', address };
    if (version === 0 && program.length === 32) return { type: 'p2wsh', label: 'P2WSH', address };
    if (version === 1 && program.length === 32) return { type: 'p2tr', label: 'P2TR', address };
    return { type: 'witness_unknown', label: `SegWit v${version}`, address };
  }
  if (n > 0 && spk[0] === 0x6a) return { type: 'op_return', label: 'OP_RETURN', address: null };
  // P2PK: <33|65 bytes> OP_CHECKSIG (las primeras monedas, p. ej. las de Satoshi)
  if ((n === 35 && spk[0] === 33 || n === 67 && spk[0] === 65) && spk[n - 1] === 0xac) {
    return { type: 'p2pk', label: 'P2PK', address: null };
  }
  return { type: 'unknown', label: 'No estándar', address: null };
}

/** Datos de un OP_RETURN como texto, si son imprimibles */
export function opReturnText(spk: Uint8Array): string | undefined {
  const pushes = parsePushes(spk.slice(1));
  if (!pushes || pushes.length === 0) return undefined;
  const data = pushes.flatMap(p => [...p]);
  if (data.length === 0) return undefined;
  const printable = data.every(b => b === 0x0a || (b >= 0x20 && b < 0x7f));
  return printable ? String.fromCharCode(...data) : undefined;
}

/** Lista de datos empujados por un script sólo-pushes (scriptSig). null si hay opcodes. */
export function parsePushes(script: Uint8Array): Uint8Array[] | null {
  const out: Uint8Array[] = [];
  let i = 0;
  while (i < script.length) {
    const op = script[i++];
    let len: number;
    if (op === 0x00) { out.push(new Uint8Array()); continue; }
    if (op <= 0x4b) len = op;
    else if (op === 0x4c) len = script[i++];
    else if (op === 0x4d) { len = script[i] | (script[i + 1] << 8); i += 2; }
    else if (op === 0x4e) { len = (script[i] | (script[i + 1] << 8) | (script[i + 2] << 16) | (script[i + 3] << 24)) >>> 0; i += 4; }
    else if (op >= 0x51 && op <= 0x60) { out.push(new Uint8Array([op - 0x50])); continue; }
    else return null;
    if (i + len > script.length) return null;
    out.push(script.slice(i, i + len));
    i += len;
  }
  return out;
}

// ─── Cómo se gastó cada input ───────────────────────────────

const SIGHASH_NAMES: Record<number, string> = {
  0x00: 'DEFAULT', 0x01: 'ALL', 0x02: 'NONE', 0x03: 'SINGLE',
  0x81: 'ALL|ANYONECANPAY', 0x82: 'NONE|ANYONECANPAY', 0x83: 'SINGLE|ANYONECANPAY',
};

/** ¿Parece una firma ECDSA en DER + byte de sighash? */
function isDerSig(b: Uint8Array): boolean {
  return b.length >= 9 && b.length <= 73 && b[0] === 0x30 && b[1] === b.length - 3;
}

function ecdsaSighash(b: Uint8Array): string {
  return SIGHASH_NAMES[b[b.length - 1]] ?? `0x${b[b.length - 1].toString(16)}`;
}

/** Firma Schnorr: 64 bytes = SIGHASH_DEFAULT implícito, 65 = último byte */
function schnorrSighash(b: Uint8Array): string | null {
  if (b.length === 64) return 'DEFAULT';
  if (b.length === 65) return SIGHASH_NAMES[b[64]] ?? `0x${b[64].toString(16)}`;
  return null;
}

/** m-de-n si el script es un OP_CHECKMULTISIG clásico */
function describeMultisig(script: Uint8Array): string | null {
  const n = script.length;
  if (n < 3 || script[n - 1] !== 0xae) return null;
  const m = script[0] - 0x50;
  const total = script[n - 2] - 0x50;
  if (m < 1 || m > 16 || total < m || total > 16) return null;
  return `multisig ${m}-de-${total}`;
}

function describeWitnessScript(script: Uint8Array): string {
  const ms = describeMultisig(script);
  if (ms) return ms;
  const ops = disassemble(script);
  if (ops.includes('OP_CHECKSEQUENCEVERIFY') || ops.includes('OP_CHECKLOCKTIMEVERIFY')) return 'script con timelock';
  if (ops.includes('OP_CHECKSIGADD')) return 'multisig Tapscript';
  if (ops.includes('OP_IF') || ops.includes('OP_NOTIF')) return 'script con ramas (OP_IF)';
  return `script de ${script.length} bytes`;
}

function analyseSpend(
  type: ScriptType | null,
  scriptSig: Uint8Array,
  witness: Uint8Array[],
): { spend: string; sighashes: string[] } {
  const pushes = parsePushes(scriptSig) ?? [];
  const ecdsa = (items: Uint8Array[]) => items.filter(isDerSig).map(ecdsaSighash);

  switch (type) {
    case 'p2pkh':
      return { spend: 'firma + clave pública en el scriptSig', sighashes: ecdsa(pushes) };
    case 'p2pk':
      return { spend: 'firma en el scriptSig', sighashes: ecdsa(pushes) };
    case 'p2wpkh':
      return { spend: 'firma + clave pública en el witness', sighashes: ecdsa(witness) };
    case 'p2wsh': {
      const ws = witness[witness.length - 1];
      return {
        spend: ws ? `witnessScript: ${describeWitnessScript(ws)}` : 'P2WSH',
        sighashes: ecdsa(witness.slice(0, -1)),
      };
    }
    case 'p2sh': {
      const redeem = pushes[pushes.length - 1];
      if (redeem && redeem.length === 22 && redeem[0] === 0x00 && redeem[1] === 0x14) {
        return { spend: 'P2SH-P2WPKH (SegWit anidado en P2SH)', sighashes: ecdsa(witness) };
      }
      if (redeem && redeem.length === 34 && redeem[0] === 0x00 && redeem[1] === 0x20) {
        const ws = witness[witness.length - 1];
        return {
          spend: `P2SH-P2WSH anidado${ws ? ` · ${describeWitnessScript(ws)}` : ''}`,
          sighashes: ecdsa(witness.slice(0, -1)),
        };
      }
      return {
        spend: redeem ? `redeemScript: ${describeWitnessScript(redeem)}` : 'P2SH',
        sighashes: ecdsa(pushes.slice(0, -1)),
      };
    }
    case 'p2tr': {
      // BIP341: si hay ≥2 elementos y el último empieza por 0x50, es el annex
      const items = witness.length >= 2 && witness[witness.length - 1][0] === 0x50 ? witness.slice(0, -1) : witness;
      if (items.length === 1) {
        const sh = schnorrSighash(items[0]);
        return { spend: 'key-path: una sola firma Schnorr', sighashes: sh ? [sh] : [] };
      }
      const control = items[items.length - 1];
      const leaf = items[items.length - 2];
      const depth = Math.max(0, (control.length - 33) / 32);
      const sigs = items.slice(0, -2).map(schnorrSighash).filter((s): s is string => !!s);
      return {
        spend: `script-path: ${describeWitnessScript(leaf)} · prueba Merkle de profundidad ${depth}`,
        sighashes: sigs,
      };
    }
    default:
      return { spend: 'desconocido (falta la tx previa)', sighashes: [...ecdsa(pushes), ...ecdsa(witness)] };
  }
}

// ─── nSequence y nLockTime ──────────────────────────────────

export const SEQUENCE_FINAL = 0xffffffff;

/**
 * nSequence tiene tres vidas:
 *   - 0xffffffff → "final": sin RBF y (si todos lo son) nLockTime desactivado
 *   - < 0xfffffffe → señala Replace-By-Fee (BIP125)
 *   - con version ≥ 2 y bit 31 a 0 → además es un timelock RELATIVO (BIP68)
 */
export function describeSequence(seq: number, version: number): { info: string; rbf: boolean } {
  const rbf = seq < 0xfffffffe;
  if (seq === SEQUENCE_FINAL) return { info: 'final (sin RBF)', rbf };
  if (seq === 0xfffffffe) return { info: 'sin RBF, activa nLockTime', rbf };
  const parts = ['señala RBF'];
  if (version >= 2 && !(seq & 0x80000000)) {
    const value = seq & 0xffff;
    if (seq & 0x00400000) parts.push(`timelock relativo ${value * 512} s (BIP68)`);
    else if (value > 0) parts.push(`timelock relativo ${value} bloques (BIP68)`);
  }
  return { info: parts.join(' · '), rbf };
}

export const LOCKTIME_THRESHOLD = 500_000_000;

export function describeLocktime(locktime: number, allFinal: boolean, blockHeight?: number): string {
  if (locktime === 0) return 'sin nLockTime';
  const base = locktime < LOCKTIME_THRESHOLD
    ? `no válida antes del bloque ${locktime.toLocaleString('es-ES')}`
    : `no válida antes de ${new Date(locktime * 1000).toISOString().replace('T', ' ').slice(0, 16)} UTC`;
  if (allFinal) return `${base} — pero ignorado: todos los inputs tienen nSequence final`;
  if (blockHeight && locktime < LOCKTIME_THRESHOLD && blockHeight - locktime >= 0 && blockHeight - locktime <= 10) {
    return `${base} — anti fee-sniping: la wallet puso la altura del momento (minada en ${blockHeight.toLocaleString('es-ES')})`;
  }
  return base;
}

// ─── Prevouts verificados ─────────────────────────────────

const NULL_TXID = '0'.repeat(64);

/** La coinbase (1.ª tx de cada bloque) no gasta nada: crea la subvención + comisiones */
export function isCoinbaseInput(prevTxId: string, prevVout: number): boolean {
  // >>> 0: el parser lee el vout con signo, y 0xffffffff llegaría como -1
  return prevTxId === NULL_TXID && prevVout >>> 0 === 0xffffffff;
}

/**
 * Busca el output que gasta cada input dentro de su tx previa, comprobando que
 * el hash de esa tx coincide con el txid del outpoint.
 */
export function resolvePrevouts(
  tx: Transaction,
  prevTxs: Record<string, string>,
): { status: PrevoutStatus; prevout: Prevout | null }[] {
  const parsed = new Map<string, Transaction | null>();
  return tx.inputs.map(inp => {
    if (isCoinbaseInput(inp.prevTxId, inp.prevVout)) return { status: 'coinbase', prevout: null };
    const hex = prevTxs[inp.prevTxId];
    if (!hex) return { status: 'missing', prevout: null };
    if (!parsed.has(inp.prevTxId)) {
      try {
        const prev = parseTxStrict(hex);
        parsed.set(inp.prevTxId, txidOf(prev) === inp.prevTxId ? prev : null);
      } catch {
        parsed.set(inp.prevTxId, null);
      }
    }
    const prev = parsed.get(inp.prevTxId);
    if (!prev) return { status: 'mismatch', prevout: null };
    const out = prev.outputs[inp.prevVout];
    if (!out) return { status: 'mismatch', prevout: null };
    return { status: 'verified', prevout: { value: out.value, scriptPubKey: out.scriptPubKey } };
  });
}

// ─── Pistas de cambio (heurísticas de privacidad) ───────────

/** ¿Importe "redondo"? Los pagos suelen serlo; el cambio casi nunca. */
export function isRoundAmount(sats: bigint): boolean {
  return sats >= 10_000n && sats % 10_000n === 0n;
}

function outputHints(outputs: OutputView[], inputs: InputView[]): void {
  const spendable = outputs.filter(o => o.script.type !== 'op_return');
  if (spendable.length < 2) return;
  const inTypes = new Set(inputs.map(i => i.script?.type).filter(Boolean));
  const inAddrs = new Set(inputs.map(i => i.script?.address).filter(Boolean));
  const round = spendable.filter(o => isRoundAmount(o.value));
  const sameType = spendable.filter(o => inTypes.size === 1 && inTypes.has(o.script.type));

  for (const o of spendable) {
    if (o.script.address && inAddrs.has(o.script.address)) {
      o.hints.push('vuelve a una dirección de entrada → cambio seguro (y reutilizar direcciones daña la privacidad)');
      continue;
    }
    if (round.length === 1 && round[0] === o) o.hints.push('importe redondo → probable pago');
    if (round.length === 1 && round[0] !== o) o.hints.push('importe no redondo frente a uno redondo → probable cambio');
    if (sameType.length === 1 && sameType[0] === o) o.hints.push('mismo tipo de script que las entradas → probable cambio');
  }
}

// ─── Vista completa ─────────────────────────────────────────

export function buildTxView(
  hex: string,
  prevTxs: Record<string, string>,
  opts: { mainnet?: boolean; blockHeight?: number } = {},
): TxView {
  const mainnet = opts.mainnet ?? true;
  const tx = parseTxStrict(hex);
  const segwit = hasWitness(tx);
  const raw = hexToBytes(rawHex(tx));
  const legacy = serializeLegacy(tx);

  // BIP141: weight = base·4 + witness = base·3 + total. Un byte de witness "pesa" 1/4.
  const size = raw.length;
  const baseSize = legacy.raw.length;
  const weight = baseSize * 3 + size;
  const vsize = Math.ceil(weight / 4);

  const prevouts = resolvePrevouts(tx, prevTxs);

  const inputs: InputView[] = tx.inputs.map((inp, i) => {
    const { status, prevout } = prevouts[i];
    const script = prevout ? classifyScript(prevout.scriptPubKey, mainnet) : null;
    const witness = tx.witnesses?.[i] ?? [];
    const { spend, sighashes } = status === 'coinbase'
      ? { spend: 'coinbase: monedas nuevas (subvención + comisiones del bloque)', sighashes: [] }
      : analyseSpend(script?.type ?? null, inp.scriptSig, witness);
    const seq = describeSequence(inp.sequence, tx.version);
    return {
      index: i,
      prevTxId: inp.prevTxId,
      prevVout: inp.prevVout >>> 0,
      status,
      value: prevout?.value ?? null,
      script,
      spend,
      sequence: inp.sequence,
      sequenceInfo: seq.info,
      signalsRbf: seq.rbf,
      scriptSig: inp.scriptSig,
      witness,
      sighashes,
    };
  });

  const outputs: OutputView[] = tx.outputs.map((out, i) => {
    const script = classifyScript(out.scriptPubKey, mainnet);
    return {
      index: i,
      value: out.value,
      script,
      scriptPubKey: out.scriptPubKey,
      opReturnText: script.type === 'op_return' ? opReturnText(out.scriptPubKey) : undefined,
      hints: [],
    };
  });
  outputHints(outputs, inputs);

  const totalOut = outputs.reduce((s, o) => s + o.value, 0n);
  const allKnown = inputs.every(i => i.value !== null);
  const totalIn = allKnown ? inputs.reduce((s, i) => s + (i.value ?? 0n), 0n) : null;
  const fee = totalIn !== null ? totalIn - totalOut : null;
  const allFinal = tx.inputs.every(i => i.sequence === SEQUENCE_FINAL);

  return {
    tx,
    txid: legacy.txid,
    wtxid: segwit ? hash256Reversed(raw) : legacy.txid,
    segwit,
    version: tx.version,
    size,
    baseSize,
    weight,
    vsize,
    inputs,
    outputs,
    totalIn,
    totalOut,
    fee,
    feeRate: fee !== null ? Number(fee) / vsize : null,
    signalsRbf: inputs.some(i => i.signalsRbf),
    locktime: tx.locktime,
    locktimeInfo: describeLocktime(tx.locktime, allFinal, opts.blockHeight),
  };
}

// ─── Formato ────────────────────────────────────────────────

export function formatBtc(sats: bigint): string {
  const neg = sats < 0n;
  const abs = neg ? -sats : sats;
  const whole = abs / 100_000_000n;
  const frac = (abs % 100_000_000n).toString().padStart(8, '0');
  return `${neg ? '-' : ''}${whole}.${frac}`;
}

export function formatSatsBig(sats: bigint): string {
  return sats.toString().replace(/\B(?=(\d{3})+(?!\d))/g, '.');
}
