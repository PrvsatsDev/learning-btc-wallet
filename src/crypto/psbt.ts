/**
 * PSBT — Partially Signed Bitcoin Transaction (BIP174) desde cero.
 *
 * Una PSBT es el SOBRE estándar que se pasan entre sí las partes que construyen
 * y firman una transacción cuando NINGUNA tiene por sí sola todo lo necesario
 * para firmarla. Es exactamente el caso multisig: la tx necesita 2 firmas de 3
 * cosignatarios que viven en dispositivos distintos (una hardware wallet no ve
 * la blockchain; un nodo watch-only no tiene claves privadas). La PSBT es el
 * formato que los coordina.
 *
 * LA IDEA CENTRAL, y es más simple de lo que parece:
 *
 *   Una PSBT es solo un conjunto de MAPAS de pares clave→valor.
 *     - 1 mapa GLOBAL          (contiene la tx sin firmar, entre otras cosas)
 *     - 1 mapa por cada INPUT  (UTXO gastado, witnessScript, firmas parciales…)
 *     - 1 mapa por cada OUTPUT (scripts, derivaciones…)
 *
 *   Firmar NO reescribe la transacción: solo AÑADE un par (PSBT_IN_PARTIAL_SIG)
 *   al mapa del input correspondiente. Combinar el trabajo de dos cosignatarios
 *   es, literalmente, la UNIÓN de sus mapas.
 *
 * Serialización en bytes (BIP174):
 *
 *   magic  = 0x70 0x73 0x62 0x74 0xff   ("psbt" + separador 0xff)
 *   <mapa global>
 *   <mapa input 0> <mapa input 1> ...
 *   <mapa output 0> <mapa output 1> ...
 *
 *   Cada MAPA = secuencia de pares, terminada por un byte 0x00 (una clave de
 *   longitud 0 hace de separador):
 *
 *     <compactSize keylen> <key>  <compactSize vallen> <value>
 *     ...
 *     0x00
 *
 *   El primer byte de cada `key` es el TIPO (keytype). Algunas claves llevan más
 *   bytes tras el tipo (keydata): p. ej. PARTIAL_SIG = 0x02 || pubkey(33B), lo que
 *   permite tener VARIOS pares del mismo tipo (una firma por cosignatario) en el
 *   mismo mapa sin colisionar.
 *
 * Por la red, una PSBT viaja normalmente en Base64 (texto que se copia/pega o va
 * en un QR). Aquí implementamos ambos: bytes crudos y Base64.
 *
 * Los SEIS ROLES de BIP174 (cada parte va tocando el sobre por turnos):
 *   Creator    → crea la PSBT con la tx sin firmar.
 *   Updater    → añade info del UTXO, el witnessScript, el sighash type…
 *   Signer     → calcula el sighash BIP143, firma y añade su PARTIAL_SIG.
 *   Combiner   → une varias PSBTs de la misma tx (unión de mapas).
 *   Finalizer  → con firmas suficientes, monta el scriptWitness definitivo.
 *   Extractor  → saca la transacción cruda lista para hacer broadcast.
 *
 * Alcance de esta implementación: SegWit v0 (P2WPKH y, sobre todo, P2WSH multisig
 * m-of-n), que es lo que ya construimos en el proyecto. Taproot (campos PSBT v1/v2
 * y BIP371) queda para el módulo siguiente.
 */

import {
  type Transaction,
  type TxInput,
  type TxOutput,
  serializeVarInt,
  parseVarInt,
  serializeLegacy,
  serializeWitness,
  parseTxHex,
} from './transaction';
import { computeSighashBIP143, SIGHASH, p2wpkhScriptCode } from './sighash';
import { computeSighashTaproot, SIGHASH_DEFAULT } from './sighash-taproot';
import { ecdsaSign } from './ecdsa';
import { schnorrSign } from './schnorr';
import { tweakPrivateKey } from './taproot';
import { tapLeafHash, parseTapscriptMultisig, TAPROOT_LEAF_VERSION } from './tapscript';
import { getPublicKey, compressPublicKey } from './secp256k1';

// ─── Tipos de clave (keytype) — el subconjunto SegWit v0 ────

/** Tipos de clave del mapa GLOBAL. */
export const PSBT_GLOBAL = {
  UNSIGNED_TX: 0x00, // la transacción sin firmar (scriptSigs y witness vacíos)
  VERSION: 0xfb,     // versión de la PSBT (opcional)
} as const;

/** Tipos de clave de cada mapa de INPUT. */
export const PSBT_IN = {
  NON_WITNESS_UTXO: 0x00,   // la tx previa ENTERA (para inputs legacy)
  WITNESS_UTXO: 0x01,       // solo el output gastado (value + scriptPubKey) — SegWit
  PARTIAL_SIG: 0x02,        // key = 0x02||pubkey, value = firma DER + sighash type
  SIGHASH_TYPE: 0x03,       // uint32 LE
  REDEEM_SCRIPT: 0x04,      // para P2SH envuelto
  WITNESS_SCRIPT: 0x05,     // el witnessScript (el script multisig m-of-n)
  BIP32_DERIVATION: 0x06,   // key = 0x06||pubkey, value = fingerprint(4)||path
  FINAL_SCRIPTSIG: 0x07,    // scriptSig definitivo (legacy/P2SH)
  FINAL_SCRIPTWITNESS: 0x08,// witness definitivo (SegWit)
  // Taproot (BIP371):
  TAP_KEY_SIG: 0x13,        // firma Schnorr del gasto key-path (64 o 65 bytes)
  TAP_SCRIPT_SIG: 0x14,     // key = 0x14||pubkey||leafhash — firma de un script-path
  TAP_LEAF_SCRIPT: 0x15,    // key = 0x15||controlblock — script + leafVersion
  TAP_BIP32_DERIVATION: 0x16,
  TAP_INTERNAL_KEY: 0x17,   // clave interna x-only (32 bytes)
  TAP_MERKLE_ROOT: 0x18,    // raíz del árbol de scripts (32 bytes; ausente si no hay árbol)
} as const;

/** Tipos de clave de cada mapa de OUTPUT. */
export const PSBT_OUT = {
  REDEEM_SCRIPT: 0x00,
  WITNESS_SCRIPT: 0x01,
  BIP32_DERIVATION: 0x02,
} as const;

/** Los 5 bytes mágicos que abren toda PSBT: "psbt" + 0xff. */
export const PSBT_MAGIC = new Uint8Array([0x70, 0x73, 0x62, 0x74, 0xff]);

// ─── Modelo de datos ────────────────────────────────────────

/** Un par clave→valor. El tipo va en key[0]; el resto de key es keydata. */
export interface KeyPair {
  key: Uint8Array;
  value: Uint8Array;
}

/** Un mapa PSBT es una lista de pares (el orden no es significativo). */
export type PsbtMap = KeyPair[];

/** Una PSBT: un mapa global + un mapa por input + un mapa por output. */
export interface Psbt {
  global: PsbtMap;
  inputs: PsbtMap[];
  outputs: PsbtMap[];
}

// ─── Utilidades de bytes ────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function uint32LE(n: number): Uint8Array {
  const b = new Uint8Array(4);
  b[0] = n & 0xff; b[1] = (n >> 8) & 0xff;
  b[2] = (n >> 16) & 0xff; b[3] = (n >> 24) & 0xff;
  return b;
}

function readUint32LE(data: Uint8Array, offset: number): number {
  return (data[offset] | (data[offset + 1] << 8) |
          (data[offset + 2] << 16) | (data[offset + 3] << 24)) >>> 0;
}

function int64LE(n: bigint): Uint8Array {
  const b = new Uint8Array(8);
  for (let i = 0; i < 8; i++) b[i] = Number((n >> BigInt(i * 8)) & 0xffn);
  return b;
}

function readUint64LE(data: Uint8Array, offset: number): bigint {
  let v = 0n;
  for (let i = 0; i < 8; i++) v |= BigInt(data[offset + i]) << BigInt(i * 8);
  return v;
}

// ─── Acceso al mapa por tipo ────────────────────────────────

/**
 * Inserta (o REEMPLAZA si ya existe una clave idéntica) un par en un mapa.
 * BIP174 prohíbe claves duplicadas exactas; distintos keydata (p. ej. dos
 * PARTIAL_SIG con pubkeys distintas) sí conviven.
 */
export function setKeyPair(map: PsbtMap, key: Uint8Array, value: Uint8Array): void {
  const existing = map.find(kp => bytesEqual(kp.key, key));
  if (existing) existing.value = value;
  else map.push({ key, value });
}

/** Devuelve todos los pares cuyo keytype (key[0]) coincide. */
export function getKeyPairs(map: PsbtMap, keytype: number): KeyPair[] {
  return map.filter(kp => kp.key[0] === keytype);
}

/** Devuelve el value del primer par de ese keytype, o undefined. */
export function getValue(map: PsbtMap, keytype: number): Uint8Array | undefined {
  return map.find(kp => kp.key[0] === keytype)?.value;
}

// ─── Serialización BIP174 ───────────────────────────────────

/** Serializa un mapa: pares (keylen,key,vallen,value) + separador 0x00. */
function serializeMap(map: PsbtMap): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const kp of map) {
    parts.push(serializeVarInt(kp.key.length), kp.key);
    parts.push(serializeVarInt(kp.value.length), kp.value);
  }
  parts.push(new Uint8Array([0x00])); // separador de fin de mapa
  return concat(...parts);
}

/** Serializa una PSBT completa a bytes crudos. */
export function serializePsbt(psbt: Psbt): Uint8Array {
  return concat(
    PSBT_MAGIC,
    serializeMap(psbt.global),
    ...psbt.inputs.map(serializeMap),
    ...psbt.outputs.map(serializeMap),
  );
}

/** Lee un único mapa a partir de `offset`. Devuelve el mapa y el nuevo offset. */
function readMap(data: Uint8Array, offset: number): { map: PsbtMap; offset: number } {
  const map: PsbtMap = [];
  while (true) {
    const { value: keyLen, bytesRead: kb } = parseVarInt(data, offset);
    offset += kb;
    if (keyLen === 0) break; // 0x00 → separador de fin de mapa
    const key = data.slice(offset, offset + keyLen);
    offset += keyLen;
    const { value: valLen, bytesRead: vb } = parseVarInt(data, offset);
    offset += vb;
    const value = data.slice(offset, offset + valLen);
    offset += valLen;
    map.push({ key, value });
  }
  return { map, offset };
}

/** Deserializa una PSBT desde bytes crudos. */
export function deserializePsbt(data: Uint8Array): Psbt {
  for (let i = 0; i < PSBT_MAGIC.length; i++) {
    if (data[i] !== PSBT_MAGIC[i]) throw new Error('No es una PSBT: faltan los bytes mágicos');
  }
  let offset = PSBT_MAGIC.length;

  const g = readMap(data, offset);
  const global = g.map;
  offset = g.offset;

  // ¿Cuántos inputs/outputs? Lo dice la tx sin firmar del mapa global.
  const unsignedTxBytes = getValue(global, PSBT_GLOBAL.UNSIGNED_TX);
  if (!unsignedTxBytes) throw new Error('PSBT sin PSBT_GLOBAL_UNSIGNED_TX');
  const tx = parseTxHex(bytesToHex(unsignedTxBytes));

  const inputs: PsbtMap[] = [];
  for (let i = 0; i < tx.inputs.length; i++) {
    const r = readMap(data, offset);
    inputs.push(r.map);
    offset = r.offset;
  }
  const outputs: PsbtMap[] = [];
  for (let i = 0; i < tx.outputs.length; i++) {
    const r = readMap(data, offset);
    outputs.push(r.map);
    offset = r.offset;
  }

  return { global, inputs, outputs };
}

// ─── Base64 (formato de transporte habitual) ────────────────

function bytesToBase64(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64.trim());
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Serializa la PSBT al Base64 que se copia/pega o va en un QR. */
export function psbtToBase64(psbt: Psbt): string {
  return bytesToBase64(serializePsbt(psbt));
}

/** Reconstruye una PSBT desde su Base64. */
export function psbtFromBase64(b64: string): Psbt {
  return deserializePsbt(base64ToBytes(b64));
}

// ─── Rol 1: CREATOR ─────────────────────────────────────────

/**
 * Creator — crea una PSBT a partir de una transacción SIN FIRMAR.
 *
 * "Sin firmar" es literal: se fuerzan los scriptSig a vacío y se descartan los
 * witness. Lo único que la PSBT guarda en el mapa global es esa tx-esqueleto
 * (PSBT_GLOBAL_UNSIGNED_TX): quién gasta qué y a dónde va, pero sin ninguna prueba
 * de autorización todavía. Los mapas de input/output nacen vacíos.
 */
export function createPsbt(tx: Transaction): Psbt {
  const unsignedTx: Transaction = {
    version: tx.version,
    locktime: tx.locktime,
    inputs: tx.inputs.map((i): TxInput => ({
      prevTxId: i.prevTxId,
      prevVout: i.prevVout,
      scriptSig: new Uint8Array(0), // vaciado: aún no hay autorización
      sequence: i.sequence,
    })),
    outputs: tx.outputs.map((o): TxOutput => ({ value: o.value, scriptPubKey: o.scriptPubKey })),
    // witnesses: descartados a propósito
  };

  const global: PsbtMap = [];
  setKeyPair(global, new Uint8Array([PSBT_GLOBAL.UNSIGNED_TX]), serializeLegacy(unsignedTx).raw);

  return {
    global,
    inputs: tx.inputs.map(() => [] as PsbtMap),
    outputs: tx.outputs.map(() => [] as PsbtMap),
  };
}

/** Recupera la transacción sin firmar guardada en el mapa global. */
export function getUnsignedTx(psbt: Psbt): Transaction {
  const bytes = getValue(psbt.global, PSBT_GLOBAL.UNSIGNED_TX);
  if (!bytes) throw new Error('PSBT sin transacción sin firmar');
  return parseTxHex(bytesToHex(bytes));
}

// ─── Rol 2: UPDATER ─────────────────────────────────────────

/**
 * Updater — añade a un input el UTXO que gasta (WITNESS_UTXO).
 *
 * En SegWit basta con el output concreto que se gasta (value + scriptPubKey), no
 * la tx previa entera. Esto es la clave práctica de BIP143: el firmante conoce el
 * `amount` y puede verificar la comisión sin descargar la tx anterior completa.
 */
export function updateInputWitnessUtxo(psbt: Psbt, inputIndex: number, utxo: TxOutput): void {
  const value = concat(
    int64LE(utxo.value),
    serializeVarInt(utxo.scriptPubKey.length),
    utxo.scriptPubKey,
  );
  setKeyPair(psbt.inputs[inputIndex], new Uint8Array([PSBT_IN.WITNESS_UTXO]), value);
}

/** Lee el WITNESS_UTXO de un input: el output gastado (value + scriptPubKey). */
export function getWitnessUtxo(map: PsbtMap): TxOutput | undefined {
  const v = getValue(map, PSBT_IN.WITNESS_UTXO);
  if (!v) return undefined;
  const value = readUint64LE(v, 0);
  const { value: spkLen, bytesRead } = parseVarInt(v, 8);
  const scriptPubKey = v.slice(8 + bytesRead, 8 + bytesRead + spkLen);
  return { value, scriptPubKey };
}

/**
 * Updater — añade el witnessScript de un input P2WSH (p. ej. el multisig m-of-n).
 *
 * Es el script que se revela al gastar. En la dirección P2WSH solo va su SHA-256;
 * el script en claro tiene que aportarlo el que gasta, y aquí es donde viaja para
 * que cada firmante sepa exactamente sobre qué está firmando.
 */
export function updateInputWitnessScript(psbt: Psbt, inputIndex: number, witnessScript: Uint8Array): void {
  setKeyPair(psbt.inputs[inputIndex], new Uint8Array([PSBT_IN.WITNESS_SCRIPT]), witnessScript);
}

/** Lee el WITNESS_SCRIPT de un input (o undefined si no lo tiene). */
export function getWitnessScript(map: PsbtMap): Uint8Array | undefined {
  return getValue(map, PSBT_IN.WITNESS_SCRIPT);
}

/** Updater — fija el sighash type de un input (por defecto se asume SIGHASH_ALL). */
export function updateInputSighashType(psbt: Psbt, inputIndex: number, sighashType: number): void {
  setKeyPair(psbt.inputs[inputIndex], new Uint8Array([PSBT_IN.SIGHASH_TYPE]), uint32LE(sighashType));
}

/** Lee el sighash type de un input, o SIGHASH_ALL si no está fijado. */
export function getSighashType(map: PsbtMap): number {
  const v = getValue(map, PSBT_IN.SIGHASH_TYPE);
  return v ? readUint32LE(v, 0) : SIGHASH.ALL;
}

// ─── Rol 3: SIGNER ──────────────────────────────────────────

export interface SignInputResult {
  sighash: Uint8Array;        // el hash BIP143 que se firmó
  scriptCode: Uint8Array;     // el scriptCode usado (witnessScript en P2WSH)
  pubkey: Uint8Array;         // pubkey comprimida del firmante (33B)
  signature: Uint8Array;      // firma DER + byte de sighash type
}

/**
 * Signer — firma un input y añade su firma parcial (PSBT_IN_PARTIAL_SIG).
 *
 * El firmante NO necesita nada de fuera de la PSBT: saca el UTXO (para el amount),
 * el witnessScript (que hace de scriptCode en P2WSH) y el sighash type del propio
 * sobre. Calcula el sighash BIP143, lo firma con ECDSA y GUARDA la firma indexada
 * por su pubkey. No toca la transacción; solo AÑADE un par al mapa del input.
 *
 * Detecta el tipo de input:
 *   - Si hay witnessScript → P2WSH: scriptCode = witnessScript.
 *   - Si no → P2WPKH: scriptCode = P2PKH-equivalente del hash de la pubkey.
 *
 * @returns info didáctica de la firma (o null si la pubkey no participa en el script).
 */
export function signInput(
  psbt: Psbt,
  inputIndex: number,
  privateKey: bigint,
): SignInputResult {
  const tx = getUnsignedTx(psbt);
  const map = psbt.inputs[inputIndex];

  const utxo = getWitnessUtxo(map);
  if (!utxo) throw new Error(`Input ${inputIndex} sin WITNESS_UTXO: no se puede firmar`);

  // La pubkey comprimida del firmante (33B) — sale de la privada.
  const pubkey = hexToBytes(compressPublicKey(getPublicKey(privateKey)));

  // scriptCode: witnessScript en P2WSH, P2PKH-equivalente en P2WPKH.
  const witnessScript = getWitnessScript(map);
  let scriptCode: Uint8Array;
  if (witnessScript) {
    scriptCode = witnessScript;
  } else {
    // P2WPKH: el scriptPubKey es OP_0 <20B hash>. El scriptCode se deriva del hash.
    const spk = utxo.scriptPubKey;
    if (spk.length !== 22 || spk[0] !== 0x00 || spk[1] !== 0x14) {
      throw new Error('Input sin witnessScript y scriptPubKey no es P2WPKH: tipo no soportado');
    }
    scriptCode = p2wpkhScriptCode(spk.slice(2));
  }

  const sighashType = getSighashType(map);
  const { sighash } = computeSighashBIP143(tx, inputIndex, scriptCode, utxo.value, sighashType);

  // Firma ECDSA (RFC 6979, low-s, DER) + byte de sighash type al final.
  const { der } = ecdsaSign(sighash, privateKey);
  const signature = concat(der, new Uint8Array([sighashType]));

  // PARTIAL_SIG: la clave incluye la pubkey → varias firmas conviven en el mapa.
  const key = concat(new Uint8Array([PSBT_IN.PARTIAL_SIG]), pubkey);
  setKeyPair(map, key, signature);

  return { sighash, scriptCode, pubkey, signature };
}

export interface PartialSig {
  pubkey: Uint8Array;   // 33B comprimida (viene del keydata de la clave)
  signature: Uint8Array;// DER + sighash type
}

/** Lee todas las firmas parciales de un input. */
export function getPartialSigs(map: PsbtMap): PartialSig[] {
  return getKeyPairs(map, PSBT_IN.PARTIAL_SIG).map(kp => ({
    pubkey: kp.key.slice(1),
    signature: kp.value,
  }));
}

// ─── Rol 4: COMBINER ────────────────────────────────────────

function cloneMap(map: PsbtMap): PsbtMap {
  return map.map(kp => ({ key: kp.key.slice(), value: kp.value.slice() }));
}

/** Copia profunda de una PSBT (para simular dispositivos independientes). */
export function clonePsbt(psbt: Psbt): Psbt {
  return {
    global: cloneMap(psbt.global),
    inputs: psbt.inputs.map(cloneMap),
    outputs: psbt.outputs.map(cloneMap),
  };
}

/** Une los pares de `src` sobre `dst` sin duplicar claves (gana el primero visto). */
function mergeInto(dst: PsbtMap, src: PsbtMap): void {
  for (const kp of src) {
    if (!dst.find(e => bytesEqual(e.key, kp.key))) {
      dst.push({ key: kp.key.slice(), value: kp.value.slice() });
    }
  }
}

/**
 * Combiner — fusiona varias PSBTs de la MISMA transacción en una sola.
 *
 * Es la operación que junta el trabajo de los cosignatarios: cada uno devuelve su
 * PSBT con su PARTIAL_SIG, y combinar es la UNIÓN de los mapas. Como las firmas se
 * indexan por pubkey, las de A y las de C no colisionan: acaban juntas en el mismo
 * mapa de input. Requisito: todas deben compartir la misma tx sin firmar.
 */
export function combine(...psbts: Psbt[]): Psbt {
  if (psbts.length === 0) throw new Error('combine necesita al menos una PSBT');
  const base = clonePsbt(psbts[0]);
  const baseTx = serializePsbt({ global: base.global, inputs: [], outputs: [] });

  for (let p = 1; p < psbts.length; p++) {
    const other = psbts[p];
    // Deben ser la misma transacción (mismo mapa global mínimo).
    const otherTx = serializePsbt({ global: other.global, inputs: [], outputs: [] });
    if (bytesToHex(otherTx) !== bytesToHex(baseTx)) {
      throw new Error('combine: las PSBTs no comparten la misma transacción sin firmar');
    }
    if (other.inputs.length !== base.inputs.length || other.outputs.length !== base.outputs.length) {
      throw new Error('combine: número de inputs/outputs distinto');
    }
    mergeInto(base.global, other.global);
    other.inputs.forEach((m, i) => mergeInto(base.inputs[i], m));
    other.outputs.forEach((m, i) => mergeInto(base.outputs[i], m));
  }
  return base;
}

// ─── Parser de witnessScript multisig ───────────────────────

export interface MultisigScriptInfo {
  m: number;              // umbral de firmas
  n: number;              // número de claves
  pubKeys: Uint8Array[];  // claves EN EL ORDEN del script (importa para CHECKMULTISIG)
}

/**
 * Parsea un witnessScript multisig: OP_m <pk1>...<pkN> OP_n OP_CHECKMULTISIG.
 * Devuelve m, n y las claves EN ORDEN — el orden en que aparecen es el que exige
 * OP_CHECKMULTISIG para las firmas (por eso el finalizer las ordena así).
 */
export function parseMultisigScript(script: Uint8Array): MultisigScriptInfo {
  let offset = 0;
  const first = script[offset++];
  if (first < 0x51 || first > 0x60) throw new Error('witnessScript no empieza por OP_m');
  const m = first - 0x50;

  const pubKeys: Uint8Array[] = [];
  while (offset < script.length) {
    const b = script[offset];
    if (b >= 0x51 && b <= 0x60) break; // OP_n → fin de las claves
    if (b < 0x01 || b > 0x4b) throw new Error(`push de clave inesperado: 0x${b.toString(16)}`);
    offset++;
    pubKeys.push(script.slice(offset, offset + b));
    offset += b;
  }
  const n = script[offset++] - 0x50;
  if (script[offset] !== 0xae) throw new Error('witnessScript no termina en OP_CHECKMULTISIG');
  if (n !== pubKeys.length) throw new Error(`OP_n (${n}) no coincide con nº de claves (${pubKeys.length})`);

  return { m, n, pubKeys };
}

// ─── Rol 5: FINALIZER ───────────────────────────────────────

/** Serializa una pila witness: compactSize(nº items) + (compactSize(len)+item)… */
function serializeWitnessStack(items: Uint8Array[]): Uint8Array {
  const parts: Uint8Array[] = [serializeVarInt(items.length)];
  for (const it of items) parts.push(serializeVarInt(it.length), it);
  return concat(...parts);
}

/** Parsea una pila witness serializada de vuelta a una lista de items. */
export function parseWitnessStack(data: Uint8Array): Uint8Array[] {
  let offset = 0;
  const { value: count, bytesRead } = parseVarInt(data, offset);
  offset += bytesRead;
  const items: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    const { value: len, bytesRead: lb } = parseVarInt(data, offset);
    offset += lb;
    items.push(data.slice(offset, offset + len));
    offset += len;
  }
  return items;
}

export interface FinalizeResult {
  witnessStack: Uint8Array[];  // los items del witness montado
  usedSigs: PartialSig[];      // las m firmas seleccionadas, en orden de script
}

/**
 * Finalizer — para un input P2WSH multisig, monta el witness definitivo.
 *
 * Con suficientes firmas parciales (≥ m), construye la pila witness que gastará el
 * UTXO y la guarda como FINAL_SCRIPTWITNESS. La pila de un P2WSH multisig es:
 *
 *   [ <vacío> , <sig_1> , … , <sig_m> , <witnessScript> ]
 *
 *   - El primer elemento VACÍO es el famoso "dummy" del bug histórico de
 *     OP_CHECKMULTISIG (desapila un elemento de más).
 *   - Las firmas van EN EL ORDEN en que sus pubkeys aparecen en el witnessScript
 *     (requisito de OP_CHECKMULTISIG), no en el orden en que llegaron.
 *   - El último elemento es el witnessScript, que el consenso comprueba que hashea
 *     al programa de 32 bytes de la dirección P2WSH.
 *
 * Tras finalizar, el finalizer BIP174 elimina los campos ya innecesarios
 * (firmas parciales, sighash type, witnessScript…) y deja solo el UTXO y el
 * witness final.
 */
export function finalizeInput(psbt: Psbt, inputIndex: number): FinalizeResult {
  const map = psbt.inputs[inputIndex];
  const witnessScript = getWitnessScript(map);
  if (!witnessScript) throw new Error(`Input ${inputIndex} sin witnessScript: finalizer P2WSH no aplica`);

  const { m, pubKeys } = parseMultisigScript(witnessScript);
  const partials = getPartialSigs(map);

  // Ordena las firmas según la posición de su pubkey en el witnessScript.
  const ordered: PartialSig[] = [];
  for (const pk of pubKeys) {
    const sig = partials.find(p => bytesEqual(p.pubkey, pk));
    if (sig) ordered.push(sig);
  }
  if (ordered.length < m) {
    throw new Error(`Faltan firmas: hay ${ordered.length}, se necesitan ${m}`);
  }
  const usedSigs = ordered.slice(0, m); // solo m firmas: de más, OP_CHECKMULTISIG falla

  // Pila witness: dummy vacío + firmas en orden + witnessScript.
  const witnessStack: Uint8Array[] = [
    new Uint8Array(0),
    ...usedSigs.map(s => s.signature),
    witnessScript,
  ];

  setKeyPair(map, new Uint8Array([PSBT_IN.FINAL_SCRIPTWITNESS]), serializeWitnessStack(witnessStack));

  // El finalizer limpia lo ya innecesario (deja UTXO + witness final).
  const keepTypes = new Set<number>([PSBT_IN.WITNESS_UTXO, PSBT_IN.FINAL_SCRIPTWITNESS, PSBT_IN.FINAL_SCRIPTSIG]);
  psbt.inputs[inputIndex] = map.filter(kp => keepTypes.has(kp.key[0]));

  return { witnessStack, usedSigs };
}

/** ¿Está el input finalizado (tiene ya FINAL_SCRIPTWITNESS)? */
export function isInputFinalized(map: PsbtMap): boolean {
  return getValue(map, PSBT_IN.FINAL_SCRIPTWITNESS) !== undefined;
}

// ─── Taproot (BIP371): key-path ─────────────────────────────

/** Updater — clave interna x-only del input Taproot (32 bytes). */
export function updateInputTapInternalKey(psbt: Psbt, inputIndex: number, internalXonly: Uint8Array): void {
  if (internalXonly.length !== 32) throw new Error('la clave interna es x-only (32 bytes)');
  setKeyPair(psbt.inputs[inputIndex], new Uint8Array([PSBT_IN.TAP_INTERNAL_KEY]), internalXonly);
}

export function getTapInternalKey(map: PsbtMap): Uint8Array | undefined {
  return getValue(map, PSBT_IN.TAP_INTERNAL_KEY);
}

/**
 * Updater — raíz del árbol de scripts (merkle root). Solo si la salida Taproot
 * compromete un árbol: el firmante key-path la necesita para ajustar su clave
 * (q = p + taggedHash("TapTweak", P ‖ merkleRoot)). Sin árbol, se omite.
 */
export function updateInputTapMerkleRoot(psbt: Psbt, inputIndex: number, merkleRoot: Uint8Array): void {
  setKeyPair(psbt.inputs[inputIndex], new Uint8Array([PSBT_IN.TAP_MERKLE_ROOT]), merkleRoot);
}

export function getTapMerkleRoot(map: PsbtMap): Uint8Array | undefined {
  return getValue(map, PSBT_IN.TAP_MERKLE_ROOT);
}

export function getTapKeySig(map: PsbtMap): Uint8Array | undefined {
  return getValue(map, PSBT_IN.TAP_KEY_SIG);
}

export interface SignTaprootResult {
  sigHash: Uint8Array;      // el sighash BIP341 firmado
  signature: Uint8Array;    // firma Schnorr (64B, o 65B si hashType ≠ DEFAULT)
}

/**
 * Signer — firma un input Taproot por KEY-PATH y guarda TAP_KEY_SIG.
 *
 * Aquí se ve la gran diferencia con SegWit v0: el sighash BIP341 compromete el
 * UTXO de TODOS los inputs (importes + scriptPubKeys). Por eso el firmante lee el
 * WITNESS_UTXO de CADA input del sobre, no solo el suyo. Luego ajusta su clave
 * privada con la merkle root (si hay árbol) y firma con Schnorr.
 *
 * Con SIGHASH_DEFAULT (0x00) la firma es de 64 bytes y NO lleva byte de tipo
 * (así se ahorra un byte en el caso común). Con otros tipos, se le añade.
 */
export function signTaprootKeyPathInput(
  psbt: Psbt,
  inputIndex: number,
  privateKey: bigint,
  hashType: number = SIGHASH_DEFAULT,
  auxRand?: Uint8Array,
): SignTaprootResult {
  const tx = getUnsignedTx(psbt);

  // El sighash Taproot necesita el UTXO de TODOS los inputs.
  const prevouts = psbt.inputs.map((m, idx) => {
    const u = getWitnessUtxo(m);
    if (!u) throw new Error(`Input ${idx} sin WITNESS_UTXO: el sighash Taproot los necesita todos`);
    return u;
  });

  const map = psbt.inputs[inputIndex];
  const merkleRoot = getTapMerkleRoot(map);
  const { sigHash } = computeSighashTaproot(tx, inputIndex, prevouts, { hashType });

  const q = tweakPrivateKey(privateKey, merkleRoot);
  const sig64 = hexToBytes(schnorrSign(sigHash, q, auxRand).signatureHex);
  const signature = hashType === SIGHASH_DEFAULT ? sig64 : concat(sig64, new Uint8Array([hashType]));

  setKeyPair(map, new Uint8Array([PSBT_IN.TAP_KEY_SIG]), signature);
  return { sigHash, signature };
}

/**
 * Finalizer — para un input Taproot key-path, el witness es UN solo elemento:
 * la firma Schnorr. Sin script, sin dummy, sin nada más. Es el gasto más compacto
 * y privado de Bitcoin: en la cadena solo se ve una firma de 64 bytes.
 */
export function finalizeTaprootKeyPathInput(psbt: Psbt, inputIndex: number): { witnessStack: Uint8Array[] } {
  const map = psbt.inputs[inputIndex];
  const sig = getTapKeySig(map);
  if (!sig) throw new Error(`Input ${inputIndex} sin TAP_KEY_SIG: fírmalo primero`);

  const witnessStack: Uint8Array[] = [sig];
  setKeyPair(map, new Uint8Array([PSBT_IN.FINAL_SCRIPTWITNESS]), serializeWitnessStack(witnessStack));

  const keepTypes = new Set<number>([PSBT_IN.WITNESS_UTXO, PSBT_IN.FINAL_SCRIPTWITNESS, PSBT_IN.FINAL_SCRIPTSIG]);
  psbt.inputs[inputIndex] = map.filter(kp => keepTypes.has(kp.key[0]));
  return { witnessStack };
}

// ─── Taproot (BIP371): script-path (multisig con CHECKSIGADD) ─

/**
 * Updater — declara una hoja de script gastable (TAP_LEAF_SCRIPT).
 *   key   = 0x15 ‖ controlBlock     (la prueba Merkle de que la hoja está en Q)
 *   value = script ‖ leafVersion    (el script en claro + su versión al final)
 */
export function updateInputTapLeafScript(
  psbt: Psbt,
  inputIndex: number,
  script: Uint8Array,
  controlBlock: Uint8Array,
  leafVersion: number = TAPROOT_LEAF_VERSION,
): void {
  const key = concat(new Uint8Array([PSBT_IN.TAP_LEAF_SCRIPT]), controlBlock);
  const value = concat(script, new Uint8Array([leafVersion]));
  setKeyPair(psbt.inputs[inputIndex], key, value);
}

export interface TapLeafScriptEntry {
  controlBlock: Uint8Array;
  script: Uint8Array;
  leafVersion: number;
}

export function getTapLeafScripts(map: PsbtMap): TapLeafScriptEntry[] {
  return getKeyPairs(map, PSBT_IN.TAP_LEAF_SCRIPT).map(kp => ({
    controlBlock: kp.key.slice(1),
    script: kp.value.slice(0, kp.value.length - 1),
    leafVersion: kp.value[kp.value.length - 1],
  }));
}

export interface TapScriptSig {
  pubkey: Uint8Array;   // x-only (32B)
  leafHash: Uint8Array; // 32B
  signature: Uint8Array;
}

export function getTapScriptSigs(map: PsbtMap): TapScriptSig[] {
  return getKeyPairs(map, PSBT_IN.TAP_SCRIPT_SIG).map(kp => ({
    pubkey: kp.key.slice(1, 33),
    leafHash: kp.key.slice(33, 65),
    signature: kp.value,
  }));
}

export interface SignTaprootScriptResult {
  sigHash: Uint8Array;
  signature: Uint8Array;
  pubkey: Uint8Array;    // x-only del firmante
  leafHash: Uint8Array;
}

/**
 * Signer — firma un input Taproot por SCRIPT-PATH y guarda TAP_SCRIPT_SIG.
 *
 * Dos diferencias clave respecto al key-path:
 *   1. La clave NO se ajusta (nada de tweak): en el script-path firmas con tu
 *      clave TAL CUAL, la misma que aparece x-only dentro del script.
 *   2. El sighash incluye el `ext`: el hash de la hoja que se está ejecutando
 *      (así la firma queda atada a ESE script, no a cualquiera del árbol).
 *
 * La firma se indexa por (pubkey ‖ leafHash): así conviven las firmas de varios
 * cosignatarios sobre la misma hoja — el multisig repartido, ahora en Taproot.
 */
export function signTaprootScriptPathInput(
  psbt: Psbt,
  inputIndex: number,
  privateKey: bigint,
  leafScript: Uint8Array,
  leafVersion: number = TAPROOT_LEAF_VERSION,
  hashType: number = SIGHASH_DEFAULT,
  auxRand?: Uint8Array,
): SignTaprootScriptResult {
  const tx = getUnsignedTx(psbt);
  const prevouts = psbt.inputs.map((m, idx) => {
    const u = getWitnessUtxo(m);
    if (!u) throw new Error(`Input ${idx} sin WITNESS_UTXO: el sighash Taproot los necesita todos`);
    return u;
  });

  const map = psbt.inputs[inputIndex];
  const leafHash = tapLeafHash(leafScript, leafVersion);
  const { sigHash } = computeSighashTaproot(tx, inputIndex, prevouts, { hashType, ext: { tapLeafHash: leafHash } });

  // Script-path: se firma con la clave SIN ajustar.
  const sig64 = hexToBytes(schnorrSign(sigHash, privateKey, auxRand).signatureHex);
  const signature = hashType === SIGHASH_DEFAULT ? sig64 : concat(sig64, new Uint8Array([hashType]));
  const pubkey = hexToBytes(compressPublicKey(getPublicKey(privateKey))).slice(1); // x-only (32B)

  const key = concat(new Uint8Array([PSBT_IN.TAP_SCRIPT_SIG]), pubkey, leafHash);
  setKeyPair(map, key, signature);
  return { sigHash, signature, pubkey, leafHash };
}

/**
 * Finalizer — para un input multisig Taproot (script-path con OP_CHECKSIGADD),
 * monta el witness definitivo:
 *
 *   [ sig_pkN … sig_pk1 , script , controlBlock ]
 *
 *   - Una firma por CADA clave del script, en el orden INVERSO al del script
 *     (así CHECKSIG/CHECKSIGADD las consumen de arriba abajo); vacío para las
 *     claves que no firmaron. Se dejan exactamente k firmas (más harían que el
 *     contador supere el umbral y NUMEQUAL falle).
 *   - Luego el script (la hoja) y el control block (la prueba Merkle).
 *
 * Compárese con el P2WSH clásico: aquí no hay dummy y las firmas son Schnorr.
 */
export function finalizeTaprootScriptPathInput(psbt: Psbt, inputIndex: number): { witnessStack: Uint8Array[] } {
  const map = psbt.inputs[inputIndex];
  const leaves = getTapLeafScripts(map);
  if (leaves.length === 0) throw new Error(`Input ${inputIndex} sin TAP_LEAF_SCRIPT`);
  const { script, controlBlock, leafVersion } = leaves[0];
  const leafHash = tapLeafHash(script, leafVersion);

  const { k, pubKeys } = parseTapscriptMultisig(script);
  const sigs = getTapScriptSigs(map).filter(s => bytesEqual(s.leafHash, leafHash));
  const byPubkey = new Map(sigs.map(s => [bytesToHex(s.pubkey), s.signature]));

  // Una entrada por clave, en orden de script; nos quedamos con exactamente k.
  let kept = 0;
  const perKey: Uint8Array[] = pubKeys.map(pk => {
    const sig = byPubkey.get(bytesToHex(pk));
    if (sig && kept < k) { kept++; return sig; }
    return new Uint8Array(0); // clave sin firma (o sobrante) → elemento vacío
  });
  if (kept < k) throw new Error(`Faltan firmas: hay ${kept}, se necesitan ${k}`);

  // Orden inverso al del script + script + control block.
  const witnessStack: Uint8Array[] = [...perKey.slice().reverse(), script, controlBlock];
  setKeyPair(map, new Uint8Array([PSBT_IN.FINAL_SCRIPTWITNESS]), serializeWitnessStack(witnessStack));

  const keepTypes = new Set<number>([PSBT_IN.WITNESS_UTXO, PSBT_IN.FINAL_SCRIPTWITNESS, PSBT_IN.FINAL_SCRIPTSIG]);
  psbt.inputs[inputIndex] = map.filter(kp => keepTypes.has(kp.key[0]));
  return { witnessStack };
}

// ─── Rol 6: EXTRACTOR ───────────────────────────────────────

export interface ExtractResult {
  tx: Transaction;   // la tx final con sus witness
  hex: string;       // serialización SegWit lista para broadcast
  txid: string;      // TxID (dSHA256 de la parte legacy, byte-reversed)
}

/**
 * Extractor — saca la transacción cruda, lista para la red.
 *
 * Toma la tx sin firmar del mapa global y le engancha, en cada input, el witness
 * que dejó el finalizer (FINAL_SCRIPTWITNESS). El resultado ya NO es una PSBT: es
 * una transacción SegWit normal que se puede difundir a la red.
 */
export function extractTransaction(psbt: Psbt): ExtractResult {
  const tx = getUnsignedTx(psbt);

  const witnesses: Uint8Array[][] = [];
  for (let i = 0; i < psbt.inputs.length; i++) {
    const finalWitness = getValue(psbt.inputs[i], PSBT_IN.FINAL_SCRIPTWITNESS);
    if (!finalWitness) throw new Error(`Input ${i} no está finalizado`);
    witnesses.push(parseWitnessStack(finalWitness));
  }
  tx.witnesses = witnesses;

  const ser = serializeWitness(tx);
  return { tx, hex: ser.hex, txid: ser.txid };
}

// ─── Resumen didáctico ──────────────────────────────────────

export interface PsbtInputSummary {
  hasWitnessUtxo: boolean;
  hasWitnessScript: boolean;
  partialSigs: number;
  finalized: boolean;
}

export interface PsbtSummary {
  numInputs: number;
  numOutputs: number;
  inputs: PsbtInputSummary[];
  base64Length: number;
}

/** Un vistazo del estado de la PSBT: qué campos hay y cuántas firmas por input. */
export function summarizePsbt(psbt: Psbt): PsbtSummary {
  return {
    numInputs: psbt.inputs.length,
    numOutputs: psbt.outputs.length,
    base64Length: psbtToBase64(psbt).length,
    inputs: psbt.inputs.map((m): PsbtInputSummary => ({
      hasWitnessUtxo: getValue(m, PSBT_IN.WITNESS_UTXO) !== undefined,
      hasWitnessScript: getWitnessScript(m) !== undefined,
      partialSigs: getPartialSigs(m).length,
      finalized: isInputFinalized(m),
    })),
  };
}

export { hexToBytes };
