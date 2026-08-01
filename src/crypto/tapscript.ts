/**
 * Tapscript (BIP341/BIP342) — el SCRIPT-PATH de Taproot.
 *
 * Con el key-path (ver [[taproot]]) gastas firmando con la clave ajustada Q. El
 * SCRIPT-PATH es la otra mitad: Q también compromete un ÁRBOL de scripts
 * alternativos, y puedes gastar revelando UNA hoja del árbol + una prueba de que
 * estaba dentro. El resto del árbol nunca se ve.
 *
 * Las tres piezas:
 *
 *   1. TapLeaf   — cada script es una "hoja". Su hash es:
 *        taggedHash("TapLeaf", leafVersion(1B) ‖ compactSize(len) ‖ script)
 *      La leafVersion por defecto es 0xc0.
 *
 *   2. TapBranch — dos nodos se combinan en uno:
 *        taggedHash("TapBranch", sorted(a, b))   ← ¡se ORDENAN antes de concatenar!
 *      Ordenar hace que la prueba Merkle no dependa de izquierda/derecha: el
 *      verificador no necesita saber la posición, solo los hashes hermanos.
 *
 *   3. merkleRoot — la raíz del árbol. Es lo que entra en el tweak:
 *        Q = P + taggedHash("TapTweak", P.x ‖ merkleRoot)·G
 *
 * Para gastar por script-path revelas en el witness: [ ...inputs, script,
 * controlBlock ]. El CONTROL BLOCK es la prueba Merkle:
 *
 *   controlBlock = (leafVersion | parity)(1B) ‖ internalPubKey(32B) ‖ path(32B·k)
 *
 *   - parity = paridad de Y de la output key Q (para reconstruir Q).
 *   - path   = los hashes hermanos, de la hoja hacia la raíz.
 * El verificador recomputa el leaf hash, sube por el path recombinando con
 * TapBranch, obtiene la merkleRoot, retweakea P y comprueba que da Q. Si cuadra,
 * ejecuta el script.
 *
 * El multisig Taproot (BIP342) usa OP_CHECKSIGADD en vez de OP_CHECKMULTISIG:
 *   <pk1> CHECKSIG <pk2> CHECKSIGADD … <pkn> CHECKSIGADD <k> NUMEQUAL
 * Más limpio (sin el bug del dummy), más barato y más privado (solo se revela la
 * rama que se usa).
 *
 * Verificado contra los vectores oficiales de BIP341 (ver tapscript.test.ts).
 */

import { taggedHash } from './schnorr';
import { tweakPublicKey } from './taproot';
import { serializeVarInt } from './transaction';
import { OP } from './script';
import { bytesToHex } from './hmac';

export const TAPROOT_LEAF_VERSION = 0xc0;

// ─── Hash de hoja y de rama ─────────────────────────────────

/**
 * TapLeaf hash = taggedHash("TapLeaf", leafVersion ‖ compactSize(len) ‖ script).
 */
export function tapLeafHash(script: Uint8Array, leafVersion: number = TAPROOT_LEAF_VERSION): Uint8Array {
  return taggedHash('TapLeaf', concat(
    new Uint8Array([leafVersion]),
    serializeVarInt(script.length),
    script,
  ));
}

/**
 * TapBranch hash = taggedHash("TapBranch", sorted(a, b)).
 * Los dos hashes de 32 bytes se ordenan lexicográficamente ANTES de concatenar.
 */
export function tapBranchHash(a: Uint8Array, b: Uint8Array): Uint8Array {
  const [lo, hi] = compareBytes(a, b) <= 0 ? [a, b] : [b, a];
  return taggedHash('TapBranch', concat(lo, hi));
}

// ─── Árbol de scripts ───────────────────────────────────────

/** Una hoja del árbol: un script con su versión. */
export interface TapLeaf {
  script: Uint8Array;
  leafVersion?: number;
}

/** Un árbol es una hoja, o un par [izquierda, derecha] de subárboles. */
export type TapTree = TapLeaf | [TapTree, TapTree];

export interface TaptreeLeafInfo {
  leaf: TapLeaf;
  leafHash: Uint8Array;
  path: Uint8Array[];   // hashes hermanos, de la hoja hacia la raíz
}

export interface TaptreeResult {
  merkleRoot: Uint8Array;
  leaves: TaptreeLeafInfo[];   // una entrada por hoja, con su prueba Merkle
}

function isLeaf(t: TapTree): t is TapLeaf {
  return !Array.isArray(t);
}

/**
 * Recorre el árbol y devuelve la merkleRoot y, por cada hoja, su prueba Merkle
 * (los hashes hermanos de abajo arriba). Al combinar dos subárboles, cada hoja de
 * la izquierda añade a su path el hash de la derecha, y viceversa.
 */
export function computeTaptree(tree: TapTree): TaptreeResult {
  if (isLeaf(tree)) {
    const leafHash = tapLeafHash(tree.script, tree.leafVersion ?? TAPROOT_LEAF_VERSION);
    return { merkleRoot: leafHash, leaves: [{ leaf: tree, leafHash, path: [] }] };
  }
  const left = computeTaptree(tree[0]);
  const right = computeTaptree(tree[1]);
  const merkleRoot = tapBranchHash(left.merkleRoot, right.merkleRoot);

  const leaves: TaptreeLeafInfo[] = [
    ...left.leaves.map(l => ({ ...l, path: [...l.path, right.merkleRoot] })),
    ...right.leaves.map(l => ({ ...l, path: [...l.path, left.merkleRoot] })),
  ];
  return { merkleRoot, leaves };
}

// ─── Control block ──────────────────────────────────────────

/**
 * Monta el control block de una hoja: la prueba que va en el witness para gastar
 * por script-path.
 *
 *   (leafVersion | parity)(1B) ‖ internalPubKey(32B) ‖ path(32B·k)
 *
 * @param internalX  - clave interna x-only (32B, como bigint)
 * @param parity     - paridad de Y de la output key Q (0/1)
 * @param path       - hashes hermanos de la prueba Merkle
 */
export function controlBlock(
  internalX: Uint8Array,
  parity: number,
  path: Uint8Array[],
  leafVersion: number = TAPROOT_LEAF_VERSION,
): Uint8Array {
  return concat(new Uint8Array([leafVersion | parity]), internalX, ...path);
}

// ─── Salida Taproot con árbol de scripts ────────────────────

export interface TaprootScriptOutput {
  merkleRoot: Uint8Array;
  outputKey: bigint;       // Q.x
  parity: number;          // paridad de Q (para los control blocks)
  leaves: TaptreeLeafInfo[];
  controlBlocks: Uint8Array[];  // uno por hoja, alineado con `leaves`
}

/**
 * A partir de una clave interna x-only y un árbol de scripts, calcula la
 * merkleRoot, la output key Q (con su paridad) y el control block de cada hoja.
 */
export function taprootScriptOutput(internalX: bigint, tree: TapTree): TaprootScriptOutput {
  const { merkleRoot, leaves } = computeTaptree(tree);
  const { outputKey, parity } = tweakPublicKey(internalX, merkleRoot);
  const internalXBytes = bigintTo32(internalX);
  const controlBlocks = leaves.map(l =>
    controlBlock(internalXBytes, parity, l.path, l.leaf.leafVersion ?? TAPROOT_LEAF_VERSION));
  return { merkleRoot, outputKey, parity, leaves, controlBlocks };
}

// ─── Multisig Taproot (k-of-n con OP_CHECKSIGADD) ───────────

/**
 * Construye el script de un multisig k-of-n en Tapscript:
 *   <pk1> CHECKSIG <pk2> CHECKSIGADD … <pkn> CHECKSIGADD <k> NUMEQUAL
 *
 * Las claves son x-only (32 bytes). A diferencia del P2WSH clásico, no hay dummy
 * ni OP_CHECKMULTISIG: cada firma válida suma 1 a un contador y al final se
 * compara con el umbral k. Para gastar, el witness aporta una firma por cada
 * clave EN ORDEN (firma vacía para las que no firman).
 */
export function tapscriptMultisig(k: number, xonlyPubKeys: Uint8Array[]): Uint8Array {
  const n = xonlyPubKeys.length;
  if (n < 1 || n > 999) throw new Error('n fuera de rango');
  if (k < 1 || k > n) throw new Error(`k (umbral) debe estar entre 1 y ${n}`);
  for (const pk of xonlyPubKeys) {
    if (pk.length !== 32) throw new Error('las claves de Tapscript son x-only (32 bytes)');
  }
  if (k > 16) throw new Error('este demo solo codifica k ≤ 16 (OP_1..OP_16)');

  const parts: number[] = [];
  xonlyPubKeys.forEach((pk, i) => {
    parts.push(0x20, ...pk);                       // push de la clave x-only (32B)
    parts.push(i === 0 ? OP.OP_CHECKSIG : OP.OP_CHECKSIGADD);
  });
  parts.push(0x50 + k);        // OP_k (umbral)
  parts.push(OP.OP_NUMEQUAL);
  return new Uint8Array(parts);
}

export interface TapscriptMultisigInfo {
  k: number;               // umbral
  pubKeys: Uint8Array[];   // claves x-only en el ORDEN del script
}

/**
 * Parsea un multisig Tapscript `<pk1> CHECKSIG <pk2> CHECKSIGADD … <k> NUMEQUAL`.
 * Devuelve el umbral k y las claves x-only en orden — el finalizer las necesita
 * para colocar cada firma en su posición.
 */
export function parseTapscriptMultisig(script: Uint8Array): TapscriptMultisigInfo {
  let offset = 0;
  const pubKeys: Uint8Array[] = [];
  while (script[offset] === 0x20) {          // push de 32 bytes (clave x-only)
    offset++;
    pubKeys.push(script.slice(offset, offset + 32));
    offset += 32;
    const op = script[offset++];             // OP_CHECKSIG (0xac) u OP_CHECKSIGADD (0xba)
    if (op !== OP.OP_CHECKSIG && op !== OP.OP_CHECKSIGADD) {
      throw new Error(`opcode inesperado tras la clave: 0x${op.toString(16)}`);
    }
  }
  const k = script[offset++] - 0x50;         // OP_k
  if (script[offset] !== OP.OP_NUMEQUAL) throw new Error('el script no termina en OP_NUMEQUAL');
  if (k < 1 || k > pubKeys.length) throw new Error(`umbral k inválido (${k})`);
  return { k, pubKeys };
}

// ─── Utilidades ─────────────────────────────────────────────

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

function bigintTo32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = n;
  for (let i = 31; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}

export { bytesToHex };
