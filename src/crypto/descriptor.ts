/**
 * Output descriptors — la "receta" completa y sin ambigüedades de una wallet.
 *
 * Un descriptor describe qué scripts controla una wallet y de qué claves salen.
 * Para multisig es la pieza IMPRESCINDIBLE: sin él (todos los xpubs + la política)
 * no se recuperan los fondos aunque tengas las semillas. Ejemplo:
 *
 *   wsh(sortedmulti(2,
 *     [1a2b3c4d/48h/0h/0h/2h]xpub6ABC…/<0;1>/*,
 *     [5e6f7a8b/48h/0h/0h/2h]xpub6DEF…/<0;1>/*,
 *     [9c0d1e2f/48h/0h/0h/2h]xpub6GHI…/<0;1>/*
 *   ))#checksum
 *
 * Aquí implementamos: el ordenado BIP67 (lo que hace `sortedmulti`), el checksum
 * de descriptor (algoritmo de Bitcoin Core) y el ensamblado de la cadena.
 */

import { createMultisig, addressP2WSH, createP2TR, addressP2TR } from './script';
import { derivePath, deriveChildPublic, getMultisigDerivationPath, type HDNode, type MultisigScriptType } from './hdwallet';
import { compressPublicKey } from './secp256k1';
import { tapscriptMultisig, tapLeafHash } from './tapscript';
import { tweakPublicKey } from './taproot';
import { bytesToBigint } from './hmac';

// ─── BIP67: orden lexicográfico de claves ───────────────────
/**
 * BIP67: ordena las claves públicas por su valor de byte, de menor a mayor.
 * `sortedmulti` aplica esto a las claves DERIVADAS en cada índice antes de
 * construir el script, de modo que el orden en que los cosignatarios se listan
 * en el descriptor deja de importar para reconstruir las mismas direcciones.
 */
export function sortPubKeysBIP67(pubKeys: Uint8Array[]): Uint8Array[] {
  return [...pubKeys].sort(comparePubKeys);
}

function comparePubKeys(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

// ─── Checksum de descriptor (algoritmo de Bitcoin Core) ─────
/**
 * Cada descriptor lleva un checksum de 8 caracteres (#xxxxxxxx) que detecta si
 * se copió mal. El algoritmo es el de Bitcoin Core: mapea cada carácter a través
 * de un INPUT_CHARSET (clase alta + posición baja) y acumula un polymod de 40
 * bits, emitiendo el resultado con el charset de bech32.
 *
 * Referencia: src/script/descriptor.cpp (DescriptorChecksum).
 */
const INPUT_CHARSET =
  '0123456789()[],\'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#"\\ ';
const CHECKSUM_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'; // el mismo de bech32

const MASK35 = 0x7ffffffffn; // 35 bits bajos

function descriptorPolyMod(c: bigint, val: number): bigint {
  const c0 = c >> 35n;
  c = ((c & MASK35) << 5n) ^ BigInt(val);
  if (c0 & 1n) c ^= 0xf5dee51989n;
  if (c0 & 2n) c ^= 0xa9fdca3312n;
  if (c0 & 4n) c ^= 0x1bab10e32dn;
  if (c0 & 8n) c ^= 0x3706b1677an;
  if (c0 & 16n) c ^= 0x644d626ffdn;
  return c;
}

/**
 * Calcula los 8 caracteres del checksum de un descriptor (sin el '#').
 * Devuelve '' si el descriptor contiene un carácter fuera del INPUT_CHARSET.
 */
export function descriptorChecksum(descriptor: string): string {
  let c = 1n;
  let cls = 0;       // acumulador de las "clases" (parte alta)
  let clscount = 0;

  for (const ch of descriptor) {
    const pos = INPUT_CHARSET.indexOf(ch);
    if (pos === -1) return '';
    c = descriptorPolyMod(c, pos & 31);        // símbolo por la posición baja
    cls = cls * 3 + (pos >> 5);                // acumula la clase
    if (++clscount === 3) {
      c = descriptorPolyMod(c, cls);           // un símbolo extra cada 3 caracteres
      cls = 0;
      clscount = 0;
    }
  }
  if (clscount > 0) c = descriptorPolyMod(c, cls);
  for (let j = 0; j < 8; j++) c = descriptorPolyMod(c, 0);
  c ^= 1n; // evita que añadir ceros no cambie el checksum

  let ret = '';
  for (let j = 0; j < 8; j++) {
    ret += CHECKSUM_CHARSET[Number((c >> BigInt(5 * (7 - j))) & 31n)];
  }
  return ret;
}

/** Añade el checksum a un descriptor: `desc` → `desc#xxxxxxxx`. */
export function withChecksum(descriptor: string): string {
  return `${descriptor}#${descriptorChecksum(descriptor)}`;
}

// ─── Ensamblado de descriptores multisig ────────────────────
/**
 * Construye un descriptor P2WSH sortedmulti a partir de las expresiones de clave
 * de los cosignatarios (con su origen), añadiendo el sufijo de derivación y el
 * checksum.
 *
 * @param keys  claves de cosignatario (deriveMultisigKey), con `[origen]xpub`.
 * @param m     umbral de firmas.
 * @param chain '0' recepción, '1' cambio, o '<0;1>' (multipath, ambas).
 */
export function buildWshSortedMulti(
  keys: { keyExpression: string }[],
  m: number,
  chain: '0' | '1' | '<0;1>' = '<0;1>',
): string {
  if (m < 1 || m > keys.length) throw new Error(`m (umbral) debe estar entre 1 y ${keys.length}`);
  const inner = keys.map(k => `${k.keyExpression}/${chain}/*`).join(',');
  return withChecksum(`wsh(sortedmulti(${m},${inner}))`);
}

// ─── Multisig Taproot: tr(NUMS, sortedmulti_a(m,…)) ─────────
/**
 * El multisig ESTÁNDAR en Taproot (el que usan Sparrow, Bitcoin Core, etc.):
 *
 *   tr( CLAVE_INTERNA , sortedmulti_a(m, key1, key2, …, keyn) )#checksum
 *
 * `sortedmulti_a` (BIP387) es el fragmento multisig de Taproot: monta la hoja
 * `<pk1> CHECKSIG <pk2> CHECKSIGADD … <m> NUMEQUAL` con claves x-only ordenadas
 * (BIP67). Se coloca como ÚNICA hoja del árbol, y la CLAVE INTERNA se pone a un
 * punto NUMS (Nothing-Up-My-Sleeve) para que NO exista gasto por key-path: así
 * el único modo de gastar es cumplir el multisig por script-path.
 */

/**
 * Punto NUMS estándar (BIP341): un punto de la curva cuyo logaritmo discreto
 * nadie conoce → clave interna "inutilizable". Con esto, la salida Taproot solo
 * se puede gastar por script-path (nunca por key-path).
 */
export const NUMS_H = '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0';

/** Ordena claves x-only (32 bytes) lexicográficamente — el orden de sortedmulti_a. */
export function sortXOnlyBIP67(keys: Uint8Array[]): Uint8Array[] {
  return [...keys].sort(comparePubKeys);
}

export interface TrMultisig {
  leafScriptHex: string;    // la hoja: <pk1> CHECKSIG … <m> NUMEQUAL
  leafHashHex: string;      // TapLeaf hash
  merkleRootHex: string;    // = leafHash (árbol de una sola hoja)
  outputKeyHex: string;     // Q.x — la clave de salida ajustada
  scriptPubKeyHex: string;  // OP_1 <Q.x>
  address: string;          // bc1p… / tb1p…
}

/**
 * Deriva la salida Taproot de un multisig m-de-n: ordena las claves (BIP67),
 * monta la hoja multi_a, la pone como única hoja del árbol y ajusta la clave
 * interna con esa merkle root. Devuelve scriptPubKey y dirección.
 *
 * @param internalXonly  clave interna x-only (32 B) — normalmente el NUMS `NUMS_H`
 * @param sorted         true = sortedmulti_a (ordena); false = multi_a (respeta orden)
 */
export function deriveTrMultisig(
  internalXonly: Uint8Array,
  m: number,
  xonlyKeys: Uint8Array[],
  sorted = true,
  mainnet = true,
): TrMultisig {
  const keys = sorted ? sortXOnlyBIP67(xonlyKeys) : xonlyKeys;
  const leaf = tapscriptMultisig(m, keys);
  const leafHash = tapLeafHash(leaf);
  const { outputKey } = tweakPublicKey(bytesToBigint(internalXonly), leafHash);
  const outBytes = bigintTo32(outputKey);
  return {
    leafScriptHex: bytesToHex(leaf),
    leafHashHex: bytesToHex(leafHash),
    merkleRootHex: bytesToHex(leafHash),
    outputKeyHex: bytesToHex(outBytes),
    scriptPubKeyHex: bytesToHex(createP2TR(outBytes)),
    address: addressP2TR(outBytes, mainnet),
  };
}

/**
 * Construye el descriptor `tr(interna,sortedmulti_a(m,…))#checksum` con las
 * expresiones de clave de los cosignatarios. Por defecto la clave interna es el
 * NUMS estándar (sin gasto por key-path).
 */
export function buildTrSortedMultiA(
  keys: { keyExpression: string }[],
  m: number,
  chain: '0' | '1' | '<0;1>' = '<0;1>',
  internalKeyExpr: string = NUMS_H,
): string {
  if (m < 1 || m > keys.length) throw new Error(`m (umbral) debe estar entre 1 y ${keys.length}`);
  const inner = keys.map(k => `${k.keyExpression}/${chain}/*`).join(',');
  return withChecksum(`tr(${internalKeyExpr},sortedmulti_a(${m},${inner}))`);
}

// ─── Derivación de dirección desde el descriptor ────────────
/**
 * Monta la dirección P2WSH de un multisig a partir de las claves públicas YA
 * derivadas de un índice. Es la parte BARATA (sin curva elíptica): ordena por
 * BIP67 (eso es `sortedmulti`), construye el witnessScript m-of-n y lo hashea.
 * Cambiar el umbral `m` solo re-ejecuta esto, no la derivación.
 */
export function p2wshMultisigAddress(
  pubKeys: Uint8Array[],
  m: number,
  mainnet = true,
): { address: string; witnessScriptHex: string } {
  const sorted = sortPubKeysBIP67(pubKeys);
  const witnessScript = createMultisig(m, sorted);
  return {
    address: addressP2WSH(witnessScript, mainnet),
    witnessScriptHex: bytesToHex(witnessScript),
  };
}

/**
 * Deriva, para los primeros `count` índices, las claves públicas de cada
 * cosignatario, PARTIENDO de sus nodos de CUENTA (no de la semilla). Deriva el
 * nodo `change` una sola vez por cosignatario y de ahí cada índice: es la parte
 * cara (curva elíptica), así que se minimiza. Devuelve, por índice, las pubkeys
 * SIN ordenar — el ordenado BIP67 y el umbral m se aplican después (barato).
 *
 * Usa CKDpub (derivación pública): funciona igual con nodos derivados de una
 * semilla que con nodos watch-only obtenidos de una xpub (sin clave privada).
 */
export function deriveIndexPubkeys(
  accountNodes: HDNode[],
  change: 0 | 1,
  count: number,
): Uint8Array[][] {
  const changeNodes = accountNodes.map(account => deriveChildPublic(account, change));
  const perIndex: Uint8Array[][] = [];
  for (let i = 0; i < count; i++) {
    perIndex.push(
      changeNodes.map(cn => hexToBytes(compressPublicKey(deriveChildPublic(cn, i).publicKey))),
    );
  }
  return perIndex;
}

/**
 * Deriva la dirección P2WSH del multisig en un índice, desde las SEMILLAS.
 *
 * OJO: deriva desde los masters privados porque en el demo tenemos las semillas.
 * Una wallet watch-only real derivaría desde los xpubs (CKDpub, derivación
 * pública) — pendiente. El resultado numérico es el mismo.
 */
export function deriveMultisigAddress(
  masters: HDNode[],
  m: number,
  scriptType: MultisigScriptType,
  change: 0 | 1,
  index: number,
  account = 0,
  coinType = 0,
  mainnet = true,
): { address: string; witnessScriptHex: string } {
  const accountPath = getMultisigDerivationPath(scriptType, account, coinType);
  const pubKeys = masters.map(master => {
    const { node } = derivePath(master, `${accountPath}/${change}/${index}`);
    return hexToBytes(compressNode(node));
  });
  return p2wshMultisigAddress(pubKeys, m, mainnet);
}

// ─── Utilidades ─────────────────────────────────────────────

function compressNode(node: HDNode): string {
  return compressPublicKey(node.publicKey);
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** bigint → 32 bytes big-endian (para claves x-only). */
function bigintTo32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = n;
  for (let i = 31; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
