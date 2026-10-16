/**
 * Árbol de derivación BIP32 navegable — Fase 4 (visualizador).
 *
 * Una HD wallet no es una lista de claves: es un ÁRBOL. Desde una única seed sale
 * la master key (m), y de cada nodo cuelgan hasta 2^32 hijos:
 *
 *   m
 *   └─ purpose'   (44' legacy · 84' SegWit · 86' Taproot)          ┐
 *      └─ coin'    (0' mainnet · 1' testnet)                       │ hardened:
 *         └─ account'  (0', 1', …)  ← aquí vive la xpub            ┘ requieren la privada
 *            └─ change   (0 = recepción · 1 = cambio)              ┐ normales: se pueden
 *               └─ index  (0, 1, 2, …) → una dirección             ┘ derivar desde la xpub
 *
 * La frontera entre los niveles hardened y los normales es justo lo que hace
 * posible una wallet watch-only (Sparrow, Liana…): exportas la xpub de la CUENTA
 * y con ella se generan todas las direcciones, pero no se puede gastar.
 *
 * El árbol se construye de forma PEREZOSA: cada derivación es una multiplicación
 * escalar en secp256k1 hecha en JS, así que sólo se calculan los hijos de los
 * nodos que el usuario despliega.
 *
 * Verificado contra los vectores de BIP44/BIP84/BIP86 en bip32-tree.test.ts.
 */

import {
  deriveChild,
  deriveChildPublic,
  fingerprint,
  serializeXpub,
  type HDNode,
} from './hdwallet';
import { sha256 } from './sha256';
import { ripemd160Hex } from './ripemd160';
import { compressPublicKey } from './secp256k1';
import { base58CheckEncode } from './base58';
import { addressP2WPKH } from './script';
import { p2trAddress } from './taproot';
import { bytesToHex } from './hmac';
import { withChecksum } from './descriptor';

// ─── Tipos ──────────────────────────────────────────────────

export type Purpose = 44 | 84 | 86;

/** Qué significa cada profundidad del árbol según BIP44 */
export type TreeLevel = 'master' | 'purpose' | 'coin' | 'account' | 'change' | 'address';

const LEVELS: TreeLevel[] = ['master', 'purpose', 'coin', 'account', 'change', 'address'];

export interface TreeNode {
  /** Ruta completa, p. ej. "m/84'/0'/0'/0/3" */
  path: string;
  level: TreeLevel;
  depth: number;
  /** Índice "humano" (sin el bit hardened): el 84 de 84' */
  index: number;
  hardened: boolean;
  /** Child number real tal cual va en el HMAC: index + 2^31 si es hardened */
  childNumber: number;
  /** Tipo de dirección de la rama (se fija en el nivel purpose) */
  purpose?: Purpose;
  hd: HDNode;
  pubKeyHex: string;
  fingerprint: string;
  /** Sólo en las hojas */
  address?: string;
}

export interface TreeOptions {
  mainnet: boolean;
  /** Cuántas cuentas mostrar bajo cada coin */
  accounts: number;
  /** Cuántas direcciones mostrar bajo cada cadena (recepción/cambio) */
  addresses: number;
}

export const HARDENED = 0x80000000;

export const PURPOSES: Purpose[] = [44, 84, 86];

// ─── Construcción del árbol ─────────────────────────────────

export function makeRoot(master: HDNode): TreeNode {
  return {
    path: 'm',
    level: 'master',
    depth: 0,
    index: 0,
    hardened: false,
    childNumber: 0,
    hd: master,
    pubKeyHex: compressPublicKey(master.publicKey),
    fingerprint: fingerprint(master),
  };
}

/** Deriva un hijo concreto (privado → privado, CKDpriv) */
export function deriveTreeChild(
  parent: TreeNode,
  index: number,
  hardened: boolean,
  mainnet: boolean,
): TreeNode {
  const hd = deriveChild(parent.hd, index, hardened);
  const depth = parent.depth + 1;
  const level = LEVELS[depth] ?? 'address';
  const purpose = level === 'purpose' ? (index as Purpose) : parent.purpose;

  const node: TreeNode = {
    path: `${parent.path}/${index}${hardened ? "'" : ''}`,
    level,
    depth,
    index,
    hardened,
    childNumber: hardened ? index + HARDENED : index,
    purpose,
    hd,
    pubKeyHex: compressPublicKey(hd.publicKey),
    fingerprint: fingerprint(hd),
  };
  if (level === 'address' && purpose) node.address = addressFor(hd, purpose, mainnet);
  return node;
}

export interface ChildSpec {
  index: number;
  hardened: boolean;
}

/**
 * Qué hijos tiene un nodo según la estructura BIP44 (sin derivarlos todavía).
 * Qué índices se generan en cada nivel es una CONVENCIÓN (BIP44/84/86), no una
 * regla de BIP32: matemáticamente cualquier nodo puede tener cualquier hijo.
 */
export function childSpecs(node: TreeNode, opts: TreeOptions): ChildSpec[] {
  switch (node.level) {
    case 'master':
      return PURPOSES.map(p => ({ index: p, hardened: true }));
    case 'purpose':
      // SLIP-0044: 0' = Bitcoin mainnet, 1' = cualquier testnet
      return [{ index: opts.mainnet ? 0 : 1, hardened: true }];
    case 'coin':
      return range(opts.accounts).map(i => ({ index: i, hardened: true }));
    case 'account':
      return [0, 1].map(i => ({ index: i, hardened: false }));
    case 'change':
      return range(opts.addresses).map(i => ({ index: i, hardened: false }));
    case 'address':
      return [];
  }
}

/** Deriva de golpe todos los hijos de un nodo (la UI lo hace de uno en uno) */
export function childrenOf(node: TreeNode, opts: TreeOptions): TreeNode[] {
  return childSpecs(node, opts).map(s => deriveTreeChild(node, s.index, s.hardened, opts.mainnet));
}

function range(n: number): number[] {
  return Array.from({ length: n }, (_, i) => i);
}

// ─── Direcciones (las tres familias, completas) ─────────────

/**
 * Dirección de una hoja según el purpose de su rama:
 *   44' → P2PKH  Base58Check(0x00 ‖ hash160(pub))        → 1…
 *   84' → P2WPKH bech32(v0, hash160(pub))                → bc1q…
 *   86' → P2TR   bech32m(v1, Q) con Q = P + tagged(P)·G  → bc1p…
 *
 * Ojo con BIP86: la dirección NO es la clave derivada, sino la clave ajustada
 * (tweak) sin script tree. Si usas la clave sin tweak sale una dirección que
 * ninguna otra wallet reconoce.
 */
export function addressFor(hd: HDNode, purpose: Purpose, mainnet: boolean): string {
  const pubBytes = hexToBytes(compressPublicKey(hd.publicKey));
  const h160 = hexToBytes(ripemd160Hex(hexToBytes(sha256(pubBytes).hash)));
  switch (purpose) {
    case 44:
      return base58CheckEncode(mainnet ? 0x00 : 0x6f, h160).address;
    case 84:
      return addressP2WPKH(h160, mainnet);
    case 86:
      return p2trAddress(hd.publicKey!.x, mainnet);
  }
}

// ─── Frontera watch-only ────────────────────────────────────

/** ¿Este nodo se puede obtener con sólo la xpub de su cuenta? */
export function isWatchOnlyDerivable(node: TreeNode): boolean {
  return node.level === 'change' || node.level === 'address';
}

/** xpub/tpub del nodo (tiene sentido mostrarla hasta el nivel cuenta) */
export function xpubOf(node: TreeNode, mainnet: boolean): string {
  return serializeXpub(node.hd, mainnet);
}

const DESCRIPTOR_FN: Record<Purpose, string> = { 44: 'pkh', 84: 'wpkh', 86: 'tr' };

/**
 * Descriptor de salida de una cuenta: TODO lo que una wallet watch-only necesita.
 *
 *   wpkh([73c5da0a/84'/0'/0']xpub…/0/*)#checksum
 *         └ origen ─────────┘└ clave ┘└ hijos ┘
 *
 * El origen (fingerprint del master + ruta) no hace falta para derivar
 * direcciones, pero sí para que un hardware wallet sepa con qué clave firmar.
 */
export function accountDescriptor(
  account: TreeNode,
  masterFingerprint: string,
  mainnet: boolean,
  chain: 0 | 1 = 0,
): string {
  if (account.level !== 'account' || !account.purpose) throw new Error('Se necesita un nodo cuenta');
  const origin = account.path.replace(/^m/, masterFingerprint);
  return withChecksum(`${DESCRIPTOR_FN[account.purpose]}([${origin}]${xpubOf(account, mainnet)}/${chain}/*)`);
}

export interface WatchOnlyCheck {
  /** Clave pública obtenida por CKDpub desde la xpub de la cuenta */
  pubKeyHex: string;
  /** ¿Coincide con la que sale por la vía privada (CKDpriv)? */
  matches: boolean;
  /** Pasos de la derivación pública, p. ej. ["xpub", "/0", "/3"] */
  route: string[];
}

/**
 * Re-deriva un nodo de recepción/cambio partiendo SÓLO de la parte pública de
 * la cuenta (lo que contiene la xpub), y comprueba que da la misma clave.
 *
 * Funciona por la homomorfía de la derivación normal:
 *   privada: k_hijo = IL + k_padre      (mod n)
 *   pública: K_hijo = IL·G + K_padre    = (IL + k_padre)·G
 * IL sale de HMAC(chainCode, K_padre ‖ i), que sólo usa datos públicos.
 */
export function verifyFromAccountXpub(account: TreeNode, node: TreeNode): WatchOnlyCheck {
  if (account.level !== 'account' || !node.path.startsWith(account.path + '/')) {
    throw new Error('El nodo no cuelga de esa cuenta');
  }
  const rel = node.path.slice(account.path.length + 1).split('/').map(Number);
  // Quitamos la privada a propósito: sólo lo que viaja en una xpub
  let cur: HDNode = { ...account.hd, privateKey: 0n };
  for (const i of rel) cur = deriveChildPublic(cur, i);
  const pubKeyHex = compressPublicKey(cur.publicKey);
  return {
    pubKeyHex,
    matches: pubKeyHex === node.pubKeyHex,
    route: ['xpub', ...rel.map(i => `/${i}`)],
  };
}

// ─── Utilidades de presentación ─────────────────────────────

/** Ancestros de una ruta: "m/84'/0'" → ["m", "m/84'", "m/84'/0'"] */
export function ancestorPaths(path: string): string[] {
  const parts = path.split('/');
  return parts.map((_, i) => parts.slice(0, i + 1).join('/'));
}

export function childNumberHex(node: TreeNode): string {
  return '0x' + (node.childNumber >>> 0).toString(16).padStart(8, '0');
}

export function chainCodeHex(node: TreeNode): string {
  return bytesToHex(node.hd.chainCode);
}

export function privateKeyHex(node: TreeNode): string {
  return node.hd.privateKey.toString(16).padStart(64, '0');
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  return bytes;
}
