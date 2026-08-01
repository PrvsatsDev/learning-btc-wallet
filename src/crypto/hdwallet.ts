/**
 * HD Wallets (Hierarchical Deterministic) — BIP32, BIP39, BIP44/84/86
 *
 * Una HD wallet genera un árbol infinito de claves a partir de una sola semilla.
 * La "seed phrase" de 12/24 palabras que ves al crear una wallet ES la semilla.
 *
 * El flujo completo:
 *   1. BIP39: Entropía → mnemónico (12-24 palabras) → seed (512 bits)
 *   2. BIP32: Seed → master key → árbol de claves derivadas
 *   3. BIP44/84/86: Convención de rutas para organizar el árbol
 *
 * ¿Por qué es brillante?
 *   - Backup: 12 palabras = toda tu wallet (infinitas direcciones)
 *   - Privacidad: cada transacción puede usar una dirección nueva
 *   - Organización: cuentas, cambio, etc. todo en un árbol lógico
 *   - Watch-only: la xpub permite generar direcciones sin clave privada
 */

import { sha256 } from './sha256';
import { ripemd160Hex } from './ripemd160';
import { hmacSha512, bytesToHex, bigintToBytes, bytesToBigint } from './hmac';
import { N, getPublicKey, compressPublicKey, decompressPublicKey, pointAdd, type Point } from './secp256k1';
import { BIP39_WORDLIST } from './bip39-wordlist';
import { addressP2WPKH, addressP2TR } from './script';
import { base58Encode, base58Decode } from './base58';

// ─── Tipos ──────────────────────────────────────────────────

/** Un nodo en el árbol de derivación BIP32 */
export interface HDNode {
  privateKey: bigint;
  publicKey: Point;
  chainCode: Uint8Array;    // 32 bytes — entropía para derivar hijos
  depth: number;            // profundidad en el árbol (master = 0)
  index: number;            // índice de este nodo entre sus hermanos
  parentFingerprint: string; // primeros 4 bytes del hash160 del padre
}

/** Resultado de generar un mnemónico (para visualización) */
export interface MnemonicResult {
  entropy: Uint8Array;
  entropyBits: string;
  checksumBits: string;
  allBits: string;
  wordIndices: number[];
  words: string[];
}

/** Un paso en la derivación (para visualización) */
export interface DerivationStep {
  path: string;
  depth: number;
  index: number;
  hardened: boolean;
  privateKeyHex: string;
  publicKeyHex: string;
  chainCodeHex: string;
  address?: string;
}

// ─── BIP39: Mnemónico ──────────────────────────────────────
/**
 * BIP39 convierte entropía aleatoria en palabras legibles.
 *
 * 1. Generar N bits de entropía (128 para 12 palabras, 256 para 24)
 * 2. Calcular checksum = primeros N/32 bits de SHA-256(entropía)
 * 3. Concatenar entropía + checksum
 * 4. Dividir en grupos de 11 bits → cada grupo es un índice en la wordlist
 *
 * 128 bits + 4 bits checksum = 132 bits = 12 × 11 bits = 12 palabras
 * 256 bits + 8 bits checksum = 264 bits = 24 × 11 bits = 24 palabras
 */
export function generateMnemonic(entropy?: Uint8Array): MnemonicResult {
  // Usar entropía proporcionada o generar 128 bits (12 palabras)
  const ent = entropy ?? crypto.getRandomValues(new Uint8Array(16));
  const entropyBits = Array.from(ent).map(b => b.toString(2).padStart(8, '0')).join('');

  // Checksum: primeros (entropyBits.length / 32) bits de SHA-256
  const hashHex = sha256(ent).hash;
  const hashBits = hexToBits(hashHex);
  const checksumLength = ent.length / 4; // bits de checksum
  const checksumBits = hashBits.slice(0, checksumLength);

  // Concatenar
  const allBits = entropyBits + checksumBits;

  // Dividir en grupos de 11 bits
  const wordIndices: number[] = [];
  for (let i = 0; i < allBits.length; i += 11) {
    wordIndices.push(parseInt(allBits.slice(i, i + 11), 2));
  }

  const words = wordIndices.map(i => BIP39_WORDLIST[i]);

  return { entropy: ent, entropyBits, checksumBits, allBits, wordIndices, words };
}

/** Valida un mnemónico: recalcula el checksum y compara */
export function validateMnemonic(words: string[]): boolean {
  if (words.length !== 12 && words.length !== 15 && words.length !== 18 &&
      words.length !== 21 && words.length !== 24) return false;

  const indices = words.map(w => BIP39_WORDLIST.indexOf(w));
  if (indices.some(i => i === -1)) return false;

  const bits = indices.map(i => i.toString(2).padStart(11, '0')).join('');
  const checksumLength = words.length / 3; // CS bits
  const entropyLength = bits.length - checksumLength;

  const entropyBits = bits.slice(0, entropyLength);
  const checksumBits = bits.slice(entropyLength);

  // Reconstruir entropía
  const entropy = new Uint8Array(entropyLength / 8);
  for (let i = 0; i < entropy.length; i++) {
    entropy[i] = parseInt(entropyBits.slice(i * 8, i * 8 + 8), 2);
  }

  // Recalcular checksum
  const hashBits = hexToBits(sha256(entropy).hash);
  const expectedChecksum = hashBits.slice(0, checksumLength);

  return checksumBits === expectedChecksum;
}

/**
 * BIP39: Convierte mnemónico + passphrase en seed de 512 bits.
 *
 * Usa PBKDF2-HMAC-SHA512 con 2048 iteraciones.
 * La passphrase es opcional (actúa como "25ª palabra").
 * Mismas palabras + diferente passphrase = wallet completamente diferente.
 * Esto permite "plausible deniability" — una passphrase para el wallet real,
 * otra para un wallet señuelo.
 */
export function mnemonicToSeed(words: string[], passphrase: string = ''): Uint8Array {
  const mnemonic = new TextEncoder().encode(words.join(' '));
  const salt = new TextEncoder().encode('mnemonic' + passphrase);
  return pbkdf2HmacSha512(mnemonic, salt, 2048);
}

// ─── BIP32: Derivación jerárquica ───────────────────────────

/**
 * Deriva la master key desde una seed.
 * HMAC-SHA512("Bitcoin seed", seed) → [IL (32 bytes) = master private key, IR = chain code]
 */
export function masterKeyFromSeed(seed: Uint8Array): HDNode {
  const hmac = hmacSha512(new TextEncoder().encode('Bitcoin seed'), seed);
  const IL = hmac.slice(0, 32);
  const IR = hmac.slice(32);

  const privateKey = bytesToBigint(IL);
  if (privateKey === 0n || privateKey >= N) {
    throw new Error('Master key inválida — seed desafortunada');
  }

  const publicKey = getPublicKey(privateKey);

  return {
    privateKey,
    publicKey,
    chainCode: IR,
    depth: 0,
    index: 0,
    parentFingerprint: '00000000',
  };
}

/**
 * Deriva una clave hija desde un nodo padre.
 *
 * Hay dos tipos de derivación:
 *
 * Normal (index < 2^31):
 *   HMAC-SHA512(chainCode, pubKey || index) → [IL, IR]
 *   childKey = IL + parentKey (mod n)
 *   Permite derivar hijos públicos desde la xpub (watch-only)
 *
 * Hardened (index >= 2^31, se escribe como i'):
 *   HMAC-SHA512(chainCode, 0x00 || privKey || index) → [IL, IR]
 *   childKey = IL + parentKey (mod n)
 *   Requiere la clave privada — más seguro, protege contra
 *   el ataque "xpub + child privkey → parent privkey"
 */
export function deriveChild(parent: HDNode, index: number, hardened: boolean = false): HDNode {
  const actualIndex = hardened ? index + 0x80000000 : index;
  const indexBytes = new Uint8Array(4);
  indexBytes[0] = (actualIndex >>> 24) & 0xff;
  indexBytes[1] = (actualIndex >>> 16) & 0xff;
  indexBytes[2] = (actualIndex >>> 8) & 0xff;
  indexBytes[3] = actualIndex & 0xff;

  let data: Uint8Array;
  if (hardened) {
    // Hardened: 0x00 || privKey (32 bytes) || index (4 bytes)
    const privBytes = bigintToBytes(parent.privateKey, 32);
    data = new Uint8Array(37);
    data[0] = 0x00;
    data.set(privBytes, 1);
    data.set(indexBytes, 33);
  } else {
    // Normal: pubKey comprimida (33 bytes) || index (4 bytes)
    const pubKeyHex = compressPublicKey(parent.publicKey);
    const pubKeyBytes = hexToBytes(pubKeyHex);
    data = new Uint8Array(37);
    data.set(pubKeyBytes, 0);
    data.set(indexBytes, 33);
  }

  const hmac = hmacSha512(parent.chainCode, data);
  const IL = bytesToBigint(hmac.slice(0, 32));
  const IR = hmac.slice(32);

  const childKey = (IL + parent.privateKey) % N;
  if (childKey === 0n) throw new Error('Clave derivada inválida');

  const childPubKey = getPublicKey(childKey);

  // Fingerprint del padre = primeros 4 bytes de Hash160(pubKey padre)
  const parentPubHex = compressPublicKey(parent.publicKey);
  const parentHash = ripemd160Hex(hexToBytes(sha256(hexToBytes(parentPubHex)).hash));

  return {
    privateKey: childKey,
    publicKey: childPubKey,
    chainCode: IR,
    depth: parent.depth + 1,
    index: actualIndex,
    parentFingerprint: parentHash.slice(0, 8),
  };
}

/**
 * CKDpub — deriva una clave hija PÚBLICA sin conocer la clave privada.
 *
 * Esta es la magia del watch-only y del multisig: con solo la xpub de un
 * cosignatario puedes generar todas sus direcciones, pero NO gastar.
 *
 *   I  = HMAC-SHA512(chainCode, pubKey_comprimida || index)
 *   childPub = IL·G + parentPub        (suma de puntos en la curva)
 *   childChainCode = IR
 *
 * Solo funciona para índices NORMALES (no hardened): la derivación hardened
 * mezcla la clave privada a propósito, justo para que esto no sea posible.
 * El nodo resultante lleva privateKey = 0n como marca de "clave privada desconocida".
 */
export function deriveChildPublic(parent: HDNode, index: number): HDNode {
  if (index >= 0x80000000) {
    throw new Error('CKDpub no puede derivar hijos hardened (haría falta la clave privada)');
  }

  const indexBytes = new Uint8Array(4);
  indexBytes[0] = (index >>> 24) & 0xff;
  indexBytes[1] = (index >>> 16) & 0xff;
  indexBytes[2] = (index >>> 8) & 0xff;
  indexBytes[3] = index & 0xff;

  const pubKeyBytes = hexToBytes(compressPublicKey(parent.publicKey));
  const data = new Uint8Array(37);
  data.set(pubKeyBytes, 0);
  data.set(indexBytes, 33);

  const hmac = hmacSha512(parent.chainCode, data);
  const IL = bytesToBigint(hmac.slice(0, 32));
  const IR = hmac.slice(32);
  if (IL >= N) throw new Error('IL ≥ n — índice inválido, probar el siguiente');

  // childPub = IL·G + parentPub
  const childPubKey = pointAdd(getPublicKey(IL), parent.publicKey);
  if (childPubKey === null) throw new Error('Clave derivada inválida (punto en el infinito)');

  const parentHash = ripemd160Hex(hexToBytes(sha256(hexToBytes(compressPublicKey(parent.publicKey))).hash));

  return {
    privateKey: 0n, // desconocida: derivación pública (watch-only)
    publicKey: childPubKey,
    chainCode: IR,
    depth: parent.depth + 1,
    index,
    parentFingerprint: parentHash.slice(0, 8),
  };
}

/**
 * Deriva una clave siguiendo una ruta BIP32 completa.
 * Ejemplo: "m/44'/0'/0'/0/0"
 *
 * m     = master key
 * 44'   = purpose (BIP44), hardened
 * 0'    = coin type (Bitcoin mainnet), hardened
 * 0'    = account 0, hardened
 * 0     = external chain (0) vs change chain (1)
 * 0     = address index
 */
export function derivePath(master: HDNode, path: string): { node: HDNode; steps: DerivationStep[] } {
  const parts = path.split('/');
  if (parts[0] !== 'm') throw new Error('La ruta debe empezar por "m"');

  const steps: DerivationStep[] = [{
    path: 'm',
    depth: 0,
    index: 0,
    hardened: false,
    privateKeyHex: master.privateKey.toString(16).padStart(64, '0'),
    publicKeyHex: compressPublicKey(master.publicKey),
    chainCodeHex: bytesToHex(master.chainCode),
  }];

  let current = master;

  for (let i = 1; i < parts.length; i++) {
    const part = parts[i];
    const hardened = part.endsWith("'") || part.endsWith('h');
    const index = parseInt(hardened ? part.slice(0, -1) : part, 10);

    current = deriveChild(current, index, hardened);

    const currentPath = parts.slice(0, i + 1).join('/');
    steps.push({
      path: currentPath,
      depth: current.depth,
      index,
      hardened,
      privateKeyHex: current.privateKey.toString(16).padStart(64, '0'),
      publicKeyHex: compressPublicKey(current.publicKey),
      chainCodeHex: bytesToHex(current.chainCode),
    });
  }

  return { node: current, steps };
}

// ─── BIP44/84/86: Rutas estándar ────────────────────────────

/**
 * BIP44: m/44'/0'/account'/change/index → P2PKH (1xxx)
 * BIP84: m/84'/0'/account'/change/index → P2WPKH (bc1qxxx)
 * BIP86: m/86'/0'/account'/change/index → P2TR (bc1pxxx)
 *
 * Estructura del árbol:
 *   purpose' — qué tipo de dirección (44, 84, 86)
 *   coin'    — qué criptomoneda (0 = Bitcoin)
 *   account' — cuenta lógica (0, 1, 2...)
 *   change   — 0 = recepción, 1 = cambio
 *   index    — dirección específica (0, 1, 2...)
 */
export function getDerivationPath(
  purpose: 44 | 84 | 86,
  account: number = 0,
  change: boolean = false,
  index: number = 0,
  coinType: number = 0,
): string {
  // coin_type según SLIP-0044: 0' = Bitcoin mainnet, 1' = cualquier testnet.
  // No es cosmético: cambia la clave derivada, así que la dirección con fondos
  // en testnet (1') es DISTINTA de la de mainnet (0') para la misma seed.
  // Por eso Sparrow/Electrum usan 1' en testnet — hay que usar lo mismo para
  // encontrar el UTXO y poder firmarlo.
  return `m/${purpose}'/${coinType}'/${account}'/${change ? 1 : 0}/${index}`;
}

/**
 * Genera la dirección correcta según el purpose.
 *
 * El parámetro `mainnet` sólo cambia el HRP del bech32 (bc vs tb) — la clave
 * derivada es la misma. Para consultar UTXOs reales en testnet4/signet hace
 * falta usar `mainnet=false` o la API de mempool.space devuelve 400.
 */
export function getAddress(node: HDNode, purpose: 44 | 84 | 86, mainnet = true): string {
  const pubKeyHex = compressPublicKey(node.publicKey);
  const pubKeyHash = ripemd160Hex(hexToBytes(sha256(hexToBytes(pubKeyHex)).hash));
  const pubKeyHashBytes = hexToBytes(pubKeyHash);

  switch (purpose) {
    case 44:
      // P2PKH — devolvemos el hash con prefijo (necesitaría Base58Check para dirección real)
      return '1...' + pubKeyHash.slice(0, 8) + '(P2PKH)';
    case 84:
      return addressP2WPKH(pubKeyHashBytes, mainnet);
    case 86: {
      // Taproot: x-only pubkey (sin tweak por simplicidad educativa)
      const xOnly = hexToBytes(node.publicKey!.x.toString(16).padStart(64, '0'));
      return addressP2TR(xOnly, mainnet);
    }
    default:
      return '?';
  }
}

// ─── BIP48 + descriptores (multisig) ───────────────────────
/**
 * BIP48 es la ruta estándar para claves de MULTISIG:
 *   m/48'/coin'/account'/script_type'
 *
 * El último nivel (hardened) indica el tipo de script del multisig:
 *   1' → P2SH-P2WSH (multisig anidado, dirección 3...)
 *   2' → P2WSH nativo (bc1q..., el estándar hoy)
 *   3' → P2TR (Taproot multisig — convención más reciente)
 *
 * Ojo: BIP48 sólo llega al nivel de la CUENTA. Lo que se comparte con los demás
 * cosignatarios es la xpub de ESE nodo (más su origen); cada uno añade luego
 * /0/* (recepción) y /1/* (cambio) por su cuenta al construir el descriptor.
 */
export type MultisigScriptType = 'p2sh-p2wsh' | 'p2wsh' | 'p2tr';

const BIP48_SCRIPT_TYPE: Record<MultisigScriptType, number> = {
  'p2sh-p2wsh': 1,
  'p2wsh': 2,
  'p2tr': 3,
};

export function getMultisigDerivationPath(
  scriptType: MultisigScriptType,
  account: number = 0,
  coinType: number = 0,
): string {
  return `m/48'/${coinType}'/${account}'/${BIP48_SCRIPT_TYPE[scriptType]}'`;
}

// Versiones de extended key (BIP32). xpub/tpub = claves PÚBLICAS extendidas.
const XPUB_VERSION_MAINNET = 0x0488b21e; // "xpub"
const XPUB_VERSION_TESTNET = 0x043587cf; // "tpub"

/**
 * Fingerprint (huella) de un nodo: primeros 4 bytes de Hash160(pubKey comprimida).
 * El fingerprint del MASTER identifica de qué semilla sale una clave en un descriptor.
 */
export function fingerprint(node: HDNode): string {
  const pubHex = compressPublicKey(node.publicKey);
  return ripemd160Hex(hexToBytes(sha256(hexToBytes(pubHex)).hash)).slice(0, 8);
}

/**
 * Serializa un nodo como extended public key (xpub) en Base58Check.
 *
 * Estructura (78 bytes + 4 de checksum):
 *   version(4) depth(1) parentFingerprint(4) childNumber(4) chainCode(32) pubKey(33)
 *
 * Solo se serializa la parte PÚBLICA: la xpub permite generar direcciones y auditar,
 * pero NO gastar. Es justo lo que se comparte entre cosignatarios de un multisig.
 */
export function serializeXpub(node: HDNode, mainnet = true): string {
  const version = mainnet ? XPUB_VERSION_MAINNET : XPUB_VERSION_TESTNET;
  const data = new Uint8Array(78);
  let o = 0;

  data[o++] = (version >>> 24) & 0xff;
  data[o++] = (version >>> 16) & 0xff;
  data[o++] = (version >>> 8) & 0xff;
  data[o++] = version & 0xff;

  data[o++] = node.depth & 0xff;

  data.set(hexToBytes(node.parentFingerprint), o); o += 4;

  const idx = node.index >>> 0;
  data[o++] = (idx >>> 24) & 0xff;
  data[o++] = (idx >>> 16) & 0xff;
  data[o++] = (idx >>> 8) & 0xff;
  data[o++] = idx & 0xff;

  data.set(node.chainCode, o); o += 32;

  data.set(hexToBytes(compressPublicKey(node.publicKey)), o); o += 33;

  // Checksum: primeros 4 bytes de SHA-256(SHA-256(data))
  const checksum = hexToBytes(sha256(hexToBytes(sha256(data).hash)).hash).slice(0, 4);

  const full = new Uint8Array(82);
  full.set(data, 0);
  full.set(checksum, 78);
  return base58Encode(full);
}

/**
 * Parsea una xpub/tpub (Base58Check) a un nodo PÚBLICO (privateKey = 0n).
 *
 * Es la puerta de entrada del watch-only: pegas la xpub de un cosignatario y
 * puedes derivar sus direcciones con `deriveChildPublic`, sin su clave privada.
 * Valida el checksum doble-SHA256 y la versión (xpub mainnet / tpub testnet).
 */
export function parseXpub(xpub: string): { node: HDNode; mainnet: boolean } {
  const data = base58Decode(xpub);
  if (data.length !== 82) throw new Error('xpub: longitud inválida (se esperan 82 bytes)');

  const payload = data.slice(0, 78);
  const checksum = data.slice(78);
  const expected = hexToBytes(sha256(hexToBytes(sha256(payload).hash)).hash).slice(0, 4);
  if (!checksum.every((b, i) => b === expected[i])) throw new Error('xpub: checksum inválido');

  const version = data[0] * 0x1000000 + data[1] * 0x10000 + data[2] * 0x100 + data[3];
  const mainnet = version === XPUB_VERSION_MAINNET;
  if (!mainnet && version !== XPUB_VERSION_TESTNET) {
    throw new Error('xpub: versión desconocida (¿es una clave privada xprv, o de otra red?)');
  }

  const depth = data[4];
  const parentFingerprint = bytesToHex(data.slice(5, 9));
  const index = data[9] * 0x1000000 + data[10] * 0x10000 + data[11] * 0x100 + data[12];
  const chainCode = data.slice(13, 45);
  const publicKey = decompressPublicKey(bytesToHex(data.slice(45, 78)));

  return {
    node: { privateKey: 0n, publicKey, chainCode, depth, index, parentFingerprint },
    mainnet,
  };
}

/** Una clave de cosignatario lista para meter en un descriptor multisig. */
export interface MultisigKey {
  fingerprint: string;     // huella del MASTER (el origen de esta clave)
  path: string;            // ruta BIP48 usada, p.ej. m/48'/0'/0'/2'
  xpub: string;            // extended public key del nodo de cuenta
  keyExpression: string;   // [fingerprint/48h/0h/0h/2h]xpub  (listo para el descriptor)
  node: HDNode;            // el nodo de cuenta (para derivar direcciones sin rehacer los niveles hardened)
}

/**
 * Deriva la clave BIP48 de un cosignatario y devuelve su "expresión de clave" para
 * descriptores, con el origen entre corchetes:  [masterFP/48h/coin h/account h/type h]xpub
 *
 * El descriptor completo (wsh(sortedmulti(...))) es el siguiente paso; aquí se
 * produce cada pieza [origen]xpub. La ruta del origen usa 'h' para hardened (forma
 * moderna de descriptor, equivalente a la comilla y sin problemas al escaparla).
 */
export function deriveMultisigKey(
  master: HDNode,
  scriptType: MultisigScriptType,
  account: number = 0,
  coinType: number = 0,
  mainnet = true,
): MultisigKey {
  const path = getMultisigDerivationPath(scriptType, account, coinType);
  const { node } = derivePath(master, path);

  const fp = fingerprint(master);
  const xpub = serializeXpub(node, mainnet);
  const originPath = path.replace(/^m\//, '').replace(/'/g, 'h');
  const keyExpression = `[${fp}/${originPath}]${xpub}`;

  return { fingerprint: fp, path, xpub, keyExpression, node };
}

// ─── PBKDF2-HMAC-SHA512 ────────────────────────────────────
/**
 * PBKDF2 (Password-Based Key Derivation Function 2)
 * Aplica HMAC-SHA512 iterativamente para hacer la derivación lenta
 * (resistente a fuerza bruta).
 *
 * BIP39 usa 2048 iteraciones, lo cual es relativamente rápido en JS.
 */
function pbkdf2HmacSha512(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  dkLen: number = 64
): Uint8Array {
  const result = new Uint8Array(dkLen);
  let offset = 0;
  let blockIndex = 1;

  while (offset < dkLen) {
    // U1 = HMAC(password, salt || INT32_BE(blockIndex))
    const blockData = new Uint8Array(salt.length + 4);
    blockData.set(salt);
    blockData[salt.length] = (blockIndex >> 24) & 0xff;
    blockData[salt.length + 1] = (blockIndex >> 16) & 0xff;
    blockData[salt.length + 2] = (blockIndex >> 8) & 0xff;
    blockData[salt.length + 3] = blockIndex & 0xff;

    let u = hmacSha512(password, blockData);
    const t = new Uint8Array(u);

    // U2..Uc = HMAC(password, U_{i-1}), T = U1 XOR U2 XOR ... XOR Uc
    for (let i = 1; i < iterations; i++) {
      u = hmacSha512(password, u);
      for (let j = 0; j < t.length; j++) {
        t[j] ^= u[j];
      }
    }

    const remaining = Math.min(t.length, dkLen - offset);
    result.set(t.slice(0, remaining), offset);
    offset += remaining;
    blockIndex++;
  }

  return result;
}

// ─── Utilidades ─────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function hexToBits(hex: string): string {
  return hex.split('').map(c => parseInt(c, 16).toString(2).padStart(4, '0')).join('');
}

export { BIP39_WORDLIST };
