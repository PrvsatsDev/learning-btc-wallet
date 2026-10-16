/**
 * Test del árbol BIP32 navegable (bip32-tree.ts).
 *
 * Vectores oficiales con el mnemónico "abandon ×11 about" (sin passphrase):
 *   BIP44: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki (vía BIP84/86)
 *   BIP84: https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
 *   BIP86: https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
 *
 * Sin framework: console.log + process.exit(1). Ejecutar bundleando:
 *   npx rolldown src/crypto/bip32-tree.test.ts --format esm -o /tmp/t.mjs && node /tmp/t.mjs
 */

import { mnemonicToSeed, masterKeyFromSeed } from './hdwallet';
import {
  makeRoot,
  childrenOf,
  deriveTreeChild,
  verifyFromAccountXpub,
  isWatchOnlyDerivable,
  ancestorPaths,
  childNumberHex,
  accountDescriptor,
  type TreeNode,
  type TreeOptions,
} from './bip32-tree';

let failed = false;
function check(name: string, ok: boolean, detail = '') {
  console.log(`${ok ? '✓' : '✗'} ${name}${!ok && detail ? `\n    ${detail}` : ''}`);
  if (!ok) failed = true;
}

const words = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'.split(' ');
const master = masterKeyFromSeed(mnemonicToSeed(words));
const root = makeRoot(master);
const opts: TreeOptions = { mainnet: true, accounts: 1, addresses: 2 };

/** Baja por el árbol siguiendo una ruta tipo "84'/0'/0'/0/1" */
function walk(path: string, mainnet = true): TreeNode {
  let node = root;
  for (const seg of path.split('/')) {
    const hardened = seg.endsWith("'");
    node = deriveTreeChild(node, parseInt(seg), hardened, mainnet);
  }
  return node;
}

// ─── 1) Vectores de direcciones ─────────────────────────────
const vectors: [string, string][] = [
  ["44'/0'/0'/0/0", '1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA'],
  ["84'/0'/0'/0/0", 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu'],
  ["84'/0'/0'/0/1", 'bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g'],
  ["84'/0'/0'/1/0", 'bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el'],
  ["86'/0'/0'/0/0", 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr'],
  ["86'/0'/0'/0/1", 'bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh'],
  ["86'/0'/0'/1/0", 'bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7'],
];
for (const [path, expected] of vectors) {
  const got = walk(path).address;
  check(`m/${path} → ${expected}`, got === expected, `obtenido: ${got}`);
}

// ─── 2) Estructura perezosa del árbol ───────────────────────
const purposes = childrenOf(root, opts);
check('master tiene 3 purposes (44/84/86, hardened)',
  purposes.map(p => p.path).join(',') === "m/44',m/84',m/86'" && purposes.every(p => p.hardened));

const coin = childrenOf(purposes[1], opts);
check("purpose 84' → coin 0' en mainnet", coin.length === 1 && coin[0].path === "m/84'/0'");
const coinTest = childrenOf(purposes[1], { ...opts, mainnet: false });
check("purpose 84' → coin 1' en testnet", coinTest[0].path === "m/84'/1'");

const account = childrenOf(coin[0], opts)[0];
const chains = childrenOf(account, opts);
check('cuenta → recepción (0) y cambio (1), no hardened',
  chains.map(c => c.path).join(',') === "m/84'/0'/0'/0,m/84'/0'/0'/1" && chains.every(c => !c.hardened));

const addrs = childrenOf(chains[0], opts);
check('cadena de recepción → 2 direcciones con address', addrs.length === 2 && addrs.every(a => !!a.address));
check('la rama hereda el purpose', addrs.every(a => a.purpose === 84));
check('childNumber hardened = índice + 2^31', childNumberHex(purposes[1]) === '0x80000054');

// ─── 3) Frontera watch-only ─────────────────────────────────
check('purpose/coin/cuenta NO son derivables desde xpub',
  ![purposes[1], coin[0], account].some(isWatchOnlyDerivable));
check('cadena y dirección SÍ lo son', isWatchOnlyDerivable(chains[0]) && isWatchOnlyDerivable(addrs[1]));

const v = verifyFromAccountXpub(account, addrs[1]);
check('CKDpub desde la xpub de la cuenta = CKDpriv (m/84\'/0\'/0\'/0/1)', v.matches);
check('ruta pública xpub/0/1', v.route.join('') === 'xpub/0/1');

const tr = walk("86'/0'/0'");
check('CKDpub también cuadra en la rama Taproot',
  verifyFromAccountXpub(tr, walk("86'/0'/0'/1/0")).matches);

// ─── 4) Descriptor de la cuenta ─────────────────────────────
// Master fingerprint y xpub de m/84'/0'/0' para "abandon…about" (la zpub de
// BIP84 re-serializada con versión xpub, como la muestran Sparrow/Core).
check('fingerprint del master = 73c5da0a', root.fingerprint === '73c5da0a', root.fingerprint);
const desc = accountDescriptor(account, root.fingerprint, true);
check('descriptor wpkh de la cuenta',
  desc.startsWith("wpkh([73c5da0a/84'/0'/0']xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/0/*)#")
  && /#[a-z0-9]{8}$/.test(desc), desc);
check('descriptor tr en la rama 86', accountDescriptor(tr, root.fingerprint, true, 1).startsWith("tr([73c5da0a/86'/0'/0']xpub"));

// ─── 5) Utilidades ──────────────────────────────────────────
check('ancestorPaths', ancestorPaths("m/84'/0'").join(',') === "m,m/84',m/84'/0'");

console.log(failed ? '\nRESULTADO: FALLOS ✗' : '\nRESULTADO: TODO OK ✓');
if (failed) process.exit(1);
