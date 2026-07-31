/**
 * Smoke test de BIP48 + serialización xpub (paso 3 de multisig).
 *
 * La serialización xpub se verifica contra los VECTORES OFICIALES de BIP32
 * (test vector 1, seed 000102030405060708090a0b0c0d0e0f):
 *   https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 *
 * Sin framework: console.log + process.exit(1). Ejecutar bundleando con esbuild.
 */

import {
  masterKeyFromSeed,
  derivePath,
  serializeXpub,
  fingerprint,
  getMultisigDerivationPath,
  deriveMultisigKey,
} from './hdwallet';

let failed = false;
function check(name: string, cond: boolean, got?: string, want?: string) {
  console.log(`${cond ? '✓' : '✗'} ${name}`);
  if (!cond) {
    failed = true;
    if (got !== undefined) console.log(`    got:  ${got}`);
    if (want !== undefined) console.log(`    want: ${want}`);
  }
}

function hexToBytes(hex: string): Uint8Array {
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  return b;
}

// ─── Vectores oficiales BIP32 (test vector 1) ───────────────
const seed = hexToBytes('000102030405060708090a0b0c0d0e0f');
const master = masterKeyFromSeed(seed);

const XPUB_M =
  'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8';
const XPUB_M_0H =
  'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw';

const gotMaster = serializeXpub(master, true);
check('xpub master coincide con BIP32 vector 1', gotMaster === XPUB_M, gotMaster, XPUB_M);

check('fingerprint del master = 3442193e', fingerprint(master) === '3442193e', fingerprint(master), '3442193e');

const { node: m0h } = derivePath(master, "m/0'");
const gotM0h = serializeXpub(m0h, true);
check("xpub m/0' coincide con BIP32 vector 1", gotM0h === XPUB_M_0H, gotM0h, XPUB_M_0H);

// ─── BIP48: rutas ───────────────────────────────────────────
check("ruta P2WSH = m/48'/0'/0'/2'",
  getMultisigDerivationPath('p2wsh') === "m/48'/0'/0'/2'", getMultisigDerivationPath('p2wsh'));
check("ruta P2SH-P2WSH = m/48'/0'/0'/1'",
  getMultisigDerivationPath('p2sh-p2wsh') === "m/48'/0'/0'/1'", getMultisigDerivationPath('p2sh-p2wsh'));
check("ruta Taproot = m/48'/0'/1'/3' (account=1)",
  getMultisigDerivationPath('p2tr', 1) === "m/48'/0'/1'/3'", getMultisigDerivationPath('p2tr', 1));

// ─── deriveMultisigKey: expresión de clave para descriptor ──
const k = deriveMultisigKey(master, 'p2wsh', 0, 0, true);
check('deriveMultisigKey: fingerprint = master', k.fingerprint === '3442193e', k.fingerprint);
check('deriveMultisigKey: path correcto', k.path === "m/48'/0'/0'/2'", k.path);
check('deriveMultisigKey: keyExpression con origen [3442193e/48h/0h/0h/2h]',
  k.keyExpression.startsWith('[3442193e/48h/0h/0h/2h]xpub'), k.keyExpression);
check('deriveMultisigKey: la xpub del origen es la del nodo derivado',
  k.keyExpression === `[3442193e/48h/0h/0h/2h]${k.xpub}`);

// La xpub de la cuenta debe ser válida y distinta del master.
check('deriveMultisigKey: xpub != master', k.xpub !== gotMaster);
check('deriveMultisigKey: xpub empieza por "xpub"', k.xpub.startsWith('xpub'));

// tpub (testnet) para la misma cuenta
const kTest = deriveMultisigKey(master, 'p2wsh', 0, 0, false);
check('deriveMultisigKey testnet: xpub empieza por "tpub"', kTest.xpub.startsWith('tpub'), kTest.xpub.slice(0, 8));

console.log(failed ? '\nRESULTADO: FALLOS ✗' : '\nRESULTADO: TODO OK ✓');
if (failed) process.exit(1);
