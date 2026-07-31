/**
 * Smoke test de CKDpub (derivación pública / watch-only) + parseXpub + descompresión.
 *
 * La propiedad clave de BIP32: derivar desde una xpub (sin clave privada) produce
 * exactamente las mismas claves públicas que la derivación privada. Se verifica
 * además contra el vector oficial BIP32 test vector 1 (m/0H/1, no hardened).
 *
 * Sin framework: console.log + process.exit(1). Ejecutar bundleando con esbuild.
 */

import {
  masterKeyFromSeed,
  derivePath,
  deriveChild,
  deriveChildPublic,
  serializeXpub,
  parseXpub,
} from './hdwallet';
import { getPublicKey, compressPublicKey, decompressPublicKey } from './secp256k1';

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
function b2h(b: Uint8Array): string {
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

const master = masterKeyFromSeed(hexToBytes('000102030405060708090a0b0c0d0e0f'));
const { node: m0h } = derivePath(master, "m/0'");
const XPUB_M0H_1 =
  'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ';

// ─── 1) CKDpub == derivación privada ────────────────────────
const priv1 = deriveChild(m0h, 1, false);       // m/0'/1 con clave privada
const pub1 = deriveChildPublic(m0h, 1);          // m/0'/1 solo con la parte pública
check('CKDpub: misma clave pública que la derivación privada',
  compressPublicKey(pub1.publicKey) === compressPublicKey(priv1.publicKey));
check('CKDpub: mismo chain code', b2h(pub1.chainCode) === b2h(priv1.chainCode));
check('CKDpub: mismo parentFingerprint', pub1.parentFingerprint === priv1.parentFingerprint);
check('CKDpub: depth e index correctos', pub1.depth === priv1.depth && pub1.index === priv1.index);
check('CKDpub: privateKey = 0n (watch-only)', pub1.privateKey === 0n);

// ─── 2) Contra el vector oficial BIP32 (m/0H/1) ─────────────
const gotXpub = serializeXpub(pub1, true);
check('CKDpub: xpub m/0H/1 coincide con BIP32 vector 1', gotXpub === XPUB_M0H_1, gotXpub, XPUB_M0H_1);

// ─── 3) No se pueden derivar hijos hardened con CKDpub ──────
let threw = false;
try { deriveChildPublic(m0h, 0x80000000); } catch { threw = true; }
check('CKDpub: rechaza índices hardened', threw);

// ─── 4) parseXpub: round-trip con serializeXpub ─────────────
const xpubStr = serializeXpub(m0h, true);
const parsed = parseXpub(xpubStr);
check('parseXpub: mainnet detectado', parsed.mainnet === true);
check('parseXpub: recupera la misma clave pública (x)',
  parsed.node.publicKey!.x === m0h.publicKey!.x);
check('parseXpub: recupera la misma clave pública (y)',
  parsed.node.publicKey!.y === m0h.publicKey!.y);
check('parseXpub: mismo chain code / depth / index / fingerprint',
  b2h(parsed.node.chainCode) === b2h(m0h.chainCode) &&
  parsed.node.depth === m0h.depth &&
  parsed.node.index === m0h.index &&
  parsed.node.parentFingerprint === m0h.parentFingerprint);

// ─── 5) Flujo watch-only real: STRING xpub → dirección hija ─
// Parsear la xpub de m/0' y derivar /1 públicamente debe dar el vector oficial.
const childFromString = deriveChildPublic(parsed.node, 1);
check('watch-only: xpub(string) → CKDpub → xpub m/0H/1 correcta',
  serializeXpub(childFromString, true) === XPUB_M0H_1);

// ─── 6) parseXpub rechaza checksum corrupto ─────────────────
const corrupt = xpubStr.slice(0, -1) + (xpubStr.slice(-1) === 'q' ? 'p' : 'q');
let threwChk = false;
try { parseXpub(corrupt); } catch { threwChk = true; }
check('parseXpub: rechaza checksum corrupto', threwChk);

// ─── 7) Descompresión de puntos (ambas paridades) ───────────
let evenOk = false, oddOk = false;
for (let k = 2n; k < 12n; k++) {
  const pt = getPublicKey(k);
  const comp = compressPublicKey(pt);
  const dec = decompressPublicKey(comp);
  if (dec!.x !== pt!.x || dec!.y !== pt!.y) { failed = true; console.log(`✗ descompresión k=${k}`); }
  if (comp.startsWith('02')) evenOk = true;
  if (comp.startsWith('03')) oddOk = true;
}
check('decompressPublicKey: round-trip correcto en ambas paridades', evenOk && oddOk);

console.log(failed ? '\nRESULTADO: FALLOS ✗' : '\nRESULTADO: TODO OK ✓');
if (failed) process.exit(1);
