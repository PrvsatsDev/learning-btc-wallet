/**
 * Smoke test del paso 4: descriptores multisig (wsh(sortedmulti(...))).
 *
 * El checksum se verifica contra el vector oficial de BIP380:
 *   raw(deadbeef)#89f8spxm
 * y el INPUT_CHARSET está copiado literal de Bitcoin Core, así que un solo
 * vector válido prueba todo el algoritmo.
 *
 * Sin framework: console.log + process.exit(1). Ejecutar bundleando con esbuild.
 */

import { masterKeyFromSeed, deriveMultisigKey } from './hdwallet';
import {
  sortPubKeysBIP67,
  descriptorChecksum,
  withChecksum,
  buildWshSortedMulti,
  deriveMultisigAddress,
} from './descriptor';

let failed = false;
function check(name: string, cond: boolean, got?: string, want?: string) {
  console.log(`${cond ? '✓' : '✗'} ${name}`);
  if (!cond) {
    failed = true;
    if (got !== undefined) console.log(`    got:  ${got}`);
    if (want !== undefined) console.log(`    want: ${want}`);
  }
}

// ─── 1) Checksum contra el vector oficial BIP380 ────────────
const cs = descriptorChecksum('raw(deadbeef)');
check('checksum raw(deadbeef) = 89f8spxm', cs === '89f8spxm', cs, '89f8spxm');
check('withChecksum añade #checksum',
  withChecksum('raw(deadbeef)') === 'raw(deadbeef)#89f8spxm', withChecksum('raw(deadbeef)'));
check('checksum vacío si hay carácter inválido', descriptorChecksum('raw(deadbeef)\n') === '');

// ─── 2) Orden BIP67 ─────────────────────────────────────────
const kA = new Uint8Array([0x03, 0xaa, 0x00]);
const kB = new Uint8Array([0x02, 0xff, 0x00]);
const kC = new Uint8Array([0x02, 0xff, 0x01]);
const sorted = sortPubKeysBIP67([kA, kB, kC]);
check('BIP67 ordena ascendente por bytes',
  sorted[0] === kB && sorted[1] === kC && sorted[2] === kA,
  sorted.map(k => k[0].toString(16) + k[1].toString(16) + k[2].toString(16)).join(' '));
// no muta el array original
const orig = [kA, kB, kC];
sortPubKeysBIP67(orig);
check('BIP67 no muta el array de entrada', orig[0] === kA);

// ─── 3) Tres cosignatarios (3 semillas distintas) ───────────
const mA = masterKeyFromSeed(new Uint8Array(16).fill(0x11));
const mB = masterKeyFromSeed(new Uint8Array(16).fill(0x22));
const mC = masterKeyFromSeed(new Uint8Array(16).fill(0x33));
const keyA = deriveMultisigKey(mA, 'p2wsh', 0, 0, true);
const keyB = deriveMultisigKey(mB, 'p2wsh', 0, 0, true);
const keyC = deriveMultisigKey(mC, 'p2wsh', 0, 0, true);

const desc = buildWshSortedMulti([keyA, keyB, keyC], 2, '<0;1>');
check('descriptor empieza por wsh(sortedmulti(2,', desc.startsWith('wsh(sortedmulti(2,'));
check('descriptor incluye multipath /<0;1>/*', desc.includes('/<0;1>/*'));
// el checksum del descriptor construido es consistente
const hashIdx = desc.lastIndexOf('#');
const body = desc.slice(0, hashIdx);
const cksum = desc.slice(hashIdx + 1);
check('descriptor: checksum de 8 caracteres', cksum.length === 8, cksum);
check('descriptor: checksum válido (recomputa igual)', descriptorChecksum(body) === cksum, descriptorChecksum(body), cksum);

// ─── 4) Derivación de dirección ─────────────────────────────
const masters = [mA, mB, mC];
const addr0 = deriveMultisigAddress(masters, 2, 'p2wsh', 0, 0, 0, 0, true);
check('dirección P2WSH mainnet (bc1q…)', addr0.address.startsWith('bc1q'), addr0.address);
check('witnessScript termina en OP_3 OP_CHECKMULTISIG (53ae)', addr0.witnessScriptHex.endsWith('53ae'));

const addr1 = deriveMultisigAddress(masters, 2, 'p2wsh', 0, 1, 0, 0, true);
check('índices distintos → direcciones distintas', addr0.address !== addr1.address);

// PROPIEDAD CLAVE de sortedmulti: el orden de los cosignatarios NO cambia la dirección
const addrReordered = deriveMultisigAddress([mC, mA, mB], 2, 'p2wsh', 0, 0, 0, 0, true);
check('sortedmulti: reordenar cosignatarios da la MISMA dirección',
  addr0.address === addrReordered.address, addrReordered.address, addr0.address);

// testnet cambia el HRP
const addrTest = deriveMultisigAddress(masters, 2, 'p2wsh', 0, 0, 0, 0, false);
check('testnet → dirección tb1q…', addrTest.address.startsWith('tb1q'), addrTest.address);

console.log(failed ? '\nRESULTADO: FALLOS ✗' : '\nRESULTADO: TODO OK ✓');
if (failed) process.exit(1);
