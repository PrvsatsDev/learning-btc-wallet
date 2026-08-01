/**
 * Test del multisig Taproot ESTÁNDAR: tr(interna, sortedmulti_a(m,…)).
 *
 *  - Verifica la tubería multi_a → scriptPubKey contra el vector OFICIAL de
 *    BIP-387 (Test Vector 2, clave interna x-only cruda):
 *      tr(a34b99f2…c5bd, multi_a(1, 669b8afc…adbd0)) → 5120 eb5bd389…074f3
 *  - Propiedad de sortedmulti_a: reordenar los cosignatarios NO cambia la
 *    dirección (las claves se ordenan BIP67 antes de montar la hoja).
 *  - Formato del descriptor con NUMS + checksum.
 */

import {
  deriveTrMultisig, buildTrSortedMultiA, sortXOnlyBIP67, NUMS_H,
  descriptorChecksum,
} from './descriptor';
import { getPublicKey } from './secp256k1';

let failures = 0;
function check(name: string, cond: boolean, got?: string, want?: string) {
  console.log(`${cond ? 'OK  ' : 'FAIL'} ${name}`);
  if (!cond) { failures++; if (got !== undefined) { console.log('  got :', got); console.log('  want:', want); } }
}
function h(hex: string): Uint8Array {
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  return b;
}
function to32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = n;
  for (let i = 31; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}

// ─── Vector oficial BIP-387 (Test Vector 2) ─────────────────

{
  const internal = h('a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd');
  const key = h('669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0');
  const wantSpk = '5120eb5bd3894327d75093891cc3a62506df7d58ec137fcd104cdd285d67816074f3';

  // multi_a(1, key): sin ordenar (sorted=false), una sola clave.
  const r = deriveTrMultisig(internal, 1, [key], false, true);
  check('BIP-387 v2: scriptPubKey de multi_a', r.scriptPubKeyHex === wantSpk, r.scriptPubKeyHex, wantSpk);
  check('BIP-387 v2: output key', r.outputKeyHex === 'eb5bd3894327d75093891cc3a62506df7d58ec137fcd104cdd285d67816074f3');
}

// ─── Multisig 2-de-3 real con NUMS (ver y probar) ───────────

{
  const privs = [
    0x00000000000000000000000000000000000000000000000000000000000000a1n,
    0x00000000000000000000000000000000000000000000000000000000000000b2n,
    0x00000000000000000000000000000000000000000000000000000000000000c3n,
  ];
  const xonly = privs.map(p => to32(getPublicKey(p)!.x));
  const nums = h(NUMS_H);

  const r = deriveTrMultisig(nums, 2, xonly, true, true);
  check('2-de-3 NUMS: dirección es bc1p…', r.address.startsWith('bc1p'));
  check('2-de-3 NUMS: scriptPubKey es OP_1 <32B>', r.scriptPubKeyHex.startsWith('5120') && r.scriptPubKeyHex.length === 68);
  console.log('  address:', r.address);

  // Propiedad sortedmulti_a: reordenar cosignatarios → misma dirección.
  const reordered = [xonly[2], xonly[0], xonly[1]];
  const r2 = deriveTrMultisig(nums, 2, reordered, true, true);
  check('sortedmulti_a: reordenar cosignatarios NO cambia la dirección', r.address === r2.address);

  // Con multi_a (sin ordenar) el orden SÍ importa (control): distinto orden → distinta dir.
  const rA = deriveTrMultisig(nums, 2, xonly, false, true);
  const rB = deriveTrMultisig(nums, 2, reordered, false, true);
  check('multi_a (sin ordenar): el orden SÍ afecta (control)', rA.address !== rB.address);

  // El sort BIP67 de x-only es estable y coincide con el usado internamente.
  const sorted = sortXOnlyBIP67(reordered);
  check('sortXOnlyBIP67 ordena igual que la derivación',
    deriveTrMultisig(nums, 2, sorted, false, true).address === r.address);
}

// ─── Formato del descriptor tr(NUMS,sortedmulti_a(…))#chk ───

{
  const cosigners = [
    { keyExpression: '[11111111/48h/0h/0h/2h]xpubAAA' },
    { keyExpression: '[22222222/48h/0h/0h/2h]xpubBBB' },
    { keyExpression: '[33333333/48h/0h/0h/2h]xpubCCC' },
  ];
  const desc = buildTrSortedMultiA(cosigners, 2);
  check('descriptor empieza por tr(NUMS,sortedmulti_a(2,', desc.startsWith(`tr(${NUMS_H},sortedmulti_a(2,`));
  check('descriptor incluye el sufijo de derivación /<0;1>/*', desc.includes('xpubAAA/<0;1>/*'));
  const chk = desc.split('#')[1];
  check('checksum de 8 caracteres', chk.length === 8 && descriptorChecksum(desc.split('#')[0]) === chk);
  console.log('  descriptor:', desc);
}

console.log(failures === 0 ? '\nTODO OK ✓' : `\n${failures} FALLO(S) ✗`);
if (failures > 0) process.exit(1);
