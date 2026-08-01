/**
 * Test del sighash Taproot (BIP341), verificado contra el vector OFICIAL
 * keyPathSpending[0] de wallet-test-vectors.json.
 *
 * La tx tiene 9 inputs (mezcla P2TR / P2PKH / P2WPKH) y 2 outputs. Se comprueban:
 *   - los 5 hashes precalculados (sha_prevouts/amounts/scriptpubkeys/sequences/outputs),
 *   - el sigMsg completo del input 0 (SIGHASH_SINGLE),
 *   - y el sigHash de los 7 inputs firmados, cubriendo TODOS los hash_type:
 *     DEFAULT / ALL / NONE / SINGLE, con y sin ANYONECANPAY.
 */

import { parseTxHex, type TxOutput } from './transaction';
import {
  computeSighashTaproot,
  shaPrevouts, shaAmounts, shaScriptPubkeys, shaSequences, shaOutputs,
} from './sighash-taproot';

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
function hex(b: Uint8Array): string {
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

const rawTx =
  '02000000097de20cbff686da83a54981d2b9bab3586f4ca7e48f57f5b55963115f3b334e9c0100000000' +
  '00000000d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127517d44759b6dafdd990000000000ff' +
  'fffffff8e1f583384333689228c5d28eac13366be082dc57441760d957275419a418420000000000ffff' +
  'fffff0689180aa63b30cb162a73c6d2a38b7eeda2a83ece74310fda0843ad604853b0100000000feffff' +
  'ffaa5202bdf6d8ccd2ee0f0202afbbb7461d9264a25e5bfd3c5a52ee1239e0ba6c0000000000feffffff9' +
  '56149bdc66faa968eb2be2d2faa29718acbfe3941215893a2a3446d32acd050000000000000000000e66' +
  '4b9773b88c09c32cb70a2a3e4da0ced63b7ba3b22f848531bbb1d5d5f4c94010000000000000000e9aa6b' +
  '8e6c9de67619e6a3924ae25696bb7b694bb677a632a74ef7eadfd4eabf0000000000ffffffffa778eb6a2' +
  '63dc090464cd125c466b5a99667720b1c110468831d058aa1b82af10100000000ffffffff0200ca9a3b00' +
  '0000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac807840cb0000000020ac9a87f5' +
  '594be208f8532db38cff670c450ed2fea8fcdefcc9a663f78bab962b0065cd1d';

const tx = parseTxHex(rawTx);

// UTXOs gastados (scriptPubKey + importe), en orden de input.
const prevouts: TxOutput[] = [
  { value: 420000000n, scriptPubKey: h('512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343') },
  { value: 462000000n, scriptPubKey: h('5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3') },
  { value: 294000000n, scriptPubKey: h('76a914751e76e8199196d454941c45d1b3a323f1433bd688ac') },
  { value: 504000000n, scriptPubKey: h('5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e') },
  { value: 630000000n, scriptPubKey: h('512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605') },
  { value: 378000000n, scriptPubKey: h('00147dd65592d0ab2fe0d0257d571abf032cd9db93dc') },
  { value: 672000000n, scriptPubKey: h('512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831') },
  { value: 546000000n, scriptPubKey: h('5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5') },
  { value: 588000000n, scriptPubKey: h('512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220') },
];

// ─── Hashes precalculados ───────────────────────────────────

check('sha_prevouts', hex(shaPrevouts(tx)) === 'e3b33bb4ef3a52ad1fffb555c0d82828eb22737036eaeb02a235d82b909c4c3f');
check('sha_amounts', hex(shaAmounts(prevouts)) === '58a6964a4f5f8f0b642ded0a8a553be7622a719da71d1f5befcefcdee8e0fde6');
check('sha_scriptpubkeys', hex(shaScriptPubkeys(prevouts)) === '23ad0f61ad2bca5ba6a7693f50fce988e17c3780bf2b1e720cfbb38fbdd52e21');
check('sha_sequences', hex(shaSequences(tx)) === '18959c7221ab5ce9e26c3cd67b22c24f8baa54bac281d8e6b05e400e6c3a957e');
check('sha_outputs', hex(shaOutputs(tx)) === 'a2e6dab7c1f0dcd297c8d61647fd17d821541ea69c3cc37dcbad7f90d4eb4bc5');

// ─── sigMsg completo del input 0 (SIGHASH_SINGLE) ───────────

const wantSigMsg =
  '0003020000000065cd1de3b33bb4ef3a52ad1fffb555c0d82828eb22737036eaeb02a235d82b909c4c3f' +
  '58a6964a4f5f8f0b642ded0a8a553be7622a719da71d1f5befcefcdee8e0fde623ad0f61ad2bca5ba6a76' +
  '93f50fce988e17c3780bf2b1e720cfbb38fbdd52e2118959c7221ab5ce9e26c3cd67b22c24f8baa54bac2' +
  '81d8e6b05e400e6c3a957e0000000000d0418f0e9a36245b9a50ec87f8bf5be5bcae434337b87139c3a5b' +
  '1f56e33cba0';
const r0 = computeSighashTaproot(tx, 0, prevouts, { hashType: 0x03 });
check('sigMsg input 0 (SINGLE)', hex(r0.sigMsg) === wantSigMsg, hex(r0.sigMsg), wantSigMsg);

// ─── sigHash de los 7 inputs firmados (todos los hash_type) ─

const cases: { pos: string; txin: number; hashType: number; want: string }[] = [
  { pos: '0', txin: 0, hashType: 0x03, want: '2514a6272f85cfa0f45eb907fcb0d121b808ed37c6ea160a5a9046ed5526d555' },
  { pos: '1', txin: 1, hashType: 0x83, want: '325a644af47e8a5a2591cda0ab0723978537318f10e6a63d4eed783b96a71a4d' },
  { pos: '2', txin: 3, hashType: 0x01, want: 'bf013ea93474aa67815b1b6cc441d23b64fa310911d991e713cd34c7f5d46669' },
  { pos: '3', txin: 4, hashType: 0x00, want: '4f900a0bae3f1446fd48490c2958b5a023228f01661cda3496a11da502a7f7ef' },
  { pos: '4', txin: 6, hashType: 0x02, want: '15f25c298eb5cdc7eb1d638dd2d45c97c4c59dcaec6679cfc16ad84f30876b85' },
  { pos: '5', txin: 7, hashType: 0x82, want: 'cd292de50313804dabe4685e83f923d2969577191a3e1d2882220dca88cbeb10' },
  { pos: '6', txin: 8, hashType: 0x81, want: 'cccb739eca6c13a8a89e6e5cd317ffe55669bbda23f2fd37b0f18755e008edd2' },
];
for (const c of cases) {
  const { sigHash } = computeSighashTaproot(tx, c.txin, prevouts, { hashType: c.hashType });
  const label = ({ 0: 'DEFAULT', 1: 'ALL', 2: 'NONE', 3: 'SINGLE' } as Record<number, string>)[c.hashType & 3]
    + ((c.hashType & 0x80) ? '|ACP' : '');
  check(`sigHash input ${c.txin} (${label})`, hex(sigHash) === c.want, hex(sigHash), c.want);
}

console.log(failures === 0 ? '\nTODO OK ✓' : `\n${failures} FALLO(S) ✗`);
if (failures > 0) process.exit(1);
