/**
 * Test de Tapscript (script-path de Taproot), verificado contra los vectores
 * OFICIALES de BIP341 (wallet-test-vectors.json):
 *
 *   - Hoja simple (índices 1 y 2): TapLeaf hash, merkleRoot, output key, control
 *     block (incluida la paridad: índice 1 → 0xc1, índice 2 → 0xc0).
 *   - Árbol de 3 hojas [L0,[L1,L2]] (índice 6): TapBranch (con su ordenación),
 *     merkleRoot, output key y los 3 control blocks con su prueba Merkle.
 *
 * Y la prueba de fuego: un multisig 2-de-3 en Tapscript (OP_CHECKSIGADD) que se
 * ejecuta con nuestro intérprete verificando firmas Schnorr reales.
 */

import {
  tapLeafHash, computeTaptree, taprootScriptOutput, tapscriptMultisig,
  type TapTree, bytesToHex,
} from './tapscript';
import { executeScript } from './script';
import { schnorrSign, schnorrVerify } from './schnorr';
import { getPublicKey } from './secp256k1';
import { bytesToBigint } from './hmac';

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

// ─── Vector 1: hoja simple, paridad impar (control block 0xc1) ──

{
  const internalX = 0x187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27n;
  const internalHex = '187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27';
  const script = h('20d85a959b0290bf19bb89ed43c916be835475d013da4b362117393e25a48229b8ac');
  const wantLeaf = '5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21';
  const wantOut = '147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3';

  check('[v1] TapLeaf hash', bytesToHex(tapLeafHash(script)) === wantLeaf, bytesToHex(tapLeafHash(script)), wantLeaf);

  const out = taprootScriptOutput(internalX, { script });
  check('[v1] merkleRoot (= leaf, árbol de 1)', bytesToHex(out.merkleRoot) === wantLeaf);
  check('[v1] output key', to32Hex(out.outputKey) === wantOut, to32Hex(out.outputKey), wantOut);
  check('[v1] paridad impar → control block 0xc1',
    bytesToHex(out.controlBlocks[0]) === 'c1' + internalHex, bytesToHex(out.controlBlocks[0]), 'c1' + internalHex);
}

// ─── Vector 2: hoja simple, paridad par (control block 0xc0) ──

{
  const internalX = 0x93478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820n;
  const internalHex = '93478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820';
  const script = h('20b617298552a72ade070667e86ca63b8f5789a9fe8731ef91202a91c9f3459007ac');
  const wantOut = 'e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e';

  const out = taprootScriptOutput(internalX, { script });
  check('[v2] output key', to32Hex(out.outputKey) === wantOut, to32Hex(out.outputKey), wantOut);
  check('[v2] paridad par → control block 0xc0',
    bytesToHex(out.controlBlocks[0]) === 'c0' + internalHex);
}

// ─── Vector 6: árbol de 3 hojas [L0,[L1,L2]] ──

{
  const internalX = 0xe0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6fn;
  const iHex = 'e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f';
  const L0 = h('2072ea6adcf1d371dea8fba1035a09f3d24ed5a059799bae114084130ee5898e69ac');
  const L1 = h('202352d137f2f3ab38d1eaa976758873377fa5ebb817372c71e2c542313d4abda8ac');
  const L2 = h('207337c0dd4253cb86f2c43a2351aadd82cccb12a172cd120452b9bb8324f2186aac');
  const hL0 = '2645a02e0aac1fe69d69755733a9b7621b694bb5b5cde2bbfc94066ed62b9817';
  const hL1 = 'ba982a91d4fc552163cb1c0da03676102d5b7a014304c01f0c77b2b8e888de1c';
  const hL2 = '9e31407bffa15fefbf5090b149d53959ecdf3f62b1246780238c24501d5ceaf6';
  const wantRoot = 'ccbd66c6f7e8fdab47b3a486f59d28262be857f30d4773f2d5ea47f7761ce0e2';
  const wantOut = '91b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605';
  const branchL1L2 = 'ffe578e9ea769027e4f5a3de40732f75a88a6353a09d767ddeb66accef85e553';

  const tree: TapTree = [{ script: L0 }, [{ script: L1 }, { script: L2 }]];
  const t = computeTaptree(tree);

  check('[v6] leaf hashes en orden [L0,L1,L2]',
    bytesToHex(t.leaves[0].leafHash) === hL0 &&
    bytesToHex(t.leaves[1].leafHash) === hL1 &&
    bytesToHex(t.leaves[2].leafHash) === hL2);
  check('[v6] merkleRoot (TapBranch ordenado)', bytesToHex(t.merkleRoot) === wantRoot, bytesToHex(t.merkleRoot), wantRoot);

  const out = taprootScriptOutput(internalX, tree);
  check('[v6] output key', to32Hex(out.outputKey) === wantOut, to32Hex(out.outputKey), wantOut);
  check('[v6] control block L0 (path = branch(L1,L2))',
    bytesToHex(out.controlBlocks[0]) === 'c0' + iHex + branchL1L2, bytesToHex(out.controlBlocks[0]), 'c0' + iHex + branchL1L2);
  check('[v6] control block L1 (path = L2 ‖ L0)',
    bytesToHex(out.controlBlocks[1]) === 'c0' + iHex + hL2 + hL0);
  check('[v6] control block L2 (path = L1 ‖ L0)',
    bytesToHex(out.controlBlocks[2]) === 'c0' + iHex + hL1 + hL0);
}

// ─── Prueba de fuego: multisig 2-de-3 Tapscript (OP_CHECKSIGADD) ──

{
  const privs = [
    0x00000000000000000000000000000000000000000000000000000000000000a1n,
    0x00000000000000000000000000000000000000000000000000000000000000b2n,
    0x00000000000000000000000000000000000000000000000000000000000000c3n,
  ];
  const xonly = privs.map(p => to32(getPublicKey(p)!.x)); // claves x-only (32B)
  const script = tapscriptMultisig(2, xonly);
  const message = new Uint8Array(32).fill(0x42); // "sighash" ficticio de 32 bytes

  const checkSig = (sig: Uint8Array, pub: Uint8Array): boolean => {
    if (sig.length !== 64) return false;
    const r = bytesToBigint(sig.slice(0, 32));
    const s = bytesToBigint(sig.slice(32, 64));
    return schnorrVerify(message, { r, s }, bytesToBigint(pub)).valid;
  };

  const sig = (i: number) => h(schnorrSign(message, privs[i]).signatureHex);

  // Firman A y B (no C). El witness aporta las firmas en orden inverso a las
  // claves (con firma vacía para C): pila bottom→top = [sigC(∅), sigB, sigA].
  const run = (items: Uint8Array[]) => {
    const parts: number[] = [];
    for (const it of items) { // se empujan de abajo a arriba
      if (it.length === 0) parts.push(0x00);      // OP_0 (firma vacía)
      else { parts.push(it.length, ...it); }
    }
    parts.push(...script);
    return executeScript(new Uint8Array(parts), checkSig);
  };

  const okAB = run([new Uint8Array(0), sig(1), sig(0)]);
  check('2-de-3: firman A y B → válido ✓', okAB.success, okAB.error);

  const okBC = run([sig(2), sig(1), new Uint8Array(0)]);
  check('2-de-3: firman B y C → válido ✓', okBC.success, okBC.error);

  const onlyA = run([new Uint8Array(0), new Uint8Array(0), sig(0)]);
  check('2-de-3: solo firma A → contador 1 ≠ 2 → inválido', !onlyA.success);
}

// ─── helper que necesita 'to32' definido arriba ──
function to32Hex(n: bigint): string {
  return n.toString(16).padStart(64, '0');
}

console.log(failures === 0 ? '\nTODO OK ✓' : `\n${failures} FALLO(S) ✗`);
if (failures > 0) process.exit(1);
