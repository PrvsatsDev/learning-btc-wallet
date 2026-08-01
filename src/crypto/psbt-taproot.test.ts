/**
 * Test del flujo PSBT Taproot key-path (BIP371), end-to-end con 2 inputs:
 *   - input 0: Taproot key-path puro (sin árbol de scripts).
 *   - input 1: la salida compromete un árbol, pero se gasta por key-path
 *     (el firmante ajusta su clave con la merkle root).
 *
 * Comprueba: Creator → Updater (WITNESS_UTXO de ambos + TAP_INTERNAL_KEY +
 * TAP_MERKLE_ROOT) → Signer key-path (usa el UTXO de TODOS los inputs) →
 * round-trip Base64 con campos Taproot → Finalizer → Extractor. Y verifica las
 * firmas Schnorr contra las output keys ajustadas.
 */

import {
  createPsbt, updateInputWitnessUtxo,
  updateInputTapInternalKey, updateInputTapMerkleRoot,
  signTaprootKeyPathInput, finalizeTaprootKeyPathInput,
  extractTransaction, getTapKeySig,
  psbtToBase64, psbtFromBase64, serializePsbt,
  hexToBytes, bytesToHex,
} from './psbt';
import type { Transaction, TxOutput } from './transaction';
import { parseTxHex } from './transaction';
import { tweakPublicKey, p2trScriptPubKey } from './taproot';
import { computeTaptree, tapscriptMultisig } from './tapscript';
import { computeSighashTaproot } from './sighash-taproot';
import { schnorrVerify } from './schnorr';
import { getPublicKey } from './secp256k1';
import { bytesToBigint } from './hmac';

let failures = 0;
function check(name: string, cond: boolean) {
  console.log(`${cond ? 'OK  ' : 'FAIL'} ${name}`);
  if (!cond) failures++;
}
function to32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = n;
  for (let i = 31; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}

// ─── Claves y salidas Taproot ───────────────────────────────

const priv0 = 0x00000000000000000000000000000000000000000000000000000000000000a7n;
const priv1 = 0x00000000000000000000000000000000000000000000000000000000000000f3n;
const internal0 = getPublicKey(priv0)!.x;
const internal1 = getPublicKey(priv1)!.x;

// input 0: key-path puro
const spk0 = p2trScriptPubKey(internal0);
const outKey0 = tweakPublicKey(internal0).outputKey;

// input 1: compromete un árbol (2-de-2 tapscript ficticio), pero se gasta key-path
const dummyKeys = [priv0, priv1].map(p => to32(getPublicKey(p)!.x));
const tree = { script: tapscriptMultisig(2, dummyKeys) };
const merkleRoot = computeTaptree(tree).merkleRoot;
const spk1 = p2trScriptPubKey(internal1, merkleRoot);
const outKey1 = tweakPublicKey(internal1, merkleRoot).outputKey;

const amount0 = 150_000n;
const amount1 = 250_000n;
const prevouts: TxOutput[] = [
  { value: amount0, scriptPubKey: spk0 },
  { value: amount1, scriptPubKey: spk1 },
];

// ─── Creator + Updater ──────────────────────────────────────

const unsigned: Transaction = {
  version: 2,
  inputs: [
    { prevTxId: '11'.repeat(32), prevVout: 0, scriptSig: new Uint8Array(0), sequence: 0xffffffff },
    { prevTxId: '22'.repeat(32), prevVout: 1, scriptSig: new Uint8Array(0), sequence: 0xffffffff },
  ],
  outputs: [{ value: 380_000n, scriptPubKey: hexToBytes('0014751e76e8199196d454941c45d1b3a323f1433bd6') }],
  locktime: 0,
};

const psbt = createPsbt(unsigned);
updateInputWitnessUtxo(psbt, 0, prevouts[0]);
updateInputTapInternalKey(psbt, 0, to32(internal0));
updateInputWitnessUtxo(psbt, 1, prevouts[1]);
updateInputTapInternalKey(psbt, 1, to32(internal1));
updateInputTapMerkleRoot(psbt, 1, merkleRoot);

// ─── Signer key-path (ambos inputs) ─────────────────────────

const s0 = signTaprootKeyPathInput(psbt, 0, priv0);
const s1 = signTaprootKeyPathInput(psbt, 1, priv1);
check('firma key-path input 0 = 64 bytes (SIGHASH_DEFAULT)', s0.signature.length === 64);
check('firma key-path input 1 = 64 bytes', s1.signature.length === 64);
check('TAP_KEY_SIG guardado en ambos inputs',
  getTapKeySig(psbt.inputs[0]) !== undefined && getTapKeySig(psbt.inputs[1]) !== undefined);

// El sighash debe coincidir con el cálculo independiente (compromete AMBOS UTXOs).
check('sighash input 0 reproducible',
  bytesToHex(s0.sigHash) === bytesToHex(computeSighashTaproot(unsigned, 0, prevouts, {}).sigHash));
check('sighash input 1 reproducible',
  bytesToHex(s1.sigHash) === bytesToHex(computeSighashTaproot(unsigned, 1, prevouts, {}).sigHash));

// ─── Round-trip Base64 con campos Taproot ───────────────────

const restored = psbtFromBase64(psbtToBase64(psbt));
check('round-trip Base64 preserva los campos Taproot',
  bytesToHex(serializePsbt(psbt)) === bytesToHex(serializePsbt(restored)));

// ─── Finalizer + Extractor ──────────────────────────────────

const f0 = finalizeTaprootKeyPathInput(psbt, 0);
const f1 = finalizeTaprootKeyPathInput(psbt, 1);
check('witness key-path = 1 solo elemento (la firma)',
  f0.witnessStack.length === 1 && f1.witnessStack.length === 1);

const { tx, hex, txid } = extractTransaction(psbt);
check('tx extraída con witness en ambos inputs',
  tx.witnesses !== undefined && tx.witnesses[0].length === 1 && tx.witnesses[1].length === 1);
check('la tx re-parsea igual (round-trip de serialización)',
  parseTxHex(hex).witnesses![0][0].length === 64);
console.log('  txid:', txid);

// ─── Verificación Schnorr contra las output keys ────────────

function verifyInput(i: number, outputKey: bigint): boolean {
  const sig = tx.witnesses![i][0];              // 64 bytes
  const r = bytesToBigint(sig.slice(0, 32));
  const s = bytesToBigint(sig.slice(32, 64));
  const sighash = computeSighashTaproot(unsigned, i, prevouts, {}).sigHash;
  return schnorrVerify(sighash, { r, s }, outputKey).valid;
}
check('firma input 0 verifica contra la output key (key-path puro) ✓', verifyInput(0, outKey0));
check('firma input 1 verifica contra la output key (con merkle root) ✓', verifyInput(1, outKey1));

// ─── hashType ≠ DEFAULT produce firma de 65 bytes ───────────

const psbt2 = createPsbt(unsigned);
updateInputWitnessUtxo(psbt2, 0, prevouts[0]);
updateInputTapInternalKey(psbt2, 0, to32(internal0));
updateInputWitnessUtxo(psbt2, 1, prevouts[1]);
updateInputTapInternalKey(psbt2, 1, to32(internal1));
updateInputTapMerkleRoot(psbt2, 1, merkleRoot);
const sAll = signTaprootKeyPathInput(psbt2, 0, priv0, 0x01); // SIGHASH_ALL explícito
check('hashType ≠ DEFAULT → firma de 65 bytes con el tipo al final',
  sAll.signature.length === 65 && sAll.signature[64] === 0x01);

console.log(failures === 0 ? '\nTODO OK ✓' : `\n${failures} FALLO(S) ✗`);
if (failures > 0) process.exit(1);
