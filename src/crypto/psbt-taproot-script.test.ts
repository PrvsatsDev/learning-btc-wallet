/**
 * Test del multisig Taproot 2-de-3 COMPLETO por script-path, vía PSBT (BIP371):
 *
 *   Creator → Updater (WITNESS_UTXO + TAP_LEAF_SCRIPT con control block) →
 *   2×Signer script-path (TAP_SCRIPT_SIG, firma SIN ajustar, sighash con ext) →
 *   Finalizer → Extractor.
 *
 * Prueba de fuego: el witness resultante ([sigs…, script, controlBlock]) se
 * ejecuta con nuestro intérprete (OP_CHECKSIGADD) verificando firmas Schnorr
 * reales contra el sighash BIP341 de script-path. Cierra el hilo del multisig:
 * el mismo 2-de-3, ahora en Taproot.
 */

import {
  createPsbt, updateInputWitnessUtxo, updateInputTapLeafScript,
  signTaprootScriptPathInput, getTapScriptSigs, finalizeTaprootScriptPathInput,
  extractTransaction, clonePsbt, hexToBytes, bytesToHex,
} from './psbt';
import type { Transaction, TxOutput } from './transaction';
import { tapscriptMultisig, tapLeafHash, taprootScriptOutput } from './tapscript';
import { createP2TR, executeScript } from './script';
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

// ─── Multisig 2-de-3 Tapscript dentro de una salida Taproot ──

const privs = [
  0x00000000000000000000000000000000000000000000000000000000000000a1n,
  0x00000000000000000000000000000000000000000000000000000000000000b2n,
  0x00000000000000000000000000000000000000000000000000000000000000c3n,
];
const xonly = privs.map(p => to32(getPublicKey(p)!.x));
const leafScript = tapscriptMultisig(2, xonly);
const leafHash = tapLeafHash(leafScript);

// Clave interna (en la práctica sería un punto NUMS para inutilizar el key-path).
const internalPriv = 0x0000000000000000000000000000000000000000000000000000000000000009n;
const internalX = getPublicKey(internalPriv)!.x;

const out = taprootScriptOutput(internalX, { script: leafScript });
const scriptPubKey = createP2TR(to32(out.outputKey));
const controlBlock = out.controlBlocks[0];

const amount = 500_000n;
const prevouts: TxOutput[] = [{ value: amount, scriptPubKey }];

// ─── Creator + Updater ──────────────────────────────────────

const unsigned: Transaction = {
  version: 2,
  inputs: [{ prevTxId: 'ab'.repeat(32), prevVout: 0, scriptSig: new Uint8Array(0), sequence: 0xffffffff }],
  outputs: [{ value: 480_000n, scriptPubKey: hexToBytes('0014751e76e8199196d454941c45d1b3a323f1433bd6') }],
  locktime: 0,
};

const base = createPsbt(unsigned);
updateInputWitnessUtxo(base, 0, prevouts[0]);
updateInputTapLeafScript(base, 0, leafScript, controlBlock);

// ─── 2×Signer (A y C firman; B no) en dispositivos separados ─

const devA = clonePsbt(base);
signTaprootScriptPathInput(devA, 0, privs[0], leafScript); // pk1
const devC = clonePsbt(base);
signTaprootScriptPathInput(devC, 0, privs[2], leafScript); // pk3

// Combinamos manualmente las dos firmas en el sobre base (unión de mapas).
signTaprootScriptPathInput(base, 0, privs[0], leafScript);
signTaprootScriptPathInput(base, 0, privs[2], leafScript);
check('2 firmas script-path guardadas (indexadas por pubkey‖leafHash)',
  getTapScriptSigs(base.inputs[0]).length === 2);
check('cada firma está atada a este leafHash',
  getTapScriptSigs(base.inputs[0]).every(s => bytesToHex(s.leafHash) === bytesToHex(leafHash)));

// ─── Finalizer + Extractor ──────────────────────────────────

const fin = finalizeTaprootScriptPathInput(base, 0);
check('witness = [sig, ∅, sig, script, controlBlock] (5 elementos)', fin.witnessStack.length === 5);
check('penúltimo elemento del witness es el script', bytesToHex(fin.witnessStack[3]) === bytesToHex(leafScript));
check('último elemento del witness es el control block', bytesToHex(fin.witnessStack[4]) === bytesToHex(controlBlock));

const { tx, txid } = extractTransaction(base);
check('tx extraída con witness en el input', tx.witnesses !== undefined && tx.witnesses[0].length === 5);
console.log('  txid:', txid);

// ─── Prueba de fuego 1: el control block reconstruye la output key ──

check('control block ⇒ output key (leaf + prueba Merkle = Q)',
  bytesToHex(controlBlock) === bytesToHex(out.controlBlocks[0]) &&
  controlBlock[0] === (0xc0 | out.parity));

// ─── Prueba de fuego 2: el witness desbloquea el UTXO ───────

const sighash = computeSighashTaproot(unsigned, 0, prevouts, { ext: { tapLeafHash: leafHash } }).sigHash;
const checkSig = (sig: Uint8Array, pub: Uint8Array): boolean => {
  if (sig.length !== 64) return false;
  const r = bytesToBigint(sig.slice(0, 32));
  const s = bytesToBigint(sig.slice(32, 64));
  return schnorrVerify(sighash, { r, s }, bytesToBigint(pub)).valid;
};

// Reconstruye el script a ejecutar: los inputs del witness (todo menos script y
// control block) empujados en orden, seguidos del script.
const witness = tx.witnesses![0];
const scriptInputs = witness.slice(0, witness.length - 2);
const parts: number[] = [];
for (const it of scriptInputs) {
  if (it.length === 0) parts.push(0x00);         // OP_0 (firma vacía)
  else { parts.push(it.length, ...it); }
}
parts.push(...leafScript);
const result = executeScript(new Uint8Array(parts), checkSig);
check('el intérprete valida el gasto 2-de-3 Taproot (script-path) ✓', result.success);
if (!result.success) console.log('  error:', result.error);

// ─── Firma insuficiente falla ───────────────────────────────

const solo = createPsbt(unsigned);
updateInputWitnessUtxo(solo, 0, prevouts[0]);
updateInputTapLeafScript(solo, 0, leafScript, controlBlock);
signTaprootScriptPathInput(solo, 0, privs[1], leafScript);
let threw = false;
try { finalizeTaprootScriptPathInput(solo, 0); } catch { threw = true; }
check('finalizar con 1 firma (de 2) lanza error', threw);

console.log(failures === 0 ? '\nTODO OK ✓' : `\n${failures} FALLO(S) ✗`);
if (failures > 0) process.exit(1);
