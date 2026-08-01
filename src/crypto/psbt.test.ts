/**
 * Test del ciclo COMPLETO de una PSBT sobre un multisig 2-de-3 P2WSH:
 *
 *   Creator → Updater → 2×Signer (dispositivos separados) → Combiner
 *          → Finalizer → Extractor
 *
 * Y la prueba de fuego: el witness que monta el finalizer se ejecuta con NUESTRO
 * propio intérprete de Bitcoin Script (executeScript), verificando de verdad las
 * firmas ECDSA contra el sighash BIP143. Si el script devuelve true, el UTXO se
 * gastaría en la red real.
 *
 * También comprueba el round-trip Base64 (el formato en que viaja una PSBT).
 */

import {
  createPsbt,
  updateInputWitnessUtxo, updateInputWitnessScript,
  signInput, getPartialSigs,
  clonePsbt, combine,
  finalizeInput, extractTransaction,
  psbtToBase64, psbtFromBase64, serializePsbt,
  summarizePsbt, hexToBytes, bytesToHex,
} from './psbt';
import type { Transaction } from './transaction';
import { getPublicKey, compressPublicKey, decompressPublicKey } from './secp256k1';
import { sortPubKeysBIP67 } from './descriptor';
import { createMultisig, createP2WSH, createP2WPKH, executeScript, OP } from './script';
import { computeSighashP2WSH } from './sighash';
import { derDecode, ecdsaVerify } from './ecdsa';
import { sha256 } from './sha256';

let failures = 0;
function check(name: string, cond: boolean) {
  console.log(`${cond ? 'OK  ' : 'FAIL'} ${name}`);
  if (!cond) failures++;
}

// ─── Montaje del multisig 2-de-3 ────────────────────────────

const privs = [
  0x1111111111111111111111111111111111111111111111111111111111111111n,
  0x2222222222222222222222222222222222222222222222222222222222222222n,
  0x3333333333333333333333333333333333333333333333333333333333333333n,
];
const pubs = privs.map(p => hexToBytes(compressPublicKey(getPublicKey(p))));

// sortedmulti (BIP67): el witnessScript usa las claves ordenadas
const sortedPubs = sortPubKeysBIP67(pubs);
const witnessScript = createMultisig(2, sortedPubs);       // OP_2 <pk><pk><pk> OP_3 OP_CHECKMULTISIG
const scriptPubKey = createP2WSH(witnessScript);            // OP_0 0x20 <sha256(witnessScript)>

// ─── Creator: tx sin firmar que gasta el UTXO P2WSH ─────────

const amount = 100_000n;
const destSpk = createP2WPKH(hexToBytes('751e76e8199196d454941c45d1b3a323f1433bd6'));
const unsigned: Transaction = {
  version: 2,
  inputs: [{
    prevTxId: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
    prevVout: 0,
    scriptSig: new Uint8Array(0),
    sequence: 0xffffffff,
  }],
  outputs: [{ value: 90_000n, scriptPubKey: destSpk }], // 10.000 sats de fee
  locktime: 0,
};

const base = createPsbt(unsigned);

// Updater: información imprescindible para firmar
updateInputWitnessUtxo(base, 0, { value: amount, scriptPubKey });
updateInputWitnessScript(base, 0, witnessScript);

// ─── Round-trip Base64 ──────────────────────────────────────

const b64 = psbtToBase64(base);
const restored = psbtFromBase64(b64);
check('base64 round-trip idéntico',
  bytesToHex(serializePsbt(base)) === bytesToHex(serializePsbt(restored)));
check('la tx sin firmar sobrevive al round-trip',
  bytesToHex(serializePsbt(getUnsignedTxAsPsbtGlobalOnly(base)))
    === bytesToHex(serializePsbt(getUnsignedTxAsPsbtGlobalOnly(restored))));

function getUnsignedTxAsPsbtGlobalOnly(p: ReturnType<typeof createPsbt>) {
  return { global: p.global, inputs: [], outputs: [] };
}

// ─── 2 × Signer, en dispositivos separados ──────────────────
// Cada cosignatario recibe una COPIA y solo añade su firma parcial.

const deviceA = clonePsbt(base);
const resA = signInput(deviceA, 0, privs[0]);   // cosignatario A
check('A produce 1 firma parcial', getPartialSigs(deviceA.inputs[0]).length === 1);

const deviceC = clonePsbt(base);
const resC = signInput(deviceC, 0, privs[2]);   // cosignatario C
check('C produce 1 firma parcial', getPartialSigs(deviceC.inputs[0]).length === 1);

check('A y C firman el MISMO sighash', bytesToHex(resA.sighash) === bytesToHex(resC.sighash));

// ─── Combiner: unión de las dos PSBTs ───────────────────────

const combined = combine(deviceA, deviceC);
check('combinada tiene 2 firmas parciales', getPartialSigs(combined.inputs[0]).length === 2);

const summaryBefore = summarizePsbt(combined);
check('resumen: input con UTXO + witnessScript + 2 sigs, sin finalizar',
  summaryBefore.inputs[0].hasWitnessUtxo &&
  summaryBefore.inputs[0].hasWitnessScript &&
  summaryBefore.inputs[0].partialSigs === 2 &&
  !summaryBefore.inputs[0].finalized);

// ─── Finalizer ──────────────────────────────────────────────

const fin = finalizeInput(combined, 0);
check('witness montado: [dummy, sig, sig, witnessScript] (4 items)', fin.witnessStack.length === 4);
check('primer item del witness es el dummy vacío', fin.witnessStack[0].length === 0);
check('último item del witness es el witnessScript',
  bytesToHex(fin.witnessStack[fin.witnessStack.length - 1]) === bytesToHex(witnessScript));
check('input queda finalizado', summarizePsbt(combined).inputs[0].finalized);

// ─── Extractor ──────────────────────────────────────────────

const { hex, txid } = extractTransaction(combined);
check('tx extraída no vacía', hex.length > 0);
check('txid tiene 32 bytes', txid.length === 64);
console.log('  txid:', txid);
console.log('  raw :', hex.slice(0, 80) + '…');

// ─── Prueba de fuego: ¿el witness desbloquea el UTXO? ───────
// 1) El witnessScript debe hashear al programa de la dirección P2WSH.
const program = scriptPubKey.slice(2); // OP_0 0x20 <32B>
check('sha256(witnessScript) == programa P2WSH',
  sha256(witnessScript).hash === bytesToHex(program));

// 2) Ejecutar el script con verificación real de firmas contra el sighash.
const sighash = computeSighashP2WSH(unsigned, 0, witnessScript, amount).sighash;

function checkSig(sig: Uint8Array, pubKey: Uint8Array): boolean {
  const der = sig.slice(0, sig.length - 1); // quita el byte de sighash type
  const { r, s } = derDecode(der);
  const pub = decompressPublicKey(bytesToHex(pubKey));
  return ecdsaVerify(sighash, { r, s }, pub).valid;
}

// Reconstruye el script a ejecutar: witness items (como pushes) + witnessScript.
const stack = fin.witnessStack;
const scriptParts: number[] = [];
for (const item of stack.slice(0, -1)) { // todos menos el witnessScript
  if (item.length === 0) scriptParts.push(OP.OP_0);
  else { scriptParts.push(item.length); scriptParts.push(...item); }
}
scriptParts.push(...witnessScript); // el witnessScript se ejecuta como código
const fullScript = new Uint8Array(scriptParts);

const result = executeScript(fullScript, checkSig);
check('el intérprete de Script valida el gasto (2-de-3) ✓', result.success);
if (!result.success) console.log('  error script:', result.error);

// ─── Firma insuficiente debe fallar ─────────────────────────

const onlyOne = clonePsbt(base);
signInput(onlyOne, 0, privs[1]);
let finalizeFailed = false;
try { finalizeInput(onlyOne, 0); } catch { finalizeFailed = true; }
check('finalizar con 1 sola firma (de 2 necesarias) lanza error', finalizeFailed);

// ─── Veredicto ──────────────────────────────────────────────

console.log(failures === 0 ? '\nTODO OK ✓' : `\n${failures} FALLO(S) ✗`);
if (failures > 0) process.exit(1);
