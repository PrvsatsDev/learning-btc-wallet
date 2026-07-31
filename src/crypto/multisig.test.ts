/**
 * Smoke test del paso 1 de multisig: createMultisig / createP2WSH y la ejecución
 * de OP_CHECKMULTISIG en el intérprete, incluido el famoso bug del elemento dummy.
 *
 * No usa framework: console.log + process.exit(1) si algo falla, igual que
 * sighash.test.ts. Ejecutar bundleando con esbuild (ver comentario al final).
 */

import {
  createMultisig,
  createP2WSH,
  addressP2WSH,
  executeScript,
  disassemble,
  bech32Decode,
  OP,
} from './script';

let failed = false;
function check(name: string, cond: boolean) {
  console.log(`${cond ? '✓' : '✗'} ${name}`);
  if (!cond) failed = true;
}

// ─── Datos de prueba ────────────────────────────────────────
// 3 claves "comprimidas" ficticias (prefijo 0x02, distinguidas por el 2º byte).
function fakePubKey(id: number): Uint8Array {
  const pk = new Uint8Array(33);
  pk[0] = 0x02;
  pk[1] = id;
  return pk;
}
// Firma ficticia de 72 bytes cuyo primer byte identifica a qué clave pertenece.
function fakeSig(keyId: number): Uint8Array {
  const sig = new Uint8Array(72);
  sig[0] = keyId;
  return sig;
}
// checkSigFn didáctico: una firma es válida para la clave cuyo id coincide.
const checkSig = (sig: Uint8Array, pk: Uint8Array) => sig[0] === pk[1];

const pk1 = fakePubKey(1);
const pk2 = fakePubKey(2);
const pk3 = fakePubKey(3);

// ─── 1) createMultisig: estructura de bytes ─────────────────
const redeem = createMultisig(2, [pk1, pk2, pk3]);
check('createMultisig empieza por OP_2 (0x52)', redeem[0] === 0x52);
check('createMultisig termina en OP_3 OP_CHECKMULTISIG',
  redeem[redeem.length - 2] === 0x53 && redeem[redeem.length - 1] === OP.OP_CHECKMULTISIG);
// 1 (OP_m) + 3*(1+33) + 1 (OP_n) + 1 (OP_CHECKMULTISIG) = 105 bytes
check('createMultisig longitud 2-of-3 = 105 bytes', redeem.length === 105);
const dis = disassemble(redeem);
check('disassemble muestra OP_2 ... OP_3 OP_CHECKMULTISIG',
  dis[0] === 'OP_2' && dis[dis.length - 2] === 'OP_3' && dis[dis.length - 1] === 'OP_CHECKMULTISIG');

// ─── 2) createP2WSH + dirección ─────────────────────────────
const spk = createP2WSH(redeem);
check('createP2WSH = OP_0 0x20 <32 bytes>', spk[0] === OP.OP_0 && spk[1] === 0x20 && spk.length === 34);
const addr = addressP2WSH(redeem, true);
check('addressP2WSH es bech32 mainnet (bc1q…)', addr.startsWith('bc1q'));
const decoded = bech32Decode(addr);
check('addressP2WSH round-trip: versión 0, programa de 32 bytes',
  decoded !== null && decoded.version === 0 && decoded.program.length === 32);

// ─── 3) Gasto correcto 2-of-3 (con el dummy) ────────────────
function pushData(bytes: Uint8Array): number[] {
  return [bytes.length, ...bytes];
}
// witness/scriptSig didáctico: <dummy=OP_0> <sig1> <sig2>  ++  witnessScript
const spendOk = new Uint8Array([
  OP.OP_0,                    // el elemento dummy que exige el bug
  ...pushData(fakeSig(1)),
  ...pushData(fakeSig(2)),
  ...redeem,
]);
const resOk = executeScript(spendOk, checkSig);
check('2-of-3 con firmas correctas y dummy → success', resOk.success === true);

// ─── 4) Firmas en orden equivocado → falla ──────────────────
const spendBadOrder = new Uint8Array([
  OP.OP_0,
  ...pushData(fakeSig(2)),   // orden invertido respecto a las claves
  ...pushData(fakeSig(1)),
  ...redeem,
]);
const resBad = executeScript(spendBadOrder, checkSig);
check('firmas en orden incorrecto → NO success', resBad.success === false);

// ─── 5) El bug del dummy: sin OP_0 se subdesborda la pila ────
const spendNoDummy = new Uint8Array([
  ...pushData(fakeSig(1)),
  ...pushData(fakeSig(2)),
  ...redeem,
]);
const resNoDummy = executeScript(spendNoDummy, checkSig);
check('sin el dummy → falla con error de dummy',
  resNoDummy.success === false && /dummy/i.test(resNoDummy.error ?? ''));

// ─── 6) Firma insuficiente (solo 1 de 2) → falla ────────────
// Aportamos una sola firma pero el script exige 2 → faltan firmas en la pila.
const spendUnderSigned = new Uint8Array([
  OP.OP_0,
  ...pushData(fakeSig(1)),
  ...redeem,
]);
const resUnder = executeScript(spendUnderSigned, checkSig);
check('firmas insuficientes → NO success', resUnder.success === false);

console.log(failed ? '\nRESULTADO: FALLOS ✗' : '\nRESULTADO: TODO OK ✓');
if (failed) process.exit(1);
