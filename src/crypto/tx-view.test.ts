/**
 * Test del visor de transacciones (tx-view.ts) contra transacciones REALES de
 * mainnet (tx-view.fixtures.ts). Lo esperado viene de mempool.space, una fuente
 * independiente: si nuestra fee, peso o direcciones cuadran con las suyas, el
 * parseo, la verificación de prevouts y la codificación de direcciones están bien.
 *
 * Sin framework: console.log + process.exit(1). Ejecutar bundleando:
 *   npx rolldown src/crypto/tx-view.test.ts --format esm -o /tmp/t.mjs && node /tmp/t.mjs
 */

import {
  buildTxView,
  parseTxStrict,
  resolvePrevouts,
  classifyScript,
  describeSequence,
  describeLocktime,
  isRoundAmount,
  formatBtc,
} from './tx-view';
import { TX_FIXTURES } from './tx-view.fixtures';
import { serializeWitness } from './transaction';

let failed = false;
function check(name: string, ok: boolean, detail = '') {
  console.log(`${ok ? '✓' : '✗'} ${name}${!ok && detail ? `\n    ${detail}` : ''}`);
  if (!ok) failed = true;
}

/** Nombres de tipo de mempool.space → los nuestros */
const MEMPOOL_TYPE: Record<string, string> = {
  p2pkh: 'p2pkh', p2sh: 'p2sh', v0_p2wpkh: 'p2wpkh', v0_p2wsh: 'p2wsh',
  v1_p2tr: 'p2tr', op_return: 'op_return', p2pk: 'p2pk',
};

// ─── 1) Las 6 transacciones reales ──────────────────────────
for (const f of TX_FIXTURES) {
  const v = buildTxView(f.hex, f.prevTxs, { blockHeight: f.blockHeight });
  const e = f.expected;
  const tag = `[${f.id}]`;
  check(`${tag} txid calculado = ${f.txid.slice(0, 12)}…`, v.txid === f.txid, v.txid);
  check(`${tag} size ${e.size} B y weight ${e.weight} WU`, v.size === e.size && v.weight === e.weight,
    `size ${v.size}, weight ${v.weight}`);
  check(`${tag} todos los prevouts verificados por hash`, v.inputs.every(i => i.status === 'verified'));
  check(`${tag} fee = ${e.fee} sats`, v.fee === BigInt(e.fee), `obtenido ${v.fee}`);
  check(`${tag} direcciones y tipos de entrada`,
    JSON.stringify(v.inputs.map(i => i.script?.address ?? null)) === JSON.stringify(e.inputAddresses)
    && v.inputs.every((i, k) => i.script?.type === MEMPOOL_TYPE[e.inputTypes[k]]),
    JSON.stringify(v.inputs.map(i => [i.script?.type, i.script?.address])));
  check(`${tag} direcciones y tipos de salida`,
    JSON.stringify(v.outputs.map(o => o.script.address)) === JSON.stringify(e.outputAddresses)
    && v.outputs.every((o, k) => o.script.type === MEMPOOL_TYPE[e.outputTypes[k]]),
    JSON.stringify(v.outputs.map(o => [o.script.type, o.script.address])));
}

// ─── 2) Detalles concretos de algunas ───────────────────────
const byId = (id: string) => {
  const f = TX_FIXTURES.find(x => x.id === id)!;
  return { f, v: buildTxView(f.hex, f.prevTxs, { blockHeight: f.blockHeight }) };
};

const segwit = byId('segwit').v;
check('[segwit] wtxid ≠ txid (el witness no entra en el txid)', segwit.segwit && segwit.wtxid !== segwit.txid);
check('[segwit] señala RBF (nSequence 0xfffffffd)', segwit.signalsRbf);
check('[segwit] locktime = anti fee-sniping', /anti fee-sniping/.test(segwit.locktimeInfo), segwit.locktimeInfo);
check('[segwit] vsize = ceil(weight/4) = 141', segwit.vsize === 141);
check('[segwit] firma ECDSA con SIGHASH_ALL', segwit.inputs[0].sighashes.join() === 'ALL');

const legacy = byId('legacy').v;
check('[legacy] sin witness: wtxid = txid y weight = 4·size', !legacy.segwit && legacy.wtxid === legacy.txid && legacy.weight === 4 * legacy.size);

const tr = byId('taproot').v;
check('[taproot] key-path con firma Schnorr DEFAULT (64 B)',
  /key-path/.test(tr.inputs[0].spend) && tr.inputs[0].sighashes.join() === 'DEFAULT', tr.inputs[0].spend);

const tr2 = byId('taproot2').v;
check('[taproot2] nSequence 0 en v2 = RBF, sin timelock relativo',
  tr2.inputs[0].signalsRbf && !/BIP68/.test(tr2.inputs[0].sequenceInfo), tr2.inputs[0].sequenceInfo);
check('[taproot2] la entrada con 3 elementos de witness es script-path',
  /script-path/.test(tr2.inputs[0].spend), tr2.inputs[0].spend);

const mixed = byId('mixed').v;
check('[mixed] entrada P2SH reconocida como SegWit anidado', /P2SH-P2W/.test(mixed.inputs[0].spend), mixed.inputs[0].spend);
check('[mixed] entrada P2WSH reconocida como multisig', /multisig/.test(mixed.inputs[1].spend), mixed.inputs[1].spend);

const opr = byId('opreturn').v;
const opOut = opr.outputs.find(o => o.script.type === 'op_return');
check('[opreturn] OP_RETURN sin dirección y con 0 sats', !!opOut && opOut.script.address === null && opOut.value === 0n);

// ─── 3) Verificación de prevouts: la parte de "no confíes" ──
const f0 = TX_FIXTURES[0];
const tx0 = parseTxStrict(f0.hex);
check('sin tx previa → missing, fee desconocida',
  resolvePrevouts(tx0, {})[0].status === 'missing' && buildTxView(f0.hex, {}).fee === null);

// Inflamos 1 sat el importe en la tx previa: su hash ya no es el txid del outpoint
const prevId = tx0.inputs[0].prevTxId;
const prev = parseTxStrict(f0.prevTxs[prevId]);
prev.outputs[tx0.inputs[0].prevVout].value += 1n;
check('importe de la tx previa inflado 1 sat → mismatch (no se acepta)',
  resolvePrevouts(tx0, { [prevId]: serializeWitness(prev).hex })[0].status === 'mismatch');

// En cambio, tocar el WITNESS de la tx previa no cambia su txid (BIP141): el
// importe sigue verificado, porque el importe no vive en el witness.
const prevW = parseTxStrict(f0.prevTxs[prevId]);
prevW.witnesses![0][0] = new Uint8Array(prevW.witnesses![0][0]).map((b, k) => (k === 10 ? b ^ 1 : b));
check('witness de la tx previa alterado → sigue verified (el witness no entra en el txid)',
  resolvePrevouts(tx0, { [prevId]: serializeWitness(prevW).hex })[0].status === 'verified');

// ─── 4) Parseo estricto ─────────────────────────────────────
const rejects = (hex: string) => { try { parseTxStrict(hex); return false; } catch { return true; } };
check('rechaza hex truncado', rejects(f0.hex.slice(0, -10)));
check('rechaza basura no-hex', rejects('hola mundo'));
check('rechaza bytes de más al final', rejects(f0.hex + '00'));

// ─── 5) Piezas sueltas ──────────────────────────────────────
check('classifyScript P2PKH testnet → m/n…',
  /^[mn]/.test(classifyScript(new Uint8Array([0x76, 0xa9, 0x14, ...new Uint8Array(20), 0x88, 0xac]), false).address ?? ''));
check('BIP68: 0x00400002 en v2 = 1024 s', /1024 s/.test(describeSequence(0x00400002, 2).info));
check('BIP68 no aplica en version 1', !/BIP68/.test(describeSequence(10, 1).info));
check('nLockTime ignorado si todos los inputs son final', /ignorado/.test(describeLocktime(800000, true)));
check('isRoundAmount', isRoundAmount(1_000_000n) && !isRoundAmount(1_234_567n));
check('formatBtc', formatBtc(123_456_789n) === '1.23456789' && formatBtc(-5n) === '-0.00000005');

console.log(failed ? '\nRESULTADO: FALLOS ✗' : '\nRESULTADO: TODO OK ✓');
if (failed) process.exit(1);
