/**
 * Test de la timeline de UTXOs contra historiales REALES de mainnet
 * (utxoTimeline.fixtures.ts). La referencia independiente es el propio
 * servidor: su lista de UTXOs y sus estadísticas (funded/spent) se calculan
 * aparte de la lista de tx que usamos nosotros, así que si coinciden con
 * nuestra reconstrucción, la reconstrucción está bien.
 *
 * Sin framework: console.log + process.exit(1). Ejecutar bundleando:
 *   npx rolldown src/api/utxoTimeline.test.ts --format esm -o /tmp/t.mjs && node /tmp/t.mjs
 */

import {
  buildTimeline,
  checkAgainstServer,
  sortChronologically,
  networkOfAddress,
  type TimelineTx,
  type Coin,
} from './utxoTimeline';
import { TIMELINE_FIXTURES } from './utxoTimeline.fixtures';

let failed = false;
function check(name: string, ok: boolean, detail = '') {
  console.log(`${ok ? '✓' : '✗'} ${name}${!ok && detail ? `\n    ${detail}` : ''}`);
  if (!ok) failed = true;
}

/** ¿Está viva la moneda justo después de la tx número `order`? */
const aliveAfter = (c: Coin, order: number) =>
  (c.born?.order ?? -1) <= order && (c.spent?.at.order ?? Infinity) > order;

// ─── 1) Las direcciones reales ──────────────────────────────
for (const f of TIMELINE_FIXTURES) {
  const tl = buildTimeline(f.address, f.txs);
  const s = f.info.chain_stats, m = f.info.mempool_stats;
  const tag = `[${f.id}]`;
  const srv = checkAgainstServer(tl, f.utxos, f.info);

  check(`${tag} nº de tx = tx_count del servidor (${s.tx_count + m.tx_count})`, tl.events.length === s.tx_count + m.tx_count);
  check(`${tag} monedas nacidas = funded_txo_count (${s.funded_txo_count})`, tl.coins.length === s.funded_txo_count + m.funded_txo_count);
  check(`${tag} monedas muertas = spent_txo_count (${s.spent_txo_count})`,
    tl.coins.filter(c => c.spent).length === s.spent_txo_count + m.spent_txo_count);
  check(`${tag} UTXOs vivos = /utxo del servidor (${f.utxos.length})`, srv.utxosMatch, JSON.stringify({ missing: srv.missing, extra: srv.extra }));
  check(`${tag} saldo = funded − spent del servidor`, srv.balanceMatch, `${tl.balance} vs ${srv.serverBalance}`);
  check(`${tag} historial completo: ningún gasto huérfano`, tl.orphanSpends === 0);

  // El saldo corrido de cada evento = Σ monedas vivas en ese instante
  const runningOk = tl.events.every(e =>
    e.balanceAfter === tl.coins.filter(c => aliveAfter(c, e.at.order)).reduce((a, c) => a + c.value, 0));
  check(`${tag} saldo tras cada tx = Σ monedas vivas en ese momento`, runningOk);
  check(`${tag} el saldo nunca es negativo`, tl.events.every(e => e.balanceAfter >= 0));

  // Orden cronológico: alturas no decrecientes y cada gasto después del nacimiento
  check(`${tag} eventos en orden de bloque`, tl.events.every((e, i) => i === 0 || (e.at.height ?? Infinity) >= (tl.events[i - 1].at.height ?? Infinity)));
  check(`${tag} toda moneda muere después de nacer`, tl.coins.every(c => !c.spent || !c.born || c.spent.at.order > c.born.order));

  // Carriles: nunca dos monedas solapadas en el mismo, y hacen falta tantos
  // como el máximo de monedas vivas a la vez
  const overlap = tl.coins.some(a => tl.coins.some(b => a !== b && a.lane === b.lane
    && (a.born?.order ?? -1) < (b.spent?.at.order ?? Infinity) && (b.born?.order ?? -1) < (a.spent?.at.order ?? Infinity)));
  const maxAlive = Math.max(0, ...tl.events.map(e => tl.coins.filter(c => aliveAfter(c, e.at.order)).length));
  check(`${tag} carriles sin solapes y nº de carriles = máx. vivas a la vez (${maxAlive})`, !overlap && tl.lanes === maxAlive, `lanes ${tl.lanes}`);
}

// ─── 2) Rasgos concretos de cada dirección ──────────────────
const byId = (id: string) => {
  const f = TIMELINE_FIXTURES.find(x => x.id === id)!;
  return { f, tl: buildTimeline(f.address, f.txs) };
};

const acc = byId('acumula').tl;
check('[acumula] reutilizada: recibió en 13 tx distintas', acc.fundingTxs === 13);
check('[acumula] su único gasto devolvió el cambio a la misma dirección', acc.events.filter(e => e.consumed.length).every(e => e.changeBack));

const many = byId('muchas').tl;
check('[muchas] hay tx que gastan varias monedas juntas (consolidación)', many.events.some(e => e.consumed.length > 1));

// ─── 3) Casos sintéticos ────────────────────────────────────
const A = 'bc1qtestaddress';
const tx = (txid: string, height: number | null, vin: TimelineTx['vin'], vout: TimelineTx['vout']): TimelineTx => ({
  txid,
  status: height === null ? { confirmed: false } : { confirmed: true, block_height: height, block_time: 1_700_000_000 + height * 600 },
  vin, vout,
});
const pay = (value: number, to = A) => ({ scriptpubkey_address: to, scriptpubkey_type: 'v0_p2wpkh', value });
const spend = (txid: string, vout: number, value: number, from = A) => ({ txid, vout, prevout: { scriptpubkey_address: from, value } });

// Madre e hija en el MISMO bloque, y el API las da en el orden "malo"
const mother = tx('aa', 100, [spend('ff', 0, 5000, 'otra')], [pay(4000)]);
const child = tx('bb', 100, [spend('aa', 0, 4000)], [pay(3000, 'otra'), pay(800)]);
const sorted = sortChronologically([mother, child]);   // API: nuevas primero → aquí la hija iría antes
check('mismo bloque: la madre se ordena antes que la hija', sorted[0].txid === 'aa' && sorted[1].txid === 'bb', sorted.map(t => t.txid).join());
const same = buildTimeline(A, [mother, child]);
check('mismo bloque: saldo final 800 y sin huérfanas', same.balance === 800 && same.orphanSpends === 0);
check('cambio a la misma dirección detectado', same.events[1].changeBack);
check('entrada de otra dirección contada como ajena', same.events[0].foreignInputs === 0 && buildTimeline(A, [
  tx('cc', 1, [spend('x', 0, 1000), spend('y', 0, 2000, 'otra')], [pay(2900, 'otra')]),
]).events[0].foreignInputs === 1);

// Mempool: va al final y no cuenta como confirmado
const unconf = tx('dd', null, [spend('bb', 1, 800)], [pay(700, 'otra')]);
const mp = buildTimeline(A, [unconf, child, mother]);
check('tx en mempool ordenada al final', mp.events[2].tx.txid === 'dd' && mp.events[2].at.height === null);
check('gasto en mempool: saldo 0, la moneda ya no está viva', mp.balance === 0 && mp.live.length === 0);
const mpIn = buildTimeline(A, [tx('ee', null, [spend('zz', 0, 9000, 'otra')], [pay(1234)])]);
check('recibo en mempool: cuenta en saldo pero no en confirmado', mpIn.balance === 1234 && mpIn.confirmedBalance === 0);

// Historial truncado: falta la tx que creó la moneda
const trunc = buildTimeline(A, [child]);
check('historial truncado → gasto huérfano, moneda sin nacimiento', trunc.orphanSpends === 1 && trunc.coins.some(c => c.born === null && c.spent));
check('historial truncado: el saldo vivo sigue siendo correcto', trunc.balance === 800);

// Polvo y coinbase
const cb = buildTimeline(A, [tx('cb', 5, [{ txid: '00'.repeat(32), vout: 0xffffffff, prevout: null }], [pay(312_500_000), pay(546)])]);
check('coinbase reconocida', cb.events[0].coinbase);
check('546 sats marcado como polvo', cb.coins.find(c => c.value === 546)!.dust && !cb.coins.find(c => c.value === 312_500_000)!.dust);

// tx duplicada (p. ej. al solapar páginas) no se cuenta dos veces
check('tx duplicadas se ignoran', buildTimeline(A, [mother, mother, child]).events.length === 2);

check('red por prefijo', networkOfAddress('bc1qxyz') === 'mainnet' && networkOfAddress('1A1z') === 'mainnet'
  && networkOfAddress('tb1qxyz') === 'test' && networkOfAddress('mxyz') === 'test' && networkOfAddress('zzz') === null);

console.log(failed ? '\nRESULTADO: FALLOS ✗' : '\nRESULTADO: TODO OK ✓');
if (failed) process.exit(1);
