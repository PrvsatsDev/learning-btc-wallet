/**
 * Timeline de UTXOs por dirección — Fase 4 (visual, estilo Sparrow)
 *
 * Arriba, el saldo de la dirección a lo largo del tiempo (una escalera: sube al
 * recibir, baja al gastar). Debajo, cada moneda (UTXO) como una barra que va
 * de la tx que la crea a la tx que la gasta; las que siguen vivas llegan hasta
 * "ahora". El saldo en cada instante es exactamente la suma de las barras que
 * atraviesan ese instante.
 *
 * La película se reconstruye a partir del historial (utxoTimeline.ts) y se
 * COMPRUEBA contra la lista de UTXOs y las estadísticas que el servidor calcula
 * por su cuenta. Los ejemplos son direcciones reales de mainnet congeladas en
 * utxoTimeline.fixtures.ts, así que funcionan sin red.
 */

import { useState, useMemo, useRef, type ReactNode } from 'react';
import {
  buildTimeline,
  checkAgainstServer,
  fetchAddressHistory,
  lifespanBlocks,
  networkOfAddress,
  MAX_HISTORY_PAGES,
  DUST_SATS,
  type AddressTimeline,
  type Coin,
  type TimelineEvent,
  type TimelineTx,
  type TimePoint,
} from '../api/utxoTimeline';
import { TIMELINE_FIXTURES } from '../api/utxoTimeline.fixtures';
import { formatBtc, formatSatsBig } from '../crypto/tx-view';
import type { AddressInfo, Network, UTXO } from '../api/mempool';
import './UtxoTimelineExplorer.css';

interface Source {
  key: string;
  address: string;
  network: Network;
  info: AddressInfo;
  utxos: UTXO[];
  txs: TimelineTx[];
  now: number;          // unix (s) del momento de la descarga
  truncated: boolean;
}

type Selection = { kind: 'coin'; id: string } | { kind: 'event'; order: number } | null;
type AxisMode = 'time' | 'order';

// ─── Geometría del SVG ───
const W = 920;
const X0 = 24;
const X1 = W - 24;
const BAL_TOP = 26;
const BAL_H = 110;
const AXIS_Y = BAL_TOP + BAL_H + 16;
const LANES_TOP = AXIS_Y + 26;
const LANE_H = 14;
const LANE_GAP = 5;

const LIVE_COLOR = '#4ade80';
const SPENT_COLOR = '#64748b';
const DUST_COLOR = '#c084fc';
const SECONDS_PER_DAY = 86_400;

function fixtureSource(i: number): Source {
  const f = TIMELINE_FIXTURES[i];
  return { key: f.id, address: f.address, network: 'mainnet', info: f.info, utxos: f.utxos, txs: f.txs, now: f.fetchedAt, truncated: false };
}

function shortStr(s: string, head = 10, tail = 8): string {
  return s.length <= head + tail + 1 ? s : `${s.slice(0, head)}…${s.slice(-tail)}`;
}

function mempoolUrl(network: Network, kind: 'tx' | 'address', id: string): string {
  return `https://mempool.space/${network === 'mainnet' ? '' : network + '/'}${kind}/${id}`;
}

const btc = (sats: number) => formatBtc(BigInt(sats));
const satsStr = (sats: number) => formatSatsBig(BigInt(sats));

/** Importe corto para etiquetas dentro de las barras */
function compact(sats: number): string {
  if (sats >= 100_000_000) return `${(sats / 1e8).toFixed(2)} BTC`;
  if (sats >= 100_000) return `${(sats / 1e8).toFixed(4)} BTC`;
  return `${satsStr(sats)} sats`;
}

function dateStr(unix: number | null, withTime = true): string {
  if (unix == null) return 'en mempool';
  return new Date(unix * 1000).toLocaleString('es-ES', withTime ? { dateStyle: 'medium', timeStyle: 'short' } : { dateStyle: 'medium' });
}

function whenStr(p: TimePoint): string {
  return p.height == null ? 'sin confirmar (mempool)' : `bloque ${p.height.toLocaleString('es-ES')} · ${dateStr(p.time)}`;
}

function daysStr(seconds: number): string {
  const d = seconds / SECONDS_PER_DAY;
  if (d < 1) return `${Math.max(1, Math.round(seconds / 3600))} h`;
  if (d < 60) return `${Math.round(d)} días`;
  return `${(d / 30.44).toFixed(1)} meses`;
}

function median(xs: number[]): number | null {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

/**
 * Escala horizontal. En modo "tiempo" la x es la fecha real (se ve cuánto vive
 * cada moneda); en modo "por tx" cada tx ocupa un hueco igual (se ven bien las
 * ráfagas de actividad que en tiempo real quedarían apiladas).
 */
function makeScale(tl: AddressTimeline, mode: AxisMode, now: number) {
  const n = tl.events.length;
  const span = X1 - X0;
  const tmin = tl.firstTime ?? now;
  const useTime = mode === 'time' && now - tmin > 0;
  const at = (p: TimePoint): number => {
    if (!useTime) return X0 + ((p.order + 1) / (n + 1)) * span;
    const t = p.time ?? now;
    return X0 + span * (0.03 + 0.94 * ((t - tmin) / (now - tmin)));
  };
  return {
    at,
    start: (c: Coin) => (c.born ? at(c.born) : X0),
    end: (c: Coin) => (c.spent ? at(c.spent.at) : X1),
    useTime,
    tmin,
  };
}

export function UtxoTimelineExplorer() {
  const [source, setSource] = useState<Source>(() => fixtureSource(0));
  const [selection, setSelection] = useState<{ key: string; sel: Selection }>({ key: '', sel: null });
  const [axis, setAxis] = useState<AxisMode>('time');
  const [query, setQuery] = useState('');
  const [network, setNetwork] = useState<Network>('mainnet');
  const [load, setLoad] = useState<{ busy: boolean; msg?: string; error?: string }>({ busy: false });
  const reqRef = useRef(0);

  const tl = useMemo(() => buildTimeline(source.address, source.txs), [source]);
  const server = useMemo(() => checkAgainstServer(tl, source.utxos, source.info), [tl, source]);

  // La selección pertenece a una fuente concreta: al cambiar de dirección se olvida
  const sel = selection.key === source.key ? selection.sel : null;
  const select = (s: Selection) => setSelection({ key: source.key, sel: s });

  const showFixture = (i: number) => {
    reqRef.current++; // cancela cualquier descarga en curso
    setSource(fixtureSource(i));
    setLoad({ busy: false });
  };

  const handleLoad = async () => {
    const address = query.trim();
    if (!address) return;
    const kind = networkOfAddress(address);
    if (!kind) {
      setLoad({ busy: false, error: 'No parece una dirección Bitcoin (bc1…, 1…, 3… en mainnet; tb1…, m…, n…, 2… en testnet/signet)' });
      return;
    }
    // El prefijo manda: una bc1 solo existe en mainnet, una tb1 nunca
    let net = network;
    if (kind === 'mainnet') net = 'mainnet';
    else if (net === 'mainnet') net = 'testnet4';
    setNetwork(net);

    const req = ++reqRef.current;
    try {
      const h = await fetchAddressHistory(address, net, msg => {
        if (req === reqRef.current) setLoad({ busy: true, msg });
      }, () => req !== reqRef.current);
      if (!h || req !== reqRef.current) return;
      setSource({ key: `${net}:${address}:${Date.now()}`, address, network: net, ...h, now: Math.floor(Date.now() / 1000) });
      setLoad({ busy: false });
    } catch (e) {
      if (req === reqRef.current) setLoad({ busy: false, error: `No se pudo cargar: ${(e as Error).message}` });
    }
  };

  const activeFixture = TIMELINE_FIXTURES.findIndex(f => f.id === source.key);

  return (
    <div className="ut">
      <header className="ut-header">
        <span className="ut-phase-tag">Fase 4 · UI visual</span>
        <h1>Timeline de UTXOs</h1>
        <p className="ut-subtitle">
          Una dirección no guarda un "saldo": tiene <strong>monedas</strong> que nacen cuando alguien le paga y
          mueren cuando se gastan. Aquí ves la vida de cada una y cómo su suma dibuja el saldo. Todo se
          reconstruye del historial y se <strong>comprueba</strong> contra lo que el servidor calcula por separado.
        </p>
      </header>

      <section className="ut-source">
        <div className="ut-examples">
          <span className="ut-source-label">Ejemplos reales (mainnet, sin red):</span>
          {TIMELINE_FIXTURES.map((f, i) => (
            <button key={f.id} className={`ut-chip ${i === activeFixture ? 'active' : ''}`} onClick={() => showFixture(i)}>
              {f.label}
            </button>
          ))}
        </div>
        <form className="ut-load" onSubmit={e => { e.preventDefault(); void handleLoad(); }}>
          <input
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="O pega una dirección (bc1…, tb1…, 1…, 3…)"
            spellCheck={false}
            aria-label="Dirección"
          />
          <div className="ut-toggle" role="group" aria-label="Red">
            {(['mainnet', 'testnet4', 'signet'] as Network[]).map(n => (
              <button type="button" key={n} className={network === n ? 'active' : ''} onClick={() => setNetwork(n)}>{n}</button>
            ))}
          </div>
          <button type="submit" className="ut-btn" disabled={load.busy || !query.trim()}>Ver</button>
        </form>
        {load.busy && <div className="ut-status"><span className="ut-spinner" />{load.msg}</div>}
        {load.error && <div className="ut-status ut-status--error">{load.error}</div>}
      </section>

      <div className="ut-addr">
        <span className="ut-k">Dirección</span> <code>{source.address}</code>{' '}
        <a href={mempoolUrl(source.network, 'address', source.address)} target="_blank" rel="noreferrer">mempool.space ↗</a>
        {source.network !== 'mainnet' && <span className="ut-badge on">{source.network}</span>}
      </div>

      {tl.events.length === 0 ? (
        <div className="ut-empty">Esta dirección no tiene ninguna transacción: nunca ha recibido nada.</div>
      ) : (
        <>
          <SummaryCards tl={tl} now={source.now} />
          <ServerCheckPanel tl={tl} server={server} source={source} />

          <div className="ut-diagram-wrap">
            <div className="ut-diagram-head">
              <div className="ut-legend">
                <span><i style={{ background: LIVE_COLOR }} />viva (UTXO)</span>
                <span><i style={{ background: SPENT_COLOR }} />gastada</span>
                <span><i style={{ background: DUST_COLOR }} />polvo (&lt; {satsStr(DUST_SATS)} sats)</span>
              </div>
              <div className="ut-toggle" role="group" aria-label="Eje horizontal">
                <button type="button" className={axis === 'time' ? 'active' : ''} onClick={() => setAxis('time')}>tiempo real</button>
                <button type="button" className={axis === 'order' ? 'active' : ''} onClick={() => setAxis('order')}>por tx</button>
              </div>
            </div>
            <TimelineSvg tl={tl} axis={axis} now={source.now} sel={sel} onSelect={select} />
          </div>

          <div className="ut-detail">
            {sel?.kind === 'coin' && tl.coins.find(c => c.id === sel.id) ? (
              <CoinDetail coin={tl.coins.find(c => c.id === sel.id)!} tl={tl} network={source.network} now={source.now} onSelect={select} />
            ) : sel?.kind === 'event' && tl.events[sel.order] ? (
              <EventDetail ev={tl.events[sel.order]} tl={tl} network={source.network} onSelect={select} />
            ) : (
              <p className="ut-note ut-hint">
                Pincha una <strong>barra</strong> para ver la vida de esa moneda, o un <strong>punto</strong> del eje
                (o una fila de la tabla) para ver qué hizo esa transacción con las monedas de la dirección.
              </p>
            )}
          </div>

          <Insights tl={tl} now={source.now} />
          <EventTable tl={tl} sel={sel} onSelect={select} />
        </>
      )}
    </div>
  );
}

// ─── Resumen ───────────────────────────────────────────────

function SummaryCards({ tl, now }: { tl: AddressTimeline; now: number }) {
  const lives = tl.coins.map(c => (c.born?.time != null && c.spent?.at.time != null ? c.spent.at.time - c.born.time : null)).filter((x): x is number => x != null);
  const med = median(lives);
  const oldestLive = Math.min(...tl.live.map(c => c.born?.time ?? Infinity));
  return (
    <div className="ut-cards">
      <div className="ut-card ut-card--bal">
        <span className="ut-card-label">Saldo = Σ monedas vivas</span>
        <span className="ut-card-value">{btc(tl.balance)} <small>BTC</small></span>
        <span className="ut-card-sub">
          {tl.confirmedBalance !== tl.balance ? `${btc(tl.confirmedBalance)} confirmado` : `${satsStr(tl.balance)} sats`}
        </span>
      </div>
      <div className="ut-card">
        <span className="ut-card-label">Monedas vivas</span>
        <span className="ut-card-value">{tl.live.length} <small>de {tl.coins.length}</small></span>
        <span className="ut-card-sub">máx. {tl.lanes} a la vez</span>
      </div>
      <div className="ut-card">
        <span className="ut-card-label">Transacciones</span>
        <span className="ut-card-value">{tl.events.length}</span>
        <span className="ut-card-sub">{tl.firstTime ? `desde ${dateStr(tl.firstTime, false)}` : 'todas en mempool'}</span>
      </div>
      <div className="ut-card">
        <span className="ut-card-label">Vida mediana de una moneda</span>
        <span className="ut-card-value">{med != null ? daysStr(med) : '—'}</span>
        <span className="ut-card-sub">
          {Number.isFinite(oldestLive) ? `la viva más antigua: ${daysStr(now - oldestLive)}` : 'ninguna gastada aún'}
        </span>
      </div>
    </div>
  );
}

function ServerCheckPanel({ tl, server, source }: { tl: AddressTimeline; server: ReturnType<typeof checkAgainstServer>; source: Source }) {
  const ok = server.utxosMatch && server.balanceMatch;
  return (
    <div className={`ut-check ${ok ? 'ok' : 'bad'}`}>
      <strong>{ok ? '✓ Reconstrucción comprobada' : '✗ La reconstrucción no cuadra con el servidor'}</strong>
      <ul>
        <li>
          Monedas vivas según nuestra película: <strong>{tl.live.length}</strong> · lista <code>/utxo</code> del servidor:{' '}
          <strong>{source.utxos.length}</strong>{' '}
          {server.utxosMatch ? <span className="ok">mismos outpoints</span>
            : <span className="bad">difieren ({server.missing.length} nos faltan, {server.extra.length} sobran)</span>}
        </li>
        <li>
          Saldo: Σ vivas = <code>{satsStr(tl.balance)}</code> · servidor (recibido − gastado) ={' '}
          <code>{satsStr(server.serverBalance)}</code>{' '}
          {server.balanceMatch ? <span className="ok">✓</span> : <span className="bad">✗</span>}
        </li>
      </ul>
      {source.truncated && (
        <p className="ut-note warn">
          Historial truncado: solo se han descargado {MAX_HISTORY_PAGES} páginas ({source.txs.length} de{' '}
          {source.info.chain_stats.tx_count + source.info.mempool_stats.tx_count} tx). Faltan las más antiguas.
        </p>
      )}
      {tl.orphanSpends > 0 && (
        <p className="ut-note warn">
          {tl.orphanSpends} gasto(s) de monedas cuyo nacimiento no está en lo cargado: se dibujan desde el borde
          izquierdo y el saldo histórico de esa zona no es fiable.
        </p>
      )}
      {!ok && !source.truncated && (
        <p className="ut-note">
          Si acaba de entrar una tx entre una petición y otra, recarga: el historial, la lista de UTXOs y las
          estadísticas se piden por separado.
        </p>
      )}
      <p className="ut-note">
        Son dos cálculos independientes: nosotros recorremos tx a tx (nace con cada salida a la dirección, muere con
        cada entrada que la gasta); el servidor mantiene su propio índice de UTXOs. Si coinciden, no se nos ha
        escapado ninguna moneda.
      </p>
    </div>
  );
}

// ─── Diagrama ──────────────────────────────────────────────

function TimelineSvg({ tl, axis, now, sel, onSelect }: {
  tl: AddressTimeline; axis: AxisMode; now: number; sel: Selection; onSelect: (s: Selection) => void;
}) {
  const sc = makeScale(tl, axis, now);
  const height = LANES_TOP + tl.lanes * (LANE_H + LANE_GAP) + 18;
  const maxBal = Math.max(1, ...tl.events.map(e => e.balanceAfter));
  const yBal = (v: number) => BAL_TOP + BAL_H - (v / maxBal) * BAL_H;

  // Escalera del saldo: horizontal hasta cada tx, vertical al nuevo saldo
  let d = `M ${X0} ${yBal(0)}`;
  for (const e of tl.events) d += ` H ${sc.at(e.at).toFixed(1)} V ${yBal(e.balanceAfter).toFixed(1)}`;
  d += ` H ${X1}`;
  const area = `${d} V ${yBal(0)} Z`;

  const selCoin = sel?.kind === 'coin' ? tl.coins.find(c => c.id === sel.id) : undefined;
  const selEvent = sel?.kind === 'event' ? tl.events[sel.order] : undefined;
  // Monedas "hermanas": gastadas en la misma tx que la seleccionada
  const sibling = (c: Coin) => !!selCoin && c !== selCoin && !!selCoin.spent && c.spent?.txid === selCoin.spent.txid;
  const createdHere = new Set(selEvent?.created.map(c => c.id));
  const consumedHere = new Set(selEvent?.consumed.map(c => c.id));

  const ticks = axisTicks(tl, sc, now);

  return (
    <svg className="ut-svg" viewBox={`0 0 ${W} ${height}`} role="img" aria-label="Timeline de monedas y saldo de la dirección">
      {/* Guías verticales de cada tx */}
      {tl.events.map(e => (
        <line key={`g${e.at.order}`} x1={sc.at(e.at)} x2={sc.at(e.at)} y1={BAL_TOP} y2={height - 10}
          className={`ut-guide ${selEvent === e ? 'active' : ''}`} />
      ))}

      {/* Saldo */}
      <text x={X0} y={BAL_TOP - 10} className="ut-axis-label">saldo · máx. {compact(maxBal)}</text>
      <line x1={X0} x2={X1} y1={yBal(0)} y2={yBal(0)} className="ut-baseline" />
      <path d={area} className="ut-bal-area" />
      <path d={d} className="ut-bal-line" />

      {/* Eje con un punto por tx: verde si entra dinero, rojo si sale */}
      <line x1={X0} x2={X1} y1={AXIS_Y} y2={AXIS_Y} className="ut-baseline" />
      {ticks.map(t => (
        <text key={t.x} x={t.x} y={AXIS_Y + 18} className="ut-tick" textAnchor={t.anchor}>{t.label}</text>
      ))}
      {sc.useTime && <text x={X1} y={AXIS_Y + 18} className="ut-tick" textAnchor="end">ahora</text>}
      {tl.events.map(e => (
        <circle key={`e${e.at.order}`} cx={sc.at(e.at)} cy={AXIS_Y} r={selEvent === e ? 7 : 5}
          className={`ut-event ${e.delta > 0 ? 'in' : e.delta < 0 ? 'out' : 'zero'} ${e.at.height == null ? 'pending' : ''} ${selEvent === e ? 'active' : ''}`}
          onClick={() => onSelect({ kind: 'event', order: e.at.order })}>
          <title>{`${e.delta >= 0 ? '+' : ''}${satsStr(e.delta)} sats · ${whenStr(e.at)}`}</title>
        </circle>
      ))}

      {/* Una barra por moneda, en su carril. Las más cortas se pintan encima: si
          una moneda vive un instante y su cambio nace en la misma tx (mismo
          carril), la barra larga no debe taparla. */}
      {[...tl.coins].sort((a, b) => (sc.end(b) - sc.start(b)) - (sc.end(a) - sc.start(a))).map(c => {
        const x = sc.start(c);
        const w = Math.max(3, sc.end(c) - x);
        const y = LANES_TOP + c.lane * (LANE_H + LANE_GAP);
        const color = c.dust ? DUST_COLOR : c.spent ? SPENT_COLOR : LIVE_COLOR;
        const pending = c.born?.height === null || (!!c.spent && c.spent.at.height === null);
        const cls = [
          'ut-coin',
          selCoin === c ? 'active' : '',
          sibling(c) ? 'sibling' : '',
          createdHere.has(c.id) ? 'created' : '',
          consumedHere.has(c.id) ? 'consumed' : '',
          pending ? 'pending' : '',
        ].join(' ');
        return (
          <g key={c.id} className={cls} onClick={() => onSelect({ kind: 'coin', id: c.id })}>
            <rect x={x} y={y} width={w} height={LANE_H} rx={3} fill={color} fillOpacity={c.spent ? 0.55 : 0.85} />
            {!c.spent && <path d={`M ${X1} ${y} l 6 ${LANE_H / 2} l -6 ${LANE_H / 2} Z`} fill={color} />}
            {w > 74 && <text x={x + 5} y={y + LANE_H - 3.5} className="ut-coin-label">{compact(c.value)}</text>}
            <title>{`${compact(c.value)} · ${c.spent ? 'gastada' : 'viva'} · ${c.id}`}</title>
          </g>
        );
      })}
    </svg>
  );
}

/** Marcas del eje: fechas en modo tiempo, alturas de bloque en modo "por tx" */
type Tick = { x: number; label: string; anchor: 'start' | 'middle' | 'end' };

function axisTicks(tl: AddressTimeline, sc: ReturnType<typeof makeScale>, now: number): Tick[] {
  if (sc.useTime) {
    const N = 4;
    const ticks: Tick[] = [];
    for (let k = 0; k < N; k++) {
      const t = sc.tmin + ((now - sc.tmin) * k) / N;
      ticks.push({
        x: sc.at({ order: 0, height: 0, time: t }),
        label: new Date(t * 1000).toLocaleDateString('es-ES', { month: 'short', year: '2-digit' }),
        anchor: 'middle',
      });
    }
    return ticks;
  }
  const confirmed = tl.events.filter(e => e.at.height != null);
  if (!confirmed.length) return [];
  const picks = [confirmed[0], confirmed[confirmed.length >> 1], confirmed[confirmed.length - 1]];
  // Los extremos se alinean hacia dentro para no salirse del dibujo
  return [...new Set(picks)].map((e, i, arr) => ({
    x: sc.at(e.at),
    label: `#${e.at.height!.toLocaleString('es-ES')}`,
    anchor: i === 0 ? 'start' : i === arr.length - 1 ? 'end' : 'middle',
  }));
}

// ─── Detalle ───────────────────────────────────────────────

function TxLink({ network, txid }: { network: Network; txid: string }) {
  return <a href={mempoolUrl(network, 'tx', txid)} target="_blank" rel="noreferrer"><code>{shortStr(txid, 12, 6)}</code></a>;
}

function CoinDetail({ coin, tl, network, now, onSelect }: {
  coin: Coin; tl: AddressTimeline; network: Network; now: number; onSelect: (s: Selection) => void;
}) {
  const blocks = lifespanBlocks(coin);
  const endTime = coin.spent ? coin.spent.at.time : now;
  const secs = coin.born?.time != null && endTime != null ? endTime - coin.born.time : null;
  const spendEvent = coin.spent ? tl.events[coin.spent.at.order] : undefined;
  const siblings = spendEvent ? spendEvent.consumed.filter(c => c !== coin) : [];
  return (
    <>
      <h3>Moneda de {compact(coin.value)} <span className={coin.spent ? 'ut-k' : 'ok'}>{coin.spent ? '· gastada' : '· viva (UTXO)'}</span></h3>
      <dl className="ut-fields">
        <dt>Outpoint</dt>
        <dd><code className="wrap">{coin.txid}:{coin.vout}</code><span className="ut-k">la "identidad" de la moneda: tx que la creó + nº de salida</span></dd>
        <dt>Importe</dt>
        <dd><code>{btc(coin.value)} BTC</code> · {satsStr(coin.value)} sats{coin.dust && <span className="warn"> · polvo</span>}</dd>
        <dt>Nace</dt>
        <dd>
          {coin.born ? <>
            salida #{coin.vout} de <TxLink network={network} txid={coin.txid} /> · {whenStr(coin.born)}{' '}
            <button className="ut-linkbtn" onClick={() => onSelect({ kind: 'event', order: coin.born!.order })}>ver tx</button>
          </> : <span className="warn">antes del historial cargado</span>}
        </dd>
        <dt>Muere</dt>
        <dd>
          {coin.spent ? <>
            entrada #{coin.spent.vin} de <TxLink network={network} txid={coin.spent.txid} /> · {whenStr(coin.spent.at)}{' '}
            <button className="ut-linkbtn" onClick={() => onSelect({ kind: 'event', order: coin.spent!.at.order })}>ver tx</button>
          </> : <span className="ok">aún no: es parte del saldo actual. Gastarla requiere firmar con la clave de la dirección.</span>}
        </dd>
        <dt>Vida</dt>
        <dd>
          {secs != null ? daysStr(secs) : '—'}
          {blocks != null && <> · {blocks.toLocaleString('es-ES')} bloques</>}
          {!coin.spent && secs != null && <span className="ut-k"> (y sigue)</span>}
        </dd>
        {coin.spent && (
          <>
            <dt>Gastada junto a</dt>
            <dd>
              {siblings.length === 0 && !spendEvent?.foreignInputs ? 'ninguna otra entrada: se gastó sola.' : <>
                {siblings.length > 0 && <>{siblings.length} moneda(s) más de esta dirección. </>}
                {spendEvent!.foreignInputs > 0 && <>{spendEvent!.foreignInputs} entrada(s) de otras direcciones. </>}
                <span className="warn">Heurística de propiedad común: quien gasta varias entradas juntas suele ser su único dueño.</span>
              </>}
            </dd>
          </>
        )}
      </dl>
      <p className="ut-note">
        Una moneda no se gasta "a medias": la tx que la consume la destruye entera y crea monedas nuevas
        (el pago y, normalmente, el cambio). Por eso cada barra tiene un final limpio.
      </p>
    </>
  );
}

function EventDetail({ ev, tl, network, onSelect }: {
  ev: TimelineEvent; tl: AddressTimeline; network: Network; onSelect: (s: Selection) => void;
}) {
  const before = ev.at.order > 0 ? tl.events[ev.at.order - 1].balanceAfter : 0;
  const kind = ev.coinbase ? 'Coinbase (recompensa de bloque)'
    : ev.consumed.length && ev.created.length ? 'Gasto con cambio de vuelta'
    : ev.consumed.length ? 'Gasto' : 'Recibo';
  const coinBtn = (c: Coin) => (
    <button key={c.id} className="ut-coinbtn" onClick={() => onSelect({ kind: 'coin', id: c.id })}>
      {compact(c.value)} <span className="ut-k">:{c.vout}</span>
    </button>
  );
  return (
    <>
      <h3>{kind} <span className={ev.delta >= 0 ? 'ok' : 'bad'}>{ev.delta >= 0 ? '+' : ''}{satsStr(ev.delta)} sats</span></h3>
      <dl className="ut-fields">
        <dt>Transacción</dt>
        <dd><TxLink network={network} txid={ev.tx.txid} /> · {whenStr(ev.at)}</dd>
        <dt>Mueren</dt>
        <dd>{ev.consumed.length ? <div className="ut-coinlist">{ev.consumed.map(coinBtn)}</div> : <span className="ut-k">ninguna moneda de esta dirección</span>}</dd>
        <dt>Nacen</dt>
        <dd>{ev.created.length ? <div className="ut-coinlist">{ev.created.map(coinBtn)}</div> : <span className="ut-k">ninguna para esta dirección</span>}</dd>
        <dt>Saldo</dt>
        <dd><code>{btc(before)}</code> → <code>{btc(ev.balanceAfter)}</code> BTC</dd>
        {ev.tx.fee != null && ev.consumed.length > 0 && (
          <>
            <dt>Comisión de la tx</dt>
            <dd>{satsStr(ev.tx.fee)} sats{ev.foreignInputs > 0 && <span className="ut-k"> (pagada entre todas las entradas)</span>}</dd>
          </>
        )}
      </dl>
      {ev.changeBack && (
        <p className="ut-note warn">
          La tx gasta monedas de esta dirección y le devuelve una salida: el cambio vuelve a la misma dirección.
          Así cualquiera distingue el pago (la otra salida) del cambio, y sabe cuánto te queda.
        </p>
      )}
      {ev.consumed.length > 0 && ev.foreignInputs > 0 && (
        <p className="ut-note warn">
          También gasta {ev.foreignInputs} entrada(s) de otras direcciones. Salvo CoinJoin o PayJoin, eso enlaza
          esas direcciones con esta: probablemente son del mismo dueño.
        </p>
      )}
    </>
  );
}

// ─── Lo que revela ─────────────────────────────────────────

function Insights({ tl, now }: { tl: AddressTimeline; now: number }) {
  const consolidations = tl.events.filter(e => e.consumed.length > 1).length;
  const foreign = tl.events.filter(e => e.foreignInputs > 0).length;
  const changeBack = tl.events.filter(e => e.changeBack).length;
  const dust = tl.coins.filter(c => c.dust);
  const liveDust = dust.filter(c => !c.spent).length;
  const items: { level: 'warn' | 'info'; text: ReactNode }[] = [];

  if (tl.fundingTxs > 1) items.push({ level: 'warn', text: <>
    <strong>Dirección reutilizada:</strong> recibió en {tl.fundingTxs} tx distintas. Al ser la misma dirección,
    cualquiera ve que esas {tl.coins.length} monedas son del mismo dueño y suma su saldo. Las wallets HD dan una
    dirección nueva para cada cobro precisamente para evitarlo.
  </> });
  if (consolidations) items.push({ level: 'warn', text: <>
    <strong>{consolidations} tx gastan varias monedas juntas</strong> (consolidación). Quien firma todas esas
    entradas controla todas esas monedas: en una wallet con direcciones distintas, este gesto es lo que las enlaza.
  </> });
  if (foreign) items.push({ level: 'warn', text: <>
    <strong>En {foreign} tx se gastó junto a entradas de otras direcciones:</strong> según la heurística de
    propiedad común, son del mismo dueño (salvo que sea un CoinJoin).
  </> });
  if (changeBack) items.push({ level: 'warn', text: <>
    <strong>En {changeBack} gasto(s) el cambio volvió aquí:</strong> el cambio queda delatado, y con él cuál era el pago.
  </> });
  if (dust.length) items.push({ level: liveDust ? 'warn' : 'info', text: <>
    <strong>{dust.length} moneda(s) de polvo</strong> (&lt; {satsStr(DUST_SATS)} sats){liveDust ? `, ${liveDust} sin gastar` : ''}.
    Mandar polvo a direcciones reutilizadas es un ataque típico: si lo gastas junto a otras monedas, enlazas tus
    direcciones. Sparrow permite "congelar" esas monedas para no usarlas nunca.
  </> });
  if (tl.live.length > 1) {
    const oldest = Math.min(...tl.live.map(c => c.born?.time ?? now));
    items.push({ level: 'info', text: <>
      <strong>{tl.live.length} monedas vivas:</strong> para gastar el saldo entero habría que meterlas todas como
      entradas, y cada una pesa en la tx (y en la comisión). La más antigua lleva {daysStr(now - oldest)} quieta.
    </> });
  }
  if (!items.length) return null;
  return (
    <section className="ut-insights">
      <h3>Lo que cualquiera puede leer en esta timeline</h3>
      <ul>
        {items.map((it, i) => <li key={i} className={it.level}>{it.text}</li>)}
      </ul>
    </section>
  );
}

// ─── Tabla de eventos ──────────────────────────────────────

function EventTable({ tl, sel, onSelect }: { tl: AddressTimeline; sel: Selection; onSelect: (s: Selection) => void }) {
  const rows = [...tl.events].reverse();
  return (
    <section className="ut-table-wrap">
      <h3>Historial ({tl.events.length} tx, más reciente arriba)</h3>
      <div className="ut-table-scroll">
        <table className="ut-table">
          <thead>
            <tr><th>Cuándo</th><th>Tx</th><th>Mueren</th><th>Nacen</th><th className="num">Δ sats</th><th className="num">Saldo BTC</th></tr>
          </thead>
          <tbody>
            {rows.map(e => (
              <tr key={e.tx.txid} className={sel?.kind === 'event' && sel.order === e.at.order ? 'active' : ''}
                onClick={() => onSelect({ kind: 'event', order: e.at.order })}>
                <td>{e.at.height == null ? <span className="warn">mempool</span> : dateStr(e.at.time, false)}</td>
                <td><code>{shortStr(e.tx.txid, 8, 4)}</code></td>
                <td>{e.consumed.length || ''}</td>
                <td>{e.created.length || ''}</td>
                <td className={`num ${e.delta >= 0 ? 'ok' : 'bad'}`}>{e.delta >= 0 ? '+' : ''}{satsStr(e.delta)}</td>
                <td className="num">{btc(e.balanceAfter)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
