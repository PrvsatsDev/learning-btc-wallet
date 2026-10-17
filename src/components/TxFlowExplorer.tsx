/**
 * Vista de transacción inputs → outputs — Fase 4 (visual, estilo Sparrow)
 *
 * Diagrama de flujo: cada entrada (un UTXO que se gasta) fluye hacia la tx y de
 * ahí a las salidas y a la comisión del minero. El grosor de cada cinta es
 * proporcional al importe, así que "se ve" que Σ entradas = Σ salidas + comisión.
 *
 * Los importes de entrada no están en la tx: se sacan de las tx previas y se
 * VERIFICAN hasheándolas (tx-view.ts). Los ejemplos son tx reales de mainnet
 * guardadas en tx-view.fixtures.ts, así que funcionan sin red; con un txid se
 * descarga el hex de mempool.space y se recalcula todo aquí.
 */

import { useState, useMemo, useRef } from 'react';
import {
  buildTxView,
  parseTxStrict,
  txidOf,
  isCoinbaseInput,
  formatBtc,
  formatSatsBig,
  type TxView,
  type InputView,
  type OutputView,
  type ScriptType,
} from '../crypto/tx-view';
import { TX_FIXTURES } from '../crypto/tx-view.fixtures';
import { disassemble } from '../crypto/script';
import { getTransaction, getTransactionHex, type Network } from '../api/mempool';
import './TxFlowExplorer.css';

/** Máximo de tx previas a descargar (la API pública limita peticiones) */
const MAX_PREV_FETCH = 25;

interface Source {
  key: string;
  label: string;
  hex: string;
  prevTxs: Record<string, string>;
  blockHeight?: number;
  network: Network;
}

type Selection = { kind: 'in' | 'out'; index: number } | { kind: 'fee' } | null;

const TYPE_COLOR: Record<ScriptType, string> = {
  p2pk: '#c084fc',
  p2pkh: '#a78bfa',
  p2sh: '#f472b6',
  p2wpkh: '#22d3ee',
  p2wsh: '#38bdf8',
  p2tr: '#f7931a',
  op_return: '#94a3b8',
  witness_unknown: '#64748b',
  unknown: '#64748b',
};
const FEE_COLOR = '#fca5a5';
const UNKNOWN_COLOR = '#475569';
const COINBASE_COLOR = '#4ade80';

function fixtureSource(i: number): Source {
  const f = TX_FIXTURES[i];
  return { key: f.id, label: f.label, hex: f.hex, prevTxs: f.prevTxs, blockHeight: f.blockHeight, network: 'mainnet' };
}

function shortStr(s: string, head = 10, tail = 8): string {
  return s.length <= head + tail + 1 ? s : `${s.slice(0, head)}…${s.slice(-tail)}`;
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

function mempoolUrl(network: Network, txid: string): string {
  return `https://mempool.space/${network === 'mainnet' ? '' : network + '/'}tx/${txid}`;
}

export function TxFlowExplorer() {
  const [source, setSource] = useState<Source>(() => fixtureSource(0));
  const [selection, setSelection] = useState<{ key: string; sel: Selection }>({ key: 'segwit', sel: { kind: 'in', index: 0 } });
  const [query, setQuery] = useState('');
  const [network, setNetwork] = useState<Network>('mainnet');
  const [load, setLoad] = useState<{ busy: boolean; msg?: string; error?: string }>({ busy: false });
  const reqRef = useRef(0);

  const result = useMemo((): { view: TxView } | { error: string } => {
    try {
      return { view: buildTxView(source.hex, source.prevTxs, { mainnet: source.network === 'mainnet', blockHeight: source.blockHeight }) };
    } catch (e) {
      return { error: (e as Error).message };
    }
  }, [source]);

  // La selección pertenece a una fuente concreta: al cambiar de tx se olvida
  const sel = selection.key === source.key ? selection.sel : null;
  const select = (s: Selection) => setSelection({ key: source.key, sel: s });

  const showSource = (s: Source) => {
    reqRef.current++; // cancela cualquier descarga en curso
    setSource(s);
    setLoad({ busy: false });
  };

  const handleLoad = async () => {
    const q = query.trim().toLowerCase().replace(/\s+/g, '');
    if (!q) return;
    const req = ++reqRef.current;
    const isTxid = /^[0-9a-f]{64}$/.test(q);
    try {
      let hex = q;
      let blockHeight: number | undefined;
      if (isTxid) {
        setLoad({ busy: true, msg: 'Descargando la transacción…' });
        const [h, info] = await Promise.all([getTransactionHex(q, network), getTransaction(q, network)]);
        hex = h;
        blockHeight = info.status.block_height;
      }
      const tx = parseTxStrict(hex);
      if (isTxid && txidOf(tx) !== q) throw new Error('El servidor devolvió unos bytes cuyo hash no es ese txid');

      const ids = [...new Set(
        tx.inputs.filter(i => !isCoinbaseInput(i.prevTxId, i.prevVout)).map(i => i.prevTxId),
      )];
      const wanted = ids.slice(0, MAX_PREV_FETCH);
      const prevTxs: Record<string, string> = {};
      for (const [k, id] of wanted.entries()) {
        if (req !== reqRef.current) return;
        setLoad({ busy: true, msg: `Descargando tx previas ${k + 1}/${wanted.length} (para conocer los importes)…` });
        try {
          prevTxs[id] = await getTransactionHex(id, network);
        } catch {
          // se queda como "missing": la vista lo muestra sin importe
        }
      }
      if (req !== reqRef.current) return;

      const txid = txidOf(tx);
      showSource({ key: `${network}:${txid}`, label: shortStr(txid, 12, 6), hex, prevTxs, blockHeight, network });
      setSelection({ key: `${network}:${txid}`, sel: { kind: 'in', index: 0 } });
      if (ids.length > wanted.length) {
        setLoad({ busy: false, msg: `Sólo se descargaron ${wanted.length} de ${ids.length} tx previas: la comisión queda sin calcular.` });
      }
    } catch (e) {
      if (req === reqRef.current) setLoad({ busy: false, error: (e as Error).message });
    }
  };

  return (
    <div className="tf">
      <header className="tf-header">
        <span className="tf-phase-tag">Fase 4 · UI visual</span>
        <h1>Vista de transacción</h1>
        <p className="tf-subtitle">
          Una transacción no «envía desde una dirección»: <strong>consume UTXOs enteros</strong> y crea
          otros nuevos. Lo que sobra entre lo que entra y lo que sale es la comisión del minero — y no
          aparece escrita en ningún sitio.
        </p>
      </header>

      {/* ─── Fuente ─── */}
      <section className="tf-source">
        <div className="tf-examples">
          <span className="tf-source-label">Ejemplos reales de mainnet (sin red):</span>
          {TX_FIXTURES.map((f, i) => (
            <button
              key={f.id}
              className={`tf-chip ${source.key === f.id ? 'active' : ''}`}
              onClick={() => { showSource(fixtureSource(i)); setSelection({ key: f.id, sel: { kind: 'in', index: 0 } }); }}
            >
              {f.label}
            </button>
          ))}
        </div>
        <div className="tf-load">
          <input
            type="text"
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') void handleLoad(); }}
            placeholder="Pega un txid o el hex crudo de una transacción"
            spellCheck={false}
          />
          <div className="tf-toggle">
            {(['mainnet', 'testnet4', 'signet'] as const).map(n => (
              <button key={n} className={network === n ? 'active' : ''} onClick={() => setNetwork(n)}>{n}</button>
            ))}
          </div>
          <button className="tf-btn" onClick={() => void handleLoad()} disabled={load.busy || !query.trim()}>
            {load.busy ? 'Cargando…' : 'Ver'}
          </button>
        </div>
        {load.busy && <div className="tf-status"><span className="tf-spinner" /> {load.msg}</div>}
        {!load.busy && load.msg && <div className="tf-status tf-status--warn">{load.msg}</div>}
        {load.error && <div className="tf-status tf-status--error">✗ {load.error}</div>}
      </section>

      {'error' in result ? (
        <div className="tf-status tf-status--error">✗ {result.error}</div>
      ) : (
        <TxDisplay view={result.view} source={source} sel={sel} onSelect={select} />
      )}
    </div>
  );
}

// ─── Vista de una transacción ───────────────────────────────

interface TxDisplayProps {
  view: TxView;
  source: Source;
  sel: Selection;
  onSelect: (s: Selection) => void;
}

function TxDisplay({ view, source, sel, onSelect }: TxDisplayProps) {
  const witnessBytes = view.size - view.baseSize;
  const discount = 1 - view.weight / (view.size * 4);
  const unverified = view.inputs.filter(i => i.status === 'missing' || i.status === 'mismatch').length;
  const coinbase = view.inputs.some(i => i.status === 'coinbase');

  return (
    <>
      <div className="tf-ids">
        <div><span className="tf-k">txid</span> <code>{view.txid}</code></div>
        {view.segwit && <div><span className="tf-k">wtxid</span> <code>{view.wtxid}</code></div>}
        <a href={mempoolUrl(source.network, view.txid)} target="_blank" rel="noreferrer noopener">ver en mempool.space ↗</a>
      </div>

      {/* ─── Resumen ─── */}
      <div className="tf-cards">
        <div className="tf-card">
          <span className="tf-card-label">Entradas ({view.inputs.length})</span>
          <span className="tf-card-value">
            {coinbase ? 'monedas nuevas' : <>{view.totalIn !== null ? formatBtc(view.totalIn) : '¿?'} <small>BTC</small></>}
          </span>
        </div>
        <div className="tf-card">
          <span className="tf-card-label">Salidas ({view.outputs.length})</span>
          <span className="tf-card-value">{formatBtc(view.totalOut)} <small>BTC</small></span>
        </div>
        <div className="tf-card tf-card--fee">
          <span className="tf-card-label">Comisión = entradas − salidas</span>
          <span className="tf-card-value">
            {view.fee !== null ? <>{formatSatsBig(view.fee)} <small>sats</small></> : coinbase ? 'no aplica' : '¿?'}
          </span>
          {coinbase && <span className="tf-card-sub">la coinbase cobra las comisiones, no las paga</span>}
          {view.feeRate !== null && <span className="tf-card-sub">{view.feeRate.toFixed(2)} sat/vB</span>}
        </div>
        <div className="tf-card">
          <span className="tf-card-label">Tamaño virtual</span>
          <span className="tf-card-value">{view.vsize} <small>vB</small></span>
          <span className="tf-card-sub">{view.weight} WU · {view.size} B</span>
        </div>
      </div>

      <div className="tf-badges">
        <span className={`tf-badge ${view.segwit ? 'on' : ''}`}>{view.segwit ? 'SegWit' : 'Legacy (sin witness)'}</span>
        <span className={`tf-badge ${view.signalsRbf ? 'warn' : ''}`}>{view.signalsRbf ? 'Señala RBF' : 'Sin RBF'}</span>
        <span className="tf-badge">versión {view.version}</span>
        <span className="tf-badge">nLockTime: {view.locktimeInfo}</span>
      </div>

      {unverified > 0 && (
        <div className="tf-status tf-status--warn">
          {unverified} entrada(s) sin tx previa verificada: no se conoce su importe, así que la comisión no se puede calcular.
        </div>
      )}

      {/* ─── Diagrama ─── */}
      <section className="tf-diagram-wrap">
        <FlowDiagram view={view} sel={sel} onSelect={onSelect} />
      </section>

      {/* ─── Peso ─── */}
      <section className="tf-weight">
        <div className="tf-weight-head">
          <strong>Peso (BIP141)</strong>
          <span>weight = bytes base × 4 + bytes witness × 1</span>
        </div>
        <div className="tf-weight-bar">
          <div className="tf-weight-base" style={{ flexGrow: view.baseSize * 4 }}>
            base {view.baseSize} B × 4 = {view.baseSize * 4} WU
          </div>
          {witnessBytes > 0 && (
            <div className="tf-weight-wit" style={{ flexGrow: witnessBytes }}>
              witness {witnessBytes} B × 1
            </div>
          )}
        </div>
        <p className="tf-note">
          {view.segwit
            ? <>Sin el descuento SegWit pesaría {view.size * 4} WU. Las firmas van en el witness y cuentan
              ¼, así que esta tx paga un <strong>{(discount * 100).toFixed(0)} % menos</strong> de comisión por el mismo contenido.
              vsize = ⌈weight / 4⌉ = {view.vsize} vB.</>
            : <>Transacción legacy: todo cuenta ×4, así que vsize = tamaño en bytes. Las firmas viven en el scriptSig
              y no hay descuento — ni wtxid distinto del txid.</>}
        </p>
      </section>

      {/* ─── Detalle ─── */}
      <section className="tf-detail">
        {!sel && <p className="tf-note">Pincha una entrada, una salida o la comisión para ver el detalle.</p>}
        {sel?.kind === 'in' && view.inputs[sel.index] && <InputDetail input={view.inputs[sel.index]} />}
        {sel?.kind === 'out' && view.outputs[sel.index] && <OutputDetail output={view.outputs[sel.index]} />}
        {sel?.kind === 'fee' && <FeeDetail view={view} />}
      </section>
    </>
  );
}

// ─── Diagrama SVG ───────────────────────────────────────────

const W = 920;
const BOX_W = 270;
const ROW_H = 62;
const GAP = 12;
const CENTER_X = W / 2;
const MAX_TRUNK = 150;

interface Row {
  key: string;
  sel: Selection;
  color: string;
  value: bigint | null;
  title: string;
  amount: string;
  sub: string;
  dashed?: boolean;
  hint?: string;
}

function FlowDiagram({ view, sel, onSelect }: { view: TxView; sel: Selection; onSelect: (s: Selection) => void }) {
  const left: Row[] = view.inputs.map((i: InputView) => {
    // La coinbase no gasta nada: dibujamos su cinta con lo que crea (Σ salidas)
    const coinbase = i.status === 'coinbase';
    return {
      key: `in${i.index}`,
      sel: { kind: 'in', index: i.index },
      color: coinbase ? COINBASE_COLOR : i.script ? TYPE_COLOR[i.script.type] : UNKNOWN_COLOR,
      value: coinbase ? view.totalOut : i.value,
      title: `#${i.index} · ${coinbase ? 'Coinbase' : i.script?.label ?? '¿?'}`,
      amount: coinbase ? 'monedas nuevas' : i.value !== null ? `${formatBtc(i.value)} BTC` : 'importe desconocido',
      sub: coinbase
        ? 'subvención + comisiones del bloque'
        : i.script?.address ? shortStr(i.script.address, 14, 8) : `${shortStr(i.prevTxId, 8, 4)}:${i.prevVout}`,
      dashed: !coinbase && i.value === null,
      hint: i.status === 'verified' ? '✓' : i.status === 'mismatch' ? '✗' : undefined,
    };
  });

  const right: Row[] = view.outputs.map((o: OutputView) => ({
    key: `out${o.index}`,
    sel: { kind: 'out', index: o.index },
    color: TYPE_COLOR[o.script.type],
    value: o.value,
    title: `#${o.index} · ${o.script.label}`,
    amount: `${formatBtc(o.value)} BTC`,
    sub: o.script.address
      ? shortStr(o.script.address, 14, 8)
      : o.opReturnText ? `«${shortStr(o.opReturnText, 24, 0)}»` : 'sin dirección',
    hint: o.hints.some(h => /cambio/.test(h)) ? '¿cambio?' : o.hints.some(h => /pago/.test(h)) ? '¿pago?' : undefined,
  }));
  if (view.fee !== null) {
    right.push({
      key: 'fee', sel: { kind: 'fee' }, color: FEE_COLOR, value: view.fee,
      title: 'Comisión → minero', amount: `${formatSatsBig(view.fee)} sats`,
      sub: view.feeRate !== null ? `${view.feeRate.toFixed(2)} sat/vB` : '',
    });
  }

  const rows = Math.max(left.length, right.length);
  const H = rows * (ROW_H + GAP) + GAP;
  const colTop = (n: number) => (H - n * (ROW_H + GAP) + GAP) / 2;

  // Escala: el lado con más valor define el grosor total del "tronco"
  const sum = (rs: Row[]) => rs.reduce((s, r) => s + (r.value ?? 0n), 0n);
  const total = Number(sum(left) > sum(right) ? sum(left) : sum(right)) || 1;
  const trunk = Math.min(MAX_TRUNK, H - 2 * GAP);
  const width = (r: Row) => (r.value === null ? 2 : Math.max(2, (Number(r.value) / total) * trunk));

  const ribbons = (rs: Row[], side: 'L' | 'R') => {
    const widths = rs.map(width);
    const stack = widths.reduce((a, b) => a + b, 0);
    let y = H / 2 - stack / 2;
    const top = colTop(rs.length);
    return rs.map((r, k) => {
      const w = widths[k];
      const yc = y + w / 2;
      y += w;
      const yb = top + k * (ROW_H + GAP) + ROW_H / 2;
      const [x1, y1, x2, y2] = side === 'L' ? [BOX_W, yb, CENTER_X, yc] : [CENTER_X, yc, W - BOX_W, yb];
      const xm = (x1 + x2) / 2;
      const active = isSelected(sel, r.sel);
      if (r.dashed) {
        return (
          <path key={r.key} d={`M ${x1} ${y1} C ${xm} ${y1}, ${xm} ${y2}, ${x2} ${y2}`}
            stroke={r.color} strokeWidth={2} strokeDasharray="4 4" fill="none"
            opacity={active ? 0.95 : 0.6} className="tf-ribbon" onClick={() => onSelect(r.sel)} />
        );
      }
      // Cinta con el grosor real en el tronco, que se estrecha para caber en su caja
      const boxW = Math.min(w, ROW_H - 12);
      const [a, b] = side === 'L' ? [boxW / 2, w / 2] : [w / 2, boxW / 2];
      const d = `M ${x1} ${y1 - a} C ${xm} ${y1 - a}, ${xm} ${y2 - b}, ${x2} ${y2 - b}`
        + ` L ${x2} ${y2 + b} C ${xm} ${y2 + b}, ${xm} ${y1 + a}, ${x1} ${y1 + a} Z`;
      return (
        <path key={r.key} d={d} fill={r.color} opacity={active ? 0.9 : 0.4}
          className="tf-ribbon" onClick={() => onSelect(r.sel)} />
      );
    });
  };

  const boxes = (rs: Row[], x: number) => {
    const top = colTop(rs.length);
    return rs.map((r, k) => {
      const y = top + k * (ROW_H + GAP);
      const active = isSelected(sel, r.sel);
      return (
        <g key={r.key} className="tf-box" onClick={() => onSelect(r.sel)}>
          <rect x={x} y={y} width={BOX_W} height={ROW_H} rx={8}
            className={active ? 'tf-box-rect active' : 'tf-box-rect'}
            stroke={r.color} strokeDasharray={r.dashed ? '4 3' : undefined} />
          <rect x={x} y={y} width={5} height={ROW_H} rx={2} fill={r.color} />
          <text x={x + 14} y={y + 18} className="tf-box-title">{r.title}</text>
          {r.hint && <text x={x + BOX_W - 10} y={y + 18} textAnchor="end" className="tf-box-hint">{r.hint}</text>}
          <text x={x + 14} y={y + 37} className="tf-box-amount">{r.amount}</text>
          <text x={x + 14} y={y + 53} className="tf-box-sub">{r.sub}</text>
        </g>
      );
    });
  };

  const stackL = left.map(width).reduce((a, b) => a + b, 0);
  const stackR = right.map(width).reduce((a, b) => a + b, 0);
  const trunkH = Math.max(stackL, stackR, 24);

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="tf-svg" role="img" aria-label="Diagrama de entradas y salidas">
      {ribbons(left, 'L')}
      {ribbons(right, 'R')}
      <rect x={CENTER_X - 7} y={H / 2 - trunkH / 2} width={14} height={trunkH} rx={4} className="tf-trunk" />
      <text x={CENTER_X} y={H / 2 - trunkH / 2 - 8} textAnchor="middle" className="tf-trunk-label">tx</text>
      {boxes(left, 0)}
      {boxes(right, W - BOX_W)}
    </svg>
  );
}

function isSelected(a: Selection, b: Selection): boolean {
  if (!a || !b || a.kind !== b.kind) return false;
  return a.kind === 'fee' || (a.index === (b as { index: number }).index);
}

// ─── Paneles de detalle ─────────────────────────────────────

const STATUS_TEXT = {
  verified: { cls: 'ok', text: '✓ importe verificado: el hash de la tx previa es el txid del outpoint' },
  mismatch: { cls: 'bad', text: '✗ la tx previa no hashea al txid del outpoint — importe rechazado' },
  missing: { cls: 'warn', text: 'tx previa no disponible: importe y tipo de script desconocidos' },
  coinbase: { cls: 'ok', text: 'coinbase: no gasta ningún UTXO, crea monedas nuevas' },
} as const;

function InputDetail({ input }: { input: InputView }) {
  const st = STATUS_TEXT[input.status];
  return (
    <div>
      <h3>Entrada #{input.index}</h3>
      <p className="tf-note">
        Una entrada no contiene importe ni dirección: sólo <strong>apunta</strong> a un output anterior
        (outpoint) y aporta la prueba de que puede gastarlo.
      </p>
      <dl className="tf-fields">
        <dt>Outpoint</dt><dd><code className="wrap">{input.prevTxId}:{input.prevVout}</code></dd>
        <dt>Estado</dt><dd className={st.cls}>{st.text}</dd>
        {input.value !== null && <><dt>Importe</dt><dd>{formatBtc(input.value)} BTC · {formatSatsBig(input.value)} sats</dd></>}
        {input.script && <><dt>Tipo</dt><dd>{input.script.label}</dd></>}
        {input.script?.address && <><dt>Dirección</dt><dd><code className="wrap">{input.script.address}</code></dd></>}
        <dt>Desbloqueo</dt><dd>{input.spend}</dd>
        {input.sighashes.length > 0 && <><dt>Sighash</dt><dd>{input.sighashes.join(', ')}</dd></>}
        <dt>nSequence</dt>
        <dd><code>0x{input.sequence.toString(16).padStart(8, '0')}</code> — {input.sequenceInfo}</dd>
        {input.scriptSig.length > 0 && (
          <>
            <dt>scriptSig</dt>
            <dd><code className="wrap">{disassemble(input.scriptSig).map(op => shortStr(op, 40, 12)).join(' ')}</code></dd>
          </>
        )}
        {input.witness.length > 0 && (
          <>
            <dt>Witness</dt>
            <dd>
              <ol className="tf-witness">
                {input.witness.map((w, k) => (
                  <li key={k}><span className="tf-k">{w.length} B</span> <code>{w.length ? shortStr(bytesToHex(w), 32, 16) : '(vacío)'}</code></li>
                ))}
              </ol>
            </dd>
          </>
        )}
      </dl>
    </div>
  );
}

function OutputDetail({ output }: { output: OutputView }) {
  return (
    <div>
      <h3>Salida #{output.index}</h3>
      <p className="tf-note">
        Cada salida es un UTXO nuevo: un importe y un <strong>scriptPubKey</strong> (la condición para
        gastarlo). La «dirección» es sólo una forma legible de escribir ese script.
      </p>
      <dl className="tf-fields">
        <dt>Importe</dt><dd>{formatBtc(output.value)} BTC · {formatSatsBig(output.value)} sats</dd>
        <dt>Tipo</dt><dd>{output.script.label}</dd>
        {output.script.address && <><dt>Dirección</dt><dd><code className="wrap">{output.script.address}</code></dd></>}
        <dt>scriptPubKey</dt><dd><code className="wrap">{disassemble(output.scriptPubKey).join(' ')}</code></dd>
        {output.opReturnText && <><dt>Datos</dt><dd>«{output.opReturnText}»</dd></>}
        {output.script.type === 'op_return' && (
          <><dt>Nota</dt><dd>OP_RETURN hace el output ingastable a propósito: sirve para anclar datos en la cadena sin engordar el conjunto de UTXOs.</dd></>
        )}
      </dl>
      {output.hints.length > 0 && (
        <div className="tf-hints">
          <strong>Pistas de privacidad (heurísticas, no certezas):</strong>
          <ul>{output.hints.map((h, k) => <li key={k}>{h}</li>)}</ul>
          <span className="tf-note">Así razona un analista de cadena para adivinar cuál es el cambio. Sparrow lo sabe con certeza porque conoce tus direcciones.</span>
        </div>
      )}
    </div>
  );
}

function FeeDetail({ view }: { view: TxView }) {
  if (view.fee === null || view.totalIn === null) return null;
  return (
    <div>
      <h3>Comisión</h3>
      <p className="tf-note">
        No hay ningún output «para el minero»: la comisión es lo que <strong>falta</strong>. El minero la
        reclama sumándola a su propia transacción coinbase.
      </p>
      <div className="tf-formula">
        <div>{formatBtc(view.totalIn)} BTC <span className="tf-k">entradas</span></div>
        <div>− {formatBtc(view.totalOut)} BTC <span className="tf-k">salidas</span></div>
        <div className="tf-formula-total">= {formatSatsBig(view.fee)} sats</div>
        <div>{formatSatsBig(view.fee)} sats ÷ {view.vsize} vB = <strong>{view.feeRate!.toFixed(2)} sat/vB</strong></div>
      </div>
      <p className="tf-note">
        Los mineros ordenan por sat/vB, no por comisión total: les importa cuánto pagas por el espacio que
        ocupas en el bloque.
        {view.signalsRbf && ' Esta tx señala RBF, así que mientras no se confirme se podría sustituir por otra con más comisión.'}
      </p>
    </div>
  );
}
