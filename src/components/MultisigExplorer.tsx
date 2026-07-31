/**
 * Multisig Explorer — Fase 4 (sección interactiva)
 *
 * Dos modos:
 *  - Semillas de prueba: genera cosignatarios (masters) y deriva todo.
 *  - Watch-only: pega las xpubs de los cosignatarios y deriva direcciones y
 *    descriptor SIN ninguna clave privada (CKDpub). Es como se monta un multisig
 *    real: cada cosignatario aporta su xpub, nadie comparte su semilla.
 *
 * Rendimiento: la derivación usa curva elíptica en JS puro (lenta). El trabajo
 * caro va con estado de carga y debounce; cambiar el umbral m reusa las pubkeys
 * ya derivadas y es instantáneo. Ver [[feedback_debounce]].
 */

import { useState, useEffect, useMemo } from 'react';
import { masterKeyFromSeed, deriveMultisigKey, parseXpub, type HDNode } from '../crypto/hdwallet';
import {
  buildWshSortedMulti,
  deriveIndexPubkeys,
  p2wshMultisigAddress,
} from '../crypto/descriptor';
import './MultisigExplorer.css';

const MAX_N = 5;
const ADDR_COUNT = 3;
const DEBOUNCE_MS = 300;

type Mode = 'seeds' | 'watch';

interface Cosigner {
  keyExpression: string;
  fingerprint: string;
  path: string;
  node: HDNode;
}

interface Derived {
  sig: string;
  cosigners?: Cosigner[];
  indexPubkeys?: Uint8Array[][];
  mainnet?: boolean;
  error?: string;
}

function randomSeedHex(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  return bytes;
}

/** Parsea lo que pega el usuario: una xpub o `[huella/ruta]xpub` (con o sin sufijo /..). */
function parseCosignerInput(raw: string): { cosigner?: Cosigner; mainnet?: boolean; error?: string } {
  const input = raw.trim();
  if (!input) return { error: 'vacío' };

  let origin = '';
  let rest = input;
  if (input.startsWith('[')) {
    const close = input.indexOf(']');
    if (close === -1) return { error: 'falta el corchete de cierre ]' };
    origin = input.slice(1, close);
    rest = input.slice(close + 1);
  }
  const xpub = rest.split('/')[0].trim(); // descarta cualquier sufijo /0/* etc.

  try {
    const { node, mainnet } = parseXpub(xpub);
    const fingerprint = origin ? origin.split('/')[0] : '—';
    const path = origin ? 'm/' + origin.split('/').slice(1).join('/') : '—';
    const keyExpression = origin ? `[${origin}]${xpub}` : xpub;
    return { cosigner: { keyExpression, fingerprint, path, node }, mainnet };
  } catch (e) {
    return { error: (e as Error).message };
  }
}

export function MultisigExplorer() {
  const [mode, setMode] = useState<Mode>('seeds');
  const [network, setNetwork] = useState<'mainnet' | 'testnet'>('mainnet');
  const [n, setN] = useState(3);
  const [m, setM] = useState(2);
  const [seedsPool, setSeedsPool] = useState<string[]>(
    () => Array.from({ length: MAX_N }, () => randomSeedHex()),
  );
  const [xpubInputs, setXpubInputs] = useState<string[]>(() => Array<string>(MAX_N).fill(''));
  const [derived, setDerived] = useState<Derived | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const copyText = (id: string, text: string) => {
    navigator.clipboard?.writeText(text).then(() => {
      setCopiedId(id);
      setTimeout(() => setCopiedId(cur => (cur === id ? null : cur)), 1500);
    });
  };

  // Validación barata (por campo) del modo watch-only — feedback inmediato al pegar.
  const fieldStatus = useMemo(
    () => (mode === 'watch' ? xpubInputs.slice(0, n).map(parseCosignerInput) : []),
    [mode, xpubInputs, n],
  );

  const seedsSig = `seeds|${network}|${n}|${seedsPool[0]}`;
  const watchSig = `watch|${n}|${xpubInputs.slice(0, n).join('~')}`;
  const sig = mode === 'seeds' ? seedsSig : watchSig;
  const loading = !derived || derived.sig !== sig;

  // ── Trabajo CARO (curva elíptica) — con debounce ──
  useEffect(() => {
    const timer = setTimeout(() => {
      try {
        if (mode === 'seeds') {
          const mainnet = network === 'mainnet';
          const coinType = mainnet ? 0 : 1;
          const masters = seedsPool.slice(0, n).map(s => masterKeyFromSeed(hexToBytes(s)));
          const keys = masters.map(master => deriveMultisigKey(master, 'p2wsh', 0, coinType, mainnet));
          const cosigners: Cosigner[] = keys.map(k => ({
            keyExpression: k.keyExpression, fingerprint: k.fingerprint, path: k.path, node: k.node,
          }));
          const indexPubkeys = deriveIndexPubkeys(keys.map(k => k.node), 0, ADDR_COUNT);
          setDerived({ sig: seedsSig, cosigners, indexPubkeys, mainnet });
        } else {
          const parsed = xpubInputs.slice(0, n).map(parseCosignerInput);
          const bad = parsed.findIndex(p => !p.cosigner);
          if (bad !== -1) {
            setDerived({ sig: watchSig, error: `Cosignatario #${bad + 1}: ${parsed[bad].error}` });
            return;
          }
          const cosigners = parsed.map(p => p.cosigner!);
          const mainnet = parsed[0].mainnet!;
          if (parsed.some(p => p.mainnet !== mainnet)) {
            setDerived({ sig: watchSig, error: 'Las xpubs mezclan mainnet y testnet' });
            return;
          }
          const indexPubkeys = deriveIndexPubkeys(cosigners.map(c => c.node), 0, ADDR_COUNT);
          setDerived({ sig: watchSig, cosigners, indexPubkeys, mainnet });
        }
      } catch (e) {
        setDerived({ sig, error: (e as Error).message });
      }
    }, DEBOUNCE_MS);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, n, network, seedsPool, xpubInputs]);

  // ── Trabajo BARATO (sin curva elíptica) — reacciona a m al instante ──
  const result = useMemo(() => {
    if (!derived || !derived.cosigners || !derived.indexPubkeys) return null;
    const { cosigners, indexPubkeys, mainnet } = derived;
    const nEff = cosigners.length;
    const mEff = Math.min(m, nEff);
    const descriptor = buildWshSortedMulti(cosigners, mEff, '<0;1>');
    const addresses = indexPubkeys.map((pks, i) => ({
      index: i,
      address: p2wshMultisigAddress(pks, mEff, mainnet!).address,
    }));
    return { cosigners, descriptor, addresses, mEff, nEff, mainnet: mainnet! };
  }, [derived, m]);

  const setKeysTotal = (value: number) => {
    setN(value);
    if (m > value) setM(value);
  };

  const setXpubAt = (i: number, value: string) => {
    setXpubInputs(prev => { const next = [...prev]; next[i] = value; return next; });
  };

  // Rellena los campos con xpubs de ejemplo (derivadas de semillas de prueba).
  const fillExamples = () => {
    const exprs = Array.from({ length: n }, (_, i) =>
      deriveMultisigKey(masterKeyFromSeed(new Uint8Array(16).fill(i + 7)), 'p2wsh', 0, 0, true).keyExpression,
    );
    setXpubInputs(prev => { const next = [...prev]; for (let i = 0; i < n; i++) next[i] = exprs[i]; return next; });
  };

  return (
    <div className="mse">
      <header className="mse-header">
        <span className="mse-phase-tag">Fase 4 · Interactivo</span>
        <h1>Multisig Explorer</h1>
        <p className="mse-subtitle">
          Observa cómo se ensambla el descriptor <code>wsh(sortedmulti(m,…))</code> y sus
          direcciones P2WSH — a partir de semillas de prueba, o pegando solo las xpubs (watch-only).
        </p>
      </header>

      {/* ── Selector de modo ── */}
      <div className="mse-mode">
        <button className={mode === 'seeds' ? 'active' : ''} onClick={() => setMode('seeds')}>
          Semillas de prueba
        </button>
        <button className={mode === 'watch' ? 'active' : ''} onClick={() => setMode('watch')}>
          Watch-only (pegar xpubs)
        </button>
      </div>

      {mode === 'seeds' ? (
        <div className="mse-warn">
          Semillas <strong>aleatorias de prueba</strong>, generadas en el navegador solo para este
          ejemplo. Nunca introduzcas aquí una semilla con fondos reales.
        </div>
      ) : (
        <div className="mse-info">
          <strong>No hay ninguna semilla aquí.</strong> Las direcciones y el descriptor se derivan
          solo de las xpubs (derivación pública, CKDpub) — justo lo que puede compartir cada
          cosignatario sin exponer su clave privada.
        </div>
      )}

      {/* ── Controles comunes ── */}
      <div className="mse-controls">
        {mode === 'seeds' && (
          <div className="mse-control">
            <span className="mse-control-label">Red</span>
            <div className="mse-toggle">
              <button className={network === 'mainnet' ? 'active' : ''} onClick={() => setNetwork('mainnet')}>
                mainnet
              </button>
              <button className={network === 'testnet' ? 'active' : ''} onClick={() => setNetwork('testnet')}>
                testnet
              </button>
            </div>
          </div>
        )}

        <label className="mse-control">
          <span className="mse-control-label">Cosignatarios · <strong>n = {n}</strong></span>
          <input type="range" min={2} max={MAX_N} value={n}
            onChange={e => setKeysTotal(Number(e.target.value))} />
        </label>

        <label className="mse-control">
          <span className="mse-control-label">Umbral · <strong>m = {m}</strong> (instantáneo)</span>
          <input type="range" min={1} max={n} value={m}
            onChange={e => setM(Number(e.target.value))} />
        </label>

        {mode === 'seeds' ? (
          <button className="mse-regen"
            onClick={() => setSeedsPool(Array.from({ length: MAX_N }, () => randomSeedHex()))}>
            ↻ Regenerar semillas
          </button>
        ) : (
          <button className="mse-regen" onClick={fillExamples}>
            Rellenar con ejemplos
          </button>
        )}
      </div>

      {/* ── Campos de xpub (solo watch-only) ── */}
      {mode === 'watch' && (
        <div className="mse-xpubs">
          {Array.from({ length: n }, (_, i) => {
            const st = fieldStatus[i];
            const empty = !xpubInputs[i]?.trim();
            return (
              <div key={i} className="mse-xpub-field">
                <span className="mse-xpub-num">#{i + 1}</span>
                <input
                  className={`mse-xpub-input ${empty ? '' : st?.cosigner ? 'ok' : 'bad'}`}
                  value={xpubInputs[i] ?? ''}
                  onChange={e => setXpubAt(i, e.target.value)}
                  placeholder="[huella/48h/0h/0h/2h]xpub…  o  xpub…"
                  spellCheck={false}
                />
                <span className="mse-xpub-status">
                  {empty ? '' : st?.cosigner ? '✓' : `✗ ${st?.error ?? ''}`}
                </span>
              </div>
            );
          })}
        </div>
      )}

      <div className="mse-scheme-line">
        Esquema: <strong>{result?.mEff ?? m}-of-{result?.nEff ?? n}</strong>
        {result && result.mEff < result.nEff && (
          <span className="mse-scheme-note">
            {' '}· tolera perder {result.nEff - result.mEff} llave{result.nEff - result.mEff > 1 ? 's' : ''}
          </span>
        )}
        {result && <span className="mse-scheme-note"> · {result.mainnet ? 'mainnet' : 'testnet'}</span>}
      </div>

      {loading && (
        <div className="mse-loading">
          <span className="mse-spinner" /> Derivando claves (curva elíptica en JS, es lento a propósito)…
        </div>
      )}

      {!loading && derived?.error && (
        <div className="mse-error">
          {mode === 'watch' && !xpubInputs.slice(0, n).some(s => s.trim())
            ? 'Pega las xpubs de los cosignatarios (o usa «Rellenar con ejemplos»).'
            : derived.error}
        </div>
      )}

      {result && !loading && (
        <>
          {/* ── Cosignatarios ── */}
          <section className="mse-section">
            <span className="mse-label">Cosignatarios · expresión de clave (origen + xpub)</span>
            <div className="mse-cosigners">
              {result.cosigners.map((k, i) => (
                <div key={i} className="mse-cosigner">
                  <span className="mse-cosigner-idx">#{i + 1}</span>
                  <div className="mse-cosigner-body">
                    <div className="mse-cosigner-meta">
                      huella <code>{k.fingerprint}</code> · ruta <code>{k.path}</code>
                    </div>
                    <code className="mse-cosigner-key">{k.keyExpression}</code>
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* ── Descriptor ── */}
          <section className="mse-section">
            <div className="mse-label-row">
              <span className="mse-label">Descriptor de la wallet</span>
              <button className="mse-copy" onClick={() => copyText('desc', result.descriptor)}>
                {copiedId === 'desc' ? '✓ copiado' : 'copiar'}
              </button>
            </div>
            <div className="mse-descriptor">
              <code>{result.descriptor}</code>
            </div>
            <p className="mse-hint">
              Esto es lo que <strong>cada cosignatario debe guardar</strong> (junto a su propia
              semilla): no gasta fondos, pero sin él no se recuperan. El <code>#…</code> final es el
              checksum que detecta copias erróneas.
            </p>
          </section>

          {/* ── Direcciones ── */}
          <section className="mse-section">
            <span className="mse-label">Primeras direcciones de recepción (rama 0)</span>
            <div className="mse-addresses">
              {result.addresses.map(a => (
                <div key={a.index} className="mse-addr">
                  <span className="mse-addr-path">/0/{a.index}</span>
                  <code className="mse-addr-value">{a.address}</code>
                  <button
                    className="mse-addr-copy"
                    onClick={() => copyText(`addr-${a.index}`, a.address)}
                  >
                    {copiedId === `addr-${a.index}` ? '✓' : 'copiar'}
                  </button>
                </div>
              ))}
            </div>
            <p className="mse-hint">
              El orden de los cosignatarios no cambia estas direcciones: <code>sortedmulti</code>
              ordena las claves (BIP67) antes de construir cada script.
            </p>
          </section>
        </>
      )}
    </div>
  );
}
