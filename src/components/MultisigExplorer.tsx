/**
 * Multisig Explorer — Fase 4 (sección interactiva)
 *
 * Genera varios cosignatarios (semillas de PRUEBA), deriva sus xpubs BIP48 con
 * origen, ensambla el descriptor wsh(sortedmulti(m,...)) con su checksum y muestra
 * las primeras direcciones P2WSH. Es la contraparte práctica de la guía conceptual.
 *
 * Rendimiento: derivar claves usa curva elíptica en JS puro (~lento). Por eso el
 * trabajo caro (generar/regenerar/cambiar de red) va detrás de un estado de carga
 * y con debounce; cambiar el umbral m reusa las pubkeys ya derivadas y es instantáneo.
 * Ver [[feedback_debounce]].
 */

import { useState, useEffect, useMemo } from 'react';
import { masterKeyFromSeed, deriveMultisigKey } from '../crypto/hdwallet';
import {
  buildWshSortedMulti,
  deriveIndexPubkeys,
  p2wshMultisigAddress,
} from '../crypto/descriptor';
import './MultisigExplorer.css';

const MAX_N = 5;         // máximo de cosignatarios que se generan
const ADDR_COUNT = 3;    // direcciones de recepción a mostrar
const DEBOUNCE_MS = 300; // espera antes de recalcular lo caro

function randomSeedHex(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  return bytes;
}

function truncate(s: string, head = 24, tail = 12): string {
  return s.length <= head + tail + 1 ? s : `${s.slice(0, head)}…${s.slice(-tail)}`;
}

// Resultado del trabajo CARO (derivación con curva elíptica), cacheado.
interface Derived {
  keys: ReturnType<typeof deriveMultisigKey>[];
  indexPubkeys: Uint8Array[][]; // por índice, las n pubkeys sin ordenar
  mainnet: boolean;
  sig: string;                  // firma de los inputs con los que se derivó
}

export function MultisigExplorer() {
  const [network, setNetwork] = useState<'mainnet' | 'testnet'>('mainnet');
  const [n, setN] = useState(3);
  const [m, setM] = useState(2);
  const [seedsPool, setSeedsPool] = useState<string[]>(
    () => Array.from({ length: MAX_N }, () => randomSeedHex()),
  );
  const [derived, setDerived] = useState<Derived | null>(null);
  const [copied, setCopied] = useState(false);

  // Firma de las entradas CARAS (red, nº de cosignatarios, semilla). Si lo derivado
  // no corresponde a esta firma, estamos "cargando" — sin setState en el efecto.
  const sig = `${network}|${n}|${seedsPool[0]}`;
  const loading = !derived || derived.sig !== sig;

  // ── Trabajo CARO (curva elíptica) — con debounce ──
  useEffect(() => {
    const timer = setTimeout(() => {
      const mainnet = network === 'mainnet';
      const coinType = mainnet ? 0 : 1; // BIP48: 0 = Bitcoin, 1 = testnet
      const masters = seedsPool.slice(0, n).map(s => masterKeyFromSeed(hexToBytes(s)));
      const keys = masters.map(master => deriveMultisigKey(master, 'p2wsh', 0, coinType, mainnet));
      const indexPubkeys = deriveIndexPubkeys(keys.map(k => k.node), 0, ADDR_COUNT);
      setDerived({ keys, indexPubkeys, mainnet, sig: `${network}|${n}|${seedsPool[0]}` });
    }, DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [seedsPool, n, network]);

  // ── Trabajo BARATO (sin curva elíptica) — reacciona a m al instante ──
  const result = useMemo(() => {
    if (!derived) return null;
    const { keys, indexPubkeys, mainnet } = derived;
    const nEff = keys.length;                 // n real de lo ya derivado
    const mEff = Math.min(m, nEff);            // robustez durante el recálculo
    const descriptor = buildWshSortedMulti(keys, mEff, '<0;1>');
    const addresses = indexPubkeys.map((pks, i) => ({
      index: i,
      address: p2wshMultisigAddress(pks, mEff, mainnet).address,
    }));
    return { keys, descriptor, addresses, mEff, nEff };
  }, [derived, m]);

  const setKeysTotal = (value: number) => {
    setN(value);
    if (m > value) setM(value);
  };

  const copyDescriptor = () => {
    if (!result) return;
    navigator.clipboard?.writeText(result.descriptor).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };

  return (
    <div className="mse">
      <header className="mse-header">
        <span className="mse-phase-tag">Fase 4 · Interactivo</span>
        <h1>Multisig Explorer</h1>
        <p className="mse-subtitle">
          Genera cosignatarios de prueba, observa sus xpubs con origen, y mira cómo se ensambla el
          descriptor <code>wsh(sortedmulti(m,…))</code> con su checksum y las primeras direcciones.
        </p>
      </header>

      <div className="mse-warn">
        Semillas <strong>aleatorias de prueba</strong>, generadas en el navegador solo para este
        ejemplo. Nunca introduzcas aquí una semilla con fondos reales.
      </div>

      {/* ── Controles ── */}
      <div className="mse-controls">
        <div className="mse-control">
          <span className="mse-control-label">Red</span>
          <div className="mse-toggle">
            <button
              className={network === 'mainnet' ? 'active' : ''}
              onClick={() => setNetwork('mainnet')}
            >
              mainnet
            </button>
            <button
              className={network === 'testnet' ? 'active' : ''}
              onClick={() => setNetwork('testnet')}
            >
              testnet
            </button>
          </div>
        </div>

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

        <button
          className="mse-regen"
          onClick={() => setSeedsPool(Array.from({ length: MAX_N }, () => randomSeedHex()))}
        >
          ↻ Regenerar semillas
        </button>
      </div>

      <div className="mse-scheme-line">
        Esquema: <strong>{result?.mEff ?? m}-of-{result?.nEff ?? n}</strong>
        {result && result.mEff < result.nEff && (
          <span className="mse-scheme-note">
            {' '}· tolera perder {result.nEff - result.mEff} llave{result.nEff - result.mEff > 1 ? 's' : ''}
          </span>
        )}
      </div>

      {loading && (
        <div className="mse-loading">
          <span className="mse-spinner" /> Derivando claves (curva elíptica en JS, es lento a propósito)…
        </div>
      )}

      {result && !loading && (
        <>
          {/* ── Cosignatarios ── */}
          <section className="mse-section">
            <span className="mse-label">Cosignatarios · expresión de clave (origen + xpub)</span>
            <div className="mse-cosigners">
              {result.keys.map((k, i) => (
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
              <button className="mse-copy" onClick={copyDescriptor}>
                {copied ? '✓ copiado' : 'copiar'}
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
                  <code className="mse-addr-value">{truncate(a.address, 20, 10)}</code>
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
