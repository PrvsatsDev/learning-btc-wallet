/**
 * Timelock Explorer (estilo Liana) — Fase 4 (sección interactiva)
 *
 * VER y PROBAR una bóveda Taproot con dos rutas de gasto:
 *   · PRIMARIA     — la llave de siempre, gasta cuando quiera.
 *   · RECUPERACIÓN — otra llave que SOLO funciona pasado un retardo (OP_CSV).
 *
 * El corazón visual: un deslizador de «bloques transcurridos desde que se recibió
 * el UTXO» (= nSequence del input). Por debajo del retardo, la recuperación
 * FALLA; al alcanzarlo, VALIDA. Se firma de verdad (Schnorr) y se ejecuta el
 * witness con el intérprete, que aplica el timelock (BIP68/BIP112).
 *
 * Toda la cripto es la de timelock.ts (verificada en timelock.test.ts). El trabajo
 * pesado (curva elíptica en JS) se hace con estado de carga. Ver [[feedback_debounce]].
 */

import { useState, useEffect, useMemo } from 'react';
import { buildLianaVault, spendVault, type LianaVault, type SpendResult } from '../crypto/timelock';
import { disassemble } from '../crypto/script';
import { getPublicKey } from '../crypto/secp256k1';
import { bytesToBigint } from '../crypto/hmac';
import './TimelockExplorer.css';

const DEBOUNCE_MS = 250;
const MAX_TIMELOCK = 20;

function to32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = n;
  for (let i = 31; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  return bytes;
}
function randomHex32(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}
function shortHex(hex: string, head = 10, tail = 6): string {
  return hex.length <= head + tail + 1 ? hex : `${hex.slice(0, head)}…${hex.slice(-tail)}`;
}

interface Derived {
  sig: string;
  primaryPriv: bigint;
  recoveryPriv: bigint;
  primaryXonly: Uint8Array;
  recoveryXonly: Uint8Array;
}

export function TimelockExplorer() {
  const [network, setNetwork] = useState<'mainnet' | 'testnet'>('mainnet');
  const [timelock, setTimelock] = useState(6);
  const [primarySeed, setPrimarySeed] = useState(randomHex32);
  const [recoverySeed, setRecoverySeed] = useState(randomHex32);
  const [derived, setDerived] = useState<Derived | null>(null);
  const [path, setPath] = useState<'primary' | 'recovery'>('recovery');
  const [elapsed, setElapsed] = useState(6); // bloques transcurridos (nSequence en recuperación)
  const [spend, setSpend] = useState<SpendResult | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const copyText = (id: string, text: string) => {
    navigator.clipboard?.writeText(text).then(() => {
      setCopiedId(id);
      setTimeout(() => setCopiedId(cur => (cur === id ? null : cur)), 1500);
    });
  };

  const sig = `${primarySeed}|${recoverySeed}`;
  const loading = !derived || derived.sig !== sig;

  // ── Trabajo CARO: derivar las dos claves (curva elíptica) ──
  useEffect(() => {
    const timer = setTimeout(() => {
      const primaryPriv = bytesToBigint(hexToBytes(primarySeed));
      const recoveryPriv = bytesToBigint(hexToBytes(recoverySeed));
      setDerived({
        sig,
        primaryPriv, recoveryPriv,
        primaryXonly: to32(getPublicKey(primaryPriv)!.x),
        recoveryXonly: to32(getPublicKey(recoveryPriv)!.x),
      });
      setSpend(null);
    }, DEBOUNCE_MS);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [primarySeed, recoverySeed]);

  // ── Trabajo medio: construir la bóveda (tweak Taproot) ──
  const vault: LianaVault | null = useMemo(() => {
    if (!derived) return null;
    return buildLianaVault({
      primaryXonly: derived.primaryXonly,
      recoveryXonly: derived.recoveryXonly,
      timelockBlocks: timelock,
      mainnet: network === 'mainnet',
    });
  }, [derived, timelock, network]);

  const doSpend = () => {
    if (!vault || !derived) return;
    if (path === 'primary') {
      setSpend(spendVault({ vault, path: 'primary', privateKey: derived.primaryPriv }));
    } else {
      setSpend(spendVault({ vault, path: 'recovery', privateKey: derived.recoveryPriv, nSequence: elapsed }));
    }
  };

  const matured = elapsed >= timelock;

  return (
    <div className="tl">
      <header className="tl-header">
        <span className="tl-phase-tag">Fase 4 · Interactivo</span>
        <h1>Timelock Explorer <span className="tl-liana">estilo Liana</span></h1>
        <p className="tl-subtitle">
          Una bóveda Taproot con <strong>dos rutas</strong>: una llave <strong>primaria</strong> que
          gasta siempre, y una de <strong>recuperación</strong> que solo funciona tras un retardo
          (<code>OP_CHECKSEQUENCEVERIFY</code>). Mueve el deslizador de bloques y mira cómo la
          recuperación pasa de <em>inválida</em> a <em>válida</em>.
        </p>
      </header>

      <div className="tl-info">
        <strong>Dead man's switch on-chain.</strong> Si pierdes la llave primaria (o te ocurre algo),
        pasado el timelock la llave de recuperación puede mover los fondos. Cada ruta es una
        <strong> hoja del árbol Taproot</strong>: al gastar revelas solo la que usas, así nadie ve
        la política de recuperación. Clave interna <code>NUMS</code> → el key-path queda inutilizado.
      </div>

      {/* ── Controles ── */}
      <div className="tl-controls">
        <div className="tl-control">
          <span className="tl-control-label">Red</span>
          <div className="tl-toggle">
            <button className={network === 'mainnet' ? 'active' : ''} onClick={() => { setNetwork('mainnet'); setSpend(null); }}>mainnet</button>
            <button className={network === 'testnet' ? 'active' : ''} onClick={() => { setNetwork('testnet'); setSpend(null); }}>testnet</button>
          </div>
        </div>
        <label className="tl-control">
          <span className="tl-control-label">Retardo de recuperación · <strong>{timelock} bloques</strong></span>
          <input type="range" min={1} max={MAX_TIMELOCK} value={timelock}
            onChange={e => { const v = Number(e.target.value); setTimelock(v); setElapsed(v); setSpend(null); }} />
        </label>
        <button className="tl-regen" onClick={() => { setPrimarySeed(randomHex32()); setSpend(null); }}>↻ Clave primaria</button>
        <button className="tl-regen" onClick={() => { setRecoverySeed(randomHex32()); setSpend(null); }}>↻ Clave recuperación</button>
      </div>

      {loading && (
        <div className="tl-loading"><span className="tl-spinner" /> Derivando claves y construyendo la bóveda (curva elíptica en JS)…</div>
      )}

      {vault && !loading && (
        <>
          {/* ── Dirección ── */}
          <section className="tl-section">
            <div className="tl-label-row">
              <span className="tl-label">Dirección de la bóveda (recibe aquí)</span>
              <button className="tl-copy" onClick={() => copyText('addr', vault.address)}>{copiedId === 'addr' ? '✓ copiado' : 'copiar'}</button>
            </div>
            <div className="tl-address"><code>{vault.address}</code></div>
          </section>

          {/* ── Descriptor ── */}
          <section className="tl-section">
            <div className="tl-label-row">
              <span className="tl-label">Descriptor (estilo Liana / miniscript)</span>
              <button className="tl-copy" onClick={() => copyText('desc', vault.descriptor)}>{copiedId === 'desc' ? '✓ copiado' : 'copiar'}</button>
            </div>
            <div className="tl-descriptor"><code>{vault.descriptor}</code></div>
            <p className="tl-hint">
              <code>pk(primaria)</code> <strong>o</strong> <code>and_v(v:older({timelock}), pk(recuperación))</code>:
              la primaria gasta ya; la recuperación exige <code>older({timelock})</code> = {timelock} bloques de maduración.
            </p>
          </section>

          {/* ── Las dos hojas ── */}
          <section className="tl-section">
            <span className="tl-label">Las dos rutas (hojas del árbol Taproot)</span>
            <div className="tl-leaves">
              <div className="tl-leaf primary">
                <div className="tl-leaf-head">🔑 Primaria — gasta siempre</div>
                <div className="tl-script">
                  {disassemble(vault.primaryLeaf).map((op, i) => (
                    <span key={i} className={`tl-op ${op.startsWith('OP_') ? 'kw' : ''}`}>
                      {op.startsWith('PUSH(') ? `PUSH ${shortHex(op.slice(5, -1), 8, 6)}` : op}
                    </span>
                  ))}
                </div>
              </div>
              <div className="tl-leaf recovery">
                <div className="tl-leaf-head">⏳ Recuperación — tras {timelock} bloques</div>
                <div className="tl-script">
                  {disassemble(vault.recoveryLeaf).map((op, i) => (
                    <span key={i} className={`tl-op ${op.startsWith('OP_') ? 'kw' : ''}`}>
                      {op.startsWith('PUSH(') ? `PUSH ${shortHex(op.slice(5, -1), 8, 6)}` : op}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </section>

          {/* ── Probar gasto ── */}
          <section className="tl-section tl-spend">
            <span className="tl-label">Prueba un gasto — ¿por qué ruta?</span>
            <div className="tl-paths">
              <button className={`tl-path ${path === 'primary' ? 'on' : ''}`} onClick={() => { setPath('primary'); setSpend(null); }}>🔑 Primaria</button>
              <button className={`tl-path ${path === 'recovery' ? 'on' : ''}`} onClick={() => { setPath('recovery'); setSpend(null); }}>⏳ Recuperación</button>
            </div>

            {path === 'recovery' && (
              <div className="tl-elapsed">
                <span className="tl-control-label">
                  Bloques transcurridos desde que se recibió el UTXO (nSequence) ·{' '}
                  <strong className={matured ? 'ok' : 'low'}>{elapsed}</strong> / {timelock}
                </span>
                <input type="range" min={0} max={MAX_TIMELOCK} value={elapsed}
                  onChange={e => { setElapsed(Number(e.target.value)); setSpend(null); }} />
                <div className={`tl-maturity ${matured ? 'ok' : 'low'}`}>
                  {matured
                    ? `✓ El UTXO ha madurado (${elapsed} ≥ ${timelock}) — la recuperación debería validar`
                    : `⏳ Aún inmaduro (${elapsed} < ${timelock}) — OP_CSV rechazará el gasto`}
                </div>
              </div>
            )}

            <button className="tl-sign-btn" onClick={doSpend}>Firmar y probar gasto →</button>

            {spend && (
              <>
                <div className={`tl-verdict ${spend.valid ? 'good' : 'bad'}`}>
                  {spend.valid
                    ? `✓ Witness válido — este gasto por la ruta ${spend.path === 'primary' ? 'primaria' : 'de recuperación'} se aceptaría en la red`
                    : `✗ El witness NO valida${spend.error ? ` — ${spend.error}` : ''}`}
                </div>
                <div className="tl-txmeta">
                  <span>tx version <strong>{spend.txVersion}</strong></span>
                  <span>nSequence <strong>{spend.nSequence === 0xffffffff ? '0xffffffff (final)' : spend.nSequence}</strong></span>
                </div>
                <span className="tl-label tl-label--mt">Witness montado</span>
                <div className="tl-witness">
                  {spend.witness.map((w, i) => (
                    <div key={i} className={`tl-witem ${w.kind}`}>
                      <span className="tl-witem-idx">{i}</span>
                      <span className="tl-witem-label">{w.label}</span>
                      <code className="tl-witem-hex">{shortHex(w.hex, 14, 8)}</code>
                    </div>
                  ))}
                </div>
                <div className="tl-label-row tl-label--mt">
                  <span className="tl-label">Transacción cruda · TxID {shortHex(spend.txid, 10, 8)}</span>
                  <button className="tl-copy" onClick={() => copyText('rawtx', spend.txHex)}>{copiedId === 'rawtx' ? '✓ copiado' : 'copiar'}</button>
                </div>
                <div className="tl-raw"><code>{spend.txHex}</code></div>
              </>
            )}
          </section>
        </>
      )}
    </div>
  );
}
