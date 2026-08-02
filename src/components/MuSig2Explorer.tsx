/**
 * MuSig2 Explorer — Fase 4 (sección interactiva)
 *
 * VER cómo n firmantes producen UNA sola firma Schnorr (n-de-n key-path).
 * Recorre las DOS rondas de MuSig2 (BIP327) con todos los pasos intermedios:
 *
 *   Ronda 1 — claves y nonces:
 *     · cada firmante aporta su clave Pᵢ y DOS nonces R_{i,1}, R_{i,2}
 *     · L = H(P₁‖…‖Pₙ), coeficientes aᵢ = H(L,Pᵢ)  → defensa rogue-key
 *     · Q = Σ aᵢ·Pᵢ   (la clave pública agregada, lo que iría en tr(Q))
 *     · R₁=ΣR_{i,1}, R₂=ΣR_{i,2}, b=H(R₁‖R₂‖Q.x‖m), R=R₁+b·R₂
 *
 *   Ronda 2 — firmas parciales:
 *     · e = H(R.x‖Q.x‖m)  (challenge BIP340 normal)
 *     · sᵢ = kᵢ + e·aᵢ·dᵢ  → cada parcial se puede verificar por separado
 *     · s = Σ sᵢ  → firma (R.x, s)
 *
 * El PAYOFF: la firma agregada VERIFICA con el schnorrVerify normal contra Q.x.
 * Para la red es una firma Schnorr cualquiera → privacidad total, fees mínimos.
 * Solo es posible por la LINEALIDAD de Schnorr (ECDSA no lo permite).
 *
 * Toda la cripto es la de musig2.ts (verificada en musig2.test.ts). El trabajo
 * pesado (curva elíptica en JS puro) se hace con estado de carga. Ver
 * [[feedback_debounce]].
 */

import { useState, useEffect } from 'react';
import { runMuSig2Session, partialVerify, type Signer, type SecretNonce } from '../crypto/musig2';
import { schnorrVerify } from '../crypto/schnorr';
import { getPublicKey } from '../crypto/secp256k1';
import { sha256 } from '../crypto/sha256';
import { bytesToBigint, bytesToHex } from '../crypto/hmac';
import './MuSig2Explorer.css';

const MAX_N = 5;
const DEBOUNCE_MS = 250;

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
function hex32(n: bigint): string { return n.toString(16).padStart(64, '0'); }
function randomHex32(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}
function shortHex(hex: string, head = 10, tail = 6): string {
  return hex.length <= head + tail + 1 ? hex : `${hex.slice(0, head)}…${hex.slice(-tail)}`;
}
function letter(i: number): string { return String.fromCharCode(65 + i); }

/** Deriva dos escalares de nonce (k1,k2) desde una semilla, de forma reproducible. */
function nonceScalars(seed: string): [bigint, bigint] {
  const s = hexToBytes(seed);
  const k1 = bytesToBigint(hexToBytes(sha256(new Uint8Array([...s, 0x01])).hash));
  const k2 = bytesToBigint(hexToBytes(sha256(new Uint8Array([...s, 0x02])).hash));
  return [k1, k2];
}

interface SignerView {
  label: string;
  pubX: string;      // Pᵢ.x
  coeff: string;     // aᵢ
  R1: string;        // R_{i,1} comprimido
  R2: string;        // R_{i,2} comprimido
  partialS: string;  // sᵢ
  partialOk: boolean;
}

interface SessionView {
  sig: string;
  signers: SignerView[];
  L: string;
  aggX: string;          // Q.x
  aggParity: boolean;    // ¿Q tenía y impar? (se negó)
  R1: string; R2: string; b: string; finalR: string; rParity: boolean;
  challenge: string;
  s: string;
  signatureHex: string;
  valid: boolean;
}

function buildSession(seeds: string[], nonceSeeds: string[], n: number, message: Uint8Array): SessionView {
  const privs = seeds.slice(0, n).map(s => bytesToBigint(hexToBytes(s)));
  const signers: Signer[] = privs.map(d => ({ privateKey: d, publicKey: getPublicKey(d)! }));
  const secretNonces: SecretNonce[] = nonceSeeds.slice(0, n).map(seed => {
    const [k1, k2] = nonceScalars(seed);
    return { k1, k2 };
  });

  const session = runMuSig2Session(signers, secretNonces, message);
  const { keyAgg, publicNonces, nonceAgg, challenge, partialSignatures } = session;

  // Todo va alineado por el orden canónico (KeySort) de keyAgg.publicKeys.
  const signerViews: SignerView[] = keyAgg.publicKeys.map((pk, i): SignerView => {
    const point = pk!; // las claves agregadas nunca son el punto en el infinito
    const ok = partialVerify(partialSignatures[i], publicNonces[i], point, nonceAgg, keyAgg, challenge);
    return {
      label: letter(i),
      pubX: hex32(point.x),
      coeff: hex32(keyAgg.coefficients[i]),
      R1: bytesToHex(to33(publicNonces[i].R1)),
      R2: bytesToHex(to33(publicNonces[i].R2)),
      partialS: hex32(partialSignatures[i].s),
      partialOk: ok,
    };
  });

  const valid = schnorrVerify(message, session.signature, keyAgg.aggregateXOnly).valid;

  return {
    sig: '', // se rellena fuera
    signers: signerViews,
    L: keyAgg.L,
    aggX: hex32(keyAgg.aggregateXOnly),
    aggParity: keyAgg.parityNegated,
    R1: bytesToHex(to33(nonceAgg.R1)),
    R2: bytesToHex(to33(nonceAgg.R2)),
    b: hex32(nonceAgg.b),
    finalR: hex32(nonceAgg.finalNonceX),
    rParity: nonceAgg.parityNegated,
    challenge: hex32(challenge),
    s: hex32(session.s),
    signatureHex: session.signatureHex,
    valid,
  };
}

/** Serializa un punto en formato comprimido (33 bytes) — para mostrar nonces. */
function to33(point: { x: bigint; y: bigint } | null): Uint8Array {
  if (point === null) return new Uint8Array(33);
  const out = new Uint8Array(33);
  out[0] = point.y % 2n === 0n ? 0x02 : 0x03;
  out.set(to32(point.x), 1);
  return out;
}

export function MuSig2Explorer() {
  const [n, setN] = useState(3);
  const [seeds, setSeeds] = useState<string[]>(() => Array.from({ length: MAX_N }, randomHex32));
  const [nonceSeeds, setNonceSeeds] = useState<string[]>(() => Array.from({ length: MAX_N }, randomHex32));
  const [message, setMessage] = useState('Hola Bitcoin');
  const [view, setView] = useState<SessionView | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const copyText = (id: string, text: string) => {
    navigator.clipboard?.writeText(text).then(() => {
      setCopiedId(id);
      setTimeout(() => setCopiedId(cur => (cur === id ? null : cur)), 1500);
    });
  };

  const msgHashHex = sha256(new TextEncoder().encode(message)).hash;
  const sig = `${n}|${seeds.slice(0, n).join('')}|${nonceSeeds.slice(0, n).join('')}|${msgHashHex}`;
  const loading = !view || view.sig !== sig;

  // ── Trabajo CARO: sesión MuSig2 completa (muchas mults de curva elíptica) ──
  useEffect(() => {
    const timer = setTimeout(() => {
      const msgBytes = hexToBytes(msgHashHex);
      const built = buildSession(seeds, nonceSeeds, n, msgBytes);
      setView({ ...built, sig });
    }, DEBOUNCE_MS);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [n, seeds, nonceSeeds, msgHashHex]);

  const regenKeys = () => setSeeds(Array.from({ length: MAX_N }, randomHex32));
  const regenNonces = () => setNonceSeeds(Array.from({ length: MAX_N }, randomHex32));

  const shown = view && !loading ? view : null;

  return (
    <div className="m2">
      <header className="m2-header">
        <span className="m2-phase-tag">Fase 4 · Interactivo</span>
        <h1>MuSig2 Explorer</h1>
        <p className="m2-subtitle">
          <strong>n firmantes → una sola firma Schnorr</strong> (n-de-n key-path).
          Recorre las dos rondas de <code>MuSig2 (BIP327)</code> y comprueba que la firma
          agregada verifica como una firma individual normal contra la clave agregada
          <code> Q.x</code>.
        </p>
      </header>

      <div className="m2-info">
        <strong>¿Por qué solo funciona con Schnorr?</strong> La verificación es lineal
        (<code>s·G = R + e·P</code>): sumar las <code>sᵢ</code>, los <code>Rᵢ</code> y los
        <code> Pᵢ</code> mantiene la ecuación. ECDSA tiene una inversa modular
        <code> s⁻¹</code> que rompe esa linealidad. <br />
        <strong>Ojo:</strong> MuSig2 es <strong>n-de-n</strong> (todos firman). El m-de-n con
        clave agregada sería FROST; el m-de-n de árbol Taproot ya lo tienes en
        <em> Taproot Multisig</em>.
      </div>

      {/* ── Controles ── */}
      <div className="m2-controls">
        <label className="m2-control m2-control--wide">
          <span className="m2-control-label">Mensaje a firmar (se hashea a 32 bytes)</span>
          <input
            className="m2-msg-input"
            type="text"
            value={message}
            onChange={e => setMessage(e.target.value)}
            placeholder="Escribe algo…"
          />
        </label>
        <label className="m2-control">
          <span className="m2-control-label">Firmantes · <strong>n = {n}</strong></span>
          <input type="range" min={2} max={MAX_N} value={n} onChange={e => setN(Number(e.target.value))} />
        </label>
        <button className="m2-regen" onClick={regenKeys}>↻ Regenerar claves</button>
        <button className="m2-regen" onClick={regenNonces}>↻ Regenerar nonces</button>
      </div>

      <div className="m2-scheme">
        Esquema: <strong>{n}-de-{n}</strong>
        <span className="m2-scheme-note"> · sighash = SHA256("{shortHex(message, 18, 0)}") = {shortHex(msgHashHex, 10, 6)}</span>
      </div>

      {loading && (
        <div className="m2-loading"><span className="m2-spinner" /> Agregando claves, nonces y firmas (curva elíptica en JS, lento a propósito)…</div>
      )}

      {shown && (
        <>
          {/* ══ RONDA 1 ══ */}
          <div className="m2-round">
            <span className="m2-round-tag">Ronda 1</span>
            <span className="m2-round-title">Agregar claves y nonces</span>
          </div>

          {/* Firmantes: clave + coeficiente + dos nonces */}
          <section className="m2-section">
            <span className="m2-label">Cada firmante aporta su clave Pᵢ y DOS nonces (el «2» de MuSig2)</span>
            <div className="m2-signers">
              {shown.signers.map((s) => (
                <div key={s.label} className="m2-signer-card">
                  <div className="m2-signer-head">Firmante {s.label}</div>
                  <div className="m2-kv"><span>Pᵢ.x</span><code>{shortHex(s.pubX, 12, 8)}</code></div>
                  <div className="m2-kv"><span>aᵢ (coef)</span><code className="m2-accent">{shortHex(s.coeff, 12, 8)}</code></div>
                  <div className="m2-kv"><span>R<sub>i,1</sub></span><code>{shortHex(s.R1, 10, 6)}</code></div>
                  <div className="m2-kv"><span>R<sub>i,2</sub></span><code>{shortHex(s.R2, 10, 6)}</code></div>
                </div>
              ))}
            </div>
            <p className="m2-hint">
              El coeficiente <code>aᵢ = H(L, Pᵢ)</code> depende de <em>todo</em> el conjunto de
              claves <code>L</code>. Por eso un firmante no puede elegir su clave para «cancelar»
              la de otro (<strong>ataque rogue-key neutralizado</strong>).
            </p>
          </section>

          {/* Agregación de claves */}
          <section className="m2-section">
            <span className="m2-label">Agregación de claves → Q</span>
            <div className="m2-formula">
              <div className="m2-kv"><span>L = H(P₁‖…‖Pₙ)</span><code>{shortHex(shown.L, 14, 10)}</code></div>
              <div className="m2-eq">Q = Σ aᵢ · Pᵢ</div>
              <div className="m2-result-row">
                <div className="m2-label-row">
                  <span className="m2-label m2-label--sm">Clave pública agregada Q.x {shown.aggParity && <em className="m2-parity">(y impar → negada)</em>}</span>
                  <button className="m2-copy" onClick={() => copyText('q', shown.aggX)}>{copiedId === 'q' ? '✓' : 'copiar'}</button>
                </div>
                <div className="m2-highlight"><code>{shown.aggX}</code></div>
              </div>
            </div>
            <p className="m2-hint">
              Esta <code>Q.x</code> es la clave que iría en un output <code>tr(Q)</code>. En la
              cadena es una x-only pubkey normal: nadie sabe que detrás hay {n} personas.
            </p>
          </section>

          {/* Agregación de nonces */}
          <section className="m2-section">
            <span className="m2-label">Agregación de nonces → R (el corazón del «2»)</span>
            <div className="m2-formula">
              <div className="m2-kv"><span>R₁ = Σ R<sub>i,1</sub></span><code>{shortHex(shown.R1, 12, 8)}</code></div>
              <div className="m2-kv"><span>R₂ = Σ R<sub>i,2</sub></span><code>{shortHex(shown.R2, 12, 8)}</code></div>
              <div className="m2-kv"><span>b = H(R₁‖R₂‖Q.x‖m)</span><code className="m2-accent">{shortHex(shown.b, 12, 8)}</code></div>
              <div className="m2-eq">R = R₁ + b · R₂</div>
              <div className="m2-kv"><span>R.x {shown.rParity && <em className="m2-parity">(y impar → nonces negados)</em>}</span><code>{shortHex(shown.finalR, 12, 8)}</code></div>
            </div>
            <p className="m2-hint">
              El coeficiente <code>b</code> mezcla ambos nonces de cada firmante e impide
              «pre-cocinar» combinaciones (ataque de Wagner). Gracias a él bastan <strong>2
              rondas</strong> en vez de 3 — esa es la innovación de MuSig<strong>2</strong>.
            </p>
          </section>

          {/* ══ RONDA 2 ══ */}
          <div className="m2-round">
            <span className="m2-round-tag">Ronda 2</span>
            <span className="m2-round-title">Firmas parciales y agregación</span>
          </div>

          <section className="m2-section">
            <div className="m2-kv m2-kv--big"><span>e = H(R.x‖Q.x‖m)</span><code>{shortHex(shown.challenge, 14, 10)}</code></div>
            <span className="m2-label m2-label--mt">Cada firmante calcula sᵢ = kᵢ + e·aᵢ·dᵢ</span>
            <div className="m2-partials">
              {shown.signers.map((s) => (
                <div key={s.label} className="m2-partial">
                  <span className="m2-partial-idx">{s.label}</span>
                  <code className="m2-partial-s">s<sub>{s.label}</sub> = {shortHex(s.partialS, 12, 8)}</code>
                  <span className={`m2-partial-ok ${s.partialOk ? 'ok' : 'bad'}`}>
                    {s.partialOk ? '✓ verifica' : '✗ inválida'}
                  </span>
                </div>
              ))}
            </div>
            <p className="m2-hint">
              Cada firma parcial se verifica por separado (<code>partialVerify</code>): si alguien
              hace trampa, se detecta <em>antes</em> de agregar y no arruina la sesión.
            </p>
          </section>

          {/* Firma final + veredicto */}
          <section className="m2-section">
            <span className="m2-label">Agregación final: s = Σ sᵢ</span>
            <div className="m2-final">
              <div className="m2-kv"><span>s</span><code>{shortHex(shown.s, 16, 10)}</code></div>
              <div className="m2-label-row m2-label--mt">
                <span className="m2-label m2-label--sm">Firma (R.x ‖ s) — 64 bytes</span>
                <button className="m2-copy" onClick={() => copyText('sig', shown.signatureHex)}>{copiedId === 'sig' ? '✓' : 'copiar'}</button>
              </div>
              <div className="m2-highlight"><code>{shown.signatureHex}</code></div>
            </div>

            <div className={`m2-verdict ${shown.valid ? 'good' : 'bad'}`}>
              {shown.valid
                ? `✓ schnorrVerify(m, firma, Q.x) = válida — ${n} firmantes produjeron UNA firma Schnorr indistinguible de la de un único firmante`
                : '✗ La firma agregada NO verifica'}
            </div>
          </section>
        </>
      )}
    </div>
  );
}
