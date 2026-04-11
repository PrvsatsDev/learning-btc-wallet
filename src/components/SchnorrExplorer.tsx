import { useState, useMemo } from 'react';
import {
  schnorrSign,
  schnorrVerify,
  taggedHash,
} from '../crypto/schnorr';
import { sha256 } from '../crypto/sha256';
import { getPublicKey, N, formatBigInt } from '../crypto/secp256k1';
import { bytesToHex, bigintToBytes } from '../crypto/hmac';
import { hexToBytes } from '../crypto/ecdsa';
import './SchnorrExplorer.css';

export function SchnorrExplorer() {
  const [message, setMessage] = useState('Hello, Taproot!');
  const [privKeyHex, setPrivKeyHex] = useState('1');
  const [showComparison, setShowComparison] = useState(false);
  const [showTaggedHash, setShowTaggedHash] = useState(false);

  const privKey = useMemo(() => {
    try {
      const k = BigInt('0x' + (privKeyHex || '0'));
      if (k <= 0n || k >= N) return null;
      return k;
    } catch {
      return null;
    }
  }, [privKeyHex]);

  const result = useMemo(() => {
    if (!privKey) return null;
    try {
      // Schnorr firma 32 bytes (un hash)
      const msgHash = hexToBytes(sha256(message).hash);
      const signResult = schnorrSign(msgHash, privKey);
      const verifyResult = schnorrVerify(msgHash, signResult.signature, signResult.publicKeyX);
      return { sign: signResult, verify: verifyResult, msgHash: bytesToHex(msgHash) };
    } catch {
      return null;
    }
  }, [message, privKey]);

  // Demostración de tagged hash
  const taggedHashDemo = useMemo(() => {
    if (!showTaggedHash) return null;
    const tag = 'BIP0340/challenge';
    const data = new TextEncoder().encode('test data');
    const tagHashHex = sha256(new TextEncoder().encode(tag)).hash;
    const resultHash = bytesToHex(taggedHash(tag, data));
    return { tag, tagHashHex, resultHash, dataHex: bytesToHex(data) };
  }, [showTaggedHash]);

  return (
    <div className="schnorr-explorer">
      <header className="schnorr-header">
        <h1>Schnorr (BIP340)</h1>
        <p className="subtitle">
          El esquema de firma moderno de Bitcoin, activado con Taproot en 2021.
          Matemáticamente más simple que ECDSA: la verificación es una sola ecuación
          lineal s·G = R + e·P. Sin inversas modulares, y con firmas de 64 bytes fijos.
        </p>
      </header>

      {/* Input */}
      <section className="schnorr-section">
        <label className="section-label">Mensaje y clave privada</label>
        <div className="input-group">
          <label className="input-label">Mensaje</label>
          <input
            type="text"
            className="schnorr-input"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            placeholder="Escribe un mensaje..."
          />
        </div>
        <div className="input-group">
          <label className="input-label">Clave privada (hex)</label>
          <div className="privkey-input-row">
            <span className="hex-prefix">0x</span>
            <input
              type="text"
              className="schnorr-input privkey"
              value={privKeyHex}
              onChange={(e) => setPrivKeyHex(e.target.value.replace(/[^0-9a-fA-F]/g, ''))}
              placeholder="1"
            />
          </div>
        </div>
        {!privKey && privKeyHex && (
          <div className="error-msg">Debe ser un hex válido entre 1 y n-1</div>
        )}
      </section>

      {/* Tagged Hash explicación */}
      <section className="schnorr-section">
        <div className="section-header-row">
          <label className="section-label">Tagged Hashes (separación de dominios)</label>
          <button className="toggle-btn" onClick={() => setShowTaggedHash(!showTaggedHash)}>
            {showTaggedHash ? 'Ocultar' : 'Mostrar'} ejemplo
          </button>
        </div>
        <p className="section-description">
          BIP340 no usa SHA-256 directamente — usa "tagged hashes". La idea es que
          un hash calculado para un propósito (ej: generar el nonce) nunca pueda
          confundirse con otro (ej: el challenge). Es como un namespace para hashes.
        </p>
        <div className="tagged-formula">
          <code>tagged_hash(tag, data) = SHA256(SHA256(tag) || SHA256(tag) || data)</code>
        </div>

        {showTaggedHash && taggedHashDemo && (
          <div className="tagged-demo">
            <div className="tagged-step">
              <span className="tagged-label">tag</span>
              <span className="tagged-value">"{taggedHashDemo.tag}"</span>
            </div>
            <div className="tagged-step">
              <span className="tagged-label">SHA256(tag)</span>
              <span className="tagged-value mono">{taggedHashDemo.tagHashHex.slice(0, 32)}...</span>
            </div>
            <div className="tagged-step">
              <span className="tagged-label">data</span>
              <span className="tagged-value mono">{taggedHashDemo.dataHex}</span>
            </div>
            <div className="tagged-arrow">↓ SHA256(SHA256(tag) || SHA256(tag) || data)</div>
            <div className="tagged-step result-step">
              <span className="tagged-label">resultado</span>
              <span className="tagged-value mono result-val">{taggedHashDemo.resultHash}</span>
            </div>
          </div>
        )}
      </section>

      {result && (
        <>
          {/* x-only public key */}
          <section className="schnorr-section">
            <label className="section-label">Clave pública x-only (32 bytes)</label>
            <p className="section-description">
              BIP340 usa "x-only public keys": solo la coordenada x, sin prefijo.
              Se asume siempre y par. Si y resulta impar, se niega la clave privada (d → n-d).
              Esto ahorra 1 byte por clave pública y simplifica el protocolo.
            </p>
            <div className="xonly-display">
              <span className="xonly-value">
                {result.sign.publicKeyX.toString(16).padStart(64, '0')}
              </span>
              <span className="xonly-size">32 bytes (vs 33 en formato comprimido)</span>
            </div>
          </section>

          {/* Paso 1: Nonce */}
          <section className="schnorr-section">
            <label className="section-label">Paso 1 — Nonce k (determinístico)</label>
            <p className="section-description">
              A diferencia de ECDSA que usa RFC 6979, Schnorr/BIP340 deriva el nonce con
              tagged hashes y XOR con randomness auxiliar. Esto protege contra ataques
              de canal lateral (timing, consumo eléctrico).
            </p>
            <div className="nonce-chain">
              <div className="nonce-step">
                <span className="nonce-label">t = d XOR tagged_hash("BIP0340/aux", aux)</span>
                <span className="nonce-value">{result.sign.t.slice(0, 32)}...</span>
              </div>
              <div className="tagged-arrow">↓ tagged_hash("BIP0340/nonce", t || P.x || m)</div>
              <div className="nonce-step">
                <span className="nonce-label">k (nonce)</span>
                <span className="nonce-value">{formatBigInt(result.sign.k, 24)}</span>
              </div>
            </div>
          </section>

          {/* Paso 2: R y challenge */}
          <section className="schnorr-section highlight-section">
            <label className="section-label">Paso 2 — R y challenge e</label>
            <div className="sign-chain">
              <div className="sign-step">
                <span className="sign-label">R = k × G</span>
                <div className="sign-value">
                  x: {result.sign.R ? result.sign.R.x.toString(16).padStart(64, '0') : '?'}
                </div>
                <div className="sign-note">
                  {result.sign.R && result.sign.R.y % 2n === 0n ? '(y es par ✓)' : '(y negado para ser par)'}
                </div>
              </div>
              <div className="tagged-arrow">↓ e = tagged_hash("BIP0340/challenge", R.x || P.x || m)</div>
              <div className="sign-step">
                <span className="sign-label">e (challenge)</span>
                <span className="sign-value">{result.sign.eHash.slice(0, 48)}...</span>
              </div>
            </div>
          </section>

          {/* Paso 3: s */}
          <section className="schnorr-section">
            <label className="section-label">Paso 3 — Calcular s = k + e·d mod n</label>
            <p className="section-description">
              La fórmula es lineal — no hay inversa modular como en ECDSA.
              Esta linealidad es la que permite agregar firmas (MuSig2, multisig nativo).
            </p>
            <div className="formula-simple">
              <div className="formula-item">
                <span className="formula-sym">k</span>
                <span className="formula-txt">{formatBigInt(result.sign.k, 16)}</span>
              </div>
              <div className="formula-op">+</div>
              <div className="formula-item">
                <span className="formula-sym">e · d</span>
                <span className="formula-txt">{formatBigInt(result.sign.e, 12)} × {formatBigInt(BigInt('0x' + privKeyHex), 12)}</span>
              </div>
              <div className="formula-op">=</div>
              <div className="formula-item result-item">
                <span className="formula-sym">s</span>
                <span className="formula-txt">{formatBigInt(result.sign.s, 20)}</span>
              </div>
            </div>
          </section>

          {/* Firma final */}
          <section className="schnorr-section signature-section">
            <label className="section-label">La firma (64 bytes fijos)</label>
            <p className="section-description">
              A diferencia de DER en ECDSA (longitud variable, 70-72 bytes), Schnorr
              siempre produce exactamente 64 bytes: R.x (32) || s (32). Simple y predecible.
            </p>
            <div className="schnorr-sig-display">
              <div className="sig-half">
                <span className="sig-label">R.x (32 bytes)</span>
                <span className="sig-bytes r-color">
                  {result.sign.rX.toString(16).padStart(64, '0')}
                </span>
              </div>
              <div className="sig-half">
                <span className="sig-label">s (32 bytes)</span>
                <span className="sig-bytes s-color">
                  {result.sign.s.toString(16).padStart(64, '0')}
                </span>
              </div>
            </div>
          </section>

          {/* Verificación */}
          <section className="schnorr-section verify-section">
            <label className="section-label">Verificación: s·G = R + e·P</label>
            <p className="section-description">
              La elegancia de Schnorr: una sola ecuación. No necesita inversas modulares.
              Solo multiplicación escalar y suma de puntos.
            </p>
            <div className="verify-equation">
              <div className="eq-side">
                <span className="eq-label">s · G</span>
                <span className="eq-value">
                  {result.verify.sG ? `(${formatBigInt(result.verify.sG.x, 12)}, ...)` : '?'}
                </span>
              </div>
              <div className="eq-equals">==</div>
              <div className="eq-side">
                <span className="eq-label">R + e · P</span>
                <span className="eq-value">
                  {result.verify.R ? `(${formatBigInt(result.verify.R.x, 12)}, ...)` : '?'}
                </span>
              </div>
            </div>
            <div className={`verify-badge ${result.verify.valid ? 'valid' : 'invalid'}`}>
              {result.verify.valid
                ? '✓ s·G = R + e·P — Firma Schnorr válida'
                : '✗ Los puntos no coinciden — Firma inválida'}
            </div>
          </section>

          {/* Comparativa ECDSA vs Schnorr */}
          <section className="schnorr-section">
            <div className="section-header-row">
              <label className="section-label">ECDSA vs Schnorr</label>
              <button className="toggle-btn" onClick={() => setShowComparison(!showComparison)}>
                {showComparison ? 'Ocultar' : 'Comparar'}
              </button>
            </div>

            {showComparison && (
              <div className="comparison-table">
                <div className="comp-header">
                  <span></span>
                  <span className="comp-col-label">ECDSA</span>
                  <span className="comp-col-label schnorr-col">Schnorr</span>
                </div>
                {[
                  ['Fórmula firma', 's = k⁻¹(z + rd)', 's = k + e·d'],
                  ['Verificación', 'u1·G + u2·P = R', 's·G = R + e·P'],
                  ['Inversa modular', 'Sí (k⁻¹ y s⁻¹)', 'No'],
                  ['Tamaño firma', '70-72 bytes (DER)', '64 bytes (fijo)'],
                  ['Agregación', 'No nativa', 'Sí (MuSig2)'],
                  ['Batch verify', 'No eficiente', 'Sí, lineal'],
                  ['Encoding', 'DER (complejo)', 'R.x || s (simple)'],
                  ['En Bitcoin desde', '2009 (génesis)', '2021 (Taproot)'],
                  ['Patente', 'Libre siempre', 'Expiró 2008'],
                ].map(([label, ecdsa, schnorr], i) => (
                  <div key={i} className="comp-row">
                    <span className="comp-label">{label}</span>
                    <span className="comp-ecdsa">{ecdsa}</span>
                    <span className="comp-schnorr">{schnorr}</span>
                  </div>
                ))}
              </div>
            )}
          </section>
        </>
      )}
    </div>
  );
}
