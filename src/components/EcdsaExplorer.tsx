import { useState, useMemo } from 'react';
import {
  ecdsaSign,
  ecdsaVerify,
  recoverPrivateKeyFromReusedK,
  hexToBytes,
} from '../crypto/ecdsa';
import { sha256 } from '../crypto/sha256';
import { getPublicKey, N, formatBigInt } from '../crypto/secp256k1';
import './EcdsaExplorer.css';

function toBytes(hex: string): Uint8Array {
  return hexToBytes(hex);
}

export function EcdsaExplorer() {
  const [message, setMessage] = useState('Hello, Bitcoin!');
  const [privKeyHex, setPrivKeyHex] = useState('1');
  const [showDer, setShowDer] = useState(false);
  const [showReusedK, setShowReusedK] = useState(false);

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
      const msgHash = toBytes(sha256(message).hash);
      const signResult = ecdsaSign(msgHash, privKey);
      const pubKey = getPublicKey(privKey);
      const verifyResult = ecdsaVerify(msgHash, signResult.signature, pubKey);
      return { sign: signResult, verify: verifyResult, pubKey };
    } catch {
      return null;
    }
  }, [message, privKey]);

  // Demostración: reutilización de k
  const reusedKDemo = useMemo(() => {
    if (!privKey || !showReusedK) return null;
    try {
      const k = 42n; // k fijo — PELIGROSO
      const msg1Hash = toBytes(sha256('Mensaje 1').hash);
      const msg2Hash = toBytes(sha256('Mensaje 2').hash);
      const sig1 = ecdsaSign(msg1Hash, privKey, k);
      const sig2 = ecdsaSign(msg2Hash, privKey, k);
      // Usar s original (pre-normalización low-s) para que la matemática cuadre
      const recovered = recoverPrivateKeyFromReusedK(
        sig1.z, sig1.s,
        sig2.z, sig2.s,
        sig1.r
      );
      return { sig1, sig2, recovered, originalKey: privKey };
    } catch {
      return null;
    }
  }, [privKey, showReusedK]);

  return (
    <div className="ecdsa-explorer">
      <header className="ecdsa-header">
        <h1>ECDSA</h1>
        <p className="subtitle">
          Firma digital de curva elíptica. El esquema de firma original de Bitcoin.
          Demuestra que conoces la clave privada sin revelarla. Cada firma usa un
          nonce k único — si se reutiliza, la clave privada se filtra.
        </p>
      </header>

      {/* Input: mensaje + clave privada */}
      <section className="ecdsa-section">
        <label className="section-label">Mensaje y clave privada</label>
        <div className="input-group">
          <label className="input-label">Mensaje</label>
          <input
            type="text"
            className="ecdsa-input"
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
              className="ecdsa-input privkey"
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

      {result && (
        <>
          {/* Paso 1: hash del mensaje */}
          <section className="ecdsa-section">
            <label className="section-label">Paso 1 — Hash del mensaje</label>
            <p className="section-description">
              No firmamos el mensaje directamente, sino su hash SHA-256.
              Esto produce un número z de 256 bits que entra en la fórmula.
            </p>
            <div className="hash-display">
              <div className="hash-row">
                <span className="hash-label">mensaje</span>
                <span className="hash-value msg-val">"{message}"</span>
              </div>
              <div className="hash-arrow">↓ SHA-256</div>
              <div className="hash-row">
                <span className="hash-label">z (hash)</span>
                <span className="hash-value z-val">{result.sign.messageHash}</span>
              </div>
            </div>
          </section>

          {/* Paso 2: nonce k */}
          <section className="ecdsa-section">
            <label className="section-label">Paso 2 — Nonce k (RFC 6979)</label>
            <p className="section-description">
              El nonce k es CRÍTICO. Debe ser único para cada firma. RFC 6979 lo
              deriva determinísticamente de la clave privada + el mensaje usando HMAC,
              eliminando la necesidad de un buen generador de números aleatorios.
            </p>
            <div className="value-display">
              <span className="val-label">k</span>
              <span className="val-hex">{formatBigInt(result.sign.k, 24)}</span>
            </div>
          </section>

          {/* Paso 3: punto R */}
          <section className="ecdsa-section highlight-section">
            <label className="section-label">Paso 3 — Calcular R = k × G</label>
            <p className="section-description">
              Multiplicamos k por el punto generador G (la misma operación que para
              derivar claves públicas). Solo nos quedamos con R.x como r.
            </p>
            <div className="computation-chain">
              <div className="comp-step">
                <span className="comp-label">R = k × G</span>
                <div className="comp-coords">
                  <div>
                    <span className="coord-label">x:</span>
                    <span className="comp-value">
                      {result.sign.R ? result.sign.R.x.toString(16).padStart(64, '0') : '?'}
                    </span>
                  </div>
                  <div>
                    <span className="coord-label">y:</span>
                    <span className="comp-value">
                      {result.sign.R ? result.sign.R.y.toString(16).padStart(64, '0') : '?'}
                    </span>
                  </div>
                </div>
              </div>
              <div className="hash-arrow">↓ tomar x mod n</div>
              <div className="value-display">
                <span className="val-label">r</span>
                <span className="val-hex r-val">{result.sign.r.toString(16).padStart(64, '0')}</span>
              </div>
            </div>
          </section>

          {/* Paso 4: calcular s */}
          <section className="ecdsa-section">
            <label className="section-label">Paso 4 — Calcular s</label>
            <p className="section-description">
              La fórmula: s = k⁻¹ · (z + r·d) mod n. Combina el nonce, el hash,
              r y la clave privada. La inversa modular k⁻¹ es la operación más costosa.
            </p>
            <div className="formula-breakdown">
              <div className="formula-row">
                <span className="formula-part">z</span>
                <span className="formula-val">{formatBigInt(result.sign.z, 16)}</span>
                <span className="formula-desc">hash del mensaje</span>
              </div>
              <div className="formula-row">
                <span className="formula-part">r · d</span>
                <span className="formula-val">{formatBigInt(result.sign.r * privKey!, 16)}</span>
                <span className="formula-desc">r × clave privada</span>
              </div>
              <div className="formula-row">
                <span className="formula-part">z + r·d</span>
                <span className="formula-val">{formatBigInt(result.sign.z + result.sign.r * privKey!, 16)}</span>
                <span className="formula-desc">suma</span>
              </div>
              <div className="formula-row">
                <span className="formula-part">k⁻¹</span>
                <span className="formula-val">{formatBigInt(result.sign.k, 16)}</span>
                <span className="formula-desc">inversa modular del nonce</span>
              </div>
              <div className="formula-divider" />
              <div className="formula-row result-row">
                <span className="formula-part">s</span>
                <span className="formula-val s-val">{formatBigInt(result.sign.sLow, 20)}</span>
                <span className="formula-desc">
                  {result.sign.s !== result.sign.sLow ? '(normalizado, low-s)' : ''}
                </span>
              </div>
            </div>
          </section>

          {/* Firma final */}
          <section className="ecdsa-section signature-section">
            <label className="section-label">La firma (r, s)</label>
            <div className="signature-display">
              <div className="sig-part">
                <span className="sig-label">r</span>
                <span className="sig-value r-val">{result.sign.r.toString(16).padStart(64, '0')}</span>
              </div>
              <div className="sig-part">
                <span className="sig-label">s</span>
                <span className="sig-value s-val">{result.sign.signature.s.toString(16).padStart(64, '0')}</span>
              </div>
            </div>
          </section>

          {/* DER encoding */}
          <section className="ecdsa-section">
            <div className="section-header-row">
              <label className="section-label">
                Codificación DER ({result.sign.der.length} bytes)
              </label>
              <button className="toggle-btn" onClick={() => setShowDer(!showDer)}>
                {showDer ? 'Ocultar' : 'Mostrar'} detalle
              </button>
            </div>
            <p className="section-description">
              Bitcoin codifica las firmas ECDSA en formato DER (Distinguished Encoding Rules)
              dentro de las transacciones. Es una secuencia de bytes con estructura tipo-longitud-valor.
            </p>

            <div className="der-hex">
              {result.sign.derFields.map((field, i) => (
                <span key={i} className="der-bytes" style={{ color: field.color }}>
                  {field.bytes.map(b => b.toString(16).padStart(2, '0')).join('')}
                </span>
              ))}
            </div>

            {showDer && (
              <div className="der-breakdown">
                {result.sign.derFields.map((field, i) => (
                  <div key={i} className="der-field">
                    <span className="der-field-bytes" style={{ color: field.color }}>
                      {field.bytes.map(b => b.toString(16).padStart(2, '0')).join(' ')}
                    </span>
                    <span className="der-field-name">{field.name}</span>
                    <span className="der-field-desc">{field.description}</span>
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* Verificación */}
          <section className="ecdsa-section verify-section">
            <label className="section-label">Verificación</label>
            <p className="section-description">
              Cualquiera con la clave pública puede verificar la firma. No necesita
              conocer la clave privada ni el nonce k. La matemática se sostiene sola.
            </p>
            <div className="verify-chain">
              <div className="verify-step">
                <span className="verify-label">s⁻¹ mod n</span>
                <span className="verify-value">{formatBigInt(result.verify.sInv, 16)}</span>
              </div>
              <div className="verify-step">
                <span className="verify-label">u1 = z · s⁻¹</span>
                <span className="verify-value">{formatBigInt(result.verify.u1, 16)}</span>
              </div>
              <div className="verify-step">
                <span className="verify-label">u2 = r · s⁻¹</span>
                <span className="verify-value">{formatBigInt(result.verify.u2, 16)}</span>
              </div>
              <div className="verify-step">
                <span className="verify-label">R' = u1·G + u2·P</span>
                <span className="verify-value">
                  x: {result.verify.Rprime ? formatBigInt(result.verify.Rprime.x, 16) : '?'}
                </span>
              </div>
              <div className="verify-step">
                <span className="verify-label">R'.x mod n</span>
                <span className="verify-value">{formatBigInt(result.verify.rRecovered, 16)}</span>
              </div>
              <div className={`verify-result ${result.verify.valid ? 'valid' : 'invalid'}`}>
                {result.verify.valid
                  ? '✓ R\'.x === r — Firma válida'
                  : '✗ R\'.x ≠ r — Firma inválida'}
              </div>
            </div>
          </section>

          {/* Ataque: reutilización de k */}
          <section className="ecdsa-section danger-section">
            <div className="section-header-row">
              <label className="section-label">Ataque: reutilizar k</label>
              <button className="toggle-btn danger-btn" onClick={() => setShowReusedK(!showReusedK)}>
                {showReusedK ? 'Ocultar' : 'Demostrar'} ataque
              </button>
            </div>
            <p className="section-description">
              Si firmas dos mensajes distintos con el mismo k, cualquiera puede calcular
              tu clave privada. Esto le pasó a Sony con PlayStation 3 en 2010: usaron
              un k fijo y se filtró la clave de firma de juegos.
            </p>

            {showReusedK && reusedKDemo && (
              <div className="attack-demo">
                <div className="attack-step">
                  <span className="attack-label">k reutilizado</span>
                  <span className="attack-value danger-val">42 (para ambos mensajes)</span>
                </div>
                <div className="attack-step">
                  <span className="attack-label">Firma 1 ("Mensaje 1")</span>
                  <span className="attack-value">r = {formatBigInt(reusedKDemo.sig1.r, 16)}, s = {formatBigInt(reusedKDemo.sig1.signature.s, 16)}</span>
                </div>
                <div className="attack-step">
                  <span className="attack-label">Firma 2 ("Mensaje 2")</span>
                  <span className="attack-value">r = {formatBigInt(reusedKDemo.sig2.r, 16)}, s = {formatBigInt(reusedKDemo.sig2.signature.s, 16)}</span>
                </div>
                <div className="attack-step">
                  <span className="attack-label">¡Mismo r!</span>
                  <span className="attack-value danger-val">
                    Ambas firmas tienen r idéntico — señal de k reutilizado
                  </span>
                </div>
                <div className="attack-divider" />
                <div className="attack-step">
                  <span className="attack-label">k recuperado</span>
                  <span className="attack-value">{formatBigInt(reusedKDemo.recovered.k, 16)}</span>
                </div>
                <div className="attack-step">
                  <span className="attack-label">Clave privada recuperada</span>
                  <span className="attack-value danger-val">
                    0x{reusedKDemo.recovered.privateKey.toString(16)}
                  </span>
                </div>
                <div className="attack-step">
                  <span className="attack-label">Clave privada original</span>
                  <span className="attack-value">
                    0x{reusedKDemo.originalKey.toString(16)}
                  </span>
                </div>
                <div className={`verify-result ${reusedKDemo.recovered.privateKey === reusedKDemo.originalKey ? 'invalid' : 'valid'}`}>
                  {reusedKDemo.recovered.privateKey === reusedKDemo.originalKey
                    ? '⚠ Clave privada completamente comprometida'
                    : 'Claves no coinciden (error en la demo)'}
                </div>
              </div>
            )}
          </section>
        </>
      )}
    </div>
  );
}
