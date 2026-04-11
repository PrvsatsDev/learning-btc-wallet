import { useState, useMemo } from 'react';
import {
  G, N, P,
  getPublicKey,
  compressPublicKey,
  uncompressPublicKey,
  isOnCurve,
  scalarMultiplyWithSteps,
  formatBigInt,
  type Point,
} from '../crypto/secp256k1';
import { sha256Hex } from '../crypto/sha256';
import { ripemd160Hex } from '../crypto/ripemd160';
import './Secp256k1Explorer.css';

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function pointToShortStr(p: Point): string {
  if (p === null) return '(infinito)';
  return `(${formatBigInt(p.x, 12)}, ${formatBigInt(p.y, 12)})`;
}

export function Secp256k1Explorer() {
  const [privKeyHex, setPrivKeyHex] = useState('1');
  const [showSteps, setShowSteps] = useState(false);

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
    const pubKey = getPublicKey(privKey);
    const compressed = compressPublicKey(pubKey);
    const uncompressed = uncompressPublicKey(pubKey);

    // Hash160 de la clave pública comprimida (como en Bitcoin)
    const shaHash = sha256Hex(hexToBytes(compressed));
    const hash160 = ripemd160Hex(hexToBytes(shaHash));

    const { steps } = scalarMultiplyWithSteps(privKey, G);

    return { pubKey, compressed, uncompressed, hash160, steps, onCurve: isOnCurve(pubKey) };
  }, [privKey]);

  return (
    <div className="secp-explorer">
      <header className="secp-header">
        <h1>secp256k1</h1>
        <p className="subtitle">
          La curva elíptica de Bitcoin. Tu clave privada (un número) se multiplica
          por el punto generador G para obtener tu clave pública. Fácil de calcular,
          imposible de revertir.
        </p>
      </header>

      {/* The equation */}
      <section className="secp-section">
        <label className="section-label">La curva</label>
        <div className="equation">y² = x³ + 7 <span className="mod-p">(mod p)</span></div>
        <div className="params-grid">
          <div className="param">
            <span className="param-name">p</span>
            <span className="param-value">{formatBigInt(P, 20)}</span>
            <span className="param-desc">El primo del campo finito (256 bits)</span>
          </div>
          <div className="param">
            <span className="param-name">n</span>
            <span className="param-value">{formatBigInt(N, 20)}</span>
            <span className="param-desc">Orden del grupo (cuántos puntos hay)</span>
          </div>
          <div className="param">
            <span className="param-name">G</span>
            <span className="param-value">{pointToShortStr(G)}</span>
            <span className="param-desc">Punto generador (fijo para todos)</span>
          </div>
        </div>
      </section>

      {/* Private key input */}
      <section className="secp-section">
        <label className="section-label">Clave privada (número secreto)</label>
        <p className="section-description">
          Cualquier número entre 1 y n-1. En la realidad son 256 bits aleatorios (~77 dígitos decimales).
          Prueba con números pequeños para explorar.
        </p>
        <div className="privkey-input-row">
          <span className="hex-prefix">0x</span>
          <input
            type="text"
            className="secp-input"
            value={privKeyHex}
            onChange={(e) => setPrivKeyHex(e.target.value.replace(/[^0-9a-fA-F]/g, ''))}
            placeholder="1"
          />
        </div>
        {!privKey && privKeyHex && (
          <div className="error-msg">Debe ser un hex válido entre 1 y n-1</div>
        )}
        <div className="quick-keys">
          {['1', '2', '3', 'ff', 'deadbeef', 'cafebabe'].map((k) => (
            <button key={k} className="quick-btn" onClick={() => setPrivKeyHex(k)}>
              0x{k}
            </button>
          ))}
        </div>
      </section>

      {result && (
        <>
          {/* The multiplication */}
          <section className="secp-section derivation-section">
            <label className="section-label">Derivación: privKey × G = pubKey</label>
            <div className="derivation-chain">
              <div className="deriv-step">
                <span className="deriv-label">Clave privada</span>
                <span className="deriv-value privkey-val">
                  0x{privKey!.toString(16)}
                </span>
              </div>
              <div className="deriv-arrow">× G (punto generador)</div>
              <div className="deriv-step">
                <span className="deriv-label">Clave pública (x, y)</span>
                <div className="deriv-coords">
                  <div>
                    <span className="coord-label">x:</span>
                    <span className="deriv-value pubkey-val">
                      {result.pubKey!.x.toString(16).padStart(64, '0')}
                    </span>
                  </div>
                  <div>
                    <span className="coord-label">y:</span>
                    <span className="deriv-value pubkey-val">
                      {result.pubKey!.y.toString(16).padStart(64, '0')}
                    </span>
                  </div>
                </div>
              </div>
              <div className="on-curve-badge">
                {result.onCurve ? 'En la curva' : 'FUERA de la curva'}
              </div>
            </div>
          </section>

          {/* Compressed vs uncompressed */}
          <section className="secp-section">
            <label className="section-label">Formatos de clave pública</label>
            <div className="format-comparison">
              <div className="format-box">
                <h3>Comprimida (33 bytes)</h3>
                <div className="format-value compressed-val">{result.compressed}</div>
                <p className="format-desc">
                  <span className="prefix-highlight">{result.compressed.slice(0, 2)}</span> = prefijo
                  ({result.compressed.startsWith('02') ? 'y es par' : 'y es impar'}),
                  luego solo la coordenada x. Como y² = x³+7 tiene dos soluciones,
                  basta 1 bit para elegir cuál.
                </p>
              </div>
              <div className="format-box">
                <h3>Sin comprimir (65 bytes)</h3>
                <div className="format-value uncompressed-val">{result.uncompressed}</div>
                <p className="format-desc">
                  <span className="prefix-highlight">04</span> = prefijo,
                  luego x (32 bytes) + y (32 bytes). El doble de grande.
                </p>
              </div>
            </div>
          </section>

          {/* Hash160 preview */}
          <section className="secp-section">
            <label className="section-label">Hacia la dirección Bitcoin</label>
            <div className="address-chain">
              <div className="addr-step">
                <span className="addr-label">pubKey comprimida</span>
                <span className="addr-value">{formatBigInt(BigInt('0x' + result.compressed), 20)}</span>
              </div>
              <div className="addr-arrow">↓ SHA-256</div>
              <div className="addr-arrow">↓ RIPEMD-160</div>
              <div className="addr-step">
                <span className="addr-label">Hash160 (20 bytes)</span>
                <span className="addr-value hash160-val">{result.hash160}</span>
              </div>
              <div className="addr-note">
                Falta Base58Check o Bech32 para la dirección final — lo veremos a continuación.
              </div>
            </div>
          </section>

          {/* Double-and-add steps */}
          <section className="secp-section">
            <div className="section-header-row">
              <label className="section-label">
                Algoritmo double-and-add ({result.steps.length} pasos)
              </label>
              <button className="toggle-btn" onClick={() => setShowSteps(!showSteps)}>
                {showSteps ? 'Ocultar' : 'Mostrar'} pasos
              </button>
            </div>
            <p className="section-description">
              En vez de sumar G consigo mismo k veces (imposible para k de 256 bits),
              recorremos los bits de k. En cada paso duplicamos, y si el bit es 1, sumamos.
              Así k × G se resuelve en ~256 operaciones.
            </p>

            {showSteps && (
              <div className="steps-table">
                <div className="steps-header">
                  <span>Bit</span>
                  <span>Valor</span>
                  <span>Operación</span>
                  <span>Acumulador</span>
                </div>
                {result.steps.map((step, i) => (
                  <div key={i} className={`step-row ${step.bit ? 'bit-one' : 'bit-zero'}`}>
                    <span className="step-idx">#{step.bitIndex}</span>
                    <span className="step-bit">{step.bit}</span>
                    <span className="step-op">
                      {step.bit ? 'double + add' : 'double'}
                    </span>
                    <span className="step-acc">
                      {step.accumulator ? pointToShortStr(step.accumulator) : '(infinito)'}
                    </span>
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
