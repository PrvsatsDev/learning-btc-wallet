import { useState, useMemo } from 'react';
import { ripemd160, type Ripemd160Result } from '../crypto/ripemd160';
import { sha256 } from '../crypto/sha256';
import './Ripemd160Explorer.css';

function toHex(n: number): string {
  return (n >>> 0).toString(16).padStart(8, '0');
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function Ripemd160Explorer() {
  const [input, setInput] = useState('hello');
  const [showRounds, setShowRounds] = useState(false);
  const [selectedRound, setSelectedRound] = useState(0);
  const [mode, setMode] = useState<'direct' | 'hash160'>('direct');

  const result: Ripemd160Result = useMemo(() => {
    if (mode === 'hash160') {
      const shaResult = sha256(input);
      return ripemd160(hexToBytes(shaResult.hash));
    }
    return ripemd160(input);
  }, [input, mode]);

  const shaHash = useMemo(() => {
    if (mode === 'hash160') return sha256(input).hash;
    return null;
  }, [input, mode]);

  return (
    <div className="ripemd-explorer">
      <header className="ripemd-header">
        <h1>RIPEMD-160</h1>
        <p className="subtitle">
          El hash europeo que comprime las direcciones Bitcoin a 20 bytes.
          Diseñado en Bélgica como alternativa a los hashes de la NSA.
        </p>
      </header>

      {/* Mode selector */}
      <section className="ripemd-section">
        <div className="mode-toggle">
          <button
            className={mode === 'direct' ? 'active' : ''}
            onClick={() => setMode('direct')}
          >
            RIPEMD-160 directo
          </button>
          <button
            className={mode === 'hash160' ? 'active' : ''}
            onClick={() => setMode('hash160')}
          >
            Hash160 (como Bitcoin)
          </button>
        </div>
        {mode === 'hash160' && (
          <p className="mode-description">
            Hash160 = RIPEMD-160(SHA-256(input)) — la cadena de hashes que Bitcoin
            usa para derivar direcciones desde claves públicas.
          </p>
        )}
      </section>

      {/* Input */}
      <section className="ripemd-section">
        <label className="section-label">Entrada</label>
        <input
          type="text"
          className="ripemd-input"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Escribe cualquier texto..."
        />
        <div className="input-meta">
          {input.length} caracteres → {new TextEncoder().encode(input).length} bytes
        </div>
      </section>

      {/* Hash160 chain */}
      {mode === 'hash160' && shaHash && (
        <section className="ripemd-section chain-section">
          <label className="section-label">Cadena de hashes</label>
          <div className="chain">
            <div className="chain-step">
              <span className="chain-label">Entrada</span>
              <span className="chain-value input-val">"{input}"</span>
            </div>
            <div className="chain-arrow">↓ SHA-256</div>
            <div className="chain-step">
              <span className="chain-label">32 bytes</span>
              <span className="chain-value sha-val">{shaHash}</span>
            </div>
            <div className="chain-arrow">↓ RIPEMD-160</div>
            <div className="chain-step">
              <span className="chain-label">20 bytes</span>
              <span className="chain-value ripemd-val">{result.hash}</span>
            </div>
          </div>
        </section>
      )}

      {/* Hash Result */}
      <section className="ripemd-section">
        <label className="section-label">
          {mode === 'hash160' ? 'Hash160' : 'RIPEMD-160'} (160 bits = 40 caracteres hex)
        </label>
        <div className="hash-output">{result.hash}</div>
        <div className="hash-comparison">
          <span>SHA-256: 32 bytes (256 bits)</span>
          <span className="highlight">RIPEMD-160: 20 bytes (160 bits)</span>
          <span>↑ 37.5% más corto = direcciones más compactas</span>
        </div>
      </section>

      {/* Dual-track explanation */}
      <section className="ripemd-section">
        <label className="section-label">Arquitectura de dos líneas paralelas</label>
        <p className="section-description">
          Lo que hace único a RIPEMD-160 es que procesa cada bloque por <strong>dos caminos
          independientes</strong> (izquierda y derecha) que usan funciones y constantes
          diferentes. Al final de las 80 rondas, ambos resultados se combinan.
          Un atacante tendría que romper ambos caminos simultáneamente.
        </p>
        <div className="dual-track-diagram">
          <div className="track">
            <div className="track-header left">Línea Izquierda</div>
            <div className="track-detail">Funciones f en orden: 0→4</div>
            <div className="track-detail">Constantes KL</div>
            <div className="track-detail">Permutación RL de words</div>
          </div>
          <div className="track-merge">
            <div className="merge-label">Combinación final</div>
          </div>
          <div className="track">
            <div className="track-header right">Línea Derecha</div>
            <div className="track-detail">Funciones f en orden: 4→0</div>
            <div className="track-detail">Constantes KR</div>
            <div className="track-detail">Permutación RR de words</div>
          </div>
        </div>
      </section>

      {/* Padding */}
      <section className="ripemd-section">
        <label className="section-label">
          Padding ({result.paddedBytes.length} bytes)
        </label>
        <p className="section-description">
          Mismo esquema que SHA-256, pero la longitud se codifica en <strong>little-endian</strong> (bytes
          menos significativos primero). RIPEMD-160 sigue la convención de MD4/MD5.
        </p>
        <div className="padding-grid">
          {Array.from(result.paddedBytes).map((byte, i) => {
            let className = 'padding-byte';
            if (i < result.inputBytes.length) {
              className += ' byte-message';
            } else if (i === result.inputBytes.length) {
              className += ' byte-separator';
            } else if (i >= result.paddedBytes.length - 8) {
              className += ' byte-length';
            } else {
              className += ' byte-zero';
            }
            return (
              <span key={i} className={className} title={`Byte ${i}: 0x${byte.toString(16).padStart(2, '0')}`}>
                {byte.toString(16).padStart(2, '0')}
              </span>
            );
          })}
        </div>
        <div className="padding-legend">
          <span><span className="legend-dot byte-message" /> Mensaje</span>
          <span><span className="legend-dot byte-separator" /> Separador</span>
          <span><span className="legend-dot byte-zero" /> Relleno</span>
          <span><span className="legend-dot byte-length" /> Longitud (little-endian)</span>
        </div>
      </section>

      {/* Rounds */}
      <section className="ripemd-section">
        <div className="section-header-row">
          <label className="section-label">Rondas de compresión (80 rondas)</label>
          <button className="toggle-btn" onClick={() => setShowRounds(!showRounds)}>
            {showRounds ? 'Ocultar' : 'Mostrar'} rondas
          </button>
        </div>

        {showRounds && result.rounds[selectedRound] && (
          <div className="rounds-container">
            <div className="round-slider">
              <label>Ronda {selectedRound} / 79 — Grupo {Math.floor(selectedRound / 16) + 1}/5</label>
              <input
                type="range"
                min={0}
                max={result.rounds.length - 1}
                value={selectedRound}
                onChange={(e) => setSelectedRound(Number(e.target.value))}
              />
            </div>

            <div className="dual-state">
              <div className="state-column">
                <h3 className="state-title left">Izquierda</h3>
                {(['al', 'bl', 'cl', 'dl', 'el'] as const).map((reg) => (
                  <div key={reg} className="state-register">
                    <span className="reg-name">{reg.replace('l', '')}</span>
                    <span className="reg-value">{toHex(result.rounds[selectedRound][reg])}</span>
                  </div>
                ))}
                <div className="state-register word-reg">
                  <span className="reg-name">W</span>
                  <span className="reg-value">{toHex(result.rounds[selectedRound].wl)}</span>
                </div>
              </div>

              <div className="state-column">
                <h3 className="state-title right">Derecha</h3>
                {(['ar', 'br', 'cr', 'dr', 'er'] as const).map((reg) => (
                  <div key={reg} className="state-register">
                    <span className="reg-name">{reg.replace('r', '')}</span>
                    <span className="reg-value">{toHex(result.rounds[selectedRound][reg])}</span>
                  </div>
                ))}
                <div className="state-register word-reg">
                  <span className="reg-name">W</span>
                  <span className="reg-value">{toHex(result.rounds[selectedRound].wr)}</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
