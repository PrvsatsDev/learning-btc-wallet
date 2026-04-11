import { useState, useMemo } from 'react';
import { sha256, toHex, toBinary, type Sha256Result } from '../crypto/sha256';
import './Sha256Explorer.css';

export function Sha256Explorer() {
  const [input, setInput] = useState('hello');
  const [showRounds, setShowRounds] = useState(false);
  const [selectedRound, setSelectedRound] = useState(0);
  const [viewMode, setViewMode] = useState<'hex' | 'binary'>('hex');

  const result: Sha256Result = useMemo(() => sha256(input), [input]);
  const format = viewMode === 'hex' ? toHex : toBinary;

  return (
    <div className="sha256-explorer">
      <header className="sha256-header">
        <h1>SHA-256</h1>
        <p className="subtitle">
          La función hash que asegura toda la red Bitcoin.
          Escribe algo y observa cómo se transforma en una huella digital de 256 bits.
        </p>
      </header>

      {/* Input */}
      <section className="sha256-section">
        <label className="section-label">Entrada</label>
        <input
          type="text"
          className="sha256-input"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Escribe cualquier texto..."
        />
        <div className="input-meta">
          {input.length} caracteres → {new TextEncoder().encode(input).length} bytes
        </div>
      </section>

      {/* Hash Result */}
      <section className="sha256-section">
        <label className="section-label">Hash (256 bits = 64 caracteres hex)</label>
        <div className="hash-output">{result.hash}</div>
        <p className="hash-hint">
          Cambia un solo carácter y observa cómo cambia completamente el hash (efecto avalancha).
        </p>
      </section>

      {/* Padding visualization */}
      <section className="sha256-section">
        <label className="section-label">
          Padding ({result.paddedBytes.length} bytes = {result.paddedBytes.length * 8} bits)
        </label>
        <p className="section-description">
          SHA-256 necesita bloques de 512 bits. El mensaje se rellena con: un bit "1",
          ceros, y la longitud original en 64 bits al final.
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
              <span key={i} className={className} title={`Byte ${i}: 0x${byte.toString(16).padStart(2, '0')} (${byte})`}>
                {byte.toString(16).padStart(2, '0')}
              </span>
            );
          })}
        </div>
        <div className="padding-legend">
          <span><span className="legend-dot byte-message" /> Mensaje</span>
          <span><span className="legend-dot byte-separator" /> Separador (0x80)</span>
          <span><span className="legend-dot byte-zero" /> Relleno (ceros)</span>
          <span><span className="legend-dot byte-length" /> Longitud (64 bits)</span>
        </div>
      </section>

      {/* Compression rounds */}
      <section className="sha256-section">
        <div className="section-header-row">
          <label className="section-label">Rondas de compresión</label>
          <button className="toggle-btn" onClick={() => setShowRounds(!showRounds)}>
            {showRounds ? 'Ocultar' : 'Mostrar'} las 64 rondas
          </button>
        </div>
        <p className="section-description">
          Cada bloque pasa por 64 rondas. En cada ronda, los 8 registros (a-h)
          se mezclan con un word del mensaje y una constante K.
        </p>

        {showRounds && (
          <div className="rounds-container">
            <div className="view-toggle">
              <button
                className={viewMode === 'hex' ? 'active' : ''}
                onClick={() => setViewMode('hex')}
              >
                Hex
              </button>
              <button
                className={viewMode === 'binary' ? 'active' : ''}
                onClick={() => setViewMode('binary')}
              >
                Binario
              </button>
            </div>

            {/* Round selector */}
            <div className="round-slider">
              <label>Ronda {selectedRound} / 63</label>
              <input
                type="range"
                min={0}
                max={result.rounds.length - 1}
                value={selectedRound}
                onChange={(e) => setSelectedRound(Number(e.target.value))}
              />
            </div>

            {/* State for selected round */}
            {result.rounds[selectedRound] && (
              <div className="round-state">
                <div className="state-grid">
                  {(['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'] as const).map((reg) => (
                    <div key={reg} className="state-register">
                      <span className="reg-name">{reg}</span>
                      <span className="reg-value">{format(result.rounds[selectedRound][reg])}</span>
                    </div>
                  ))}
                </div>
                <div className="round-extras">
                  <div>
                    <span className="reg-name">W[{selectedRound}]</span>
                    <span className="reg-value">{format(result.rounds[selectedRound].w)}</span>
                  </div>
                  <div>
                    <span className="reg-name">K[{selectedRound}]</span>
                    <span className="reg-value">{format(result.rounds[selectedRound].k)}</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </section>
    </div>
  );
}
