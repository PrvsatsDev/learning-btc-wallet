import { useState, useMemo } from 'react';
import {
  serializeLegacy,
  serializeWitness,
  parseTxHex,
  exampleLegacyTx,
  exampleSegwitTx,
  type Transaction,
  type TxField,
} from '../crypto/transaction';
import './TransactionExplorer.css';

type ViewMode = 'build' | 'parse';
type TxExample = 'legacy' | 'segwit';

export function TransactionExplorer() {
  const [viewMode, setViewMode] = useState<ViewMode>('build');
  const [txExample, setTxExample] = useState<TxExample>('legacy');
  const [hoveredField, setHoveredField] = useState<number | null>(null);
  const [showWitness, setShowWitness] = useState(false);
  const [rawHexInput, setRawHexInput] = useState('');

  // Build mode: serialize example transactions
  const buildResult = useMemo(() => {
    const tx = txExample === 'legacy' ? exampleLegacyTx() : exampleSegwitTx();
    const legacy = serializeLegacy(tx);
    const witness = tx.witnesses ? serializeWitness(tx) : null;
    return { tx, legacy, witness };
  }, [txExample]);

  const activeResult = showWitness && buildResult.witness ? buildResult.witness : buildResult.legacy;

  // Parse mode
  const parseResult = useMemo(() => {
    if (!rawHexInput || rawHexInput.length < 20) return null;
    try {
      const tx = parseTxHex(rawHexInput);
      const serialized = tx.witnesses
        ? serializeWitness(tx)
        : serializeLegacy(tx);
      return { tx, serialized };
    } catch (e) {
      return { error: (e as Error).message };
    }
  }, [rawHexInput]);

  return (
    <div className="tx-explorer">
      <header className="tx-header">
        <h1>Transacciones</h1>
        <p className="subtitle">
          Una transacción es el mensaje fundamental de Bitcoin: "mueve valor de aquí a allí".
          Es una secuencia de bytes con estructura precisa: version, inputs, outputs y locktime.
          El TxID es el doble SHA-256 de esta secuencia.
        </p>
      </header>

      {/* Mode selector */}
      <section className="tx-section">
        <div className="mode-selector">
          <button
            className={`mode-btn ${viewMode === 'build' ? 'active' : ''}`}
            onClick={() => setViewMode('build')}
          >
            Explorar estructura
          </button>
          <button
            className={`mode-btn ${viewMode === 'parse' ? 'active' : ''}`}
            onClick={() => setViewMode('parse')}
          >
            Decodificar raw hex
          </button>
        </div>
      </section>

      {viewMode === 'build' && (
        <>
          {/* Example selector */}
          <section className="tx-section">
            <label className="section-label">Transacción de ejemplo</label>
            <div className="example-selector">
              <button
                className={`scenario-btn ${txExample === 'legacy' ? 'active' : ''}`}
                onClick={() => { setTxExample('legacy'); setShowWitness(false); }}
              >
                Legacy (P2PKH)
              </button>
              <button
                className={`scenario-btn ${txExample === 'segwit' ? 'active' : ''}`}
                onClick={() => setTxExample('segwit')}
              >
                SegWit (P2WPKH)
              </button>
              {txExample === 'segwit' && (
                <button
                  className={`toggle-btn ${showWitness ? 'active-toggle' : ''}`}
                  onClick={() => setShowWitness(!showWitness)}
                >
                  {showWitness ? 'Sin' : 'Con'} witness
                </button>
              )}
            </div>
          </section>

          {/* Transaction structure */}
          <section className="tx-section">
            <label className="section-label">Estructura</label>
            <div className="tx-structure">
              <div className="struct-row">
                <span className="struct-label">Version</span>
                <span className="struct-value">{buildResult.tx.version}</span>
              </div>
              <div className="struct-row">
                <span className="struct-label">Inputs</span>
                <span className="struct-value">{buildResult.tx.inputs.length}</span>
              </div>
              {buildResult.tx.inputs.map((input, i) => (
                <div key={i} className="struct-sub">
                  <div className="struct-detail">
                    <span className="detail-label">prevTxId</span>
                    <span className="detail-value">{input.prevTxId.slice(0, 16)}...</span>
                  </div>
                  <div className="struct-detail">
                    <span className="detail-label">vout</span>
                    <span className="detail-value">{input.prevVout}</span>
                  </div>
                  <div className="struct-detail">
                    <span className="detail-label">scriptSig</span>
                    <span className="detail-value">
                      {input.scriptSig.length === 0
                        ? '(vacío — SegWit)'
                        : `${input.scriptSig.length} bytes`}
                    </span>
                  </div>
                  <div className="struct-detail">
                    <span className="detail-label">sequence</span>
                    <span className="detail-value">0x{input.sequence.toString(16).padStart(8, '0')}</span>
                  </div>
                </div>
              ))}
              <div className="struct-row">
                <span className="struct-label">Outputs</span>
                <span className="struct-value">{buildResult.tx.outputs.length}</span>
              </div>
              {buildResult.tx.outputs.map((output, i) => (
                <div key={i} className="struct-sub">
                  <div className="struct-detail">
                    <span className="detail-label">value</span>
                    <span className="detail-value">
                      {output.value.toLocaleString()} sats ({(Number(output.value) / 1e8).toFixed(8)} BTC)
                    </span>
                  </div>
                  <div className="struct-detail">
                    <span className="detail-label">scriptPubKey</span>
                    <span className="detail-value">{output.scriptPubKey.length} bytes</span>
                  </div>
                </div>
              ))}
              <div className="struct-row">
                <span className="struct-label">Locktime</span>
                <span className="struct-value">
                  {buildResult.tx.locktime === 0
                    ? '0 (sin restricción)'
                    : buildResult.tx.locktime.toLocaleString()}
                </span>
              </div>
              {showWitness && buildResult.tx.witnesses && (
                <>
                  <div className="struct-row witness-row">
                    <span className="struct-label">Witness</span>
                    <span className="struct-value">{buildResult.tx.witnesses.length} input(s)</span>
                  </div>
                  {buildResult.tx.witnesses.map((items, i) => (
                    <div key={i} className="struct-sub witness-sub">
                      {items.map((item, j) => (
                        <div key={j} className="struct-detail">
                          <span className="detail-label">item[{j}]</span>
                          <span className="detail-value">
                            {item.length} bytes {j === 0 ? '(firma)' : '(pubkey)'}
                          </span>
                        </div>
                      ))}
                    </div>
                  ))}
                </>
              )}
            </div>
          </section>

          {/* TxID */}
          <section className="tx-section txid-section">
            <label className="section-label">TxID</label>
            <p className="section-description">
              El TxID es el doble SHA-256 de la serialización legacy (sin witness),
              con los bytes invertidos. Incluso para transacciones SegWit, el TxID
              se calcula sin los datos witness — esto fue el gran fix de maleabilidad.
            </p>
            <div className="txid-display">
              <div className="txid-chain">
                <span className="txid-step">Serialización legacy ({activeResult.size} bytes)</span>
                <span className="txid-arrow">↓ SHA-256</span>
                <span className="txid-arrow">↓ SHA-256</span>
                <span className="txid-arrow">↓ reverse bytes</span>
              </div>
              <div className="txid-value">{activeResult.txid}</div>
            </div>
          </section>

          {/* Hex dump */}
          <section className="tx-section">
            <label className="section-label">
              Raw hex ({activeResult.hex.length / 2} bytes)
              {activeResult.isSegwit && ' — formato SegWit'}
            </label>
            <p className="section-description">
              Pasa el ratón sobre los bytes para ver qué campo representan.
              Cada color corresponde a un tipo de campo diferente.
            </p>

            <div className="hex-dump">
              {activeResult.fields.map((field, i) => (
                <span
                  key={i}
                  className={`hex-field ${hoveredField === i ? 'hovered' : ''}`}
                  style={{ color: field.color }}
                  onMouseEnter={() => setHoveredField(i)}
                  onMouseLeave={() => setHoveredField(null)}
                >
                  {Array.from(field.bytes).map(b => b.toString(16).padStart(2, '0')).join('')}
                </span>
              ))}
            </div>

            <div
              className={`field-tooltip ${hoveredField !== null ? 'visible' : ''}`}
              style={hoveredField !== null ? { borderColor: activeResult.fields[hoveredField].color } : undefined}
            >
              {hoveredField !== null && (
                <>
                  <span className="tooltip-name" style={{ color: activeResult.fields[hoveredField].color }}>
                    {activeResult.fields[hoveredField].name}
                  </span>
                  <span className="tooltip-desc">{activeResult.fields[hoveredField].description}</span>
                  <span className="tooltip-bytes">
                    {activeResult.fields[hoveredField].bytes.length} byte(s):
                    {' '}{Array.from(activeResult.fields[hoveredField].bytes).map(b => b.toString(16).padStart(2, '0')).join(' ')}
                  </span>
                </>
              )}
            </div>
          </section>

          {/* Field legend */}
          <section className="tx-section">
            <label className="section-label">Campos</label>
            <div className="field-legend">
              {activeResult.fields.map((field, i) => (
                <div
                  key={i}
                  className={`legend-row ${hoveredField === i ? 'legend-active' : ''}`}
                  onMouseEnter={() => setHoveredField(i)}
                  onMouseLeave={() => setHoveredField(null)}
                >
                  <span className="legend-color" style={{ background: field.color }} />
                  <span className="legend-name">{field.name}</span>
                  <span className="legend-size">{field.bytes.length}B</span>
                  <span className="legend-desc">{field.description}</span>
                </div>
              ))}
            </div>
          </section>
        </>
      )}

      {viewMode === 'parse' && (
        <>
          <section className="tx-section">
            <label className="section-label">Pegar raw transaction hex</label>
            <p className="section-description">
              Pega el hex de cualquier transacción Bitcoin y la decodificaremos campo a campo.
            </p>
            <textarea
              className="hex-textarea"
              value={rawHexInput}
              onChange={(e) => setRawHexInput(e.target.value.replace(/[^0-9a-fA-F]/g, ''))}
              placeholder="Pega aquí el hex crudo de una transacción..."
              rows={4}
            />
          </section>

          {parseResult && !('error' in parseResult) && (
            <>
              <section className="tx-section">
                <label className="section-label">Transacción decodificada</label>
                <div className="tx-structure">
                  <div className="struct-row">
                    <span className="struct-label">Version</span>
                    <span className="struct-value">{parseResult.tx.version}</span>
                  </div>
                  <div className="struct-row">
                    <span className="struct-label">Inputs</span>
                    <span className="struct-value">{parseResult.tx.inputs.length}</span>
                  </div>
                  {parseResult.tx.inputs.map((input, i) => (
                    <div key={i} className="struct-sub">
                      <div className="struct-detail">
                        <span className="detail-label">prevTxId</span>
                        <span className="detail-value">{input.prevTxId}</span>
                      </div>
                      <div className="struct-detail">
                        <span className="detail-label">vout</span>
                        <span className="detail-value">{input.prevVout}</span>
                      </div>
                      <div className="struct-detail">
                        <span className="detail-label">scriptSig</span>
                        <span className="detail-value">{input.scriptSig.length} bytes</span>
                      </div>
                    </div>
                  ))}
                  <div className="struct-row">
                    <span className="struct-label">Outputs</span>
                    <span className="struct-value">{parseResult.tx.outputs.length}</span>
                  </div>
                  {parseResult.tx.outputs.map((output, i) => (
                    <div key={i} className="struct-sub">
                      <div className="struct-detail">
                        <span className="detail-label">value</span>
                        <span className="detail-value">{output.value.toLocaleString()} sats</span>
                      </div>
                      <div className="struct-detail">
                        <span className="detail-label">scriptPubKey</span>
                        <span className="detail-value">{output.scriptPubKey.length} bytes</span>
                      </div>
                    </div>
                  ))}
                  <div className="struct-row">
                    <span className="struct-label">Locktime</span>
                    <span className="struct-value">{parseResult.tx.locktime}</span>
                  </div>
                  {parseResult.tx.witnesses && (
                    <div className="struct-row witness-row">
                      <span className="struct-label">SegWit</span>
                      <span className="struct-value">Sí — {parseResult.tx.witnesses.length} witness(es)</span>
                    </div>
                  )}
                </div>
              </section>

              <section className="tx-section txid-section">
                <label className="section-label">TxID</label>
                <div className="txid-value">{parseResult.serialized.txid}</div>
              </section>

              <section className="tx-section">
                <label className="section-label">Hex coloreado</label>
                <div className="hex-dump">
                  {parseResult.serialized.fields.map((field, i) => (
                    <span
                      key={i}
                      className={`hex-field ${hoveredField === i ? 'hovered' : ''}`}
                      style={{ color: field.color }}
                      onMouseEnter={() => setHoveredField(i)}
                      onMouseLeave={() => setHoveredField(null)}
                    >
                      {Array.from(field.bytes).map(b => b.toString(16).padStart(2, '0')).join('')}
                    </span>
                  ))}
                </div>
                <div
                  className={`field-tooltip ${hoveredField !== null && parseResult.serialized.fields[hoveredField] ? 'visible' : ''}`}
                  style={hoveredField !== null && parseResult.serialized.fields[hoveredField] ? { borderColor: parseResult.serialized.fields[hoveredField].color } : undefined}
                >
                  {hoveredField !== null && parseResult.serialized.fields[hoveredField] && (
                    <>
                      <span className="tooltip-name" style={{ color: parseResult.serialized.fields[hoveredField].color }}>
                        {parseResult.serialized.fields[hoveredField].name}
                      </span>
                      <span className="tooltip-desc">{parseResult.serialized.fields[hoveredField].description}</span>
                    </>
                  )}
                </div>
              </section>
            </>
          )}

          {parseResult && 'error' in parseResult && (
            <section className="tx-section">
              <div className="parse-error">Error al parsear: {parseResult.error}</div>
            </section>
          )}
        </>
      )}

      {/* Conceptos clave */}
      <section className="tx-section">
        <label className="section-label">Conceptos clave</label>
        <div className="concepts-grid">
          <div className="concept-item">
            <h4>Little-endian</h4>
            <p>Los números se almacenan con el byte menos significativo primero. El 1 se escribe como 01000000 (4 bytes).</p>
          </div>
          <div className="concept-item">
            <h4>VarInt</h4>
            <p>Formato compacto para cantidades: 1 byte si &lt;253, 3 bytes si &lt;65535, etc. Se usa para contar inputs, outputs y longitudes.</p>
          </div>
          <div className="concept-item">
            <h4>TxID reversed</h4>
            <p>El TxID se muestra con los bytes al revés por razones históricas. El hash real está en "internal byte order".</p>
          </div>
          <div className="concept-item">
            <h4>SegWit</h4>
            <p>Separa las firmas (witness) del cuerpo de la transacción. El TxID se calcula sin witness, resolviendo la maleabilidad.</p>
          </div>
        </div>
      </section>
    </div>
  );
}
