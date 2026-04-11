import { useState, useMemo } from 'react';
import {
  executeScript,
  createP2PKH,
  createP2WPKH,
  createP2TR,
  disassemble,
  addressP2WPKH,
  addressP2TR,
  type ScriptStep,
} from '../crypto/script';
import { sha256 } from '../crypto/sha256';
import { ripemd160Hex } from '../crypto/ripemd160';
import { getPublicKey, compressPublicKey } from '../crypto/secp256k1';
import './ScriptExplorer.css';

// ─── Utilidades locales ──────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

type ScriptType = 'p2pkh' | 'p2wpkh' | 'p2tr';

// ─── Componente ──────────────────────────────────────────────

export function ScriptExplorer() {
  const [privKeyHex, setPrivKeyHex] = useState('1');
  const [scriptType, setScriptType] = useState<ScriptType>('p2pkh');
  const [activeStep, setActiveStep] = useState<number | null>(null);
  const [showAllSteps, setShowAllSteps] = useState(true);

  // Derivar claves y hashes
  const keyData = useMemo(() => {
    try {
      const privKey = BigInt('0x' + (privKeyHex || '0'));
      if (privKey <= 0n) return null;

      const pubPoint = getPublicKey(privKey)!;
      const pubKeyHex = compressPublicKey(pubPoint);
      const pubKeyBytes = hexToBytes(pubKeyHex);

      // Hash160 = RIPEMD-160(SHA-256(pubKey))
      const shaHash = sha256(pubKeyBytes).hash;
      const hash160 = ripemd160Hex(hexToBytes(shaHash));
      const hash160Bytes = hexToBytes(hash160);

      // X-only para Taproot (32 bytes, sin prefijo de paridad)
      const xOnlyHex = pubPoint.x.toString(16).padStart(64, '0');
      const xOnlyBytes = hexToBytes(xOnlyHex);

      return { privKey, pubKeyHex, pubKeyBytes, hash160, hash160Bytes, xOnlyHex, xOnlyBytes };
    } catch {
      return null;
    }
  }, [privKeyHex]);

  // Generar scripts según el tipo
  const scriptData = useMemo(() => {
    if (!keyData) return null;

    const { pubKeyBytes, hash160Bytes, xOnlyBytes } = keyData;

    switch (scriptType) {
      case 'p2pkh': {
        // scriptSig: <sig> <pubKey>  |  scriptPubKey: OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
        const scriptPubKey = createP2PKH(hash160Bytes);

        // Simular scriptSig + scriptPubKey para ejecución
        // Firma simulada (72 bytes de ejemplo) + pubKey comprimida (33 bytes)
        const fakeSig = new Uint8Array(72).fill(0xab);
        const combined = new Uint8Array([
          fakeSig.length, ...fakeSig,     // PUSH sig
          pubKeyBytes.length, ...pubKeyBytes,  // PUSH pubKey
          ...scriptPubKey,
        ]);

        return {
          scriptPubKey,
          scriptPubKeyHex: bytesToHex(scriptPubKey),
          disassembled: disassemble(scriptPubKey),
          combined,
          execution: executeScript(combined),
        };
      }
      case 'p2wpkh': {
        const scriptPubKey = createP2WPKH(hash160Bytes);
        return {
          scriptPubKey,
          scriptPubKeyHex: bytesToHex(scriptPubKey),
          disassembled: disassemble(scriptPubKey),
          combined: scriptPubKey,
          execution: null, // SegWit no ejecuta scriptSig+scriptPubKey de forma clásica
        };
      }
      case 'p2tr': {
        const scriptPubKey = createP2TR(xOnlyBytes);
        return {
          scriptPubKey,
          scriptPubKeyHex: bytesToHex(scriptPubKey),
          disassembled: disassemble(scriptPubKey),
          combined: scriptPubKey,
          execution: null, // Taproot usa witness
        };
      }
    }
  }, [keyData, scriptType]);

  // Direcciones
  const addresses = useMemo(() => {
    if (!keyData) return null;
    const { hash160, hash160Bytes, xOnlyBytes } = keyData;
    return {
      p2pkh: '1...(Base58Check de 00' + hash160.slice(0, 8) + '...)',
      p2wpkh: addressP2WPKH(hash160Bytes),
      p2tr: addressP2TR(xOnlyBytes),
    };
  }, [keyData]);

  return (
    <div className="script-explorer">
      <div className="script-header">
        <h1>Bitcoin Script</h1>
        <p className="subtitle">
          Bitcoin usa un lenguaje de pila (stack) para definir las condiciones de gasto de cada UTXO.
          No es Turing-completo: no tiene bucles, solo operaciones simples sobre una pila.
        </p>
      </div>

      {/* Input: clave privada */}
      <div className="script-section">
        <span className="section-label">Clave privada</span>
        <p className="section-description">
          La misma clave privada genera tres tipos de dirección diferentes.
          Cada tipo usa un script distinto para proteger los fondos.
        </p>
        <input
          type="text"
          value={privKeyHex}
          onChange={e => setPrivKeyHex(e.target.value.replace(/[^0-9a-fA-F]/g, ''))}
          placeholder="Clave privada (hex)"
          style={{
            width: '100%', padding: '0.5rem 0.75rem',
            fontFamily: "'JetBrains Mono', monospace", fontSize: '0.85rem',
            background: '#0f172a', color: '#e2e8f0',
            border: '1px solid #334155', borderRadius: '8px',
            boxSizing: 'border-box',
          }}
        />
        {keyData && (
          <div style={{ marginTop: '0.5rem', fontSize: '0.75rem', color: '#64748b' }}>
            PubKey: {keyData.pubKeyHex.slice(0, 20)}...&nbsp;&nbsp;|&nbsp;&nbsp;
            Hash160: {keyData.hash160.slice(0, 16)}...
          </div>
        )}
      </div>

      {/* Selector de tipo de script */}
      <div className="script-section">
        <span className="section-label">Tipo de script</span>
        <div className="script-type-selector">
          <button
            className={`script-type-btn ${scriptType === 'p2pkh' ? 'active' : ''}`}
            onClick={() => setScriptType('p2pkh')}
          >
            <span className="script-type-label">P2PKH</span>
            <span className="script-type-addr">1xxx... (legacy)</span>
          </button>
          <button
            className={`script-type-btn ${scriptType === 'p2wpkh' ? 'active' : ''}`}
            onClick={() => setScriptType('p2wpkh')}
          >
            <span className="script-type-label">P2WPKH</span>
            <span className="script-type-addr">bc1qxxx... (SegWit v0)</span>
          </button>
          <button
            className={`script-type-btn ${scriptType === 'p2tr' ? 'active' : ''}`}
            onClick={() => setScriptType('p2tr')}
          >
            <span className="script-type-label">P2TR</span>
            <span className="script-type-addr">bc1pxxx... (Taproot)</span>
          </button>
        </div>

        {/* Explicación del tipo */}
        {scriptType === 'p2pkh' && (
          <p className="section-description">
            <strong>Pay to Public Key Hash</strong> — el script original de Bitcoin.
            El scriptPubKey contiene el hash de tu clave publica. Para gastar, debes
            proporcionar la firma + clave publica en el scriptSig. El nodo verifica que
            el hash coincida y que la firma sea valida.
          </p>
        )}
        {scriptType === 'p2wpkh' && (
          <p className="section-description">
            <strong>Pay to Witness Public Key Hash</strong> — SegWit nativo (v0).
            El scriptPubKey es minimalista: solo OP_0 + hash160. La firma va en el
            campo "witness" de la transaccion, fuera del script clasico. Esto reduce el
            tamano efectivo y elimina problemas de maleabilidad de txid.
          </p>
        )}
        {scriptType === 'p2tr' && (
          <p className="section-description">
            <strong>Pay to Taproot</strong> — SegWit v1 (BIP341/342).
            Solo OP_1 + x-only pubkey (32 bytes). Usa firmas Schnorr en el witness.
            Un gasto por key-path es indistinguible de un pago simple, mejorando la
            privacidad. Tambien soporta scripts complejos ocultos en el arbol Merkle.
          </p>
        )}
      </div>

      {/* ScriptPubKey desensamblado */}
      {scriptData && (
        <div className="script-section">
          <span className="section-label">scriptPubKey</span>
          <p className="section-description">
            El script que bloquea los fondos. Se guarda en la salida (output) de la transaccion.
          </p>

          <div className="script-code">
            {scriptData.disassembled.map((line, i) => {
              const isOpcode = line.startsWith('OP_');
              const isData = line.startsWith('PUSH(');
              return (
                <div key={i} className="script-line">
                  {isOpcode && <span className="script-opcode">{line}</span>}
                  {isData && (
                    <>
                      <span className="script-opcode">PUSH</span>
                      <span className="script-data">{line.slice(5, -1)}</span>
                    </>
                  )}
                  {!isOpcode && !isData && <span className="script-data">{line}</span>}
                </div>
              );
            })}
          </div>

          <div style={{ marginTop: '0.75rem', fontSize: '0.72rem', color: '#64748b' }}>
            Hex: <code style={{ color: '#94a3b8' }}>{scriptData.scriptPubKeyHex}</code>
          </div>
        </div>
      )}

      {/* Ejecucion paso a paso (solo P2PKH tiene ejecucion clasica) */}
      {scriptType === 'p2pkh' && scriptData?.execution && (
        <div className="script-section">
          <span className="section-label">Ejecucion del script</span>
          <p className="section-description">
            El nodo ejecuta scriptSig (firma + pubKey) seguido de scriptPubKey.
            Si la pila queda con "true" en el tope, la transaccion es valida.
          </p>

          <div className="exec-controls">
            <button
              className={`exec-btn ${showAllSteps ? 'primary' : ''}`}
              onClick={() => { setShowAllSteps(true); setActiveStep(null); }}
            >
              Todos los pasos
            </button>
            <button
              className={`exec-btn ${!showAllSteps ? 'primary' : ''}`}
              onClick={() => { setShowAllSteps(false); setActiveStep(0); }}
            >
              Paso a paso
            </button>
            {!showAllSteps && activeStep !== null && (
              <>
                <button
                  className="exec-btn"
                  onClick={() => setActiveStep(Math.max(0, activeStep - 1))}
                  disabled={activeStep === 0}
                >
                  ← Anterior
                </button>
                <button
                  className="exec-btn"
                  onClick={() => setActiveStep(Math.min(scriptData.execution!.steps.length - 1, activeStep + 1))}
                  disabled={activeStep === scriptData.execution!.steps.length - 1}
                >
                  Siguiente →
                </button>
                <span style={{ fontSize: '0.75rem', color: '#64748b', alignSelf: 'center' }}>
                  {activeStep + 1} / {scriptData.execution!.steps.length}
                </span>
              </>
            )}
          </div>

          <div className="stack-container">
            {scriptData.execution.steps
              .filter((_, i) => showAllSteps || i === activeStep)
              .map((step, displayIdx) => {
                const stepIdx = showAllSteps ? displayIdx : activeStep!;
                return (
                  <StackStepRow
                    key={stepIdx}
                    step={step}
                    index={stepIdx}
                    isActive={activeStep === stepIdx}
                    onClick={() => setActiveStep(stepIdx)}
                    showAllSteps={showAllSteps}
                  />
                );
              })}
          </div>

          <div className={`exec-result ${scriptData.execution.success ? 'success' : 'failure'}`}>
            {scriptData.execution.success
              ? 'Script valido — gasto autorizado'
              : `Script invalido${scriptData.execution.error ? ': ' + scriptData.execution.error : ''}`}
          </div>
        </div>
      )}

      {/* SegWit / Taproot: explicar witness */}
      {scriptType !== 'p2pkh' && (
        <div className="script-section">
          <span className="section-label">
            {scriptType === 'p2wpkh' ? 'Witness (SegWit v0)' : 'Witness (Taproot)'}
          </span>
          <p className="section-description">
            {scriptType === 'p2wpkh'
              ? 'En P2WPKH, el scriptSig esta vacio. La firma y la clave publica van en el campo witness de la transaccion. El nodo valida internamente como si fuera P2PKH pero con los datos del witness.'
              : 'En P2TR (key path), el witness contiene solo la firma Schnorr de 64 bytes. No hay clave publica explicita — se deduce del scriptPubKey. Esto es mas eficiente y privado.'}
          </p>
          <div className="script-code">
            {scriptType === 'p2wpkh' ? (
              <>
                <div className="script-line">
                  <span className="script-opcode">witness[0]</span>
                  <span className="script-data">&lt;firma DER + sighash&gt; (71-73 bytes)</span>
                </div>
                <div className="script-line">
                  <span className="script-opcode">witness[1]</span>
                  <span className="script-data">&lt;pubKey comprimida&gt; (33 bytes)</span>
                </div>
              </>
            ) : (
              <div className="script-line">
                <span className="script-opcode">witness[0]</span>
                <span className="script-data">&lt;firma Schnorr&gt; (64 bytes)</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Comparativa de direcciones */}
      {addresses && (
        <div className="script-section">
          <span className="section-label">Una clave, tres direcciones</span>
          <p className="section-description">
            La misma clave privada genera tres direcciones distintas.
            Cada una usa un script diferente para proteger los fondos.
          </p>
          <div className="address-comparison">
            <div className="addr-row">
              <div>
                <div className="addr-type">P2PKH</div>
                <div className="addr-meta">Legacy</div>
              </div>
              <div className="addr-value">{addresses.p2pkh}</div>
            </div>
            <div className="addr-row">
              <div>
                <div className="addr-type">P2WPKH</div>
                <div className="addr-meta">SegWit v0</div>
              </div>
              <div className="addr-value">{addresses.p2wpkh}</div>
            </div>
            <div className="addr-row">
              <div>
                <div className="addr-type">P2TR</div>
                <div className="addr-meta">Taproot</div>
              </div>
              <div className="addr-value">{addresses.p2tr}</div>
            </div>
          </div>
        </div>
      )}

      {/* Referencia de opcodes */}
      <div className="script-section">
        <span className="section-label">Referencia de opcodes</span>
        <p className="section-description">
          Bitcoin Script tiene ~100 opcodes, pero solo unos pocos se usan en la practica.
          Estos son los esenciales para P2PKH:
        </p>
        <div className="opcode-grid">
          {[
            { name: 'OP_DUP', hex: '0x76', desc: 'Duplica el tope de la pila' },
            { name: 'OP_HASH160', hex: '0xa9', desc: 'SHA-256 + RIPEMD-160' },
            { name: 'OP_EQUALVERIFY', hex: '0x88', desc: 'Compara y falla si no son iguales' },
            { name: 'OP_CHECKSIG', hex: '0xac', desc: 'Verifica firma ECDSA/Schnorr' },
            { name: 'OP_0', hex: '0x00', desc: 'Apila un valor vacio (false)' },
            { name: 'OP_1', hex: '0x51', desc: 'Apila 1 (true / witness v1)' },
            { name: 'OP_EQUAL', hex: '0x87', desc: 'Compara dos items, deja true/false' },
            { name: 'OP_RETURN', hex: '0x6a', desc: 'Marca salida como no gastable (datos)' },
          ].map(op => (
            <div key={op.name} className="opcode-card">
              <span className="opcode-name">{op.name}</span>
              <span className="opcode-hex">{op.hex}</span>
              <div className="opcode-desc">{op.desc}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Conceptos clave */}
      <div className="script-section">
        <span className="section-label">Conceptos clave</span>
        <div className="concepts-grid">
          <div className="concept-item">
            <h4>No Turing-completo</h4>
            <p>
              Sin bucles ni recursion. Cada script termina siempre.
              Esto evita ataques de denegacion de servicio.
            </p>
          </div>
          <div className="concept-item">
            <h4>scriptSig + scriptPubKey</h4>
            <p>
              El remitente proporciona la prueba (scriptSig),
              el receptor define las condiciones (scriptPubKey).
            </p>
          </div>
          <div className="concept-item">
            <h4>SegWit (witness)</h4>
            <p>
              Mueve la firma fuera del script clasico. Reduce tamano,
              elimina maleabilidad del txid, habilita Lightning.
            </p>
          </div>
          <div className="concept-item">
            <h4>Taproot</h4>
            <p>
              Un gasto simple es indistinguible de uno complejo.
              Mejora privacidad y reduce costes para scripts avanzados.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Subcomponente: fila de paso del stack ───────────────────

function StackStepRow({
  step,
  index,
  isActive,
  onClick,
  showAllSteps,
}: {
  step: ScriptStep;
  index: number;
  isActive: boolean;
  onClick: () => void;
  showAllSteps: boolean;
}) {
  return (
    <div
      className={`stack-step ${isActive && !showAllSteps ? 'active-step' : ''}`}
      onClick={onClick}
    >
      <div className="step-info">
        <div className="step-opcode">
          <span style={{ color: '#475569', marginRight: '0.5rem' }}>#{index + 1}</span>
          {step.opcodeName}
        </div>
        <div className="step-desc">{step.description}</div>
        {step.consumed.length > 0 && (
          <div className="step-consumed">
            - {step.consumed.map(c => truncHex(c)).join(', ')}
          </div>
        )}
        {step.produced.length > 0 && (
          <div className="step-produced">
            + {step.produced.map(p => truncHex(p)).join(', ')}
          </div>
        )}
      </div>
      <div className="stack-visual">
        {step.stack.length === 0 ? (
          <div className="stack-empty">(pila vacia)</div>
        ) : (
          step.stack.map((item, i) => (
            <div
              key={i}
              className={`stack-item ${step.produced.includes(item) ? 'new-item' : ''}`}
            >
              {truncHex(item, 32)}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function truncHex(hex: string, maxLen = 24): string {
  if (hex.length <= maxLen) return hex;
  return hex.slice(0, maxLen / 2) + '...' + hex.slice(-maxLen / 2);
}
