import { useState, useMemo, useCallback, useEffect } from 'react';
import {
  generateMnemonic,
  validateMnemonic,
  mnemonicToSeed,
  masterKeyFromSeed,
  derivePath,
  getDerivationPath,
  getAddress,
  BIP39_WORDLIST,
  type MnemonicResult,
  type DerivationStep,
  type HDNode,
} from '../crypto/hdwallet';
import { bytesToHex } from '../crypto/hmac';
import './HdWalletExplorer.css';

type Purpose = 44 | 84 | 86;

const PURPOSE_INFO: Record<Purpose, { label: string; desc: string; addrPrefix: string }> = {
  44: { label: 'BIP44 — P2PKH', desc: 'Legacy (1xxx)', addrPrefix: '1...' },
  84: { label: 'BIP84 — P2WPKH', desc: 'SegWit (bc1qxxx)', addrPrefix: 'bc1q...' },
  86: { label: 'BIP86 — P2TR', desc: 'Taproot (bc1pxxx)', addrPrefix: 'bc1p...' },
};

// Descripciones para cada nivel del arbol
const DEPTH_LABELS: Record<number, (step: DerivationStep) => string> = {
  0: () => 'Master key — raiz del arbol',
  1: (s) => `Purpose ${s.index}' — tipo de direccion`,
  2: () => "Coin 0' — Bitcoin mainnet",
  3: (s) => `Account ${s.index}' — cuenta logica`,
  4: (s) => s.index === 0 ? 'External — direcciones de recepcion' : 'Internal — direcciones de cambio',
  5: (s) => `Direccion #${s.index}`,
};

export function HdWalletExplorer() {
  const [mnemonicInput, setMnemonicInput] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [debouncedPassphrase, setDebouncedPassphrase] = useState('');
  const [purpose, setPurpose] = useState<Purpose>(84);
  const [numAddresses, setNumAddresses] = useState(5);
  const [selectedNode, setSelectedNode] = useState<number | null>(null);
  const [showBits, setShowBits] = useState(false);
  const [mnemonicResult, setMnemonicResult] = useState<MnemonicResult | null>(null);

  // Debounce de passphrase: esperar 500ms tras la ultima tecla
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedPassphrase(passphrase), 500);
    return () => clearTimeout(timer);
  }, [passphrase]);

  // Generar nuevo mnemonico
  const handleGenerate = useCallback(() => {
    const result = generateMnemonic();
    setMnemonicResult(result);
    setMnemonicInput(result.words.join(' '));
    setSelectedNode(null);
  }, []);

  // Parsear palabras del input
  const words = useMemo(() => {
    return mnemonicInput.trim().split(/\s+/).filter(w => w.length > 0);
  }, [mnemonicInput]);

  // Validar mnemonico
  const isValid = useMemo(() => {
    if (words.length < 12) return null; // aun no hay suficientes palabras
    return validateMnemonic(words);
  }, [words]);

  // Derivar todo el arbol
  const derivation = useMemo(() => {
    if (!isValid) return null;

    try {
      const seed = mnemonicToSeed(words, debouncedPassphrase);
      const master = masterKeyFromSeed(seed);

      // Derivar la ruta hasta la primera direccion
      const basePath = getDerivationPath(purpose, 0, false, 0);
      const { steps } = derivePath(master, basePath);

      // Generar varias direcciones
      const addressPath = basePath.split('/').slice(0, -1).join('/'); // hasta .../0
      const addresses: { index: number; address: string; privKeyHex: string }[] = [];
      for (let i = 0; i < numAddresses; i++) {
        const fullPath = `${addressPath}/${i}`;
        const { node } = derivePath(master, fullPath);
        addresses.push({
          index: i,
          address: getAddress(node, purpose),
          privKeyHex: node.privateKey.toString(16).padStart(64, '0'),
        });
      }

      return { seed, master, steps, addresses, basePath };
    } catch (e) {
      return null;
    }
  }, [isValid, words, debouncedPassphrase, purpose, numAddresses]);

  return (
    <div className="hd-explorer">
      <div className="hd-header">
        <h1>HD Wallets</h1>
        <p className="subtitle">
          Una HD wallet genera un arbol infinito de claves a partir de 12 palabras.
          BIP39 convierte entropia en palabras, BIP32 deriva el arbol, y BIP44/84/86
          definen como organizarlo.
        </p>
      </div>

      {/* BIP39: Mnemonico */}
      <div className="hd-section seed-section">
        <span className="section-label">BIP39 — Mnemonico</span>
        <p className="section-description">
          12 palabras que codifican 128 bits de entropia + 4 bits de checksum.
          Cada palabra es un indice de 11 bits en una lista de 2048 palabras.
        </p>

        <div className="hd-controls" style={{ marginBottom: '0.75rem' }}>
          <button className="hd-btn primary" onClick={handleGenerate}>
            Generar nuevo mnemonico
          </button>
          <button
            className={`hd-btn ${showBits ? 'primary' : ''}`}
            onClick={() => setShowBits(!showBits)}
          >
            {showBits ? 'Ocultar bits' : 'Ver bits'}
          </button>
        </div>

        <textarea
          className="mnemonic-input"
          rows={2}
          value={mnemonicInput}
          onChange={e => {
            setMnemonicInput(e.target.value);
            setMnemonicResult(null); // reset bits view on manual edit
          }}
          placeholder="Escribe o genera un mnemonico de 12 palabras..."
        />

        {isValid !== null && (
          <div className={`validation-msg ${isValid ? 'valid' : 'invalid'}`}>
            {isValid
              ? 'Mnemonico valido — checksum correcto'
              : 'Mnemonico invalido — checksum incorrecto o palabra desconocida'}
          </div>
        )}

        {/* Palabras como grid */}
        {words.length >= 12 && (
          <div className="mnemonic-grid" style={{ marginTop: '0.75rem' }}>
            {words.map((word, i) => {
              const idx = BIP39_WORDLIST.indexOf(word);
              return (
                <div key={i} className="mnemonic-word">
                  <span className="word-index">{i + 1}.</span>
                  <span className="word-text">{word}</span>
                  {idx >= 0 && (
                    <span style={{ fontSize: '0.6rem', color: '#475569', marginLeft: 'auto' }}>
                      {idx}
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {/* Bits detail */}
        {showBits && mnemonicResult && (
          <div className="bits-display">
            <div className="bits-row">
              <span className="bits-label">Entropia (128 bits)</span>
              <span className="bits-value bits-entropy">{mnemonicResult.entropyBits}</span>
            </div>
            <div className="bits-row">
              <span className="bits-label">Checksum ({mnemonicResult.checksumBits.length} bits = SHA-256 truncado)</span>
              <span className="bits-value bits-checksum">{mnemonicResult.checksumBits}</span>
            </div>
            <div className="bits-row">
              <span className="bits-label">Total (132 bits = 12 x 11 bits)</span>
              <span className="bits-value">
                {/* Color-code 11-bit groups */}
                {Array.from({ length: 12 }, (_, i) => {
                  const group = mnemonicResult.allBits.slice(i * 11, (i + 1) * 11);
                  const isLast = i === 11;
                  return (
                    <span
                      key={i}
                      className="bits-word-group"
                      title={`Palabra ${i + 1}: ${mnemonicResult.words[i]} (${mnemonicResult.wordIndices[i]})`}
                      style={{ color: isLast ? '#f87171' : '#38bdf8' }}
                    >
                      {group}{' '}
                    </span>
                  );
                })}
              </span>
            </div>
          </div>
        )}

        {/* Passphrase */}
        <div className="passphrase-row">
          <span className="passphrase-label">Passphrase (opcional):</span>
          <input
            className="passphrase-input"
            type="text"
            value={passphrase}
            onChange={e => setPassphrase(e.target.value)}
            placeholder='La "25a palabra" — mismas palabras + otra passphrase = otra wallet'
          />
        </div>
      </div>

      {/* Seed */}
      {derivation && (
        <div className="hd-section">
          <span className="section-label">Seed (512 bits)</span>
          <p className="section-description">
            PBKDF2-HMAC-SHA512 con 2048 iteraciones convierte el mnemonico + passphrase
            en 64 bytes de seed. Esta seed es la entrada para BIP32.
          </p>
          <div className="seed-hex">{bytesToHex(derivation.seed)}</div>
        </div>
      )}

      {/* Purpose selector */}
      {derivation && (
        <div className="hd-section">
          <span className="section-label">Tipo de derivacion</span>
          <div className="purpose-selector">
            {([44, 84, 86] as Purpose[]).map(p => (
              <button
                key={p}
                className={`purpose-btn ${purpose === p ? 'active' : ''}`}
                onClick={() => { setPurpose(p); setSelectedNode(null); }}
              >
                <span className="purpose-label">BIP{p}</span>
                <span className="purpose-sub">{PURPOSE_INFO[p].desc}</span>
              </button>
            ))}
          </div>
          <p className="section-description" style={{ margin: 0 }}>
            Ruta: <code style={{ color: '#fbbf24' }}>
              {getDerivationPath(purpose, 0, false, 0)}
            </code>
          </p>
        </div>
      )}

      {/* Arbol de derivacion */}
      {derivation && (
        <div className="hd-section">
          <span className="section-label">Arbol de derivacion BIP32</span>
          <p className="section-description">
            Cada nivel del arbol deriva una clave hija con HMAC-SHA512.
            Los niveles con ' son "hardened" (requieren clave privada).
            Haz clic en cualquier nodo para ver sus detalles.
          </p>

          <div className="derivation-tree">
            {derivation.steps.map((step, i) => {
              const indent = '  '.repeat(step.depth);
              const depthFn = DEPTH_LABELS[step.depth + (step.depth >= 5 ? 0 : 0)];
              const desc = depthFn ? depthFn(step) : '';
              const isSelected = selectedNode === i;
              const nodeClass = step.depth === 0
                ? 'node-master'
                : step.hardened
                  ? 'node-hardened'
                  : step.depth >= 5 ? 'node-leaf' : '';

              return (
                <div
                  key={i}
                  className={`tree-node ${nodeClass} ${isSelected ? 'node-active' : ''}`}
                  onClick={() => setSelectedNode(isSelected ? null : i)}
                >
                  <span className="node-indent">{indent}{step.depth > 0 ? '└─' : ''}</span>
                  <div className="node-content">
                    <div className="node-path">
                      {step.path}
                      {step.hardened && <span className="node-hardened-label"> (hardened)</span>}
                    </div>
                    {desc && <div className="node-description">{desc}</div>}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Panel de detalle del nodo seleccionado */}
          {selectedNode !== null && derivation.steps[selectedNode] && (
            <NodeDetail
              step={derivation.steps[selectedNode]}
              purpose={purpose}
              node={selectedNode === 0 ? derivation.master : undefined}
            />
          )}
        </div>
      )}

      {/* Direcciones generadas */}
      {derivation && (
        <div className="hd-section">
          <span className="section-label">Direcciones derivadas</span>
          <p className="section-description">
            Las primeras {numAddresses} direcciones de recepcion (external chain, index 0..{numAddresses - 1}).
            Cada transaccion deberia usar una direccion nueva para mayor privacidad.
          </p>

          <div className="address-list">
            {derivation.addresses.map(a => (
              <div key={a.index} className="address-row">
                <span className="addr-index">/{a.index}</span>
                <span className="addr-value">{a.address}</span>
              </div>
            ))}
          </div>

          <div className="hd-controls" style={{ marginTop: '0.75rem' }}>
            <button className="hd-btn" onClick={() => setNumAddresses(n => Math.min(n + 5, 20))}>
              Mostrar mas
            </button>
            {numAddresses > 5 && (
              <button className="hd-btn" onClick={() => setNumAddresses(5)}>
                Mostrar menos
              </button>
            )}
          </div>
        </div>
      )}

      {/* Conceptos clave */}
      <div className="hd-section">
        <span className="section-label">Conceptos clave</span>
        <div className="concepts-grid">
          <div className="concept-item">
            <h4>12 palabras = toda la wallet</h4>
            <p>
              El mnemonico codifica la entropia que genera la seed.
              De la seed se derivan infinitas claves y direcciones.
              Perder estas palabras = perder los fondos.
            </p>
          </div>
          <div className="concept-item">
            <h4>Hardened vs Normal</h4>
            <p>
              La derivacion hardened (') usa la clave privada del padre.
              La normal usa la publica. Hardened protege contra el ataque
              "xpub + child privkey = parent privkey".
            </p>
          </div>
          <div className="concept-item">
            <h4>Chain code</h4>
            <p>
              Cada nodo tiene 32 bytes extra de entropia (chain code).
              Sin el, conocer una clave no permite derivar hermanos.
              Es lo que hace el arbol realmente jerarquico.
            </p>
          </div>
          <div className="concept-item">
            <h4>Passphrase = 25a palabra</h4>
            <p>
              Las mismas 12 palabras con diferente passphrase producen
              una wallet completamente diferente. Util para "plausible
              deniability" — una wallet real y una de senuelo.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Subcomponente: detalle de un nodo ───────────────────────

function NodeDetail({
  step,
  purpose,
  node,
}: {
  step: DerivationStep;
  purpose: Purpose;
  node?: HDNode;
}) {
  return (
    <div className="node-detail">
      <div className="detail-title">{step.path}</div>
      <div className="detail-grid">
        <div className="detail-row">
          <span className="detail-key">Profundidad</span>
          <span className="detail-val">{step.depth}</span>
        </div>
        <div className="detail-row">
          <span className="detail-key">Indice</span>
          <span className="detail-val">{step.index}{step.hardened ? " (hardened)" : ""}</span>
        </div>
        <div className="detail-row">
          <span className="detail-key">Clave privada</span>
          <span className="detail-val">{step.privateKeyHex}</span>
        </div>
        <div className="detail-row">
          <span className="detail-key">Clave publica</span>
          <span className="detail-val">{step.publicKeyHex}</span>
        </div>
        <div className="detail-row">
          <span className="detail-key">Chain code</span>
          <span className="detail-val">{step.chainCodeHex}</span>
        </div>
        {step.address && (
          <div className="detail-row">
            <span className="detail-key">Direccion</span>
            <span className="detail-val address-val">{step.address}</span>
          </div>
        )}
      </div>
    </div>
  );
}
