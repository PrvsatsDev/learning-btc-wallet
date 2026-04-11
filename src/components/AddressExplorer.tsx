import { useState, useMemo } from 'react';
import { getPublicKey, compressPublicKey, uncompressPublicKey, N } from '../crypto/secp256k1';
import { sha256Hex } from '../crypto/sha256';
import { ripemd160Hex } from '../crypto/ripemd160';
import { base58CheckEncode, base58CheckValidate } from '../crypto/base58';
import { bech32Decode } from '../crypto/script';
import './AddressExplorer.css';

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function AddressExplorer() {
  const [privKeyHex, setPrivKeyHex] = useState('1');
  const [validateInput, setValidateInput] = useState('');

  const privKey = useMemo(() => {
    try {
      const k = BigInt('0x' + (privKeyHex || '0'));
      if (k <= 0n || k >= N) return null;
      return k;
    } catch {
      return null;
    }
  }, [privKeyHex]);

  const derivation = useMemo(() => {
    if (!privKey) return null;

    // 1. Clave pública
    const pubKeyPoint = getPublicKey(privKey);
    if (!pubKeyPoint) return null;
    const compressed = compressPublicKey(pubKeyPoint);
    const uncompressed = uncompressPublicKey(pubKeyPoint);

    // 2. SHA-256 de la clave pública comprimida
    const shaHash = sha256Hex(hexToBytes(compressed));

    // 3. RIPEMD-160 del SHA-256
    const hash160 = ripemd160Hex(hexToBytes(shaHash));

    // 4. Base58Check con version 0x00 (mainnet) y 0x6f (testnet)
    const mainnet = base58CheckEncode(0x00, hexToBytes(hash160));
    const testnet = base58CheckEncode(0x6f, hexToBytes(hash160));

    return {
      compressed,
      uncompressed,
      shaHash,
      hash160,
      mainnet,
      testnet,
    };
  }, [privKey]);

  const validation = useMemo(() => {
    const addr = validateInput.trim();
    if (!addr) return null;

    // Bech32/Bech32m: direcciones bc1... o tb1...
    const lower = addr.toLowerCase();
    if (lower.startsWith('bc1') || lower.startsWith('tb1')) {
      const decoded = bech32Decode(addr);
      if (decoded) {
        const programHex = Array.from(decoded.program).map(b => b.toString(16).padStart(2, '0')).join('');
        const typeLabel = decoded.version === 0
          ? (decoded.program.length === 20 ? 'P2WPKH (SegWit v0)' : 'P2WSH (SegWit v0)')
          : decoded.version === 1
            ? 'P2TR (Taproot)'
            : `SegWit v${decoded.version}`;
        return { valid: true, version: decoded.version, payload: programHex, type: typeLabel, encoding: decoded.version === 0 ? 'Bech32' : 'Bech32m' };
      }
      return { valid: false as const, error: 'Dirección Bech32/Bech32m inválida — checksum incorrecto o formato erróneo', type: '', encoding: '' };
    }

    // Legacy: Base58Check
    const result = base58CheckValidate(addr);
    if (result.valid) {
      return { ...result, type: result.version === 0 ? 'P2PKH' : result.version === 5 ? 'P2SH' : 'Desconocido', encoding: 'Base58Check' };
    }
    return { ...result, type: '', encoding: '' };
  }, [validateInput]);

  return (
    <div className="addr-explorer">
      <header className="addr-header">
        <h1>Dirección Bitcoin</h1>
        <p className="subtitle">
          El flujo completo: desde un número aleatorio (clave privada) hasta
          la dirección que compartes para recibir bitcoin. Todo con código nuestro,
          sin librerías.
        </p>
      </header>

      {/* Private key input */}
      <section className="addr-section">
        <label className="section-label">1. Clave privada</label>
        <p className="section-description">
          Un número aleatorio de 256 bits. Es lo único que necesitas guardar
          en secreto — todo lo demás se deriva de aquí.
        </p>
        <div className="privkey-input-row">
          <span className="hex-prefix">0x</span>
          <input
            type="text"
            className="addr-input"
            value={privKeyHex}
            onChange={(e) => setPrivKeyHex(e.target.value.replace(/[^0-9a-fA-F]/g, ''))}
            placeholder="1"
          />
        </div>
        <div className="quick-keys">
          {['1', '2', 'ff', 'deadbeef', 'cafebabe01234567'].map((k) => (
            <button key={k} className="quick-btn" onClick={() => setPrivKeyHex(k)}>
              0x{k}
            </button>
          ))}
        </div>
      </section>

      {derivation && (
        <>
          {/* Full derivation pipeline */}
          <section className="addr-section pipeline-section">
            <label className="section-label">Pipeline de derivación</label>
            <div className="pipeline">
              <div className="pipe-step">
                <div className="pipe-header">
                  <span className="pipe-num">1</span>
                  <span className="pipe-title">Clave privada</span>
                </div>
                <div className="pipe-value privkey-color">
                  0x{privKey!.toString(16)}
                </div>
                <div className="pipe-desc">Número secreto (256 bits)</div>
              </div>

              <div className="pipe-arrow">
                <span className="pipe-op">× G (curva elíptica secp256k1)</span>
              </div>

              <div className="pipe-step">
                <div className="pipe-header">
                  <span className="pipe-num">2</span>
                  <span className="pipe-title">Clave pública (comprimida)</span>
                </div>
                <div className="pipe-value pubkey-color">{derivation.compressed}</div>
                <div className="pipe-desc">
                  33 bytes: prefijo ({derivation.compressed.slice(0, 2)}) + coordenada x
                </div>
              </div>

              <div className="pipe-arrow">
                <span className="pipe-op">SHA-256</span>
              </div>

              <div className="pipe-step">
                <div className="pipe-header">
                  <span className="pipe-num">3</span>
                  <span className="pipe-title">SHA-256 hash</span>
                </div>
                <div className="pipe-value sha-color">{derivation.shaHash}</div>
                <div className="pipe-desc">32 bytes (256 bits)</div>
              </div>

              <div className="pipe-arrow">
                <span className="pipe-op">RIPEMD-160</span>
              </div>

              <div className="pipe-step">
                <div className="pipe-header">
                  <span className="pipe-num">4</span>
                  <span className="pipe-title">Hash160</span>
                </div>
                <div className="pipe-value ripemd-color">{derivation.hash160}</div>
                <div className="pipe-desc">20 bytes (160 bits) — el "payload" de la dirección</div>
              </div>

              <div className="pipe-arrow">
                <span className="pipe-op">Base58Check (version + checksum)</span>
              </div>

              <div className="pipe-step final-step">
                <div className="pipe-header">
                  <span className="pipe-num">5</span>
                  <span className="pipe-title">Dirección Bitcoin</span>
                </div>
                <div className="pipe-value address-color">{derivation.mainnet.address}</div>
                <div className="pipe-desc">Mainnet (version 0x00 → empieza con "1")</div>
              </div>
            </div>
          </section>

          {/* Base58Check breakdown */}
          <section className="addr-section">
            <label className="section-label">Anatomía de Base58Check</label>
            <p className="section-description">
              La dirección no es solo el hash. Se le añade un byte de versión al inicio
              y 4 bytes de checksum al final. El checksum es SHA-256(SHA-256(version + hash160)),
              para detectar errores al copiar la dirección.
            </p>
            <div className="base58-anatomy">
              <div className="anatomy-row">
                <div className="anatomy-part version-part">
                  <span className="part-label">Versión</span>
                  <span className="part-value">
                    {derivation.mainnet.fullPayload.slice(0, 2)}
                  </span>
                  <span className="part-desc">0x00 = mainnet</span>
                </div>
                <div className="anatomy-part payload-part">
                  <span className="part-label">Hash160</span>
                  <span className="part-value">{derivation.mainnet.payload}</span>
                  <span className="part-desc">20 bytes</span>
                </div>
                <div className="anatomy-part checksum-part">
                  <span className="part-label">Checksum</span>
                  <span className="part-value">{derivation.mainnet.checksum}</span>
                  <span className="part-desc">4 bytes</span>
                </div>
              </div>
              <div className="anatomy-arrow">↓ Base58 encode</div>
              <div className="anatomy-result">{derivation.mainnet.address}</div>
            </div>
          </section>

          {/* Mainnet vs Testnet */}
          <section className="addr-section">
            <label className="section-label">Mainnet vs Testnet</label>
            <div className="network-comparison">
              <div className="network-box">
                <h3>Mainnet <span className="version-badge">version 0x00</span></h3>
                <div className="network-address mainnet-color">
                  {derivation.mainnet.address}
                </div>
                <p>Empieza con <strong>1</strong> — bitcoins reales</p>
              </div>
              <div className="network-box">
                <h3>Testnet <span className="version-badge">version 0x6f</span></h3>
                <div className="network-address testnet-color">
                  {derivation.testnet.address}
                </div>
                <p>Empieza con <strong>m</strong> o <strong>n</strong> — bitcoins de prueba</p>
              </div>
            </div>
          </section>
        </>
      )}

      {/* Address validator */}
      <section className="addr-section">
        <label className="section-label">Validador de direcciones</label>
        <p className="section-description">
          Pega una dirección Bitcoin para comprobar si el checksum es correcto.
          Prueba a cambiar un carácter y mira cómo falla.
        </p>
        <input
          type="text"
          className="addr-input full-width"
          value={validateInput}
          onChange={(e) => setValidateInput(e.target.value)}
          placeholder="Pega una dirección Bitcoin..."
        />
        {validation && (
          <div className={`validation-result ${validation.valid ? 'valid' : 'invalid'}`}>
            {validation.valid ? (
              <>
                <span className="validation-icon">Válida</span>
                <span>Tipo: {validation.type} ({validation.encoding})</span>
                <span>Versión: {validation.version}</span>
                <span>{validation.encoding === 'Base58Check' ? 'Hash160' : 'Witness program'}: {validation.payload}</span>
              </>
            ) : (
              <>
                <span className="validation-icon">Inválida</span>
                <span>{validation.error}</span>
              </>
            )}
          </div>
        )}
      </section>
    </div>
  );
}
