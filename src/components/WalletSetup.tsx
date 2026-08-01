/**
 * Wallet Setup — Fase 3, Paso 1
 *
 * Aquí pasamos de "explorador educativo" a "wallet funcional".
 * En la Fase 2 aprendimos cómo funciona BIP39/BIP32. Ahora usamos
 * esas mismas primitivas para crear una wallet real.
 *
 * Flujo:
 *   1. Elegir: crear nueva wallet o importar una existente
 *   2. Generar/validar el mnemónico
 *   3. (Opcional) passphrase
 *   4. Derivar master key → direcciones de recepción
 *
 * Todo lo que ocurre aquí usa las funciones que ya implementamos
 * en hdwallet.ts — generateMnemonic, mnemonicToSeed, masterKeyFromSeed, etc.
 */

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
} from '../crypto/hdwallet';
import { bytesToHex } from '../crypto/hmac';
import type { Network } from '../api/mempool';
import './WalletSetup.css';

type Step = 'choose' | 'generate' | 'import' | 'confirm-backup' | 'wallet';

/** Datos de la wallet una vez configurada */
interface WalletData {
  words: string[];
  passphrase: string;
  seedHex: string;
  network: Network;
  addresses: { index: number; path: string; address: string }[];
}

/** Metadatos de cada red para la UI */
const NETWORKS: { id: Network; label: string; hrp: string; hint: string }[] = [
  { id: 'testnet4', label: 'Testnet4', hrp: 'tb1q', hint: 'Red de pruebas — la que usamos para experimentar' },
  { id: 'signet', label: 'Signet', hrp: 'tb1q', hint: 'Red de pruebas firmada, más estable que testnet' },
  { id: 'mainnet', label: 'Mainnet', hrp: 'bc1q', hint: 'Red real — aquí las monedas valen dinero de verdad' },
];

export function WalletSetup() {
  const [step, setStep] = useState<Step>('choose');
  const [words, setWords] = useState<string[]>([]);
  const [importInput, setImportInput] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [debouncedPassphrase, setDebouncedPassphrase] = useState('');
  const [wordCount, setWordCount] = useState<12 | 24>(12);
  const [network, setNetwork] = useState<Network>('testnet4');
  const [backupConfirmed, setBackupConfirmed] = useState(false);
  const [showWords, setShowWords] = useState(true);
  const [walletData, setWalletData] = useState<WalletData | null>(null);
  const [importError, setImportError] = useState<string | null>(null);

  // Debounce passphrase (cálculo PBKDF2 es pesado)
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedPassphrase(passphrase), 500);
    return () => clearTimeout(timer);
  }, [passphrase]);

  // ─── Generar nuevo mnemónico ─────────────────────────────
  const handleGenerate = useCallback(() => {
    const entropyBytes = wordCount === 12 ? 16 : 32; // 128 o 256 bits
    const entropy = crypto.getRandomValues(new Uint8Array(entropyBytes));
    const result = generateMnemonic(entropy);
    setWords(result.words);
    setStep('generate');
    setBackupConfirmed(false);
    setShowWords(true);
  }, [wordCount]);

  // ─── Importar mnemónico existente ────────────────────────
  const parsedImportWords = useMemo(() => {
    return importInput.trim().split(/\s+/).filter(w => w.length > 0);
  }, [importInput]);

  const importValidation = useMemo(() => {
    if (parsedImportWords.length === 0) return null;
    if (parsedImportWords.length !== 12 && parsedImportWords.length !== 24) {
      return { valid: false, msg: `Se necesitan 12 o 24 palabras (tienes ${parsedImportWords.length})` };
    }
    const unknownWords = parsedImportWords.filter(w => BIP39_WORDLIST.indexOf(w) === -1);
    if (unknownWords.length > 0) {
      return { valid: false, msg: `Palabras no reconocidas: ${unknownWords.join(', ')}` };
    }
    if (!validateMnemonic(parsedImportWords)) {
      return { valid: false, msg: 'Checksum incorrecto — revisa que las palabras sean correctas y estén en orden' };
    }
    return { valid: true, msg: 'Mnemónico válido' };
  }, [parsedImportWords]);

  // ─── Derivar wallet ──────────────────────────────────────
  const deriveWallet = useCallback((seedWords: string[], pass: string) => {
    const seed = mnemonicToSeed(seedWords, pass);
    const master = masterKeyFromSeed(seed);

    // Derivar 5 direcciones de recepción BIP84 (SegWit nativo).
    // La red cambia DOS cosas: el coin_type de la ruta (0' mainnet, 1' testnet)
    // y el HRP de la dirección (bc1q vs tb1q). El coin_type altera la clave
    // derivada, así que la misma seed da direcciones distintas en cada red.
    const coinType = network === 'mainnet' ? 0 : 1;
    const addresses: WalletData['addresses'] = [];
    for (let i = 0; i < 5; i++) {
      const path = getDerivationPath(84, 0, false, i, coinType);
      const { node } = derivePath(master, path);
      addresses.push({
        index: i,
        path,
        address: getAddress(node, 84, network === 'mainnet'),
      });
    }

    setWalletData({
      words: seedWords,
      passphrase: pass,
      seedHex: bytesToHex(seed),
      network,
      addresses,
    });
    setStep('wallet');
  }, [network]);

  // ─── Render por paso ─────────────────────────────────────

  // Selector de red compartido — se muestra en elegir/generar/importar.
  // La red controla el HRP de las direcciones y a qué API de mempool.space
  // se conectará luego el resto de la wallet (BalanceChecker, TxBuilder).
  const networkSelector = (
    <div className="network-selector">
      <span className="network-label">Red</span>
      <div className="network-options">
        {NETWORKS.map(n => (
          <button
            key={n.id}
            type="button"
            className={`network-btn ${network === n.id ? 'active' : ''}`}
            onClick={() => setNetwork(n.id)}
            title={n.hint}
          >
            <span className="network-name">{n.label}</span>
            <span className="network-hrp">{n.hrp}…</span>
          </button>
        ))}
      </div>
      <p className="network-hint">{NETWORKS.find(n => n.id === network)!.hint}</p>
    </div>
  );

  return (
    <div className="wallet-setup">
      <div className="wallet-header">
        <h1>Wallet Setup</h1>
        <p className="subtitle">
          Crea o importa una wallet Bitcoin real. Usamos las mismas primitivas
          que exploramos en las fases anteriores — BIP39 para el mnemónico,
          PBKDF2 para la seed, BIP32 para derivar claves, y BIP84 para
          direcciones SegWit nativas.
        </p>
      </div>

      {/* Breadcrumb de progreso */}
      <div className="wallet-progress">
        <span className={`progress-step ${step === 'choose' ? 'active' : 'done'}`}>
          1. Elegir
        </span>
        <span className="progress-arrow">&rarr;</span>
        <span className={`progress-step ${step === 'generate' || step === 'import' || step === 'confirm-backup' ? 'active' : step === 'wallet' ? 'done' : ''}`}>
          2. Mnemónico
        </span>
        <span className="progress-arrow">&rarr;</span>
        <span className={`progress-step ${step === 'wallet' ? 'active' : ''}`}>
          3. Wallet
        </span>
      </div>

      {/* ─── Paso 1: Elegir ──────────────────────── */}
      {step === 'choose' && (
        <div className="wallet-section">
          <span className="section-label">Elige cómo empezar</span>
          <p className="section-description">
            Una wallet Bitcoin empieza siempre con un mnemónico — 12 o 24 palabras
            que codifican toda la entropía necesaria. De esas palabras se deriva
            todo: la seed, la master key, y un árbol infinito de direcciones.
          </p>

          {networkSelector}

          <div className="choice-cards">
            <div className="choice-card" onClick={handleGenerate}>
              <div className="choice-icon">+</div>
              <h3>Crear nueva wallet</h3>
              <p>
                Genera un mnemónico nuevo con entropía criptográficamente segura
                (crypto.getRandomValues). Tendrás que hacer backup de las palabras.
              </p>
              <div className="word-count-selector">
                <button
                  className={`wc-btn ${wordCount === 12 ? 'active' : ''}`}
                  onClick={(e) => { e.stopPropagation(); setWordCount(12); }}
                >
                  12 palabras
                </button>
                <button
                  className={`wc-btn ${wordCount === 24 ? 'active' : ''}`}
                  onClick={(e) => { e.stopPropagation(); setWordCount(24); }}
                >
                  24 palabras
                </button>
              </div>
            </div>

            <div className="choice-card" onClick={() => setStep('import')}>
              <div className="choice-icon">&darr;</div>
              <h3>Importar wallet existente</h3>
              <p>
                Introduce un mnemónico que ya tengas. Se validará el checksum
                antes de derivar las claves. Útil para restaurar una wallet
                desde su backup.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* ─── Paso 2a: Generar — mostrar palabras ──── */}
      {step === 'generate' && (
        <div className="wallet-section">
          <span className="section-label">Tu mnemónico — haz backup ahora</span>
          <div className="warning-box">
            <strong>Importante:</strong> Estas {words.length} palabras son tu wallet.
            Cualquiera que las conozca puede acceder a tus fondos.
            Escríbelas en papel y guárdalas en un lugar seguro. Nunca las compartas.
          </div>

          <div className="mnemonic-display">
            {showWords ? (
              <div className="mnemonic-grid">
                {words.map((word, i) => (
                  <div key={i} className="mnemonic-word">
                    <span className="word-index">{i + 1}.</span>
                    <span className="word-text">{word}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="mnemonic-hidden">
                Palabras ocultas — haz clic en "Mostrar" para verlas
              </div>
            )}
          </div>

          <div className="wallet-controls">
            <button
              className="wallet-btn"
              onClick={() => setShowWords(!showWords)}
            >
              {showWords ? 'Ocultar' : 'Mostrar'}
            </button>
            <button className="wallet-btn" onClick={handleGenerate}>
              Generar otro
            </button>
          </div>

          {networkSelector}

          {/* Passphrase opcional */}
          <div className="passphrase-section">
            <span className="passphrase-label">Passphrase (opcional):</span>
            <input
              className="passphrase-input"
              type="text"
              value={passphrase}
              onChange={e => setPassphrase(e.target.value)}
              placeholder='Actúa como "25ª palabra" — mismas palabras + otra passphrase = otra wallet'
            />
            {passphrase && (
              <p className="passphrase-hint">
                Con passphrase activa. Recuerda: si la pierdes, pierdes acceso a esta wallet
                aunque tengas las palabras.
              </p>
            )}
          </div>

          {/* Confirmación de backup */}
          <div className="backup-confirm">
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={backupConfirmed}
                onChange={e => setBackupConfirmed(e.target.checked)}
              />
              He guardado las palabras en un lugar seguro
            </label>
            <button
              className="wallet-btn primary"
              disabled={!backupConfirmed}
              onClick={() => deriveWallet(words, debouncedPassphrase)}
            >
              Continuar
            </button>
          </div>

          <button className="wallet-btn back-btn" onClick={() => setStep('choose')}>
            &larr; Volver
          </button>
        </div>
      )}

      {/* ─── Paso 2b: Importar ───────────────────── */}
      {step === 'import' && (
        <div className="wallet-section">
          <span className="section-label">Importar mnemónico</span>
          <p className="section-description">
            Introduce tu mnemónico de 12 o 24 palabras separadas por espacios.
            Se valida el checksum BIP39 — si alguna palabra está mal o fuera de orden,
            la validación fallará.
          </p>

          <textarea
            className="mnemonic-input"
            rows={3}
            value={importInput}
            onChange={e => {
              setImportInput(e.target.value.toLowerCase());
              setImportError(null);
            }}
            placeholder="abandon ability able about above absent absorb abstract absurd abuse access accident..."
          />

          {networkSelector}

          {importValidation && (
            <div className={`validation-msg ${importValidation.valid ? 'valid' : 'invalid'}`}>
              {importValidation.msg}
            </div>
          )}

          {/* Autocompletar: sugerencias mientras escribe */}
          <WordSuggestions
            input={importInput}
            onSelect={(word) => {
              const currentWords = importInput.trim().split(/\s+/);
              currentWords[currentWords.length - 1] = word;
              setImportInput(currentWords.join(' ') + ' ');
            }}
          />

          {/* Passphrase */}
          <div className="passphrase-section">
            <span className="passphrase-label">Passphrase (opcional):</span>
            <input
              className="passphrase-input"
              type="text"
              value={passphrase}
              onChange={e => setPassphrase(e.target.value)}
              placeholder="Déjalo vacío si no usaste passphrase al crear la wallet"
            />
          </div>

          <div className="import-actions">
            <button
              className="wallet-btn primary"
              disabled={!importValidation?.valid}
              onClick={() => {
                try {
                  deriveWallet(parsedImportWords, debouncedPassphrase);
                } catch (e) {
                  setImportError(e instanceof Error ? e.message : 'Error al derivar');
                }
              }}
            >
              Importar y derivar
            </button>
            {importError && <span className="import-error">{importError}</span>}
          </div>

          <button className="wallet-btn back-btn" onClick={() => setStep('choose')}>
            &larr; Volver
          </button>
        </div>
      )}

      {/* ─── Paso 3: Wallet activa ───────────────── */}
      {step === 'wallet' && walletData && (
        <>
          <div className="wallet-section wallet-active-section">
            <span className="section-label">Wallet activa</span>
            <p className="section-description">
              Tu wallet está lista. De las {walletData.words.length} palabras se derivó la seed
              (PBKDF2, 2048 iteraciones), de la seed la master key (HMAC-SHA512),
              y de ahí las direcciones siguiendo la ruta BIP84 para SegWit nativo.
            </p>

            {/* Seed (colapsable) */}
            <details className="seed-details">
              <summary className="seed-summary">
                Seed (512 bits) — haz clic para ver
              </summary>
              <div className="seed-hex">{walletData.seedHex}</div>
            </details>
          </div>

          <div className="wallet-section">
            <span className="section-label">
              Direcciones de recepción &middot; {NETWORKS.find(n => n.id === walletData.network)!.label}
            </span>
            <p className="section-description">
              Ruta BIP84: <code>m/84'/{walletData.network === 'mainnet' ? 0 : 1}'/0'/0/i</code> — SegWit nativo
              ({walletData.network === 'mainnet' ? 'bc1q…' : 'tb1q…'}).
              Cada transacción debería usar una dirección nueva para mayor privacidad.
              Estas son tus primeras 5 direcciones.
            </p>

            <div className="address-list">
              {walletData.addresses.map(a => (
                <div key={a.index} className="address-row">
                  <span className="addr-path">{a.path}</span>
                  <span className="addr-value">{a.address}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Lo que viene */}
          <div className="wallet-section next-steps-section">
            <span className="section-label">Siguiente paso</span>
            <p className="section-description">
              La wallet ya tiene direcciones. El siguiente paso es conectar
              con la red Bitcoin para consultar el saldo y los UTXOs de estas
              direcciones, usando la API de mempool.space.
            </p>
          </div>

          <button
            className="wallet-btn back-btn"
            onClick={() => {
              setStep('choose');
              setWalletData(null);
              setWords([]);
              setImportInput('');
              setPassphrase('');
              setBackupConfirmed(false);
            }}
          >
            &larr; Empezar de nuevo
          </button>
        </>
      )}
    </div>
  );
}

// ─── Subcomponente: sugerencias de palabras ──────────────────

function WordSuggestions({
  input,
  onSelect,
}: {
  input: string;
  onSelect: (word: string) => void;
}) {
  const suggestions = useMemo(() => {
    const parts = input.trim().split(/\s+/);
    const lastWord = parts[parts.length - 1];
    if (!lastWord || lastWord.length < 2) return [];

    // Si la palabra ya es válida, no sugerir
    if (BIP39_WORDLIST.includes(lastWord)) return [];

    return BIP39_WORDLIST
      .filter(w => w.startsWith(lastWord))
      .slice(0, 6);
  }, [input]);

  if (suggestions.length === 0) return null;

  return (
    <div className="word-suggestions">
      {suggestions.map(word => (
        <button
          key={word}
          className="suggestion-btn"
          onClick={() => onSelect(word)}
        >
          {word}
        </button>
      ))}
    </div>
  );
}
