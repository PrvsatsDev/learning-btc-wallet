/**
 * Balance Checker — Fase 3, Paso 2
 *
 * Conecta la wallet con la red Bitcoin a través de mempool.space.
 *
 * ¿Cómo sabe una wallet cuánto saldo tiene?
 *   No existe un "saldo" en Bitcoin como en una cuenta bancaria.
 *   Lo que existe son UTXOs (Unspent Transaction Outputs) — "billetes"
 *   que pertenecen a tus direcciones. Tu saldo es la suma de todos
 *   los UTXOs asociados a tus direcciones.
 *
 * Flujo:
 *   1. Generar/importar seed → derivar direcciones (paso 1)
 *   2. Para cada dirección, consultar la API: ¿tiene UTXOs?
 *   3. Sumar todos los UTXOs = saldo total de la wallet
 *
 * Este componente permite:
 *   - Consultar cualquier dirección individual
 *   - Derivar una wallet completa y ver el saldo de todas sus direcciones
 *   - Ver los UTXOs individuales de cada dirección
 *   - Cambiar entre mainnet, testnet4 y signet
 */

import { useState, useCallback } from 'react';
import {
  generateMnemonic,
  validateMnemonic,
  mnemonicToSeed,
  masterKeyFromSeed,
  derivePath,
  getDerivationPath,
  getAddress,
} from '../crypto/hdwallet';
import {
  getAddressInfo,
  getAddressUtxos,
  calculateBalance,
  satsToBtc,
  formatSats,
  type Network,
  type AddressInfo,
  type UTXO,
} from '../api/mempool';
import './BalanceChecker.css';

// ─── Tipos internos ─────────────────────────────────────

interface AddressData {
  path: string;
  address: string;
  info: AddressInfo | null;
  utxos: UTXO[];
  loading: boolean;
  error: string | null;
}

interface WalletState {
  words: string[];
  addresses: AddressData[];
  totalConfirmed: number;
  totalPending: number;
}

// ─── Componente principal ───────────────────────────────

export function BalanceChecker() {
  const [network, setNetwork] = useState<Network>('testnet4');
  const [mode, setMode] = useState<'single' | 'wallet'>('single');

  // Modo dirección individual
  const [singleAddress, setSingleAddress] = useState('');
  const [singleResult, setSingleResult] = useState<{
    info: AddressInfo;
    utxos: UTXO[];
  } | null>(null);
  const [singleLoading, setSingleLoading] = useState(false);
  const [singleError, setSingleError] = useState<string | null>(null);

  // Modo wallet completa
  const [mnemonicInput, setMnemonicInput] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [walletState, setWalletState] = useState<WalletState | null>(null);
  const [walletLoading, setWalletLoading] = useState(false);
  const [walletError, setWalletError] = useState<string | null>(null);

  // UTXO expandido
  const [expandedAddr, setExpandedAddr] = useState<string | null>(null);

  // ─── Consultar dirección individual ────────────────────

  const checkSingleAddress = useCallback(async () => {
    if (!singleAddress.trim()) return;
    setSingleLoading(true);
    setSingleError(null);
    setSingleResult(null);

    try {
      const [info, utxos] = await Promise.all([
        getAddressInfo(singleAddress.trim(), network),
        getAddressUtxos(singleAddress.trim(), network),
      ]);
      setSingleResult({ info, utxos });
    } catch (e) {
      setSingleError(e instanceof Error ? e.message : 'Error al consultar');
    } finally {
      setSingleLoading(false);
    }
  }, [singleAddress, network]);

  // ─── Derivar wallet y consultar saldos ─────────────────

  const checkWallet = useCallback(async () => {
    const words = mnemonicInput.trim().split(/\s+/).filter(w => w.length > 0);
    if (!validateMnemonic(words)) {
      setWalletError('Mnemónico inválido');
      return;
    }

    setWalletLoading(true);
    setWalletError(null);
    setWalletState(null);

    try {
      const seed = mnemonicToSeed(words, passphrase);
      const master = masterKeyFromSeed(seed);

      // Derivar 5 direcciones de recepción BIP84
      const addresses: AddressData[] = [];
      for (let i = 0; i < 5; i++) {
        const path = getDerivationPath(84, 0, false, i);
        const { node } = derivePath(master, path);
        addresses.push({
          path,
          address: getAddress(node, 84),
          info: null,
          utxos: [],
          loading: true,
          error: null,
        });
      }

      // Mostrar las direcciones mientras cargan
      setWalletState({ words, addresses, totalConfirmed: 0, totalPending: 0 });

      // Consultar cada dirección en paralelo
      const results = await Promise.allSettled(
        addresses.map(async (addr) => {
          const [info, utxos] = await Promise.all([
            getAddressInfo(addr.address, network),
            getAddressUtxos(addr.address, network),
          ]);
          return { address: addr.address, info, utxos };
        })
      );

      // Actualizar estado con los resultados
      let totalConfirmed = 0;
      let totalPending = 0;

      const updatedAddresses = addresses.map((addr, i) => {
        const result = results[i];
        if (result.status === 'fulfilled') {
          const { info, utxos } = result.value;
          const balance = calculateBalance(info);
          totalConfirmed += balance.confirmed;
          totalPending += balance.pending;
          return { ...addr, info, utxos, loading: false };
        } else {
          return {
            ...addr,
            loading: false,
            error: result.reason?.message ?? 'Error',
          };
        }
      });

      setWalletState({
        words,
        addresses: updatedAddresses,
        totalConfirmed,
        totalPending,
      });
    } catch (e) {
      setWalletError(e instanceof Error ? e.message : 'Error al derivar wallet');
    } finally {
      setWalletLoading(false);
    }
  }, [mnemonicInput, passphrase, network]);

  // ─── Generar mnemónico de prueba ───────────────────────

  const handleGenerateTest = useCallback(() => {
    const result = generateMnemonic();
    setMnemonicInput(result.words.join(' '));
  }, []);

  // ─── Render ────────────────────────────────────────────

  return (
    <div className="balance-checker">
      <div className="bc-header">
        <h1>Balance Checker</h1>
        <p className="subtitle">
          Conecta con la red Bitcoin a través de la API de mempool.space.
          Consulta el saldo real de cualquier dirección o de una wallet completa
          derivada desde un mnemónico.
        </p>
      </div>

      {/* Selector de red */}
      <div className="bc-section">
        <span className="section-label">Red</span>
        <p className="section-description">
          Bitcoin tiene varias redes. Mainnet es la red real (BTC con valor).
          Testnet4 y Signet son redes de prueba donde los BTC no valen nada
          — perfectas para experimentar.
        </p>
        <div className="network-selector">
          {(['testnet4', 'signet', 'mainnet'] as Network[]).map(n => (
            <button
              key={n}
              className={`network-btn ${network === n ? 'active' : ''} ${n === 'mainnet' ? 'mainnet-btn' : ''}`}
              onClick={() => setNetwork(n)}
            >
              {n === 'testnet4' ? 'Testnet4' : n === 'signet' ? 'Signet' : 'Mainnet'}
              {n === 'testnet4' && <span className="network-rec">recomendado</span>}
            </button>
          ))}
        </div>
      </div>

      {/* Selector de modo */}
      <div className="bc-section">
        <div className="mode-selector">
          <button
            className={`mode-btn ${mode === 'single' ? 'active' : ''}`}
            onClick={() => setMode('single')}
          >
            Dirección individual
          </button>
          <button
            className={`mode-btn ${mode === 'wallet' ? 'active' : ''}`}
            onClick={() => setMode('wallet')}
          >
            Wallet completa
          </button>
        </div>
      </div>

      {/* ─── Modo: dirección individual ──────────── */}
      {mode === 'single' && (
        <div className="bc-section">
          <span className="section-label">Consultar dirección</span>
          <p className="section-description">
            Introduce cualquier dirección Bitcoin para ver su saldo y UTXOs.
            En {network === 'mainnet' ? 'mainnet' : network} las direcciones
            {network === 'testnet4' || network === 'signet'
              ? ' empiezan por tb1q (SegWit) o tb1p (Taproot).'
              : ' empiezan por bc1q (SegWit) o bc1p (Taproot).'}
          </p>

          <div className="address-input-row">
            <input
              className="address-input"
              type="text"
              value={singleAddress}
              onChange={e => setSingleAddress(e.target.value)}
              placeholder={network === 'mainnet'
                ? 'bc1q...'
                : 'tb1q...'}
              onKeyDown={e => e.key === 'Enter' && checkSingleAddress()}
            />
            <button
              className="bc-btn primary"
              onClick={checkSingleAddress}
              disabled={singleLoading || !singleAddress.trim()}
            >
              {singleLoading ? 'Consultando...' : 'Consultar'}
            </button>
          </div>

          {singleError && <div className="bc-error">{singleError}</div>}

          {singleResult && (
            <AddressInfoCard
              address={singleAddress.trim()}
              info={singleResult.info}
              utxos={singleResult.utxos}
              expanded={true}
              network={network}
            />
          )}
        </div>
      )}

      {/* ─── Modo: wallet completa ───────────────── */}
      {mode === 'wallet' && (
        <>
          <div className="bc-section">
            <span className="section-label">Mnemónico</span>
            <p className="section-description">
              Introduce un mnemónico BIP39 para derivar las direcciones (BIP84, SegWit)
              y consultar el saldo de cada una. El saldo total de la wallet es la
              suma de todos los UTXOs de todas las direcciones.
            </p>

            <textarea
              className="mnemonic-input"
              rows={2}
              value={mnemonicInput}
              onChange={e => setMnemonicInput(e.target.value.toLowerCase())}
              placeholder="abandon ability able about ..."
            />

            <div className="wallet-input-controls">
              <div className="passphrase-row">
                <span className="passphrase-label">Passphrase:</span>
                <input
                  className="passphrase-input"
                  type="text"
                  value={passphrase}
                  onChange={e => setPassphrase(e.target.value)}
                  placeholder="(opcional)"
                />
              </div>
              <div className="wallet-actions">
                <button className="bc-btn" onClick={handleGenerateTest}>
                  Generar de prueba
                </button>
                <button
                  className="bc-btn primary"
                  onClick={checkWallet}
                  disabled={walletLoading}
                >
                  {walletLoading ? 'Consultando...' : 'Derivar y consultar'}
                </button>
              </div>
            </div>

            {walletError && <div className="bc-error">{walletError}</div>}
          </div>

          {/* Resultados de la wallet */}
          {walletState && (
            <>
              {/* Resumen de saldo */}
              <div className="bc-section balance-summary">
                <span className="section-label">Saldo total</span>
                <div className="balance-row">
                  <div className="balance-item">
                    <span className="balance-label">Confirmado</span>
                    <span className="balance-btc">
                      {satsToBtc(walletState.totalConfirmed)} BTC
                    </span>
                    <span className="balance-sats">
                      {formatSats(walletState.totalConfirmed)}
                    </span>
                  </div>
                  {walletState.totalPending !== 0 && (
                    <div className="balance-item pending">
                      <span className="balance-label">Pendiente</span>
                      <span className="balance-btc">
                        {walletState.totalPending > 0 ? '+' : ''}{satsToBtc(walletState.totalPending)} BTC
                      </span>
                      <span className="balance-sats">
                        {walletState.totalPending > 0 ? '+' : ''}{formatSats(walletState.totalPending)}
                      </span>
                    </div>
                  )}
                </div>
              </div>

              {/* Direcciones */}
              <div className="bc-section">
                <span className="section-label">Direcciones derivadas</span>
                <p className="section-description">
                  Ruta BIP84: m/84'/0'/0'/0/i — SegWit nativo.
                  Haz clic en una dirección para ver sus UTXOs.
                </p>

                <div className="wallet-addresses">
                  {walletState.addresses.map((addr) => (
                    <AddressInfoCard
                      key={addr.address}
                      address={addr.address}
                      path={addr.path}
                      info={addr.info}
                      utxos={addr.utxos}
                      loading={addr.loading}
                      error={addr.error}
                      expanded={expandedAddr === addr.address}
                      onToggle={() =>
                        setExpandedAddr(expandedAddr === addr.address ? null : addr.address)
                      }
                      network={network}
                    />
                  ))}
                </div>
              </div>
            </>
          )}
        </>
      )}

      {/* Conceptos */}
      <div className="bc-section">
        <span className="section-label">Conceptos clave</span>
        <div className="concepts-grid">
          <div className="concept-item">
            <h4>No existen "saldos"</h4>
            <p>
              En Bitcoin no hay una cuenta con un número. Tu saldo es la suma
              de todos los UTXOs que controlas. Es como contar los billetes
              que tienes en el bolsillo.
            </p>
          </div>
          <div className="concept-item">
            <h4>UTXO = billete</h4>
            <p>
              Cada UTXO es un output de transacción sin gastar. Tiene un valor
              fijo (como un billete de 10). Para gastar necesitas "romper"
              el UTXO entero y recibir cambio.
            </p>
          </div>
          <div className="concept-item">
            <h4>Confirmado vs pendiente</h4>
            <p>
              Un UTXO confirmado ya está en un bloque minado.
              Uno pendiente está en el mempool — esperando a ser incluido.
              Normalmente se necesitan 1-6 confirmaciones para considerarlo seguro.
            </p>
          </div>
          <div className="concept-item">
            <h4>Privacidad</h4>
            <p>
              Cualquiera puede consultar el saldo de una dirección Bitcoin.
              Por eso las HD wallets usan una dirección nueva para cada transacción
              — dificulta que alguien vincule todas tus direcciones.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Subcomponente: tarjeta de dirección ─────────────────

function AddressInfoCard({
  address,
  path,
  info,
  utxos,
  loading,
  error,
  expanded,
  onToggle,
  network,
}: {
  address: string;
  path?: string;
  info: AddressInfo | null;
  utxos: UTXO[];
  loading?: boolean;
  error?: string | null;
  expanded: boolean;
  onToggle?: () => void;
  network: Network;
}) {
  const balance = info ? calculateBalance(info) : null;

  return (
    <div className={`addr-card ${expanded ? 'addr-card--expanded' : ''}`}>
      <div
        className="addr-card-header"
        onClick={onToggle}
        style={{ cursor: onToggle ? 'pointer' : 'default' }}
      >
        <div className="addr-card-left">
          {path && <span className="addr-card-path">{path}</span>}
          <span className="addr-card-address">{address}</span>
        </div>
        <div className="addr-card-right">
          {loading && <span className="addr-card-loading">...</span>}
          {error && <span className="addr-card-error">error</span>}
          {balance && (
            <span className={`addr-card-balance ${balance.confirmed > 0 ? 'has-balance' : ''}`}>
              {satsToBtc(balance.confirmed)} BTC
            </span>
          )}
          {onToggle && <span className="addr-card-toggle">{expanded ? '\u25B2' : '\u25BC'}</span>}
        </div>
      </div>

      {expanded && info && (
        <div className="addr-card-details">
          <div className="addr-detail-grid">
            <div className="addr-detail">
              <span className="detail-label">Confirmado</span>
              <span className="detail-value">{formatSats(balance!.confirmed)}</span>
            </div>
            {balance!.pending !== 0 && (
              <div className="addr-detail">
                <span className="detail-label">Pendiente</span>
                <span className="detail-value pending-value">
                  {balance!.pending > 0 ? '+' : ''}{formatSats(balance!.pending)}
                </span>
              </div>
            )}
            <div className="addr-detail">
              <span className="detail-label">Transacciones</span>
              <span className="detail-value">
                {info.chain_stats.tx_count + info.mempool_stats.tx_count}
              </span>
            </div>
            <div className="addr-detail">
              <span className="detail-label">Recibido total</span>
              <span className="detail-value">{formatSats(info.chain_stats.funded_txo_sum)}</span>
            </div>
          </div>

          {/* UTXOs */}
          {utxos.length > 0 ? (
            <div className="utxo-section">
              <span className="utxo-title">UTXOs ({utxos.length})</span>
              <div className="utxo-list">
                {utxos.map((utxo) => (
                  <div key={`${utxo.txid}:${utxo.vout}`} className="utxo-item">
                    <div className="utxo-txid">
                      <a
                        href={`https://mempool.space/${network === 'mainnet' ? '' : network + '/'}tx/${utxo.txid}`}
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        {utxo.txid.slice(0, 12)}...{utxo.txid.slice(-8)}
                      </a>
                      <span className="utxo-vout">:{utxo.vout}</span>
                    </div>
                    <div className="utxo-value">{formatSats(utxo.value)}</div>
                    <div className={`utxo-status ${utxo.status.confirmed ? 'confirmed' : 'unconfirmed'}`}>
                      {utxo.status.confirmed ? 'confirmado' : 'pendiente'}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="utxo-empty">Sin UTXOs — esta dirección no tiene fondos</div>
          )}

          {/* Link al explorador */}
          <a
            className="explorer-link"
            href={`https://mempool.space/${network === 'mainnet' ? '' : network + '/'}address/${address}`}
            target="_blank"
            rel="noopener noreferrer"
          >
            Ver en mempool.space
          </a>
        </div>
      )}
    </div>
  );
}
