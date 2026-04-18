/**
 * Transaction Builder — Fase 3, Paso 3
 *
 * Aquí se junta todo: UTXOs reales + coin selection + construcción de tx.
 *
 * ¿Cómo se construye una transacción Bitcoin?
 *
 *   1. INPUTS: seleccionar los UTXOs que vas a gastar.
 *      Cada input referencia un UTXO anterior (txid:vout).
 *      En SegWit nativo, el scriptSig queda vacío — la firma va en el witness.
 *
 *   2. OUTPUTS: definir a dónde va el valor.
 *      - Output de pago: la dirección del destinatario + cantidad.
 *      - Output de cambio: tu propia dirección de cambio + el resto.
 *      Cada output tiene un scriptPubKey que define las condiciones de gasto.
 *
 *   3. FEE: la diferencia entre la suma de inputs y la suma de outputs.
 *      No es un campo explícito — es lo que "sobra". Los mineros lo cobran.
 *      Fee = Σ inputs - Σ outputs. Si te olvidas del cambio, ¡todo es fee!
 *
 *   4. SERIALIZAR: convertir la estructura a bytes (el formato wire de Bitcoin).
 *      La transacción aún no está firmada — eso es el siguiente paso.
 */

import { useState, useCallback, useMemo } from 'react';
import {
  validateMnemonic,
  mnemonicToSeed,
  masterKeyFromSeed,
  derivePath,
  getDerivationPath,
  getAddress,
  generateMnemonic,
} from '../crypto/hdwallet';
import {
  getAddressUtxos,
  formatSats,
  broadcastTx,
  type Network,
  type UTXO as ApiUTXO,
} from '../api/mempool';
import { createP2WPKH } from '../crypto/script';
import { bech32Decode } from '../crypto/script';
import {
  serializeLegacy,
  serializeWitness,
  type Transaction,
  type TxField,
} from '../crypto/transaction';
import { compressPublicKey } from '../crypto/secp256k1';
import { sha256 } from '../crypto/sha256';
import { ripemd160Hex } from '../crypto/ripemd160';
import { signP2WPKHInput, type SignP2WPKHResult } from '../crypto/sighash';
import './TxBuilder.css';

// ─── Tipos ──────────────────────────────────────────────

interface WalletUTXO extends ApiUTXO {
  address: string;
  path: string;
}

// ─── Helpers ────────────────────────────────────────────

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

/**
 * Estima el tamaño virtual (vBytes) de una transacción P2WPKH.
 *
 * En SegWit, el "peso" (weight) se calcula como:
 *   peso = (tamaño_sin_witness × 4) + tamaño_witness
 *   vBytes = peso / 4
 *
 * Para P2WPKH, las estimaciones típicas son:
 *   - Overhead fijo: ~10.5 vB (version + marker + flag + locktime + counts)
 *   - Por input: ~68 vB (outpoint + sequence + witness con firma + pubkey)
 *   - Por output: ~31 vB (value + scriptPubKey P2WPKH)
 */
function estimateVBytes(numInputs: number, numOutputs: number): number {
  return Math.ceil(10.5 + numInputs * 68 + numOutputs * 31);
}

/**
 * Crea el scriptPubKey para una dirección Bitcoin.
 * Decodifica la dirección bech32/bech32m y genera el script correspondiente.
 */
function addressToScriptPubKey(address: string): Uint8Array | null {
  const decoded = bech32Decode(address);
  if (!decoded) return null;

  if (decoded.version === 0 && decoded.program.length === 20) {
    // P2WPKH: OP_0 <20 bytes>
    return createP2WPKH(decoded.program);
  }
  if (decoded.version === 1 && decoded.program.length === 32) {
    // P2TR: OP_1 <32 bytes>
    const script = new Uint8Array(34);
    script[0] = 0x51; // OP_1
    script[1] = 0x20; // push 32 bytes
    script.set(decoded.program, 2);
    return script;
  }
  return null;
}

/** Genera el pubKeyHash para una dirección de cambio */
function pubKeyHashFromCompressedKey(pubKeyHex: string): Uint8Array {
  const pubKeyBytes = hexToBytes(pubKeyHex);
  const shaHash = sha256(pubKeyBytes).hash;
  const h160 = ripemd160Hex(hexToBytes(shaHash));
  return hexToBytes(h160);
}

// ─── Componente principal ───────────────────────────────

export function TxBuilder() {
  const [network, setNetwork] = useState<Network>('testnet4');
  const [mnemonicInput, setMnemonicInput] = useState('');
  const [passphrase, setPassphrase] = useState('');

  // UTXOs disponibles
  const [walletUtxos, setWalletUtxos] = useState<WalletUTXO[]>([]);
  const [loadingUtxos, setLoadingUtxos] = useState(false);
  const [utxoError, setUtxoError] = useState<string | null>(null);

  // Construcción de la transacción
  const [selectedUtxos, setSelectedUtxos] = useState<Set<string>>(new Set());
  const [recipientAddress, setRecipientAddress] = useState('');
  const [amountInput, setAmountInput] = useState('');
  const [feeRate, setFeeRate] = useState(2); // sat/vB
  const [changeIndex] = useState(0); // dirección de cambio

  // Resultado: transacción construida (sin firmar)
  const [builtTx, setBuiltTx] = useState<{
    tx: Transaction;
    hex: string;
    fields: TxField[];
    size: number;
    fee: number;
    changeAmount: number;
  } | null>(null);

  // Resultado: transacción firmada
  const [signedTx, setSignedTx] = useState<{
    tx: Transaction;
    hex: string;
    fields: TxField[];
    vsize: number;       // tamaño virtual real (BIP141 weight/4)
    totalSize: number;   // bytes totales (con witness)
    legacySize: number;  // bytes sin witness (lo que cuenta 4x)
    signatures: SignP2WPKHResult[]; // una por input, para visualizar
  } | null>(null);
  const [signing, setSigning] = useState(false);
  const [signError, setSignError] = useState<string | null>(null);

  // Resultado: broadcast
  const [broadcasting, setBroadcasting] = useState(false);
  const [broadcastTxid, setBroadcastTxid] = useState<string | null>(null);
  const [broadcastError, setBroadcastError] = useState<string | null>(null);

  // ─── Cargar UTXOs de la wallet ──────────────────────────

  const loadWalletUtxos = useCallback(async () => {
    const words = mnemonicInput.trim().split(/\s+/).filter(w => w.length > 0);
    if (!validateMnemonic(words)) {
      setUtxoError('Mnemónico inválido');
      return;
    }

    setLoadingUtxos(true);
    setUtxoError(null);
    setWalletUtxos([]);
    setSelectedUtxos(new Set());
    setBuiltTx(null);
    setSignedTx(null);
    setBroadcastTxid(null);
    setBroadcastError(null);
    setSignError(null);

    try {
      const seed = mnemonicToSeed(words, passphrase);
      const master = masterKeyFromSeed(seed);

      // Derivar 5 direcciones de recepción + 1 de cambio
      const allUtxos: WalletUTXO[] = [];

      for (let i = 0; i < 5; i++) {
        const path = getDerivationPath(84, 0, false, i);
        const { node } = derivePath(master, path);
        const address = getAddress(node, 84);

        const utxos = await getAddressUtxos(address, network);
        for (const u of utxos) {
          allUtxos.push({ ...u, address, path });
        }
      }

      setWalletUtxos(allUtxos);
      if (allUtxos.length === 0) {
        setUtxoError('No se encontraron UTXOs. La wallet no tiene fondos en ' + network);
      }
    } catch (e) {
      setUtxoError(e instanceof Error ? e.message : 'Error al cargar UTXOs');
    } finally {
      setLoadingUtxos(false);
    }
  }, [mnemonicInput, passphrase, network]);

  // ─── Cálculos derivados ─────────────────────────────────

  const amountSats = useMemo(() => {
    const n = Math.round(parseFloat(amountInput) * 100_000_000);
    return isNaN(n) || n <= 0 ? 0 : n;
  }, [amountInput]);

  const selected = useMemo(() => {
    return walletUtxos.filter(u => selectedUtxos.has(`${u.txid}:${u.vout}`));
  }, [walletUtxos, selectedUtxos]);

  const totalSelected = useMemo(() => {
    return selected.reduce((sum, u) => sum + u.value, 0);
  }, [selected]);

  // ¿Necesitamos output de cambio?
  const numOutputs = useMemo(() => {
    if (totalSelected === 0 || amountSats === 0) return 2;
    const estimatedFee = estimateVBytes(selected.length, 1) * feeRate;
    const remainder = totalSelected - amountSats - estimatedFee;
    return remainder > 546 ? 2 : 1; // 546 = dust limit
  }, [totalSelected, amountSats, selected.length, feeRate]);

  const estimatedSize = useMemo(() => {
    if (selected.length === 0) return 0;
    return estimateVBytes(selected.length, numOutputs);
  }, [selected.length, numOutputs]);

  const estimatedFee = useMemo(() => {
    return estimatedSize * feeRate;
  }, [estimatedSize, feeRate]);

  const changeAmount = useMemo(() => {
    if (totalSelected === 0 || amountSats === 0) return 0;
    return totalSelected - amountSats - estimatedFee;
  }, [totalSelected, amountSats, estimatedFee]);

  const canBuild = useMemo(() => {
    return (
      selected.length > 0 &&
      amountSats > 0 &&
      recipientAddress.trim().length > 0 &&
      totalSelected >= amountSats + estimatedFee &&
      changeAmount >= 0
    );
  }, [selected.length, amountSats, recipientAddress, totalSelected, estimatedFee, changeAmount]);

  // ─── Auto-seleccionar UTXOs ─────────────────────────────

  const autoSelect = useCallback(() => {
    if (amountSats === 0) return;

    // Largest-first coin selection
    const sorted = [...walletUtxos].sort((a, b) => b.value - a.value);
    const newSelected = new Set<string>();
    let total = 0;

    for (const u of sorted) {
      newSelected.add(`${u.txid}:${u.vout}`);
      total += u.value;
      const nInputs = newSelected.size;
      const nOutputs = 2; // pago + cambio
      const fee = estimateVBytes(nInputs, nOutputs) * feeRate;
      if (total >= amountSats + fee) break;
    }

    setSelectedUtxos(newSelected);
  }, [walletUtxos, amountSats, feeRate]);

  // ─── Construir transacción ──────────────────────────────

  const buildTransaction = useCallback(() => {
    // Resetear estados derivados de un build anterior
    setSignedTx(null);
    setSignError(null);
    setBroadcastTxid(null);
    setBroadcastError(null);

    // Validar dirección del destinatario
    const recipientScript = addressToScriptPubKey(recipientAddress.trim());
    if (!recipientScript) {
      setUtxoError('Dirección de destinatario inválida (solo soportamos bech32/bech32m)');
      return;
    }

    // Derivar la dirección de cambio
    const words = mnemonicInput.trim().split(/\s+/);
    const seed = mnemonicToSeed(words, passphrase);
    const master = masterKeyFromSeed(seed);
    const changePath = getDerivationPath(84, 0, true, changeIndex); // change chain = true
    const { node: changeNode } = derivePath(master, changePath);
    // Para P2WPKH necesitamos el hash160 de la pubkey comprimida
    const changeNodeCompressed = compressPublicKey(changeNode.publicKey);
    const changePubKeyHash = pubKeyHashFromCompressedKey(changeNodeCompressed);
    const changeScript = createP2WPKH(changePubKeyHash);

    // Construir inputs
    const inputs = selected.map(u => ({
      prevTxId: u.txid,
      prevVout: u.vout,
      scriptSig: new Uint8Array(0), // vacío en SegWit nativo
      sequence: 0xfffffffd, // RBF habilitado (BIP125)
    }));

    // Construir outputs
    const outputs = [
      {
        value: BigInt(amountSats),
        scriptPubKey: recipientScript,
      },
    ];

    // Output de cambio (si no es dust)
    if (changeAmount > 546) {
      outputs.push({
        value: BigInt(changeAmount),
        scriptPubKey: changeScript,
      });
    }

    // Witness vacío (placeholder — se rellenará al firmar)
    const witnesses = selected.map(() => [
      new Uint8Array(72), // firma placeholder (tamaño típico DER)
      new Uint8Array(33), // pubkey placeholder (comprimida)
    ]);

    const tx: Transaction = {
      version: 2,
      inputs,
      outputs,
      locktime: 0,
      witnesses,
    };

    // Serializar (con witness placeholders para ver la estructura)
    const result = serializeWitness(tx);

    setBuiltTx({
      tx,
      hex: result.hex,
      fields: result.fields,
      size: estimatedSize,
      fee: estimatedFee,
      changeAmount: changeAmount > 546 ? changeAmount : 0,
    });
  }, [selected, recipientAddress, amountSats, changeAmount, estimatedSize, estimatedFee, mnemonicInput, passphrase, changeIndex]);

  // ─── Firmar transacción (BIP143 + ECDSA) ────────────────

  const signBuiltTransaction = useCallback(() => {
    if (!builtTx) return;

    setSigning(true);
    setSignError(null);

    try {
      // Re-derivamos claves privadas a partir del mnemónico + path de cada UTXO.
      // No guardamos las privkeys en estado — sólo existen durante la firma.
      const words = mnemonicInput.trim().split(/\s+/);
      const seed = mnemonicToSeed(words, passphrase);
      const master = masterKeyFromSeed(seed);

      // Copia profunda de la tx construida — mutamos los witnesses con firmas reales
      const txToSign: Transaction = {
        ...builtTx.tx,
        inputs: builtTx.tx.inputs.map(i => ({ ...i })),
        outputs: builtTx.tx.outputs.map(o => ({ ...o })),
        witnesses: [],
      };

      const signatures: SignP2WPKHResult[] = [];
      const witnesses: Uint8Array[][] = [];

      // Un input → una firma. El sighash precalcula hashPrevouts/Sequence/Outputs
      // UNA vez por input (trivialmente caché-able para N inputs, BIP143 así lo premia).
      for (let i = 0; i < selected.length; i++) {
        const utxo = selected[i];
        const { node } = derivePath(master, utxo.path);
        const privateKey = node.privateKey;
        const compressedPubKeyHex = compressPublicKey(node.publicKey);
        const compressedPubKey = hexToBytes(compressedPubKeyHex);
        const pubKeyHash = pubKeyHashFromCompressedKey(compressedPubKeyHex);

        const result = signP2WPKHInput(
          txToSign,
          i,
          privateKey,
          compressedPubKey,
          pubKeyHash,
          BigInt(utxo.value),
        );

        signatures.push(result);
        witnesses.push(result.witness);
      }

      txToSign.witnesses = witnesses;

      // Serializar la tx firmada y calcular vsize real (BIP141)
      //   weight = base_size * 3 + total_size
      //   vsize  = ceil(weight / 4)
      const legacy = serializeLegacy(txToSign);
      const segwit = serializeWitness(txToSign);
      const weight = legacy.size * 3 + segwit.size;
      const vsize = Math.ceil(weight / 4);

      setSignedTx({
        tx: txToSign,
        hex: segwit.hex,
        fields: segwit.fields,
        vsize,
        totalSize: segwit.size,
        legacySize: legacy.size,
        signatures,
      });
    } catch (e) {
      setSignError(e instanceof Error ? e.message : 'Error al firmar la transacción');
    } finally {
      setSigning(false);
    }
  }, [builtTx, selected, mnemonicInput, passphrase]);

  // ─── Broadcast (POST a mempool.space) ──────────────────

  const broadcastSignedTransaction = useCallback(async () => {
    if (!signedTx) return;

    // Aviso extra si es mainnet — aquí sí es dinero real
    if (network === 'mainnet') {
      const ok = window.confirm(
        'Estás a punto de emitir una transacción en MAINNET — los BTC son reales.\n\n' +
        '¿Seguro que quieres continuar?'
      );
      if (!ok) return;
    }

    setBroadcasting(true);
    setBroadcastError(null);
    setBroadcastTxid(null);

    try {
      const txid = await broadcastTx(signedTx.hex, network);
      // La API devuelve el txid como texto plano, a veces con espacios/saltos
      setBroadcastTxid(txid.trim());
    } catch (e) {
      setBroadcastError(e instanceof Error ? e.message : 'Error al hacer broadcast');
    } finally {
      setBroadcasting(false);
    }
  }, [signedTx, network]);

  // ─── Generar mnemónico de prueba ───────────────────────

  const handleGenerateTest = useCallback(() => {
    const result = generateMnemonic();
    setMnemonicInput(result.words.join(' '));
  }, []);

  // ─── Render ────────────────────────────────────────────

  return (
    <div className="tx-builder">
      <div className="txb-header">
        <h1>Transaction Builder</h1>
        <p className="subtitle">
          Construye una transacción Bitcoin paso a paso: selecciona UTXOs,
          define el destinatario, calcula la fee, firma cada input con
          BIP143 + ECDSA y emítela a la red.
        </p>
      </div>

      {/* Red */}
      <div className="txb-section">
        <span className="section-label">Red</span>
        <div className="network-selector">
          {(['testnet4', 'signet', 'mainnet'] as Network[]).map(n => (
            <button
              key={n}
              className={`network-btn ${network === n ? 'active' : ''} ${n === 'mainnet' ? 'mainnet-btn' : ''}`}
              onClick={() => { setNetwork(n); setWalletUtxos([]); setBuiltTx(null); setSignedTx(null); setBroadcastTxid(null); setBroadcastError(null); setSignError(null); }}
            >
              {n === 'testnet4' ? 'Testnet4' : n === 'signet' ? 'Signet' : 'Mainnet'}
            </button>
          ))}
        </div>
      </div>

      {/* Paso 1: Cargar wallet */}
      <div className="txb-section">
        <span className="section-label">1. Cargar wallet</span>
        <p className="section-description">
          Introduce un mnemónico para derivar las direcciones y buscar UTXOs
          disponibles en la red. Necesitas UTXOs para poder construir una transacción.
        </p>

        <textarea
          className="mnemonic-input"
          rows={2}
          value={mnemonicInput}
          onChange={e => setMnemonicInput(e.target.value.toLowerCase())}
          placeholder="abandon ability able about ..."
        />

        <div className="txb-controls">
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
          <button className="txb-btn" onClick={handleGenerateTest}>
            Generar de prueba
          </button>
          <button
            className="txb-btn primary"
            onClick={loadWalletUtxos}
            disabled={loadingUtxos}
          >
            {loadingUtxos ? 'Buscando UTXOs...' : 'Buscar UTXOs'}
          </button>
        </div>

        {utxoError && <div className="txb-error">{utxoError}</div>}
      </div>

      {/* Paso 2: Seleccionar UTXOs */}
      {walletUtxos.length > 0 && (
        <div className="txb-section">
          <span className="section-label">2. Seleccionar UTXOs (inputs)</span>
          <p className="section-description">
            Cada UTXO seleccionado se convierte en un input de la transacción.
            La suma de los inputs debe cubrir la cantidad a enviar + la fee.
            Más inputs = transacción más grande = más fee.
          </p>

          <div className="utxo-select-list">
            {walletUtxos.map(u => {
              const key = `${u.txid}:${u.vout}`;
              const isSelected = selectedUtxos.has(key);
              return (
                <label key={key} className={`utxo-select-item ${isSelected ? 'selected' : ''}`}>
                  <input
                    type="checkbox"
                    checked={isSelected}
                    onChange={() => {
                      const next = new Set(selectedUtxos);
                      if (isSelected) next.delete(key); else next.add(key);
                      setSelectedUtxos(next);
                      setBuiltTx(null);
                      setSignedTx(null);
                      setBroadcastTxid(null);
                      setBroadcastError(null);
                      setSignError(null);
                    }}
                  />
                  <div className="utxo-select-info">
                    <span className="utxo-select-path">{u.path}</span>
                    <span className="utxo-select-txid">
                      {u.txid.slice(0, 8)}...:{u.vout}
                    </span>
                  </div>
                  <span className="utxo-select-value">{formatSats(u.value)}</span>
                </label>
              );
            })}
          </div>

          <div className="utxo-select-footer">
            <span className="utxo-total">
              Seleccionado: <strong>{formatSats(totalSelected)}</strong>
              ({selected.length} UTXO{selected.length !== 1 ? 's' : ''})
            </span>
            <button className="txb-btn" onClick={autoSelect} disabled={amountSats === 0}>
              Auto-seleccionar
            </button>
          </div>
        </div>
      )}

      {/* Paso 3: Destinatario y cantidad */}
      {walletUtxos.length > 0 && (
        <div className="txb-section">
          <span className="section-label">3. Destinatario y cantidad</span>
          <p className="section-description">
            Define a dónde enviar y cuánto. La dirección se convierte en un
            scriptPubKey (las condiciones de gasto del output).
            Lo que sobre vuelve a ti como cambio.
          </p>

          <div className="recipient-row">
            <label className="field-label">Dirección destino:</label>
            <input
              className="address-input"
              type="text"
              value={recipientAddress}
              onChange={e => { setRecipientAddress(e.target.value); setBuiltTx(null); setSignedTx(null); setBroadcastTxid(null); setBroadcastError(null); setSignError(null); }}
              placeholder={network === 'mainnet' ? 'bc1q...' : 'tb1q...'}
            />
          </div>

          <div className="amount-row">
            <div className="amount-field">
              <label className="field-label">Cantidad (BTC):</label>
              <input
                className="amount-input"
                type="text"
                value={amountInput}
                onChange={e => { setAmountInput(e.target.value); setBuiltTx(null); setSignedTx(null); setBroadcastTxid(null); setBroadcastError(null); setSignError(null); }}
                placeholder="0.001"
              />
              {amountSats > 0 && (
                <span className="amount-sats">{formatSats(amountSats)}</span>
              )}
            </div>

            <div className="fee-field">
              <label className="field-label">Fee rate (sat/vB):</label>
              <input
                className="fee-input"
                type="number"
                min={1}
                value={feeRate}
                onChange={e => { setFeeRate(Math.max(1, parseInt(e.target.value) || 1)); setBuiltTx(null); setSignedTx(null); setBroadcastTxid(null); setBroadcastError(null); setSignError(null); }}
              />
            </div>
          </div>

          {/* Resumen */}
          {selected.length > 0 && amountSats > 0 && (
            <div className="tx-summary">
              <div className="summary-row">
                <span>Inputs ({selected.length}):</span>
                <span>{formatSats(totalSelected)}</span>
              </div>
              <div className="summary-row">
                <span>Enviar:</span>
                <span>-{formatSats(amountSats)}</span>
              </div>
              <div className="summary-row">
                <span>Fee estimada (~{estimatedSize} vB x {feeRate} sat/vB):</span>
                <span>-{formatSats(estimatedFee)}</span>
              </div>
              <div className={`summary-row summary-change ${changeAmount < 0 ? 'negative' : ''}`}>
                <span>Cambio:</span>
                <span>
                  {changeAmount < 0
                    ? `Faltan ${formatSats(Math.abs(changeAmount))}`
                    : changeAmount <= 546
                      ? `${formatSats(changeAmount)} (dust — va al minero)`
                      : formatSats(changeAmount)}
                </span>
              </div>
            </div>
          )}

          <button
            className="txb-btn primary build-btn"
            disabled={!canBuild}
            onClick={buildTransaction}
          >
            Construir transacción
          </button>
        </div>
      )}

      {/* Paso 4: Resultado */}
      {builtTx && (
        <div className="txb-section result-section">
          <span className="section-label">Transacción construida (sin firmar)</span>
          <p className="section-description">
            La transacción está serializada en formato SegWit. Los campos de
            witness tienen valores placeholder (ceros) — se rellenarán con la
            firma real en el siguiente paso. El hex coloreado muestra cada campo.
          </p>

          <div className="tx-stats">
            <div className="stat">
              <span className="stat-label">Inputs</span>
              <span className="stat-value">{builtTx.tx.inputs.length}</span>
            </div>
            <div className="stat">
              <span className="stat-label">Outputs</span>
              <span className="stat-value">{builtTx.tx.outputs.length}</span>
            </div>
            <div className="stat">
              <span className="stat-label">Tamaño est.</span>
              <span className="stat-value">{builtTx.size} vB</span>
            </div>
            <div className="stat">
              <span className="stat-label">Fee</span>
              <span className="stat-value">{formatSats(builtTx.fee)}</span>
            </div>
            {builtTx.changeAmount > 0 && (
              <div className="stat">
                <span className="stat-label">Cambio</span>
                <span className="stat-value">{formatSats(builtTx.changeAmount)}</span>
              </div>
            )}
          </div>

          {/* Hex coloreado */}
          <div className="tx-hex-annotated">
            <span className="section-label" style={{ marginBottom: '0.5rem' }}>
              Hex serializado (campos coloreados)
            </span>
            <div className="hex-fields">
              {builtTx.fields.map((field, i) => (
                <span
                  key={i}
                  className="hex-field"
                  style={{ color: field.color }}
                  title={`${field.name}: ${field.description}`}
                >
                  {bytesToHex(field.bytes)}
                </span>
              ))}
            </div>
          </div>

          {/* Leyenda de campos */}
          <div className="field-legend">
            {builtTx.fields.map((field, i) => (
              <div key={i} className="legend-row">
                <span className="legend-color" style={{ background: field.color }} />
                <span className="legend-name">{field.name}</span>
                <span className="legend-desc">{field.description}</span>
              </div>
            ))}
          </div>

          <div className="next-step-hint">
            La transacción está construida pero <strong>no firmada</strong>.
            Sin firma, la red la rechazaría. Pulsa <strong>Firmar</strong> abajo
            para calcular el sighash BIP143 de cada input y generar la firma ECDSA.
          </div>

          <button
            className="txb-btn primary build-btn"
            style={{ marginTop: '1rem' }}
            onClick={signBuiltTransaction}
            disabled={signing}
          >
            {signing ? 'Firmando...' : 'Firmar transacción'}
          </button>

          {signError && <div className="txb-error" style={{ marginTop: '0.75rem' }}>{signError}</div>}
        </div>
      )}

      {/* Paso 5: Firmas BIP143 + tx firmada */}
      {signedTx && (
        <div className="txb-section result-section">
          <span className="section-label">4. Firmar (BIP143 + ECDSA)</span>
          <p className="section-description">
            Para cada input calculamos el <strong>sighash BIP143</strong>: un
            preimage de 10 campos que compromete la versión, todos los prevouts,
            secuencias y outputs, más el <em>outpoint</em>, <em>scriptCode</em> y{' '}
            <em>amount</em> del input concreto. Ese preimage se hashea dos veces
            con SHA-256 y ese es el hash que firmamos con ECDSA.
          </p>

          <div className="tx-stats">
            <div className="stat">
              <span className="stat-label">Tamaño real</span>
              <span className="stat-value">{signedTx.vsize} vB</span>
            </div>
            <div className="stat">
              <span className="stat-label">Total bytes</span>
              <span className="stat-value">{signedTx.totalSize} B</span>
            </div>
            <div className="stat">
              <span className="stat-label">Inputs firmados</span>
              <span className="stat-value">{signedTx.signatures.length}</span>
            </div>
          </div>

          {/* Por cada input, mostrar preimage + sighash + firma */}
          {signedTx.signatures.map((sig, i) => (
            <div key={i} className="tx-hex-annotated" style={{ marginTop: '1rem' }}>
              <span className="section-label" style={{ marginBottom: '0.5rem' }}>
                Input #{i} — preimage BIP143 ({sig.sighashInfo.preimage.length} bytes)
              </span>
              <div className="hex-fields">
                {sig.sighashInfo.preimageFields.map((f, j) => (
                  <span
                    key={j}
                    className="hex-field"
                    style={{ color: f.color }}
                    title={`${f.name}: ${f.description}`}
                  >
                    {bytesToHex(f.bytes)}
                  </span>
                ))}
              </div>

              <div className="field-legend" style={{ marginTop: '0.75rem' }}>
                {sig.sighashInfo.preimageFields.map((f, j) => (
                  <div key={j} className="legend-row">
                    <span className="legend-color" style={{ background: f.color }} />
                    <span className="legend-name">{f.name}</span>
                    <span className="legend-desc">{f.description}</span>
                  </div>
                ))}
              </div>

              <div style={{ marginTop: '0.75rem', fontSize: '0.82rem', lineHeight: 1.5 }}>
                <div>
                  <strong style={{ color: '#f7931a' }}>sighash</strong>{' '}
                  <span style={{ color: '#94a3b8' }}>(dSHA256 del preimage):</span>
                </div>
                <code style={{ color: '#4ade80', wordBreak: 'break-all', fontSize: '0.78rem' }}>
                  {bytesToHex(sig.sighashInfo.sighash)}
                </code>

                <div style={{ marginTop: '0.5rem' }}>
                  <strong style={{ color: '#f7931a' }}>firma DER + sighash type</strong>{' '}
                  <span style={{ color: '#94a3b8' }}>
                    ({sig.signatureWithHashType.length} bytes — se incrusta en witness[0]):
                  </span>
                </div>
                <code style={{ color: '#60a5fa', wordBreak: 'break-all', fontSize: '0.78rem' }}>
                  {bytesToHex(sig.signatureWithHashType)}
                </code>

                <div style={{ marginTop: '0.5rem' }}>
                  <strong style={{ color: '#f7931a' }}>witness[1]</strong>{' '}
                  <span style={{ color: '#94a3b8' }}>(pubkey comprimida, 33 B):</span>
                </div>
                <code style={{ color: '#e879f9', wordBreak: 'break-all', fontSize: '0.78rem' }}>
                  {bytesToHex(sig.witness[1])}
                </code>
              </div>
            </div>
          ))}

          {/* Hex final firmado */}
          <div className="tx-hex-annotated" style={{ marginTop: '1rem' }}>
            <span className="section-label" style={{ marginBottom: '0.5rem' }}>
              Transacción firmada — hex listo para broadcast ({signedTx.totalSize} bytes)
            </span>
            <div className="hex-fields">
              {signedTx.fields.map((field, i) => (
                <span
                  key={i}
                  className="hex-field"
                  style={{ color: field.color }}
                  title={`${field.name}: ${field.description}`}
                >
                  {bytesToHex(field.bytes)}
                </span>
              ))}
            </div>
          </div>

          <div className="next-step-hint" style={{ marginTop: '1rem' }}>
            La tx ya tiene las firmas reales en el witness. El siguiente paso es
            enviarla a la red con <strong>POST /tx</strong> en mempool.space —
            si es válida, entra en el mempool y eventualmente se mina.
          </div>
        </div>
      )}

      {/* Paso 6: Broadcast */}
      {signedTx && (
        <div className="txb-section">
          <span className="section-label">5. Broadcast</span>
          <p className="section-description">
            Emitir la transacción = hacer <code>POST</code> del hex firmado al
            endpoint <code>/tx</code> de un nodo Bitcoin (aquí, mempool.space).
            Si la tx es válida el nodo devuelve el <em>txid</em> y la propaga por
            la red. Si algo falla (firma inválida, fee insuficiente, etc.) devuelve
            un error descriptivo.
            {network === 'mainnet' && (
              <>
                {' '}<strong style={{ color: '#f87171' }}>
                  Estás en MAINNET: los BTC son reales.
                </strong>
              </>
            )}
          </p>

          <button
            className={`txb-btn primary build-btn ${network === 'mainnet' ? 'mainnet-btn' : ''}`}
            onClick={broadcastSignedTransaction}
            disabled={broadcasting || broadcastTxid !== null}
          >
            {broadcasting
              ? 'Enviando...'
              : broadcastTxid
                ? 'Enviada ✓'
                : `Enviar a ${network}`}
          </button>

          {broadcastError && (
            <div className="txb-error" style={{ marginTop: '0.75rem' }}>
              {broadcastError}
            </div>
          )}

          {broadcastTxid && (
            <div className="next-step-hint" style={{ marginTop: '1rem' }}>
              <div style={{ marginBottom: '0.5rem' }}>
                <strong>Broadcast OK</strong> — txid:
              </div>
              <code style={{ color: '#4ade80', wordBreak: 'break-all', fontSize: '0.78rem' }}>
                {broadcastTxid}
              </code>
              <div style={{ marginTop: '0.5rem' }}>
                <a
                  href={`https://mempool.space/${network === 'mainnet' ? '' : network + '/'}tx/${broadcastTxid}`}
                  target="_blank"
                  rel="noreferrer"
                  style={{ color: '#f7931a', textDecoration: 'underline' }}
                >
                  Ver en mempool.space ↗
                </a>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Conceptos */}
      <div className="txb-section">
        <span className="section-label">Conceptos clave</span>
        <div className="concepts-grid">
          <div className="concept-item">
            <h4>Fee = lo que sobra</h4>
            <p>
              La fee no es un campo de la transacción. Es la diferencia
              entre inputs y outputs. Si te olvidas de crear el output
              de cambio, toda la diferencia es fee para el minero.
            </p>
          </div>
          <div className="concept-item">
            <h4>Dust limit (546 sats)</h4>
            <p>
              Un output con menos de 546 satoshis cuesta más gastarlo
              (por la fee) de lo que vale. Los nodos rechazan estos
              outputs "polvo". Si el cambio es dust, se dona al minero.
            </p>
          </div>
          <div className="concept-item">
            <h4>RBF (Replace-by-Fee)</h4>
            <p>
              Sequence &lt; 0xfffffffe habilita RBF (BIP125): puedes
              reemplazar una transacción pendiente por otra con más fee
              si la original tarda en confirmarse.
            </p>
          </div>
          <div className="concept-item">
            <h4>Witness separado</h4>
            <p>
              En SegWit, las firmas van en el witness (fuera del cuerpo
              de la tx). Por eso el scriptSig está vacío. Esto hace que
              el TxID no dependa de las firmas — fin de la maleabilidad.
            </p>
          </div>
          <div className="concept-item">
            <h4>BIP143: sighash O(N)</h4>
            <p>
              El sighash legacy era O(N²): reserializabas la tx entera para cada
              input. BIP143 precalcula <code>hashPrevouts</code>,{' '}
              <code>hashSequence</code> y <code>hashOutputs</code> una sola vez
              y los reutiliza por input. Firma lineal, verificación lineal.
            </p>
          </div>
          <div className="concept-item">
            <h4>amount en el preimage</h4>
            <p>
              BIP143 incluye el valor del UTXO gastado dentro del preimage.
              Esto permite a una hardware wallet calcular la fee real sin ver
              la transacción anterior — cierra el ataque "fee sorpresa" que
              existía con el sighash legacy.
            </p>
          </div>
          <div className="concept-item">
            <h4>SIGHASH_ALL (0x01)</h4>
            <p>
              El tipo de sighash va como último byte de la firma DER. 0x01
              (SIGHASH_ALL) firma todos los inputs y outputs: el caso normal.
              Otros tipos (NONE, SINGLE, ANYONECANPAY) existen para flujos
              especiales como subastas o coinjoins.
            </p>
          </div>
          <div className="concept-item">
            <h4>Witness P2WPKH = [sig, pk]</h4>
            <p>
              El witness de un input P2WPKH son siempre dos items: la firma
              DER con el byte sighash type al final, y la pubkey comprimida
              (33 bytes). El nodo hace hash160 de la pubkey y comprueba que
              coincide con el witness program del scriptPubKey.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
