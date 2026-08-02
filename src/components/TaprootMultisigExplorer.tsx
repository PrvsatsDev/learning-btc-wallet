/**
 * Taproot Multisig Explorer — Fase 4 (sección interactiva)
 *
 * VER y PROBAR un multisig Taproot m-de-n, en su forma ESTÁNDAR:
 *   tr( NUMS , sortedmulti_a(m, key1, …, keyn) )
 *
 * Las claves NO son crudas: cada cosignatario aporta su xpub BIP48 real
 * ([huella/48h/coin/0h/3h]xpub) y las claves de cada dirección se derivan por
 * CKD (m/48'/coin'/0'/3'/0/índice), igual que una wallet o un descriptor con
 * comodín /0/*. Puedes navegar por el índice de dirección y ver cómo cambia.
 *
 * - Muestra las xpubs con su origen, el descriptor con rango /0/*, la dirección
 *   bc1p del índice elegido y la hoja de script (multi_a con OP_CHECKSIGADD).
 * - Deja FIRMAR un gasto real: eliges qué cosignatarios firman, se monta la PSBT
 *   (script-path), se finaliza el witness y se VERIFICA ejecutándolo con el
 *   intérprete + firmas Schnorr reales. Si es válido, ese gasto se aceptaría en
 *   la red.
 *
 * Toda la cripto va verificada contra vectores BIP32/BIP341/BIP387. El trabajo
 * pesado (curva elíptica en JS puro) se hace con estado de carga. Ver
 * [[feedback_debounce]] y [[project_coin_type_network]].
 */

import { useState, useEffect, useMemo } from 'react';
import { NUMS_H, sortXOnlyBIP67, descriptorChecksum } from '../crypto/descriptor';
import { tapscriptMultisig, tapLeafHash, taprootScriptOutput } from '../crypto/tapscript';
import { createP2TR, addressP2TR, disassemble, executeScript } from '../crypto/script';
import {
  masterKeyFromSeed, deriveMultisigKey, deriveChild, type MultisigKey,
} from '../crypto/hdwallet';
import {
  createPsbt, updateInputWitnessUtxo, updateInputTapLeafScript,
  signTaprootScriptPathInput, finalizeTaprootScriptPathInput, extractTransaction,
  hexToBytes, bytesToHex,
} from '../crypto/psbt';
import { computeSighashTaproot } from '../crypto/sighash-taproot';
import { schnorrVerify } from '../crypto/schnorr';
import { bytesToBigint } from '../crypto/hmac';
import type { Transaction, TxOutput } from '../crypto/transaction';
import './TaprootMultisigExplorer.css';

const MAX_N = 5;
const MAX_INDEX = 9;
const DEBOUNCE_MS = 250;

function to32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = n;
  for (let i = 31; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}
function randomHex32(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}
function shortHex(hex: string, head = 10, tail = 6): string {
  return hex.length <= head + tail + 1 ? hex : `${hex.slice(0, head)}…${hex.slice(-tail)}`;
}

/** Cuentas BIP48 de cada cosignatario (nivel m/48'/coin'/0'/3'), con su xpub. */
interface Accounts {
  sig: string;
  keys: MultisigKey[];   // uno por cosignatario, con node PRIVADO (para poder firmar)
}

/** Claves derivadas para UN índice de dirección concreto (…/0/índice). */
interface IndexedKeys {
  sig: string;
  privs: bigint[];
  xonly: Uint8Array[];
}

interface MultisigInfo {
  sortedXonly: Uint8Array[];
  leaf: Uint8Array;
  leafHash: Uint8Array;
  controlBlock: Uint8Array;
  outputKeyHex: string;
  scriptPubKey: Uint8Array;
  address: string;
  descriptor: string;
}

interface WitnessRow { label: string; hex: string; empty: boolean; kind: 'sig' | 'empty' | 'script' | 'control' }
interface SpendResult {
  witness: WitnessRow[];
  valid: boolean;
  txHex: string;
  txid: string;
  error?: string;
}

/** Construye el m-de-n estándar (por índice) a partir de las x-only derivadas. */
function buildInfo(xonly: Uint8Array[], m: number, mainnet: boolean): MultisigInfo {
  const sortedXonly = sortXOnlyBIP67(xonly);
  const leaf = tapscriptMultisig(m, sortedXonly);
  const leafHash = tapLeafHash(leaf);
  const internalX = bytesToBigint(hexToBytes(NUMS_H));
  const out = taprootScriptOutput(internalX, { script: leaf });
  const outBytes = to32(out.outputKey);
  const scriptPubKey = createP2TR(outBytes);
  const address = addressP2TR(outBytes, mainnet);
  const keysStr = sortedXonly.map(bytesToHex).join(',');
  const body = `tr(${NUMS_H},sortedmulti_a(${m},${keysStr}))`;
  return {
    sortedXonly, leaf, leafHash,
    controlBlock: out.controlBlocks[0],
    outputKeyHex: bytesToHex(outBytes),
    scriptPubKey, address,
    descriptor: `${body}#${descriptorChecksum(body)}`,
  };
}

/** Firma un gasto de prueba con los cosignatarios seleccionados y lo verifica. */
function runSpend(info: MultisigInfo, signerPrivs: bigint[], amount: bigint): SpendResult {
  const dest = hexToBytes('0014751e76e8199196d454941c45d1b3a323f1433bd6');
  const unsigned: Transaction = {
    version: 2,
    inputs: [{ prevTxId: '00'.repeat(31) + '01', prevVout: 0, scriptSig: new Uint8Array(0), sequence: 0xffffffff }],
    outputs: [{ value: amount - 2000n, scriptPubKey: dest }],
    locktime: 0,
  };
  const prevout: TxOutput = { value: amount, scriptPubKey: info.scriptPubKey };

  const psbt = createPsbt(unsigned);
  updateInputWitnessUtxo(psbt, 0, prevout);
  updateInputTapLeafScript(psbt, 0, info.leaf, info.controlBlock);
  for (const priv of signerPrivs) signTaprootScriptPathInput(psbt, 0, priv, info.leaf);

  try {
    finalizeTaprootScriptPathInput(psbt, 0);
  } catch (e) {
    return { witness: [], valid: false, txHex: '', txid: '', error: (e as Error).message };
  }
  const { tx, hex, txid } = extractTransaction(psbt);

  // Verifica ejecutando el witness (menos script y control block) con Schnorr real.
  const sighash = computeSighashTaproot(unsigned, 0, [prevout], { ext: { tapLeafHash: info.leafHash } }).sigHash;
  const checkSig = (sig: Uint8Array, pub: Uint8Array): boolean => {
    if (sig.length !== 64) return false;
    return schnorrVerify(sighash,
      { r: bytesToBigint(sig.slice(0, 32)), s: bytesToBigint(sig.slice(32, 64)) },
      bytesToBigint(pub)).valid;
  };
  const wit = tx.witnesses![0];
  const scriptInputs = wit.slice(0, wit.length - 2);
  const parts: number[] = [];
  for (const it of scriptInputs) { if (it.length === 0) parts.push(0x00); else { parts.push(it.length, ...it); } }
  parts.push(...info.leaf);
  const valid = executeScript(new Uint8Array(parts), checkSig).success;

  const witness: WitnessRow[] = wit.map((it, i): WitnessRow => {
    if (i === wit.length - 1) return { label: 'control block', hex: bytesToHex(it), empty: false, kind: 'control' };
    if (i === wit.length - 2) return { label: 'script (hoja multi_a)', hex: bytesToHex(it), empty: false, kind: 'script' };
    if (it.length === 0) return { label: 'firma vacía', hex: '∅', empty: true, kind: 'empty' };
    return { label: `firma Schnorr`, hex: bytesToHex(it), empty: false, kind: 'sig' };
  });

  return { witness, valid, txHex: hex, txid };
}

export function TaprootMultisigExplorer() {
  const [network, setNetwork] = useState<'mainnet' | 'testnet'>('mainnet');
  const [n, setN] = useState(3);
  const [m, setM] = useState(2);
  const [addressIndex, setAddressIndex] = useState(0);
  const [seeds, setSeeds] = useState<string[]>(() => Array.from({ length: MAX_N }, randomHex32));
  const [accounts, setAccounts] = useState<Accounts | null>(null);
  const [indexed, setIndexed] = useState<IndexedKeys | null>(null);
  const [signers, setSigners] = useState<boolean[]>(() => [true, true, false, false, false]);
  const [spend, setSpend] = useState<SpendResult | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const mainnet = network === 'mainnet';
  const coinType = mainnet ? 0 : 1;   // BIP44/48 coin_type: 0' mainnet, 1' testnet
  const mEff = Math.min(m, n);

  const copyText = (id: string, text: string) => {
    navigator.clipboard?.writeText(text).then(() => {
      setCopiedId(id);
      setTimeout(() => setCopiedId(cur => (cur === id ? null : cur)), 1500);
    });
  };

  const accSig = `${network}|${n}|${seeds.slice(0, n).join('')}`;
  const idxSig = accounts ? `${accounts.sig}|${addressIndex}` : '';
  const loading = !accounts || accounts.sig !== accSig || !indexed || indexed.sig !== idxSig;

  // ── Trabajo CARO nivel 1: derivar las CUENTAS BIP48 (ruta hardened) ──
  // m/48'/coin'/0'/3'  → una xpub por cosignatario (nodo privado para firmar).
  useEffect(() => {
    const timer = setTimeout(() => {
      const keys = seeds.slice(0, n).map(s =>
        deriveMultisigKey(masterKeyFromSeed(hexToBytes(s)), 'p2tr', 0, coinType, mainnet));
      setAccounts({ sig: accSig, keys });
      setSpend(null);
    }, DEBOUNCE_MS);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [network, n, seeds]);

  // ── Trabajo CARO nivel 2: derivar el índice de dirección (…/0/índice) ──
  useEffect(() => {
    if (!accounts) return;
    const timer = setTimeout(() => {
      const privs: bigint[] = [];
      const xonly: Uint8Array[] = [];
      for (const k of accounts.keys) {
        const change = deriveChild(k.node, 0, false);         // rama externa (receive)
        const leaf = deriveChild(change, addressIndex, false); // índice de dirección
        privs.push(leaf.privateKey);
        xonly.push(to32(leaf.publicKey!.x));
      }
      setIndexed({ sig: `${accounts.sig}|${addressIndex}`, privs, xonly });
      setSpend(null);
    }, DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [accounts, addressIndex]);

  // ── Trabajo medio: descriptor/dirección del índice actual ──
  const info = useMemo(() => {
    if (!indexed) return null;
    return buildInfo(indexed.xonly, mEff, mainnet);
  }, [indexed, mEff, mainnet]);

  // ── Descriptor de wallet con rango /0/* (la forma REAL, con xpubs) ──
  const rangedDescriptor = useMemo(() => {
    if (!accounts) return null;
    const exprs = accounts.keys.map(k => `${k.keyExpression}/0/*`);
    const body = `tr(${NUMS_H},sortedmulti_a(${mEff},${exprs.join(',')}))`;
    return `${body}#${descriptorChecksum(body)}`;
  }, [accounts, mEff]);

  const selectedCount = signers.slice(0, n).filter(Boolean).length;

  const setKeysTotal = (value: number) => {
    setN(value);
    if (m > value) setM(value);
    setSpend(null);
  };
  const toggleSigner = (i: number) => {
    setSigners(prev => { const next = [...prev]; next[i] = !next[i]; return next; });
    setSpend(null);
  };

  const doSpend = () => {
    if (!info || !indexed) return;
    const chosen = indexed.privs.filter((_, i) => signers[i]);
    setSpend(runSpend(info, chosen, 100_000n));
  };

  return (
    <div className="tme">
      <header className="tme-header">
        <span className="tme-phase-tag">Fase 4 · Interactivo</span>
        <h1>Taproot Multisig Explorer</h1>
        <p className="tme-subtitle">
          El multisig <strong>m-de-n estándar</strong> de Taproot:
          <code> tr(NUMS, sortedmulti_a(m,…))</code>, derivado de <strong>xpubs BIP48 reales</strong>.
          Navega por el índice de dirección, míralo y <strong>pruébalo</strong> — firma un gasto
          real por script-path y comprueba que el witness desbloquea el UTXO.
        </p>
      </header>

      <div className="tme-info">
        <strong>Clave interna NUMS.</strong> La clave interna es un punto
        "Nothing-Up-My-Sleeve" sin dueño conocido: así el gasto por key-path queda
        <strong> inutilizado</strong> y el único modo de gastar es cumplir el multisig
        por script-path (la hoja <code>multi_a</code>). Es el convenio estándar.
      </div>

      {/* ── Controles ── */}
      <div className="tme-controls">
        <div className="tme-control">
          <span className="tme-control-label">Red</span>
          <div className="tme-toggle">
            <button className={mainnet ? 'active' : ''} onClick={() => setNetwork('mainnet')}>mainnet</button>
            <button className={!mainnet ? 'active' : ''} onClick={() => setNetwork('testnet')}>testnet</button>
          </div>
        </div>
        <label className="tme-control">
          <span className="tme-control-label">Cosignatarios · <strong>n = {n}</strong></span>
          <input type="range" min={2} max={MAX_N} value={n} onChange={e => setKeysTotal(Number(e.target.value))} />
        </label>
        <label className="tme-control">
          <span className="tme-control-label">Umbral · <strong>m = {mEff}</strong></span>
          <input type="range" min={1} max={n} value={mEff} onChange={e => { setM(Number(e.target.value)); setSpend(null); }} />
        </label>
        <label className="tme-control">
          <span className="tme-control-label">Índice dirección · <strong>…/0/{addressIndex}</strong></span>
          <input type="range" min={0} max={MAX_INDEX} value={addressIndex} onChange={e => { setAddressIndex(Number(e.target.value)); setSpend(null); }} />
        </label>
        <button className="tme-regen" onClick={() => { setSeeds(Array.from({ length: MAX_N }, randomHex32)); setSpend(null); }}>
          ↻ Regenerar semillas
        </button>
      </div>

      <div className="tme-scheme">
        Esquema: <strong>{mEff}-de-{n}</strong>
        {info && <span className="tme-scheme-note"> · {network} · coin_type {coinType}' · dirección …/0/{addressIndex}</span>}
      </div>

      {loading && (
        <div className="tme-loading"><span className="tme-spinner" /> Derivando xpubs y claves por CKD (curva elíptica en JS, lento a propósito)…</div>
      )}

      {info && accounts && !loading && (
        <>
          {/* ── Cosignatarios (xpubs BIP48) ── */}
          <section className="tme-section">
            <span className="tme-label">Cosignatarios — xpub BIP48 con origen</span>
            <div className="tme-xpubs">
              {accounts.keys.map((k, i) => (
                <div key={i} className="tme-xpub-row">
                  <span className="tme-xpub-tag">{String.fromCharCode(65 + i)}</span>
                  <code className="tme-xpub-expr" title={k.keyExpression}>
                    [{k.fingerprint}/{k.path.replace(/^m\//, '').replace(/'/g, 'h')}]{shortHex(k.xpub, 12, 8)}
                  </code>
                  <button className="tme-copy" onClick={() => copyText(`xpub${i}`, `${k.keyExpression}/0/*`)}>
                    {copiedId === `xpub${i}` ? '✓' : 'copiar'}
                  </button>
                </div>
              ))}
            </div>
            <p className="tme-hint">
              Cada cosignatario comparte solo su <strong>xpub</strong> (nunca la semilla). Las claves de
              cada dirección salen por derivación pública/privada CKD: <code>…/3'/0/{addressIndex}</code>.
            </p>
          </section>

          {/* ── Dirección ── */}
          <section className="tme-section">
            <div className="tme-label-row">
              <span className="tme-label">Dirección Taproot · índice …/0/{addressIndex}</span>
              <button className="tme-copy" onClick={() => copyText('addr', info.address)}>{copiedId === 'addr' ? '✓ copiado' : 'copiar'}</button>
            </div>
            <div className="tme-address"><code>{info.address}</code></div>
          </section>

          {/* ── Descriptor ── */}
          <section className="tme-section">
            <div className="tme-label-row">
              <span className="tme-label">Descriptor de wallet (con rango /0/*)</span>
              <button className="tme-copy" onClick={() => copyText('desc', rangedDescriptor ?? '')}>{copiedId === 'desc' ? '✓ copiado' : 'copiar'}</button>
            </div>
            <div className="tme-descriptor"><code>{rangedDescriptor}</code></div>
            <p className="tme-hint">
              Este es el descriptor REAL de la wallet: contiene las xpubs con su origen y el comodín
              <code> /0/*</code>. Cada índice produce una dirección distinta (la de arriba es la
              <code> {addressIndex}</code>). <code>sortedmulti_a</code> ordena las claves derivadas
              (BIP67), así el orden de los cosignatarios no cambia la dirección.
            </p>
          </section>

          {/* ── Hoja de script ── */}
          <section className="tme-section">
            <span className="tme-label">Hoja de script (multi_a) del índice {addressIndex}</span>
            <div className="tme-script">
              {disassemble(info.leaf).map((op, i) => (
                <span key={i} className={`tme-op ${op.startsWith('OP_') ? 'kw' : ''}`}>
                  {op.startsWith('PUSH(') ? `PUSH ${shortHex(op.slice(5, -1), 8, 6)}` : op}
                </span>
              ))}
            </div>
            <p className="tme-hint">
              Cada clave suma 1 al contador con <code>OP_CHECKSIG</code>/<code>OP_CHECKSIGADD</code>;
              al final <code>OP_{mEff} OP_NUMEQUAL</code> exige exactamente {mEff} firmas.
            </p>
          </section>

          {/* ── Probar gasto ── */}
          <section className="tme-section tme-spend">
            <span className="tme-label">Prueba un gasto (índice …/0/{addressIndex}) — ¿quién firma?</span>
            <div className="tme-signers">
              {Array.from({ length: n }, (_, i) => (
                <button key={i} className={`tme-signer ${signers[i] ? 'on' : ''}`} onClick={() => toggleSigner(i)}>
                  <span className="tme-signer-check">{signers[i] ? '✓' : ''}</span>
                  Cosignatario {String.fromCharCode(65 + i)}
                </button>
              ))}
            </div>
            <div className="tme-spend-bar">
              <span className={`tme-count ${selectedCount >= mEff ? 'ok' : 'low'}`}>
                {selectedCount} de {mEff} necesarias
              </span>
              <button className="tme-sign-btn" onClick={doSpend}>Firmar y probar gasto →</button>
            </div>

            {spend && (
              spend.error ? (
                <div className="tme-verdict bad">✗ {spend.error}</div>
              ) : (
                <>
                  <div className={`tme-verdict ${spend.valid ? 'good' : 'bad'}`}>
                    {spend.valid
                      ? `✓ Witness válido — este gasto ${mEff}-de-${n} se aceptaría en la red`
                      : '✗ El witness NO valida'}
                  </div>
                  <span className="tme-label tme-label--mt">Witness montado</span>
                  <div className="tme-witness">
                    {spend.witness.map((w, i) => (
                      <div key={i} className={`tme-witem ${w.kind}`}>
                        <span className="tme-witem-idx">{i}</span>
                        <span className="tme-witem-label">{w.label}</span>
                        <code className="tme-witem-hex">{w.empty ? '∅' : shortHex(w.hex, 14, 8)}</code>
                      </div>
                    ))}
                  </div>
                  <div className="tme-label-row tme-label--mt">
                    <span className="tme-label">Transacción cruda · TxID {shortHex(spend.txid, 10, 8)}</span>
                    <button className="tme-copy" onClick={() => copyText('rawtx', spend.txHex)}>{copiedId === 'rawtx' ? '✓ copiado' : 'copiar'}</button>
                  </div>
                  <div className="tme-raw"><code>{spend.txHex}</code></div>
                </>
              )
            )}
          </section>
        </>
      )}
    </div>
  );
}
