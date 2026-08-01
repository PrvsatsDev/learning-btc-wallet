/**
 * Taproot Multisig Explorer — Fase 4 (sección interactiva)
 *
 * VER y PROBAR un multisig Taproot m-de-n, en su forma ESTÁNDAR:
 *   tr( NUMS , sortedmulti_a(m, key1, …, keyn) )
 *
 * - Muestra el descriptor estándar, la dirección bc1p y la hoja de script
 *   (multi_a con OP_CHECKSIGADD).
 * - Deja FIRMAR un gasto real: eliges qué cosignatarios firman, se monta la PSBT
 *   (script-path), se finaliza el witness y se VERIFICA ejecutándolo con el
 *   intérprete + firmas Schnorr reales. Si es válido, ese gasto se aceptaría en
 *   la red.
 *
 * Toda la cripto va verificada contra vectores BIP341/BIP387. El trabajo pesado
 * (curva elíptica en JS puro) se hace con estado de carga. Ver [[feedback_debounce]].
 */

import { useState, useEffect, useMemo } from 'react';
import { NUMS_H, sortXOnlyBIP67, descriptorChecksum } from '../crypto/descriptor';
import { tapscriptMultisig, tapLeafHash, taprootScriptOutput } from '../crypto/tapscript';
import { createP2TR, addressP2TR, disassemble, executeScript } from '../crypto/script';
import { getPublicKey } from '../crypto/secp256k1';
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

interface DerivedKeys {
  sig: string;
  privs: bigint[];
  xonly: Uint8Array[];        // x-only pubkeys (sin ordenar), índice = cosignatario
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

/** Construye el 2-de-3 (o m-de-n) estándar a partir de las x-only. */
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
  const [seeds, setSeeds] = useState<string[]>(() => Array.from({ length: MAX_N }, randomHex32));
  const [derived, setDerived] = useState<DerivedKeys | null>(null);
  const [signers, setSigners] = useState<boolean[]>(() => [true, true, false, false, false]);
  const [spend, setSpend] = useState<SpendResult | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const copyText = (id: string, text: string) => {
    navigator.clipboard?.writeText(text).then(() => {
      setCopiedId(id);
      setTimeout(() => setCopiedId(cur => (cur === id ? null : cur)), 1500);
    });
  };

  const sig = `${network}|${n}|${seeds.slice(0, n).join('')}`;
  const loading = !derived || derived.sig !== sig;

  // ── Trabajo CARO: derivar las claves (n mults de curva elíptica) ──
  useEffect(() => {
    const timer = setTimeout(() => {
      const privs = seeds.slice(0, n).map(s => bytesToBigint(hexToBytes(s)));
      const xonly = privs.map(p => to32(getPublicKey(p)!.x));
      setDerived({ sig, privs, xonly });
      setSpend(null);
    }, DEBOUNCE_MS);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [network, n, seeds]);

  // ── Trabajo medio: montar descriptor/dirección (1 op de curva por m) ──
  const info = useMemo(() => {
    if (!derived) return null;
    return buildInfo(derived.xonly, Math.min(m, n), network === 'mainnet');
  }, [derived, m, n, network]);

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
    if (!info || !derived) return;
    const chosen = derived.privs.filter((_, i) => signers[i]);
    setSpend(runSpend(info, chosen, 100_000n));
  };

  return (
    <div className="tme">
      <header className="tme-header">
        <span className="tme-phase-tag">Fase 4 · Interactivo</span>
        <h1>Taproot Multisig Explorer</h1>
        <p className="tme-subtitle">
          El multisig <strong>m-de-n estándar</strong> de Taproot:
          <code> tr(NUMS, sortedmulti_a(m,…))</code>. Míralo y <strong>pruébalo</strong> —
          firma un gasto real por script-path y comprueba que el witness desbloquea el UTXO.
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
            <button className={network === 'mainnet' ? 'active' : ''} onClick={() => setNetwork('mainnet')}>mainnet</button>
            <button className={network === 'testnet' ? 'active' : ''} onClick={() => setNetwork('testnet')}>testnet</button>
          </div>
        </div>
        <label className="tme-control">
          <span className="tme-control-label">Cosignatarios · <strong>n = {n}</strong></span>
          <input type="range" min={2} max={MAX_N} value={n} onChange={e => setKeysTotal(Number(e.target.value))} />
        </label>
        <label className="tme-control">
          <span className="tme-control-label">Umbral · <strong>m = {Math.min(m, n)}</strong></span>
          <input type="range" min={1} max={n} value={Math.min(m, n)} onChange={e => { setM(Number(e.target.value)); setSpend(null); }} />
        </label>
        <button className="tme-regen" onClick={() => { setSeeds(Array.from({ length: MAX_N }, randomHex32)); setSpend(null); }}>
          ↻ Regenerar claves
        </button>
      </div>

      <div className="tme-scheme">
        Esquema: <strong>{Math.min(m, n)}-de-{n}</strong>
        {info && <span className="tme-scheme-note"> · {network} · hoja multi_a con OP_CHECKSIGADD</span>}
      </div>

      {loading && (
        <div className="tme-loading"><span className="tme-spinner" /> Derivando claves (curva elíptica en JS, lento a propósito)…</div>
      )}

      {info && !loading && (
        <>
          {/* ── Dirección ── */}
          <section className="tme-section">
            <div className="tme-label-row">
              <span className="tme-label">Dirección Taproot (recibe aquí)</span>
              <button className="tme-copy" onClick={() => copyText('addr', info.address)}>{copiedId === 'addr' ? '✓ copiado' : 'copiar'}</button>
            </div>
            <div className="tme-address"><code>{info.address}</code></div>
          </section>

          {/* ── Descriptor ── */}
          <section className="tme-section">
            <div className="tme-label-row">
              <span className="tme-label">Descriptor estándar (BIP-387)</span>
              <button className="tme-copy" onClick={() => copyText('desc', info.descriptor)}>{copiedId === 'desc' ? '✓ copiado' : 'copiar'}</button>
            </div>
            <div className="tme-descriptor"><code>{info.descriptor}</code></div>
            <p className="tme-hint">
              <code>sortedmulti_a</code> ordena las claves (BIP67), así el orden de los
              cosignatarios no cambia la dirección. El <code>#…</code> final es el checksum.
            </p>
          </section>

          {/* ── Hoja de script ── */}
          <section className="tme-section">
            <span className="tme-label">Hoja de script (multi_a)</span>
            <div className="tme-script">
              {disassemble(info.leaf).map((op, i) => (
                <span key={i} className={`tme-op ${op.startsWith('OP_') ? 'kw' : ''}`}>
                  {op.startsWith('PUSH(') ? `PUSH ${shortHex(op.slice(5, -1), 8, 6)}` : op}
                </span>
              ))}
            </div>
            <p className="tme-hint">
              Cada clave suma 1 al contador con <code>OP_CHECKSIG</code>/<code>OP_CHECKSIGADD</code>;
              al final <code>OP_{Math.min(m, n)} OP_NUMEQUAL</code> exige exactamente {Math.min(m, n)} firmas.
            </p>
          </section>

          {/* ── Probar gasto ── */}
          <section className="tme-section tme-spend">
            <span className="tme-label">Prueba un gasto — ¿quién firma?</span>
            <div className="tme-signers">
              {Array.from({ length: n }, (_, i) => (
                <button key={i} className={`tme-signer ${signers[i] ? 'on' : ''}`} onClick={() => toggleSigner(i)}>
                  <span className="tme-signer-check">{signers[i] ? '✓' : ''}</span>
                  Cosignatario {String.fromCharCode(65 + i)}
                </button>
              ))}
            </div>
            <div className="tme-spend-bar">
              <span className={`tme-count ${selectedCount >= Math.min(m, n) ? 'ok' : 'low'}`}>
                {selectedCount} de {Math.min(m, n)} necesarias
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
                      ? '✓ Witness válido — este gasto 2-de-3 se aceptaría en la red'
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
