/**
 * Taproot Multisig Explorer — Fase 4 (sección interactiva, WATCH-ONLY)
 *
 * VER y VERIFICAR un multisig Taproot m-de-n estándar a partir de las XPUBS que
 * TÚ pegas — como se monta un multisig real: cada cosignatario aporta su xpub y
 * nadie comparte su clave privada.
 *
 *   tr( NUMS , sortedmulti_a(m, [origen]xpub/<rama>/*, …) )
 *
 * - Pega una xpub por cosignatario (con o sin origen [huella/ruta]). Validación
 *   en vivo por campo: formato, red y origen.
 * - Elige rama (recibir 0 / cambio 1) e índice de dirección: las claves se derivan
 *   por CKDpub (derivación pública), igual que un descriptor con comodín /<rama>/*.
 * - Panel de verificación: comprueba que todo cuadra (xpubs válidas, misma red,
 *   descriptor con checksum válido, dirección derivada).
 *
 * Al ser watch-only NO hay firma (no hay claves privadas): esa es justo la
 * propiedad que hace seguro compartir una xpub. Toda la cripto va verificada
 * contra vectores BIP32/BIP341/BIP387. El trabajo pesado (curva elíptica en JS)
 * va con estado de carga. Ver [[feedback_debounce]] y [[project_coin_type_network]].
 */

import { useState, useEffect, useMemo } from 'react';
import { NUMS_H, sortXOnlyBIP67, descriptorChecksum } from '../crypto/descriptor';
import { tapscriptMultisig, tapLeafHash, taprootScriptOutput } from '../crypto/tapscript';
import { addressP2TR, disassemble } from '../crypto/script';
import {
  masterKeyFromSeed, deriveMultisigKey, parseXpub, deriveChildPublic, type HDNode,
} from '../crypto/hdwallet';
import { bytesToBigint } from '../crypto/hmac';
import './TaprootMultisigExplorer.css';

const MAX_N = 5;
const MAX_INDEX = 9;
const DEBOUNCE_MS = 300;

function to32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = n;
  for (let i = 31; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  return bytes;
}
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
function shortHex(hex: string, head = 10, tail = 6): string {
  return hex.length <= head + tail + 1 ? hex : `${hex.slice(0, head)}…${hex.slice(-tail)}`;
}

interface Cosigner {
  keyExpression: string;   // [origen]xpub  (listo para el descriptor)
  fingerprint: string;
  path: string;
  xpub: string;
  node: HDNode;            // nodo PÚBLICO (watch-only): sirve para derivar, no para firmar
}

/** Parsea lo que pega el usuario: una xpub o `[huella/ruta]xpub` (con o sin sufijo /..). */
function parseCosignerInput(raw: string): { cosigner?: Cosigner; mainnet?: boolean; error?: string } {
  const input = raw.trim();
  if (!input) return { error: 'vacío' };

  let origin = '';
  let rest = input;
  if (input.startsWith('[')) {
    const close = input.indexOf(']');
    if (close === -1) return { error: 'falta el corchete de cierre ]' };
    origin = input.slice(1, close);
    rest = input.slice(close + 1);
  }
  const xpub = rest.split('/')[0].trim(); // descarta cualquier sufijo /0/* etc.

  try {
    const { node, mainnet } = parseXpub(xpub);
    const fingerprint = origin ? origin.split('/')[0] : '—';
    const path = origin ? origin.split('/').slice(1).join('/') : '';
    const keyExpression = origin ? `[${origin}]${xpub}` : xpub;
    return { cosigner: { keyExpression, fingerprint, path, xpub, node }, mainnet };
  } catch (e) {
    return { error: (e as Error).message };
  }
}

/** Ejemplos válidos (derivados de semillas de prueba) para empezar a juguetear. */
function exampleExpr(i: number): string {
  return deriveMultisigKey(masterKeyFromSeed(new Uint8Array(16).fill(i + 7)), 'p2tr', 0, 0, true).keyExpression;
}

interface MultisigInfo {
  sortedXonly: Uint8Array[];
  leaf: Uint8Array;
  leafHash: Uint8Array;
  controlBlock: Uint8Array;
  outputKeyHex: string;
  address: string;
  descriptor: string;      // descriptor CONCRETO del índice (claves x-only)
}

/** Construye el m-de-n estándar (para un índice) a partir de las x-only derivadas. */
function buildInfo(xonly: Uint8Array[], m: number, mainnet: boolean): MultisigInfo {
  const sortedXonly = sortXOnlyBIP67(xonly);
  const leaf = tapscriptMultisig(m, sortedXonly);
  const leafHash = tapLeafHash(leaf);
  const internalX = bytesToBigint(hexToBytes(NUMS_H));
  const out = taprootScriptOutput(internalX, { script: leaf });
  const outBytes = to32(out.outputKey);
  const address = addressP2TR(outBytes, mainnet);
  const keysStr = sortedXonly.map(bytesToHex).join(',');
  const body = `tr(${NUMS_H},sortedmulti_a(${m},${keysStr}))`;
  return {
    sortedXonly, leaf, leafHash,
    controlBlock: out.controlBlocks[0],
    outputKeyHex: bytesToHex(outBytes),
    address,
    descriptor: `${body}#${descriptorChecksum(body)}`,
  };
}

interface Derived {
  sig: string;
  xonly: Uint8Array[];
}

export function TaprootMultisigExplorer() {
  const [n, setN] = useState(3);
  const [m, setM] = useState(2);
  const [branch, setBranch] = useState<0 | 1>(0);
  const [addressIndex, setAddressIndex] = useState(0);
  const [xpubInputs, setXpubInputs] = useState<string[]>(
    () => Array.from({ length: MAX_N }, (_, i) => (i < 3 ? exampleExpr(i) : '')),
  );
  const [derived, setDerived] = useState<Derived | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const mEff = Math.min(m, n);

  const copyText = (id: string, text: string) => {
    navigator.clipboard?.writeText(text).then(() => {
      setCopiedId(id);
      setTimeout(() => setCopiedId(cur => (cur === id ? null : cur)), 1500);
    });
  };

  // ── Validación por campo (barata: sin curva elíptica pesada) ──
  const fieldStatus = useMemo(
    () => xpubInputs.slice(0, n).map(parseCosignerInput),
    [xpubInputs, n],
  );
  const cosigners = fieldStatus.map(s => s.cosigner).filter((c): c is Cosigner => !!c);
  const allValid = cosigners.length === n;
  const networks = new Set(fieldStatus.map(s => s.mainnet).filter(v => v !== undefined));
  const mixedNetwork = networks.size > 1;
  const mainnet = networks.has(true) && networks.size === 1;
  const ready = allValid && !mixedNetwork;

  const sig = `${n}|${branch}|${addressIndex}|${xpubInputs.slice(0, n).join('~')}`;
  const loading = ready && (!derived || derived.sig !== sig);

  // ── Trabajo CARO: derivar las x-only del índice por CKDpub (…/rama/índice) ──
  useEffect(() => {
    if (!ready) { setDerived(null); return; }
    const timer = setTimeout(() => {
      const xonly = cosigners.map(c => {
        const b = deriveChildPublic(c.node, branch);
        const leaf = deriveChildPublic(b, addressIndex);
        return to32(leaf.publicKey!.x);
      });
      setDerived({ sig, xonly });
    }, DEBOUNCE_MS);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sig, ready]);

  // ── Descriptor/dirección del índice actual ──
  const info = useMemo(() => {
    if (!derived || derived.sig !== sig) return null;
    return buildInfo(derived.xonly, mEff, mainnet);
  }, [derived, sig, mEff, mainnet]);

  // ── Descriptor de wallet con rango /<rama>/* (la forma REAL, con xpubs) ──
  const rangedDescriptor = useMemo(() => {
    if (!ready) return null;
    const exprs = cosigners.map(c => `${c.keyExpression}/${branch}/*`);
    const body = `tr(${NUMS_H},sortedmulti_a(${mEff},${exprs.join(',')}))`;
    return `${body}#${descriptorChecksum(body)}`;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [xpubInputs, n, branch, mEff, ready]);

  const setKeysTotal = (value: number) => {
    setN(value);
    if (m > value) setM(value);
  };
  const setXpubAt = (i: number, value: string) => {
    setXpubInputs(prev => { const next = [...prev]; next[i] = value; return next; });
  };
  const fillExamples = () => {
    setXpubInputs(prev => { const next = [...prev]; for (let i = 0; i < n; i++) next[i] = exampleExpr(i); return next; });
  };
  const clearAll = () => setXpubInputs(Array.from({ length: MAX_N }, () => ''));

  const filledCount = xpubInputs.slice(0, n).filter(s => s.trim()).length;

  return (
    <div className="tme">
      <header className="tme-header">
        <span className="tme-phase-tag">Fase 4 · Interactivo · Watch-only</span>
        <h1>Taproot Multisig Explorer</h1>
        <p className="tme-subtitle">
          Monta un multisig <strong>m-de-n estándar</strong> de Taproot con <strong>tus propias
          xpubs</strong>: <code>tr(NUMS, sortedmulti_a(m,…))</code>. Pega las claves, elige rama e
          índice, y <strong>verifica</strong> que las direcciones y el descriptor cuadran — sin
          exponer ninguna clave privada.
        </p>
      </header>

      <div className="tme-info">
        <strong>No hay ninguna clave privada aquí.</strong> Todo se deriva de las xpubs (CKDpub) —
        justo lo que cada cosignatario puede compartir sin poder gastar. Por eso este modo verifica
        direcciones y descriptor, pero <strong>no firma</strong>: para gastar harían falta {mEff} firmas
        Schnorr reales. La clave interna <code>NUMS</code> inutiliza el key-path (solo se gasta por la
        hoja <code>multi_a</code>).
      </div>

      {/* ── Controles ── */}
      <div className="tme-controls">
        <label className="tme-control">
          <span className="tme-control-label">Cosignatarios · <strong>n = {n}</strong></span>
          <input type="range" min={2} max={MAX_N} value={n} onChange={e => setKeysTotal(Number(e.target.value))} />
        </label>
        <label className="tme-control">
          <span className="tme-control-label">Umbral · <strong>m = {mEff}</strong></span>
          <input type="range" min={1} max={n} value={mEff} onChange={e => setM(Number(e.target.value))} />
        </label>
        <div className="tme-control">
          <span className="tme-control-label">Rama</span>
          <div className="tme-toggle">
            <button className={branch === 0 ? 'active' : ''} onClick={() => setBranch(0)}>recibir /0</button>
            <button className={branch === 1 ? 'active' : ''} onClick={() => setBranch(1)}>cambio /1</button>
          </div>
        </div>
        <label className="tme-control">
          <span className="tme-control-label">Índice · <strong>…/{branch}/{addressIndex}</strong></span>
          <input type="range" min={0} max={MAX_INDEX} value={addressIndex} onChange={e => setAddressIndex(Number(e.target.value))} />
        </label>
      </div>

      {/* ── Campos de xpub ── */}
      <section className="tme-section">
        <div className="tme-label-row">
          <span className="tme-label">Xpubs de los cosignatarios ({filledCount}/{n})</span>
          <div className="tme-xpub-actions">
            <button className="tme-copy" onClick={fillExamples}>rellenar ejemplos</button>
            <button className="tme-copy" onClick={clearAll}>limpiar</button>
          </div>
        </div>
        <div className="tme-xpubs">
          {Array.from({ length: n }, (_, i) => {
            const st = fieldStatus[i];
            const empty = !xpubInputs[i]?.trim();
            const ok = !!st?.cosigner;
            return (
              <div key={i} className="tme-xpub-field">
                <span className="tme-xpub-tag">{String.fromCharCode(65 + i)}</span>
                <input
                  className={`tme-xpub-input ${empty ? '' : ok ? 'ok' : 'bad'}`}
                  value={xpubInputs[i] ?? ''}
                  onChange={e => setXpubAt(i, e.target.value)}
                  placeholder="[huella/48h/0h/0h/3h]xpub…  o  xpub…"
                  spellCheck={false}
                />
                <span className={`tme-xpub-status ${ok ? 'ok' : empty ? '' : 'bad'}`}>
                  {empty ? '' : ok ? '✓' : `✗ ${st?.error ?? ''}`}
                </span>
              </div>
            );
          })}
        </div>
        {mixedNetwork && (
          <div className="tme-verdict bad">✗ Las xpubs mezclan mainnet y testnet — deben ser todas de la misma red.</div>
        )}
      </section>

      <div className="tme-scheme">
        Esquema: <strong>{mEff}-de-{n}</strong>
        {ready && <span className="tme-scheme-note"> · {mainnet ? 'mainnet' : 'testnet'} · rama /{branch} · índice {addressIndex}</span>}
      </div>

      {!ready && !mixedNetwork && (
        <div className="tme-loading tme-loading--idle">
          Pega {n} xpubs válidas (o pulsa «rellenar ejemplos») para ver la dirección y el descriptor.
        </div>
      )}

      {loading && (
        <div className="tme-loading"><span className="tme-spinner" /> Derivando claves por CKDpub (curva elíptica en JS, lento a propósito)…</div>
      )}

      {info && ready && !loading && (
        <>
          {/* ── Verificación ── */}
          <section className="tme-section">
            <span className="tme-label">Verificación — ¿cuadra todo?</span>
            <div className="tme-checks">
              <div className="tme-check ok">✓ {n}/{n} xpubs válidas y parseadas</div>
              <div className="tme-check ok">✓ Todas en la misma red ({mainnet ? 'mainnet' : 'testnet'})</div>
              <div className="tme-check ok">✓ Descriptor con checksum válido</div>
              <div className="tme-check ok">✓ Dirección …/{branch}/{addressIndex} derivada por CKDpub</div>
            </div>
            <p className="tme-hint">
              Todo cuadra: con estas {n} xpubs cualquiera puede <strong>verificar y vigilar</strong> el
              multisig (recibir, auditar saldo). Para <strong>gastar</strong> harían falta {mEff} de los
              cosignatarios firmando con sus claves privadas (que aquí no están).
            </p>
          </section>

          {/* ── Cosignatarios parseados ── */}
          <section className="tme-section">
            <span className="tme-label">Cosignatarios — origen y xpub</span>
            <div className="tme-xpub-list">
              {cosigners.map((c, i) => (
                <div key={i} className="tme-xpub-row">
                  <span className="tme-xpub-tag">{String.fromCharCode(65 + i)}</span>
                  <code className="tme-xpub-expr" title={c.keyExpression}>
                    {c.fingerprint !== '—' ? `[${c.fingerprint}/${c.path}]` : ''}{shortHex(c.xpub, 12, 8)}
                  </code>
                  <button className="tme-copy" onClick={() => copyText(`xpub${i}`, `${c.keyExpression}/${branch}/*`)}>
                    {copiedId === `xpub${i}` ? '✓' : 'copiar'}
                  </button>
                </div>
              ))}
            </div>
          </section>

          {/* ── Dirección ── */}
          <section className="tme-section">
            <div className="tme-label-row">
              <span className="tme-label">Dirección Taproot · …/{branch}/{addressIndex}</span>
              <button className="tme-copy" onClick={() => copyText('addr', info.address)}>{copiedId === 'addr' ? '✓ copiado' : 'copiar'}</button>
            </div>
            <div className="tme-address"><code>{info.address}</code></div>
          </section>

          {/* ── Descriptor ── */}
          <section className="tme-section">
            <div className="tme-label-row">
              <span className="tme-label">Descriptor de wallet (con rango /{branch}/*)</span>
              <button className="tme-copy" onClick={() => copyText('desc', rangedDescriptor ?? '')}>{copiedId === 'desc' ? '✓ copiado' : 'copiar'}</button>
            </div>
            <div className="tme-descriptor"><code>{rangedDescriptor}</code></div>
            <p className="tme-hint">
              El descriptor REAL de la wallet: las xpubs con su origen y el comodín <code>/{branch}/*</code>.
              Cada índice da una dirección distinta (arriba, la <code>{addressIndex}</code>).
              <code> sortedmulti_a</code> ordena las claves derivadas (BIP67): el orden de los
              cosignatarios no cambia la dirección.
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
              al final <code>OP_{mEff} OP_NUMEQUAL</code> exige exactamente {mEff} firmas para gastar.
            </p>
          </section>
        </>
      )}
    </div>
  );
}
