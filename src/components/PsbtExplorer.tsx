/**
 * PSBT Explorer — Fase 4 (sección interactiva)
 *
 * Un recorrido por los SEIS ROLES de BIP174 sobre un gasto multisig 2-de-3 P2WSH.
 * La idea que queremos que se VEA: una PSBT es solo un mapa de pares clave→valor,
 * y firmar no reescribe la transacción — solo AÑADE pares al mapa del input.
 *
 * El usuario avanza rol a rol y observa cómo el mapa del input se rellena, se
 * combina, se finaliza y por fin se extrae la transacción lista para la red.
 *
 * Rendimiento: el ciclo completo (con curva elíptica en JS puro) se calcula UNA
 * sola vez al montar; navegar entre pasos es instantáneo. Ver [[feedback_debounce]].
 */

import { useState, useEffect, type ReactNode } from 'react';
import type { Transaction } from '../crypto/transaction';
import {
  createPsbt, clonePsbt,
  updateInputWitnessUtxo, updateInputWitnessScript,
  signInput, combine, finalizeInput, extractTransaction,
  psbtToBase64, bytesToHex, hexToBytes,
  PSBT_IN,
  type Psbt, type KeyPair,
} from '../crypto/psbt';
import { getPublicKey, compressPublicKey } from '../crypto/secp256k1';
import { sortPubKeysBIP67 } from '../crypto/descriptor';
import { createMultisig, createP2WSH, createP2WPKH, addressP2WSH, addressP2WPKH } from '../crypto/script';
import './PsbtExplorer.css';

// ─── Metadatos de cada rol (explicación didáctica, estática) ──

interface StageMeta {
  num: number;
  role: string;
  actor: string;
  title: string;
  points: ReactNode[];
}

const STAGES: StageMeta[] = [
  {
    num: 1, role: 'Creator', actor: 'Wallet coordinadora',
    title: 'Crea el sobre con la transacción sin firmar',
    points: [
      <>Guarda la transacción que queremos hacer (qué UTXO se gasta, a dónde va y
        cuánto) como <code>PSBT_GLOBAL_UNSIGNED_TX</code> en el mapa global.</>,
      <><strong>«Sin firmar» es literal:</strong> los <code>scriptSig</code> van
        vacíos y no hay ningún witness. Es el esqueleto: la intención, sin ninguna
        prueba de autorización todavía.</>,
      <>Los mapas de cada input y output nacen <strong>vacíos</strong>. A partir de
        aquí, todo el trabajo es rellenarlos.</>,
    ],
  },
  {
    num: 2, role: 'Updater', actor: 'Wallet coordinadora (tiene el descriptor)',
    title: 'Añade lo imprescindible para poder firmar',
    points: [
      <><code>WITNESS_UTXO</code>: el output que se gasta (importe + scriptPubKey).
        En SegWit basta con esto — el firmante conoce el importe y puede comprobar la
        comisión sin descargar la tx anterior entera (la gran mejora de BIP143).</>,
      <><code>WITNESS_SCRIPT</code>: el script multisig 2-de-3 en claro. En la
        dirección P2WSH solo va su SHA-256; aquí viaja completo para que cada
        cosignatario sepa <em>exactamente</em> sobre qué firma.</>,
      <>Fíjate: seguimos sin tocar la transacción. Solo <strong>añadimos pares</strong> al
        mapa del input.</>,
    ],
  },
  {
    num: 3, role: 'Signer · A', actor: 'Cosignatario A (su dispositivo)',
    title: 'La primera firma parcial',
    points: [
      <>El dispositivo de A recibe una <strong>copia</strong> del sobre. No necesita
        nada de fuera: saca del propio PSBT el importe, el witnessScript y el sighash
        type.</>,
      <>Calcula el sighash <strong>BIP143</strong> sobre el witnessScript, lo firma
        con su clave privada y añade un <code>PARTIAL_SIG</code>.</>,
      <>La clave del par es <code>0x02 ‖ pubkey_A</code>: la firma queda
        <strong> etiquetada con la pubkey de A</strong>. Por eso luego no chocará con
        la de C.</>,
    ],
  },
  {
    num: 4, role: 'Signer · C', actor: 'Cosignatario C (otro dispositivo)',
    title: 'La segunda firma parcial, en otro dispositivo',
    points: [
      <>C hace lo mismo, partiendo también del sobre <em>actualizado</em> — no del de
        A: son dispositivos independientes que ni se conocen.</>,
      <>Firma <strong>el mismo sighash</strong> (comprometen exactamente la misma
        transacción) y añade su <code>PARTIAL_SIG</code> etiquetado con
        <code> pubkey_C</code>.</>,
      <>Con 2 de 3 ya hay firmas suficientes. El cosignatario B no ha tenido que hacer
        nada.</>,
    ],
  },
  {
    num: 5, role: 'Combiner', actor: 'Wallet coordinadora',
    title: 'Juntar las dos firmas',
    points: [
      <>Combinar dos PSBTs de la misma transacción es la <strong>unión de sus
        mapas</strong>.</>,
      <>Como las firmas están etiquetadas por pubkey, la de A y la de C conviven en el
        mismo mapa de input sin pisarse. Esto es, en una línea, el
        <strong> multisig repartido</strong>.</>,
      <>El mapa del input pasa a tener las <strong>dos</strong> <code>PARTIAL_SIG</code>.</>,
    ],
  },
  {
    num: 6, role: 'Finalizer', actor: 'Wallet coordinadora',
    title: 'Montar el witness definitivo',
    points: [
      <>Ya hay ≥ m firmas. Construye la pila witness que gastará el UTXO:
        <code> [ vacío, sig, sig, witnessScript ]</code>.</>,
      <>El primer elemento vacío es el <strong>«dummy»</strong> del bug histórico de
        <code> OP_CHECKMULTISIG</code>. Las firmas van en el <strong>orden</strong> en
        que sus pubkeys aparecen en el script (lo exige CHECKMULTISIG), no en el que
        llegaron.</>,
      <>Guarda todo en <code>FINAL_SCRIPTWITNESS</code> y <strong>borra</strong> lo que
        ya cumplió su función (las firmas parciales y el witnessScript).</>,
    ],
  },
  {
    num: 7, role: 'Extractor', actor: 'Wallet coordinadora',
    title: 'Sacar la transacción para la red',
    points: [
      <>Coge la transacción sin firmar y le <strong>engancha el witness</strong> de
        cada input.</>,
      <>El resultado ya <strong>no es una PSBT</strong>: es una transacción SegWit
        normal, en hex, lista para hacer broadcast.</>,
      <>Aquí es donde el ciclo enlaza con la <strong>Fase 3</strong> (firmar y emitir a
        testnet/mainnet).</>,
    ],
  },
];

// ─── Descripción de cada tipo de par clave→valor ────────────

interface KeyInfo { type: string; color: string; note: string; extra?: string }

function describeGlobal(): KeyInfo {
  return { type: 'PSBT_GLOBAL_UNSIGNED_TX', color: '#a78bfa', note: 'La transacción esqueleto: qué se gasta y a dónde, sin ninguna firma' };
}

function describeInput(kp: KeyPair, pubLabel: Record<string, string>): KeyInfo {
  switch (kp.key[0]) {
    case PSBT_IN.WITNESS_UTXO:
      return { type: 'WITNESS_UTXO', color: '#4ade80', note: 'El output que gastamos: importe (8B) + scriptPubKey' };
    case PSBT_IN.WITNESS_SCRIPT:
      return { type: 'WITNESS_SCRIPT', color: '#38bdf8', note: 'El script multisig 2-de-3 en claro (scriptCode al firmar)' };
    case PSBT_IN.PARTIAL_SIG: {
      const pk = bytesToHex(kp.key.slice(1));
      const who = pubLabel[pk] ?? '?';
      return { type: 'PARTIAL_SIG', color: '#fb923c', extra: `pubkey ${who}`, note: `Firma del cosignatario ${who} (DER + sighash type), etiquetada por su pubkey` };
    }
    case PSBT_IN.SIGHASH_TYPE:
      return { type: 'SIGHASH_TYPE', color: '#94a3b8', note: 'Qué sighash se firma (0x01 = SIGHASH_ALL)' };
    case PSBT_IN.FINAL_SCRIPTWITNESS:
      return { type: 'FINAL_SCRIPTWITNESS', color: '#e879f9', note: 'La pila witness ya montada, lista para la red' };
    default:
      return { type: `0x${kp.key[0].toString(16)}`, color: '#64748b', note: 'Tipo de par' };
  }
}

// ─── Snapshots del ciclo (parte cara, se calcula una vez) ────

interface WitnessItem { label: string; hex: string; bytes: number }

interface Snapshot {
  psbt?: Psbt;                 // estado de la PSBT en este paso (undefined en Extractor)
  addedKeys: Set<string>;      // claves añadidas respecto al paso anterior (para resaltar)
  removedNote?: string;        // qué borró el finalizer
  witness?: WitnessItem[];     // pila witness montada (paso Finalizer/Extractor)
  rawHex?: string;             // tx cruda (paso Extractor)
  txid?: string;
  base64?: string;             // Base64 de la PSBT en este paso
}

interface Model {
  snapshots: Snapshot[];
  pubLabel: Record<string, string>;
  tx: { inAddr: string; inAmount: bigint; outAddr: string; outAmount: bigint; fee: bigint };
}

/** Claves (hex) presentes en global + input[0], para diffs entre pasos. */
function keySet(psbt: Psbt): Set<string> {
  const s = new Set<string>();
  for (const kp of psbt.global) s.add('g:' + bytesToHex(kp.key));
  for (const kp of psbt.inputs[0]) s.add('i:' + bytesToHex(kp.key));
  return s;
}

function diffAdded(prev: Set<string> | null, cur: Set<string>): Set<string> {
  const added = new Set<string>();
  for (const k of cur) if (!prev || !prev.has(k)) added.add(k);
  return added;
}

/** Ejecuta el ciclo PSBT completo y captura un snapshot por rol. */
function buildModel(): Model {
  // 3 cosignatarios deterministas (didáctico, reproducible).
  const privs = [
    0x1111111111111111111111111111111111111111111111111111111111111111n,
    0x2222222222222222222222222222222222222222222222222222222222222222n,
    0x3333333333333333333333333333333333333333333333333333333333333333n,
  ];
  const pubs = privs.map(p => hexToBytes(compressPublicKey(getPublicKey(p))));
  const pubLabel: Record<string, string> = {
    [bytesToHex(pubs[0])]: 'A', [bytesToHex(pubs[1])]: 'B', [bytesToHex(pubs[2])]: 'C',
  };

  const witnessScript = createMultisig(2, sortPubKeysBIP67(pubs));
  const scriptPubKey = createP2WSH(witnessScript);
  const amount = 100_000n;
  const outAmount = 90_000n;
  const destHash = hexToBytes('751e76e8199196d454941c45d1b3a323f1433bd6');
  const destSpk = createP2WPKH(destHash);

  const unsigned: Transaction = {
    version: 2,
    inputs: [{
      prevTxId: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
      prevVout: 0, scriptSig: new Uint8Array(0), sequence: 0xffffffff,
    }],
    outputs: [{ value: outAmount, scriptPubKey: destSpk }],
    locktime: 0,
  };

  const snaps: Snapshot[] = [];
  let prevKeys: Set<string> | null = null;
  const snap = (psbt: Psbt, extra: Partial<Snapshot> = {}) => {
    const cur = keySet(psbt);
    snaps.push({ psbt: clonePsbt(psbt), addedKeys: diffAdded(prevKeys, cur), base64: psbtToBase64(psbt), ...extra });
    prevKeys = cur;
  };

  // 1 · Creator
  const base = createPsbt(unsigned);
  snap(base);

  // 2 · Updater
  updateInputWitnessUtxo(base, 0, { value: amount, scriptPubKey });
  updateInputWitnessScript(base, 0, witnessScript);
  snap(base);

  // 3 · Signer A (dispositivo aparte, copia del sobre actualizado)
  const deviceA = clonePsbt(base);
  signInput(deviceA, 0, privs[0]);
  snap(deviceA);

  // 4 · Signer C (otro dispositivo, también parte del sobre actualizado)
  const deviceC = clonePsbt(base);
  signInput(deviceC, 0, privs[2]);
  // El snapshot de C muestra SU sobre (solo su firma); el diff resalta su PARTIAL_SIG.
  prevKeys = keySet(base); // C parte del sobre actualizado, no del de A
  snap(deviceC);

  // 5 · Combiner
  const combined = combine(deviceA, deviceC);
  prevKeys = keySet(base); // resalta que ahora hay DOS firmas respecto al sobre base
  snap(combined);

  // 6 · Finalizer
  const fin = finalizeInput(combined, 0);
  const witness: WitnessItem[] = fin.witnessStack.map((item, i) => {
    if (i === 0) return { label: 'dummy (vacío)', hex: '∅', bytes: 0 };
    if (i === fin.witnessStack.length - 1) return { label: 'witnessScript', hex: bytesToHex(item), bytes: item.length };
    const who = fin.usedSigs[i - 1] ? pubLabel[bytesToHex(fin.usedSigs[i - 1].pubkey)] : '?';
    return { label: `firma ${who}`, hex: bytesToHex(item), bytes: item.length };
  });
  snap(combined, { witness, removedNote: 'El finalizer eliminó las 2× PARTIAL_SIG y el WITNESS_SCRIPT: ya cumplieron su función.' });

  // 7 · Extractor (ya no es PSBT)
  const { hex, txid } = extractTransaction(combined);
  snaps.push({ addedKeys: new Set(), witness, rawHex: hex, txid });

  return {
    snapshots: snaps,
    pubLabel,
    tx: {
      inAddr: addressP2WSH(witnessScript, true),
      inAmount: amount,
      outAddr: addressP2WPKH(destHash, true),
      outAmount,
      fee: amount - outAmount,
    },
  };
}

// ─── Utilidades de presentación ─────────────────────────────

function shortHex(hex: string, head = 12, tail = 8): string {
  if (hex.length <= head + tail + 1) return hex;
  return `${hex.slice(0, head)}…${hex.slice(-tail)}`;
}

// ─── Componente ─────────────────────────────────────────────

export function PsbtExplorer() {
  const [model, setModel] = useState<Model | null>(null);
  const [step, setStep] = useState(0);
  const [copied, setCopied] = useState(false);

  // Trabajo caro (curva elíptica): una sola vez, tras pintar el spinner.
  useEffect(() => {
    const t = setTimeout(() => setModel(buildModel()), 0);
    return () => clearTimeout(t);
  }, []);

  const meta = STAGES[step];
  const snap = model?.snapshots[step];

  const copyBase64 = () => {
    if (!snap?.base64) return;
    navigator.clipboard?.writeText(snap.base64).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };

  const renderRow = (kp: KeyPair, info: KeyInfo, added: boolean) => (
    <div key={info.type + bytesToHex(kp.key)} className={`pbe-kv ${added ? 'pbe-kv--new' : ''}`}>
      <span className="pbe-kv-type" style={{ color: info.color, borderColor: info.color + '55', background: info.color + '18' }}>
        {info.type}
      </span>
      <div className="pbe-kv-body">
        <div className="pbe-kv-meta">
          {info.extra && <span className="pbe-kv-extra">{info.extra}</span>}
          {added && <span className="pbe-kv-badge">nuevo</span>}
          <span className="pbe-kv-len">{kp.value.length} B</span>
        </div>
        <code className="pbe-kv-val" title={bytesToHex(kp.value)}>{shortHex(bytesToHex(kp.value))}</code>
        <span className="pbe-kv-note">{info.note}</span>
      </div>
    </div>
  );

  return (
    <div className="pbe">
      <header className="pbe-header">
        <span className="pbe-phase-tag">Fase 4 · Interactivo</span>
        <h1>PSBT Explorer</h1>
        <p className="pbe-subtitle">
          El ciclo de <strong>BIP174</strong> sobre un gasto multisig <strong>2-de-3</strong>:
          cómo un sobre <code>PSBT</code> pasa por seis roles hasta convertirse en una
          transacción lista para la red.
        </p>
      </header>

      <div className="pbe-intro">
        <strong>Una PSBT es solo un mapa de pares clave→valor</strong> (uno global, uno por
        input, uno por output). Firmar <em>no reescribe</em> la transacción: solo
        <strong> añade pares</strong> al mapa del input. Combinar el trabajo de dos
        cosignatarios es la <strong>unión</strong> de sus mapas. Avanza paso a paso y
        obsérvalo.
      </div>

      {/* ── Riel de roles ── */}
      <div className="pbe-rail">
        {STAGES.map((s, i) => (
          <button
            key={s.num}
            className={`pbe-rail-step ${i === step ? 'active' : ''} ${i < step ? 'done' : ''}`}
            onClick={() => setStep(i)}
            disabled={!model}
            title={s.role}
          >
            <span className="pbe-rail-num">{s.num}</span>
            <span className="pbe-rail-role">{s.role}</span>
          </button>
        ))}
      </div>

      {!model ? (
        <div className="pbe-loading">
          <span className="pbe-spinner" /> Ejecutando el ciclo PSBT (firmas ECDSA en JS puro, es
          lento a propósito)…
        </div>
      ) : (
        <>
          {/* ── Explicación del rol actual ── */}
          <section className="pbe-explain">
            <div className="pbe-explain-head">
              <span className="pbe-explain-num">{meta.num}</span>
              <div>
                <h2>{meta.role} <span className="pbe-explain-sub">— {meta.title}</span></h2>
                <span className="pbe-actor">👤 {meta.actor}</span>
              </div>
            </div>
            <ul className="pbe-points">
              {meta.points.map((p, i) => <li key={i}>{p}</li>)}
            </ul>
          </section>

          {/* ── Transacción a autorizar (contexto, en el paso Creator) ── */}
          {step === 0 && model && (
            <section className="pbe-txcard">
              <span className="pbe-label">La transacción que vamos a autorizar</span>
              <div className="pbe-txflow">
                <div className="pbe-txside">
                  <span className="pbe-txrole">gasta (input)</span>
                  <code className="pbe-txaddr">{shortHex(model.tx.inAddr, 14, 8)}</code>
                  <span className="pbe-txamt">{model.tx.inAmount.toLocaleString()} sats</span>
                  <span className="pbe-txkind">P2WSH 2-de-3</span>
                </div>
                <span className="pbe-txarrow">→</span>
                <div className="pbe-txside">
                  <span className="pbe-txrole">crea (output)</span>
                  <code className="pbe-txaddr">{shortHex(model.tx.outAddr, 14, 8)}</code>
                  <span className="pbe-txamt">{model.tx.outAmount.toLocaleString()} sats</span>
                  <span className="pbe-txkind">comisión: {model.tx.fee.toLocaleString()} sats</span>
                </div>
              </div>
            </section>
          )}

          {/* ── La PSBT: mapas clave→valor ── */}
          {snap?.psbt && (
            <section className="pbe-section">
              <span className="pbe-label">Mapa GLOBAL</span>
              <div className="pbe-map">
                {snap.psbt.global.map(kp =>
                  renderRow(kp, describeGlobal(), snap.addedKeys.has('g:' + bytesToHex(kp.key))))}
              </div>

              <span className="pbe-label pbe-label--mt">Mapa INPUT #0 {snap.psbt.inputs[0].length === 0 && '· (vacío)'}</span>
              <div className="pbe-map">
                {snap.psbt.inputs[0].length === 0 ? (
                  <div className="pbe-empty">Aún sin pares — el trabajo empieza aquí.</div>
                ) : (
                  snap.psbt.inputs[0].map(kp =>
                    renderRow(kp, describeInput(kp, model.pubLabel), snap.addedKeys.has('i:' + bytesToHex(kp.key))))
                )}
              </div>

              {snap.removedNote && <p className="pbe-removed">🧹 {snap.removedNote}</p>}
              <p className="pbe-hint">
                El mapa de OUTPUT #0 existe pero está vacío en este ejemplo (no necesita
                scripts ni derivaciones para un P2WPKH de destino).
              </p>
            </section>
          )}

          {/* ── Witness montado (Finalizer / Extractor) ── */}
          {snap?.witness && (
            <section className="pbe-section">
              <span className="pbe-label">Pila witness montada</span>
              <div className="pbe-witness">
                {snap.witness.map((w, i) => (
                  <div key={i} className="pbe-witem">
                    <span className="pbe-witem-idx">{i}</span>
                    <span className="pbe-witem-label">{w.label}</span>
                    <code className="pbe-witem-hex">{w.hex === '∅' ? '∅' : shortHex(w.hex, 16, 10)}</code>
                    <span className="pbe-witem-len">{w.bytes} B</span>
                  </div>
                ))}
              </div>
              <p className="pbe-hint">
                Orden fijo: el <strong>dummy vacío</strong> (bug de OP_CHECKMULTISIG), las firmas
                en el orden de las pubkeys del script, y el <strong>witnessScript</strong> al final
                (el consenso comprueba que hashea al programa de 32 B de la dirección).
              </p>
            </section>
          )}

          {/* ── Transacción cruda (Extractor) ── */}
          {snap?.rawHex && (
            <section className="pbe-section">
              <div className="pbe-label-row">
                <span className="pbe-label">Transacción cruda — lista para broadcast</span>
              </div>
              <div className="pbe-raw"><code>{snap.rawHex}</code></div>
              <div className="pbe-txid">
                <span className="pbe-label">TxID</span>
                <code>{snap.txid}</code>
              </div>
              <p className="pbe-hint">
                Esto ya no es una PSBT: es una transacción SegWit normal. El siguiente paso sería
                emitirla — justo lo que hace la <strong>Fase 3</strong>.
              </p>
            </section>
          )}

          {/* ── Base64 del sobre (formato de transporte) ── */}
          {snap?.base64 && (
            <section className="pbe-section">
              <div className="pbe-label-row">
                <span className="pbe-label">La PSBT ahora mismo (Base64) · {snap.base64.length} chars</span>
                <button className="pbe-copy" onClick={copyBase64}>{copied ? '✓ copiado' : 'copiar'}</button>
              </div>
              <div className="pbe-b64"><code>{snap.base64}</code></div>
              <p className="pbe-hint">
                Este es el texto que un cosignatario copia/pega, envía por cualquier canal o mete en
                un QR. Crece a medida que se le añaden pares.
              </p>
            </section>
          )}

          {/* ── Navegación ── */}
          <div className="pbe-nav">
            <button className="pbe-nav-btn" onClick={() => setStep(s => Math.max(0, s - 1))} disabled={step === 0}>
              ← Anterior
            </button>
            <span className="pbe-nav-pos">{step + 1} / {STAGES.length}</span>
            <button className="pbe-nav-btn pbe-nav-btn--primary" onClick={() => setStep(s => Math.min(STAGES.length - 1, s + 1))} disabled={step === STAGES.length - 1}>
              Siguiente →
            </button>
          </div>
        </>
      )}
    </div>
  );
}
