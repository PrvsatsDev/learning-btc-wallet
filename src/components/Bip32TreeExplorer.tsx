/**
 * Árbol BIP32 navegable — Fase 4 (visual, estilo Sparrow)
 *
 * La seed se convierte en un árbol que se puede desplegar nivel a nivel:
 * m → purpose' → coin' → account' → change → index. Al seleccionar un nodo se ve
 * cómo se derivó (HMAC-SHA512 normal o hardened), sus claves, su xpub y, en las
 * hojas, la dirección.
 *
 * Lo más importante que enseña es la FRONTERA WATCH-ONLY: por encima de la cuenta
 * todo es hardened (hace falta la privada); por debajo, todo sale de la xpub. El
 * panel lo demuestra re-derivando la clave por CKDpub y comparándola.
 *
 * Coste: cada derivación es una multiplicación escalar en JS (~80 ms), y la seed
 * pasa por PBKDF2 (~1 s). Por eso el árbol es perezoso, los hijos se derivan de
 * uno en uno cediendo el hilo, y los inputs llevan debounce ([[feedback_debounce]]).
 * Lógica pura y vectores en bip32-tree.ts / bip32-tree.test.ts.
 */

import { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import {
  generateMnemonic,
  validateMnemonic,
  mnemonicToSeed,
  masterKeyFromSeed,
} from '../crypto/hdwallet';
import {
  makeRoot,
  childSpecs,
  deriveTreeChild,
  verifyFromAccountXpub,
  isWatchOnlyDerivable,
  xpubOf,
  accountDescriptor,
  ancestorPaths,
  childNumberHex,
  chainCodeHex,
  privateKeyHex,
  type TreeNode,
  type TreeLevel,
  type TreeOptions,
  type ChildSpec,
  type Purpose,
  type WatchOnlyCheck,
} from '../crypto/bip32-tree';
import './Bip32TreeExplorer.css';

const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const DEBOUNCE_MS = 500;
const ADDRESS_STEP = 5;
/** Hijos que se derivan al desplegar un nodo por primera vez */
const DEFAULT_OPTS = { accounts: 1, addresses: ADDRESS_STEP };

const PURPOSE_NAME: Record<Purpose, string> = {
  44: 'Legacy · P2PKH',
  84: 'SegWit nativo · P2WPKH',
  86: 'Taproot · P2TR',
};

const LEVEL_EXPLAIN: Record<TreeLevel, string> = {
  master:
    'La raíz del árbol. Sale de HMAC-SHA512 con la clave fija "Bitcoin seed" sobre la seed de 64 bytes. ' +
    'Su fingerprint identifica la semilla en descriptores y PSBTs sin revelar nada.',
  purpose:
    'Primer nivel BIP44: decide qué tipo de direcciones cuelgan de esta rama. Es una convención — ' +
    'la misma clave en 84\' o en 86\' daría árboles totalmente distintos.',
  coin:
    'SLIP-0044: 0\' para Bitcoin mainnet, 1\' para cualquier testnet. Separa las claves de cada red: ' +
    'unas monedas de test nunca comparten clave con las reales.',
  account:
    'Una "cuenta" lógica, como subcuentas de un banco. Es el ÚLTIMO nivel hardened: su xpub es lo ' +
    'que exportas a una wallet watch-only (Sparrow, Liana, un servidor de pagos…).',
  change:
    '0 = cadena externa (direcciones que das para recibir), 1 = cadena interna (cambio de tus propias ' +
    'transacciones). Ya no es hardened: se deriva desde la xpub.',
  address:
    'Una hoja: una clave concreta y su dirección. Las wallets avanzan el índice para no reutilizar ' +
    'direcciones (gap limit típico: 20 sin uso seguidas).',
};

function levelLabel(node: TreeNode): string {
  switch (node.level) {
    case 'master': return 'Master key';
    case 'purpose': return PURPOSE_NAME[node.index as Purpose] ?? `Purpose ${node.index}`;
    case 'coin': return node.index === 0 ? 'Bitcoin mainnet' : 'Testnet';
    case 'account': return `Cuenta #${node.index}`;
    case 'change': return node.index === 0 ? 'Recepción (externa)' : 'Cambio (interna)';
    case 'address': return `Dirección #${node.index}`;
  }
}

function segmentOf(path: string): string {
  return path.split('/').pop()!;
}

function shortStr(s: string, head = 10, tail = 6): string {
  return s.length <= head + tail + 1 ? s : `${s.slice(0, head)}…${s.slice(-tail)}`;
}

const yieldToUi = () => new Promise<void>(r => setTimeout(r, 0));

const sameSpec = (c: TreeNode, s: ChildSpec) => c.index === s.index && c.hardened === s.hardened;

export function Bip32TreeExplorer() {
  // ─── Entrada (seed) ───────────────────────────────────────
  const [mnemonicInput, setMnemonicInput] = useState(TEST_MNEMONIC);
  const [passphrase, setPassphrase] = useState('');
  const [debounced, setDebounced] = useState({ mnemonic: TEST_MNEMONIC, passphrase: '' });
  const [network, setNetwork] = useState<'mainnet' | 'testnet'>('mainnet');
  const mainnet = network === 'mainnet';

  useEffect(() => {
    const t = setTimeout(() => setDebounced({ mnemonic: mnemonicInput, passphrase }), DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [mnemonicInput, passphrase]);

  const words = useMemo(
    () => debounced.mnemonic.trim().toLowerCase().split(/\s+/).filter(Boolean),
    [debounced.mnemonic],
  );
  const valid = useMemo(() => words.length >= 12 && validateMnemonic(words), [words]);

  // ─── Árbol ────────────────────────────────────────────────
  const [root, setRoot] = useState<TreeNode | null>(null);
  const [children, setChildren] = useState<Record<string, TreeNode[]>>({});
  const [loading, setLoading] = useState<Record<string, number>>({});
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState('m');
  const [showPriv, setShowPriv] = useState(false);
  const [woCheck, setWoCheck] = useState<{ path: string; result: WatchOnlyCheck } | null>(null);

  // Fuente de verdad de los nodos derivados (los handlers async la leen sin
  // cierres obsoletos) y número de "generación" para descartar trabajo de una
  // seed/red anterior.
  const cacheRef = useRef<Record<string, TreeNode[]>>({});
  const genRef = useRef(0);

  /** Deriva (de uno en uno) los hijos que falten de `parent` */
  const ensureChildren = useCallback(async (parent: TreeNode, wanted: ChildSpec[], gen: number) => {
    const bump = (d: number) =>
      setLoading(prev => ({ ...prev, [parent.path]: (prev[parent.path] ?? 0) + d }));
    bump(1);
    try {
      for (const spec of wanted) {
        await yieldToUi();
        if (gen !== genRef.current) return;
        const have = cacheRef.current[parent.path] ?? [];
        if (have.some(c => sameSpec(c, spec))) continue;
        const child = deriveTreeChild(parent, spec.index, spec.hardened, mainnet);
        cacheRef.current = {
          ...cacheRef.current,
          [parent.path]: [...have, child].sort((a, b) => a.index - b.index),
        };
        setChildren(cacheRef.current);
      }
    } finally {
      if (gen === genRef.current) bump(-1);
    }
  }, [mainnet]);

  // Nueva seed, passphrase o red → árbol nuevo, desplegado hasta la 1.ª dirección BIP84
  const [seedStatus, setSeedStatus] = useState<'idle' | 'deriving' | 'ready'>('idle');
  useEffect(() => {
    const gen = ++genRef.current;
    cacheRef.current = {};
    let cancelled = false;

    (async () => {
      await yieldToUi();
      if (cancelled) return;
      setChildren({});
      setLoading({});
      setRoot(null);
      setWoCheck(null);
      if (!valid) { setSeedStatus('idle'); return; }

      setSeedStatus('deriving');
      await new Promise(r => setTimeout(r, 30)); // que se pinte el aviso antes del PBKDF2
      if (cancelled) return;
      const r = makeRoot(masterKeyFromSeed(mnemonicToSeed(words, debounced.passphrase)));
      setRoot(r);
      setSeedStatus('ready');

      const target = `m/84'/${mainnet ? 0 : 1}'/0'/0/0`;
      const chain = ancestorPaths(target);
      setExpanded(new Set(chain.slice(0, -1)));
      setSelected(target);

      const opts: TreeOptions = { mainnet, ...DEFAULT_OPTS };
      let node: TreeNode | undefined = r;
      for (const p of chain.slice(1)) {
        await ensureChildren(node, childSpecs(node, opts), gen);
        node = cacheRef.current[node.path]?.find(c => c.path === p);
        if (!node || cancelled) return;
      }
    })();

    return () => { cancelled = true; };
  }, [words, valid, debounced.passphrase, mainnet, ensureChildren]);

  const nodeByPath = useMemo(() => {
    const m = new Map<string, TreeNode>();
    if (root) m.set(root.path, root);
    for (const list of Object.values(children)) for (const n of list) m.set(n.path, n);
    return m;
  }, [root, children]);

  const toggle = (node: TreeNode) => {
    const next = new Set(expanded);
    if (next.has(node.path)) {
      next.delete(node.path);
    } else {
      next.add(node.path);
      void ensureChildren(node, childSpecs(node, { mainnet, ...DEFAULT_OPTS }), genRef.current);
    }
    setExpanded(next);
  };

  /** "+ cuenta" / "+ 5 direcciones": siguientes índices de la misma cadena */
  const growMore = (node: TreeNode) => {
    const have = cacheRef.current[node.path]?.length ?? 0;
    const step = node.level === 'coin' ? 1 : ADDRESS_STEP;
    const hardened = node.level === 'coin';
    const specs = Array.from({ length: step }, (_, i) => ({ index: have + i, hardened }));
    void ensureChildren(node, specs, genRef.current);
  };

  const runWatchOnlyCheck = (node: TreeNode) => {
    const account = nodeByPath.get(ancestorPaths(node.path)[3]);
    if (!account) return;
    setTimeout(() => setWoCheck({ path: node.path, result: verifyFromAccountXpub(account, node) }), 0);
  };

  const handleGenerate = () => {
    setMnemonicInput(generateMnemonic().words.join(' '));
    setShowPriv(false);
  };

  const sel = nodeByPath.get(selected) ?? null;

  // ─── Render del árbol ─────────────────────────────────────
  const renderNode = (node: TreeNode) => {
    const isLeaf = node.level === 'address';
    const open = expanded.has(node.path);
    const kids = children[node.path] ?? [];
    const busy = (loading[node.path] ?? 0) > 0;
    const canGrow = node.level === 'coin' || node.level === 'change';

    return (
      <div key={node.path} className="bt-branch">
        <div
          className={`bt-row bt-row--${node.level} ${selected === node.path ? 'selected' : ''}`}
          onClick={() => { setSelected(node.path); setShowPriv(false); }}
        >
          {isLeaf ? (
            <span className="bt-caret bt-caret--leaf">•</span>
          ) : (
            <button
              className="bt-caret"
              aria-label={open ? 'Plegar' : 'Desplegar'}
              onClick={e => { e.stopPropagation(); toggle(node); }}
            >
              {open ? '▾' : '▸'}
            </button>
          )}
          <span className={`bt-seg ${node.hardened ? 'bt-seg--hard' : ''}`}>{segmentOf(node.path)}</span>
          <span className="bt-label">{levelLabel(node)}</span>
          {node.hardened && <span className="bt-icon" title="Hardened: necesita la clave privada">🔒</span>}
          {isWatchOnlyDerivable(node) && <span className="bt-icon" title="Derivable desde la xpub">👁</span>}
          {node.level === 'account' && <span className="bt-badge">xpub</span>}
          {node.address && <code className="bt-addr">{shortStr(node.address, 12, 6)}</code>}
        </div>

        {open && !isLeaf && (
          <div className={`bt-children ${node.level === 'account' ? 'bt-children--watch' : ''}`}>
            {node.level === 'account' && (
              <div className="bt-watch-label">👁 zona watch-only — todo lo de aquí sale de la xpub de la cuenta</div>
            )}
            {kids.map(renderNode)}
            {busy && <div className="bt-loading"><span className="bt-spinner" /> derivando…</div>}
            {canGrow && !busy && kids.length > 0 && (
              <button className="bt-more" onClick={() => growMore(node)}>
                + {node.level === 'coin' ? 'otra cuenta' : `${ADDRESS_STEP} direcciones más`}
              </button>
            )}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="bt">
      <header className="bt-header">
        <span className="bt-phase-tag">Fase 4 · UI visual</span>
        <h1>Árbol de derivación BIP32</h1>
        <p className="bt-subtitle">
          Una seed no es <em>una</em> clave: es la raíz de un árbol con miles de millones de ramas.
          Despliega los nodos y mira cómo cada nivel sale del anterior con un HMAC-SHA512 — y dónde
          está la frontera que hace posible una wallet <strong>watch-only</strong>.
        </p>
      </header>

      {/* ─── Seed ─── */}
      <section className="bt-controls">
        <label className="bt-control bt-control--wide">
          <span className="bt-control-label">
            Mnemónico BIP39 {!valid && words.length > 0 && <strong className="bad">· no válido</strong>}
          </span>
          <textarea
            value={mnemonicInput}
            onChange={e => setMnemonicInput(e.target.value)}
            rows={2}
            spellCheck={false}
          />
        </label>
        <label className="bt-control">
          <span className="bt-control-label">Passphrase (opcional, «palabra 25»)</span>
          <input
            type="text"
            value={passphrase}
            onChange={e => setPassphrase(e.target.value)}
            placeholder="vacía"
            spellCheck={false}
          />
        </label>
        <div className="bt-control">
          <span className="bt-control-label">Red</span>
          <div className="bt-toggle">
            {(['mainnet', 'testnet'] as const).map(n => (
              <button key={n} className={network === n ? 'active' : ''} onClick={() => setNetwork(n)}>{n}</button>
            ))}
          </div>
        </div>
        <div className="bt-control bt-buttons">
          <button className="bt-btn" onClick={handleGenerate}>Generar nueva</button>
          <button className="bt-btn" onClick={() => { setMnemonicInput(TEST_MNEMONIC); setPassphrase(''); }}>
            Vector de prueba
          </button>
        </div>
      </section>

      <div className="bt-info">
        <strong>Prueba esto:</strong> escribe una sola letra en la passphrase y mira el fingerprint del
        master — cambia el árbol <em>entero</em>. Por eso una passphrase olvidada es irrecuperable, y por
        eso también sirve como «wallet señuelo». Con el vector de prueba (<code>abandon … about</code>)
        las direcciones coinciden con las de BIP84/86 y con Sparrow.
      </div>

      {seedStatus === 'deriving' && (
        <div className="bt-loading bt-loading--big">
          <span className="bt-spinner" /> PBKDF2-HMAC-SHA512 × 2048 iteraciones… (mnemónico → seed)
        </div>
      )}

      {root && (
        <div className="bt-layout">
          {/* ─── Árbol ─── */}
          <section className="bt-tree-panel">
            <div className="bt-legend">
              <span><span className="bt-seg bt-seg--hard">84'</span> hardened 🔒 necesita la privada</span>
              <span><span className="bt-seg">0</span> normal 👁 sale de la xpub</span>
            </div>
            <div className="bt-tree">{renderNode(root)}</div>
          </section>

          {/* ─── Detalle del nodo ─── */}
          <aside className="bt-detail">
            {!sel ? (
              <div className="bt-loading"><span className="bt-spinner" /> derivando {selected}…</div>
            ) : (
              <NodeDetail
                node={sel}
                root={root}
                mainnet={mainnet}
                showPriv={showPriv}
                onTogglePriv={() => setShowPriv(v => !v)}
                onSelect={p => { if (nodeByPath.has(p)) { setSelected(p); setShowPriv(false); } }}
                woCheck={woCheck?.path === sel.path ? woCheck.result : null}
                onWatchOnlyCheck={() => runWatchOnlyCheck(sel)}
              />
            )}
          </aside>
        </div>
      )}
    </div>
  );
}

// ─── Panel de detalle ──────────────────────────────────────

interface NodeDetailProps {
  node: TreeNode;
  root: TreeNode;
  mainnet: boolean;
  showPriv: boolean;
  onTogglePriv: () => void;
  onSelect: (path: string) => void;
  woCheck: WatchOnlyCheck | null;
  onWatchOnlyCheck: () => void;
}

function NodeDetail({ node, root, mainnet, showPriv, onTogglePriv, onSelect, woCheck, onWatchOnlyCheck }: NodeDetailProps) {
  const crumbs = ancestorPaths(node.path);
  const showXpub = node.depth <= 3;

  return (
    <div className="bt-detail-inner">
      <nav className="bt-crumbs">
        {crumbs.map((p, i) => (
          <span key={p}>
            {i > 0 && <span className="bt-crumb-sep">/</span>}
            <button className={`bt-crumb ${p === node.path ? 'active' : ''}`} onClick={() => onSelect(p)}>
              {segmentOf(p)}
            </button>
          </span>
        ))}
      </nav>

      <h2>{levelLabel(node)}</h2>
      <p className="bt-explain">{LEVEL_EXPLAIN[node.level]}</p>

      {/* Cómo se derivó */}
      <div className="bt-formula">
        {node.level === 'master' ? (
          <>
            <div>I = HMAC-SHA512(<span className="k">"Bitcoin seed"</span>, seed)</div>
            <div>k<sub>m</sub> = I<sub>L</sub> · chainCode = I<sub>R</sub></div>
          </>
        ) : (
          <>
            <div>
              I = HMAC-SHA512(chainCode<sub>padre</sub>,{' '}
              {node.hardened
                ? <><span className="hard">0x00 ‖ k<sub>padre</sub></span> ‖ i</>
                : <><span className="norm">K<sub>padre</sub></span> ‖ i</>})
            </div>
            <div>
              i = <code>{childNumberHex(node)}</code>
              {node.hardened && <> = {node.index} + 2³¹</>}
            </div>
            <div>k = I<sub>L</sub> + k<sub>padre</sub> (mod n) · chainCode = I<sub>R</sub></div>
            <p className="bt-formula-note">
              {node.hardened
                ? 'Hardened: el HMAC mete la clave PRIVADA del padre. Sin ella no hay forma de calcular este hijo.'
                : 'Normal: el HMAC sólo usa la clave PÚBLICA del padre y su chain code — justo lo que trae una xpub.'}
            </p>
          </>
        )}
      </div>

      <dl className="bt-fields">
        <dt>Profundidad</dt><dd>{node.depth}</dd>
        {node.level !== 'master' && <><dt>Fingerprint padre</dt><dd><code>{node.hd.parentFingerprint}</code></dd></>}
        <dt>Fingerprint</dt>
        <dd>
          <code>{node.fingerprint}</code>
          {node.level === 'master' && <span className="bt-hint"> ← el que ves en Sparrow y en los descriptores</span>}
        </dd>
        <dt>Chain code</dt><dd><code className="wrap">{chainCodeHex(node)}</code></dd>
        <dt>Clave pública</dt><dd><code className="wrap">{node.pubKeyHex}</code></dd>
        <dt>Clave privada</dt>
        <dd>
          {showPriv
            ? <code className="wrap bt-priv">{privateKeyHex(node)}</code>
            : <code className="bt-masked">••••••••••••••••</code>}
          <button className="bt-link" onClick={onTogglePriv}>{showPriv ? 'ocultar' : 'mostrar'}</button>
        </dd>
        {showXpub && (
          <>
            <dt>{mainnet ? 'xpub' : 'tpub'}</dt>
            <dd><code className="wrap">{xpubOf(node, mainnet)}</code></dd>
          </>
        )}
        {node.address && (
          <>
            <dt>Dirección</dt>
            <dd><code className="wrap bt-address">{node.address}</code></dd>
          </>
        )}
      </dl>

      {node.level === 'account' && (
        <div className="bt-callout bt-callout--watch">
          <strong>Ésta es la clave que exportas a una wallet watch-only.</strong> Su descriptor lo contiene
          todo: tipo de script, origen (fingerprint del master + ruta) y la xpub.
          <code className="wrap bt-descriptor">{accountDescriptor(node, root.fingerprint, mainnet)}</code>
          <span className="bt-hint">
            Sparrow muestra esta misma clave como{' '}
            <code>{node.purpose === 84 ? (mainnet ? 'zpub' : 'vpub') : (mainnet ? 'xpub' : 'tpub')}</code>
            {node.purpose === 84 && ' (la misma clave con otros 4 bytes de versión, SLIP-0132)'}.
          </span>
        </div>
      )}

      {node.depth > 0 && node.depth < 3 && (
        <div className="bt-callout bt-callout--hard">
          Compartir esta xpub sería mala idea: es un nivel por encima de la cuenta, así que expone
          todas las cuentas de la rama. Además, si se filtra una clave privada hija <em>no hardened</em> junto
          con la xpub del padre, se puede recalcular la privada del padre — por eso los niveles altos son hardened.
        </div>
      )}

      {isWatchOnlyDerivable(node) && (
        <div className="bt-callout bt-callout--watch">
          <div className="bt-wo-head">
            <span>¿Sale también desde la xpub de la cuenta, sin claves privadas?</span>
            <button className="bt-btn bt-btn--small" onClick={onWatchOnlyCheck}>Comprobar con CKDpub</button>
          </div>
          {woCheck && (
            <div className="bt-wo-result">
              <div className="bt-wo-route">
                {woCheck.route.map((r, i) => <span key={i} className="bt-seg">{r}</span>)}
              </div>
              <code className="wrap">{woCheck.pubKeyHex}</code>
              <strong className={woCheck.matches ? 'ok' : 'bad'}>
                {woCheck.matches
                  ? '✓ Idéntica a la clave derivada con la privada. K = (I_L + k)·G = I_L·G + K'
                  : '✗ No coincide'}
              </strong>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
