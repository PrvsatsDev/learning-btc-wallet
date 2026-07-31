/**
 * Multisig — Guía conceptual (Fase 2, junto a Script)
 *
 * El multisig es, ante todo, un patrón de Script, así que esta guía vive en la
 * Fase 2 (Primitivas). La herramienta INTERACTIVA de multisig (construir wallet,
 * pegar xpubs, firmar con PSBT) será parte de la Fase 4 (UI visual) — otra cosa.
 *
 * Esta sección NO firma ni construye transacciones multisig todavía: es la guía
 * visual para ENTENDER el terreno antes de tocarlo con fondos reales. Cubre los
 * esquemas m-of-n, los tres tipos de script (P2SH / P2WSH / Taproot), la anatomía
 * de un output descriptor, y —lo más importante— qué se guarda, dónde, y qué
 * puede vivir "online" y qué no.
 *
 * El gran mensaje: en multisig, sin el DESCRIPTOR no se recuperan fondos aunque
 * tengas las semillas. Ver [[project_fase4_multisig]] en memoria.
 */

import { useState } from 'react';
import './MultisigGuide.css';

// Esquemas m-of-n de ejemplo, de menor a mayor complejidad.
const SCHEMES = [
  {
    label: '2-of-2',
    m: 2,
    n: 2,
    tag: 'Sin margen de error',
    desc: 'Ambas firmas obligatorias. Wallet compartida (socios, pareja), canales Lightning. Perder una llave significa perder el acceso: no tolera fallos.',
  },
  {
    label: '2-of-3',
    m: 2,
    n: 3,
    tag: 'El más común',
    desc: 'Una llave + un segundo dispositivo + un backup (o servicio de rescate). Se puede perder 1 de las 3 llaves y seguir gastando. El punto dulce entre seguridad y resiliencia.',
    recommended: true,
  },
  {
    label: '3-of-5',
    m: 3,
    n: 5,
    tag: 'Tesorería / herencia',
    desc: 'Consejo, empresa o herencia repartida geográficamente. Tolera perder hasta 2 llaves. Más robusto, pero más piezas que custodiar y coordinar.',
  },
];

// Los tres "sabores" de script multisig, de más antiguo a más moderno.
// `badge`/`badgeKind` reflejan el recorrido de aprendizaje sugerido, no la calidad
// técnica: P2SH casi sin foco, P2WSH como escalón intermedio, Taproot como objetivo.
const SCRIPT_TYPES = [
  {
    name: 'P2SH (legacy)',
    addr: 'empieza por 3…',
    opcode: 'OP_CHECKMULTISIG',
    era: 'Pre-SegWit',
    pros: 'Compatible con todo, incluso software muy antiguo.',
    cons: 'Fees altos al gastar. El redeemScript va en el scriptSig.',
    badge: 'Casi sin foco',
    badgeKind: 'muted' as const,
  },
  {
    name: 'P2WSH (SegWit v0)',
    addr: 'bc1q… (largo, 32 bytes)',
    opcode: 'OP_CHECKMULTISIG',
    era: 'Estándar actual',
    pros: 'Fees más bajos, testigo separado. Evolución natural de P2WPKH.',
    cons: 'La dirección revela que es multisig al gastar.',
    badge: 'Escalón intermedio',
    badgeKind: 'secondary' as const,
  },
  {
    name: 'Taproot (SegWit v1)',
    addr: 'bc1p…',
    opcode: 'OP_CHECKSIGADD / MuSig2',
    era: 'Lo más nuevo',
    pros: 'Con MuSig2 parece single-sig: máxima privacidad y fees mínimos.',
    cons: 'Firma interactiva (MuSig2) o árbol de scripts. Más complejo de implementar.',
    badge: 'El objetivo',
    badgeKind: 'primary' as const,
    highlight: true,
  },
];

// Piezas de una wallet multisig y su régimen de custodia.
const STORAGE = [
  {
    piece: 'Semilla / mnemónico / xpriv',
    online: 'never',
    online_label: 'NUNCA online',
    who: 'Solo su dueño, offline (papel, metal, hardware). Con m semillas se roba.',
  },
  {
    piece: 'xpub de cada cosignatario',
    online: 'care',
    online_label: 'Técnicamente sí',
    who: 'No gasta, pero revela todo el historial y los saldos. Backup sí, publicar no.',
  },
  {
    piece: 'El descriptor completo',
    online: 'care',
    online_label: 'No gasta, pero…',
    who: 'Todos los cosignatarios deben tener copia. Es fuga de privacidad, no de fondos.',
  },
  {
    piece: 'PSBT (tx a medio firmar)',
    online: 'ok',
    online_label: 'Sí, sin problema',
    who: 'Se pasa entre firmantes por cualquier canal (email, USB, QR). Efímero.',
  },
];

export function MultisigGuide() {
  const [m, setM] = useState(2);
  const [n, setN] = useState(3);

  // El selector m-of-n mantiene m ≤ n de forma coherente.
  const setKeysTotal = (value: number) => {
    setN(value);
    if (m > value) setM(value);
  };

  const canLose = n - m;
  const pubkeys = Array.from({ length: n }, (_, i) => `<pk${i + 1}>`).join(' ');
  const descriptorKeys = Array.from({ length: n }, (_, i) => `  key${i + 1}`).join(',\n');

  return (
    <div className="mg">
      <header className="mg-header">
        <span className="mg-phase-tag">Fase 2 · Guía conceptual</span>
        <h1>Multisig</h1>
        <p className="mg-subtitle">
          Antes de custodiar fondos con varias llaves, hay que entender el terreno: qué esquemas
          existen, cómo se ven por dentro, qué es un <em>descriptor</em> y —sobre todo— qué se
          guarda, dónde, y qué puede vivir en internet y qué no.
        </p>
      </header>

      <div className="mg-note">
        <span className="mg-note-tag">ℹ️ Esta sección aún no firma</span>
        <p>
          Es una guía para <strong>consolidar el concepto</strong>. La implementación (ejecutar
          <code> OP_CHECKMULTISIG</code>, generar direcciones P2WSH, construir descriptores y
          firmar entre cosignatarios) llegará como pasos de código incrementales.
        </p>
      </div>

      {/* ─── Esquemas m-of-n ─────────────────────────────── */}
      <section className="mg-section">
        <h2>1 · El esquema base: <code>m-of-n</code></h2>
        <p className="mg-lead">
          Un multisig es una condición de gasto: <em>«hacen falta al menos <strong>m</strong>{' '}
          firmas de estas <strong>n</strong> llaves»</em>. Ninguna llave sola puede robar, y se
          pueden perder hasta <strong>n−m</strong> llaves sin perder los fondos.
        </p>
        <div className="mg-scheme-grid">
          {SCHEMES.map((s) => (
            <div key={s.label} className={`mg-scheme-card ${s.recommended ? 'mg-recommended' : ''}`}>
              {s.recommended && <span className="mg-badge">Recomendado</span>}
              <span className="mg-scheme-label">{s.label}</span>
              <span className="mg-scheme-tag">{s.tag}</span>
              <p>{s.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ─── Selector interactivo ────────────────────────── */}
      <section className="mg-section">
        <h2>2 · Pruébalo</h2>
        <p className="mg-lead">
          Ajusta cuántas firmas se exigen (<strong>m</strong>) y cuántas llaves hay en total
          (<strong>n</strong>) y observa cómo cambian el script y el descriptor.
        </p>

        <div className="mg-builder">
          <div className="mg-sliders">
            <label className="mg-slider">
              <span>Firmas requeridas · <strong>m = {m}</strong></span>
              <input
                type="range"
                min={1}
                max={n}
                value={m}
                onChange={(e) => setM(Number(e.target.value))}
              />
            </label>
            <label className="mg-slider">
              <span>Llaves totales · <strong>n = {n}</strong></span>
              <input
                type="range"
                min={2}
                max={7}
                value={n}
                onChange={(e) => setKeysTotal(Number(e.target.value))}
              />
            </label>
          </div>

          <div className="mg-builder-out">
            <div className="mg-resilience">
              <span className="mg-resilience-num">{m}-of-{n}</span>
              <span className="mg-resilience-text">
                {canLose === 0
                  ? 'Sin margen: perder una sola llave significa perder el acceso.'
                  : `Tolera perder hasta ${canLose} llave${canLose > 1 ? 's' : ''} y seguir gastando.`}
              </span>
            </div>

            <div className="mg-codeblock">
              <span className="mg-codeblock-label">witnessScript (P2WSH)</span>
              <code>
                OP_{m} {pubkeys} OP_{n} OP_CHECKMULTISIG
              </code>
            </div>

            <div className="mg-codeblock">
              <span className="mg-codeblock-label">output descriptor</span>
              <code>
                wsh(sortedmulti({m},{'\n'}{descriptorKeys}{'\n'}))
              </code>
            </div>
          </div>
        </div>

        <div className="mg-callout mg-callout-warn">
          <span className="mg-callout-tag">⚠️ El bug histórico de OP_CHECKMULTISIG</span>
          <p>
            <code>OP_CHECKMULTISIG</code> consume <strong>un elemento de más</strong> de la pila.
            Por eso toda firma multisig empieza con un elemento vacío basura (el <em>dummy</em>). No
            es un fallo: es de consenso, y hay que replicarlo cuando lo implementemos.
          </p>
        </div>
      </section>

      {/* ─── Tipos de script ─────────────────────────────── */}
      <section className="mg-section">
        <h2>3 · Los tres sabores de script</h2>
        <p className="mg-lead">
          El mismo <code>m-of-n</code> se puede envolver de tres formas según la época de Bitcoin.
          En Taproot, ojo: <code>OP_CHECKMULTISIG</code> está <strong>deshabilitado</strong> — se usa
          <code> OP_CHECKSIGADD</code> o agregación de claves con MuSig2.
        </p>
        <div className="mg-script-grid">
          {SCRIPT_TYPES.map((t) => (
            <div key={t.name} className={`mg-script-card ${t.highlight ? 'mg-recommended' : ''}`}>
              <span className={`mg-badge mg-badge-${t.badgeKind}`}>{t.badge}</span>
              <h3>{t.name}</h3>
              <span className="mg-script-addr">{t.addr}</span>
              <dl>
                <div><dt>Época</dt><dd>{t.era}</dd></div>
                <div><dt>Opcode</dt><dd><code>{t.opcode}</code></dd></div>
                <div><dt>A favor</dt><dd>{t.pros}</dd></div>
                <div><dt>En contra</dt><dd>{t.cons}</dd></div>
              </dl>
            </div>
          ))}
        </div>
      </section>

      {/* ─── Anatomía del descriptor ─────────────────────── */}
      <section className="mg-section">
        <h2>4 · Anatomía de un <em>descriptor</em></h2>
        <p className="mg-lead">
          El <strong>output descriptor</strong> es la receta completa y sin ambigüedades de la
          wallet: la política + todas las claves + de dónde salió cada una. Es la pieza que lo une
          todo.
        </p>

        <div className="mg-descriptor">
          <code>
            <span className="mg-d-func">wsh</span>(<span className="mg-d-func">sortedmulti</span>(
            <span className="mg-d-thresh">2</span>,{'\n'}
            {'  '}<span className="mg-d-origin">[1a2b3c4d/48h/0h/0h/2h]</span>
            <span className="mg-d-xpub">xpub6ABC…</span>
            <span className="mg-d-path">/&lt;0;1&gt;/*</span>,{'\n'}
            {'  '}<span className="mg-d-origin">[5e6f7a8b/48h/0h/0h/2h]</span>
            <span className="mg-d-xpub">xpub6DEF…</span>
            <span className="mg-d-path">/&lt;0;1&gt;/*</span>,{'\n'}
            {'  '}<span className="mg-d-origin">[9c0d1e2f/48h/0h/0h/2h]</span>
            <span className="mg-d-xpub">xpub6GHI…</span>
            <span className="mg-d-path">/&lt;0;1&gt;/*</span>{'\n'}
            ))<span className="mg-d-check">#checksum</span>
          </code>
        </div>

        <ul className="mg-legend">
          <li>
            <span className="mg-dot mg-d-func-bg" />
            <span className="mg-legend-text"><code>wsh / sortedmulti</code> — el envoltorio (P2WSH) y la política. <strong>sortedmulti</strong> (BIP67) ordena las claves solo, así el orden de los cosignatarios deja de importar para recuperar.</span>
          </li>
          <li>
            <span className="mg-dot mg-d-thresh-bg" />
            <span className="mg-legend-text"><code>2</code> — el umbral <strong>m</strong>: cuántas firmas hacen falta.</span>
          </li>
          <li>
            <span className="mg-dot mg-d-origin-bg" />
            <span className="mg-legend-text"><code>[fingerprint/48h/0h/0h/2h]</code> — el <strong>origen</strong>: huella del master (4 bytes) + ruta <strong>BIP48</strong> de multisig (<code>48'/coin'/account'/script_type'</code>; el último <code>2'</code> = P2WSH).</span>
          </li>
          <li>
            <span className="mg-dot mg-d-xpub-bg" />
            <span className="mg-legend-text"><code>xpub…</code> — la clave pública extendida de ese cosignatario.</span>
          </li>
          <li>
            <span className="mg-dot mg-d-path-bg" />
            <span className="mg-legend-text"><code>/&lt;0;1&gt;/*</code> — recepción (0) y cambio (1); el <code>*</code> recorre los índices.</span>
          </li>
          <li>
            <span className="mg-dot mg-d-check-bg" />
            <span className="mg-legend-text"><code>#checksum</code> — 8 caracteres que detectan si el descriptor se ha copiado mal.</span>
          </li>
        </ul>
      </section>

      {/* ─── Qué guardar y dónde ─────────────────────────── */}
      <section className="mg-section">
        <h2>5 · Qué guardar y qué NO — online vs offline</h2>
        <p className="mg-lead">
          La regla mental: una cosa es <strong>lo secreto que gasta</strong>, otra es{' '}
          <strong>lo necesario para recuperar</strong>. No son lo mismo.
        </p>
        <div className="mg-storage">
          {STORAGE.map((row) => (
            <div key={row.piece} className={`mg-storage-row mg-storage-${row.online}`}>
              <span className="mg-storage-piece">{row.piece}</span>
              <span className={`mg-storage-badge mg-badge-${row.online}`}>{row.online_label}</span>
              <span className="mg-storage-who">{row.who}</span>
            </div>
          ))}
        </div>
      </section>

      {/* ─── El gran gotcha ──────────────────────────────── */}
      <section className="mg-section">
        <div className="mg-callout mg-callout-danger">
          <span className="mg-callout-tag">⚠️ El gran <em>gotcha</em>: sin el descriptor NO recuperas</span>
          <p>
            En single-sig, una sola semilla lo recupera todo. <strong>En multisig, no.</strong> Para
            reconstruir un 2-of-3 hacen falta <strong>una semilla + las otras 2 xpubs + la política</strong>
            — es decir, el <strong>descriptor completo</strong>. Si las 3 semillas se reparten por el
            mundo pero nadie guardó el descriptor, los fondos quedan <strong>inaccesibles</strong>{' '}
            aun teniendo llaves de sobra.
          </p>
          <p className="mg-golden">
            Regla de oro: cada cosignatario guarda <strong>(1) su propia semilla</strong> — secreta —
            y <strong>(2) una copia del descriptor completo</strong>. El descriptor puede ir en claro
            junto a la semilla (no gasta), aunque algunos lo cifran por privacidad. Formatos habituales:
            BSMS (BIP129), el fichero de config de Coldcard, el export de Sparrow.
          </p>
        </div>
      </section>

      {/* ─── Próximo paso ────────────────────────────────── */}
      <section className="mg-section mg-next">
        <h2>Próximo paso</h2>
        <p>
          El destino es <strong>Taproot</strong> (MuSig2 / <code>OP_CHECKSIGADD</code>): el esquema
          más privado y moderno. Pero el primer código será el escalón intermedio en{' '}
          <code>script.ts</code>: <code>OP_CHECKMULTISIG</code> (con su <em>dummy</em>) y{' '}
          <code>createP2WSH</code>, para <strong>ver</strong> la pila de un multisig ejecutándose,
          igual que en el explorador de Script. Con esa mecánica clara, saltar a la agregación de
          claves de Taproot cuesta mucho menos. A P2SH legacy apenas se le dedica tiempo.
        </p>
      </section>
    </div>
  );
}
