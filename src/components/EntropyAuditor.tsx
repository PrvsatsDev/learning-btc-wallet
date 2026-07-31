/**
 * Entropy Auditor — Fase 3, herramienta de seguridad
 *
 * A raíz del caso ColdCard (2026): semillas generadas con ~72 bits de entropía
 * en vez de 128. Esta herramienta permite reconstruir a mano/offline los bits
 * crudos de un mnemónico y aplicar tests "a ojo" de aleatoriedad.
 *
 * Lo importante es el matiz conceptual (ver el aviso amarillo): la entropía es
 * una propiedad del GENERADOR, no de una semilla concreta. Esto detecta
 * defectos groseros, no certifica seguridad.
 */

import { useState, useMemo, useEffect } from 'react';
import {
  parseMnemonic,
  auditMnemonic,
  type CheckStatus,
} from '../crypto/entropy-audit';
import './EntropyAuditor.css';

const STATUS_ICON: Record<CheckStatus, string> = {
  ok: '✓',
  warn: '!',
  alert: '✕',
};

// Ejemplos para probar la herramienta sin generar ni teclear. Ambos tienen checksum
// BIP39 válido; la diferencia está en la entropía (verificados con auditMnemonic).
const EXAMPLE_OK = 'school useless aware lunar mesh walnut resist pair name debate fame area';
const EXAMPLE_ALERT =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const VERDICT_TEXT: Record<CheckStatus, { title: string; body: string }> = {
  ok: {
    title: 'Sin patrones sospechosos',
    body:
      'Los tests no detectan ninguna estructura obvia. Ojo: esto NO certifica ' +
      'buena entropía — solo significa que no se ve ningún defecto grosero. Una ' +
      'semilla débil tipo ColdCard (bytes de aspecto aleatorio pero de un espacio ' +
      'reducido) pasaría estos tests igualmente.',
  },
  warn: {
    title: 'Alguna señal a revisar',
    body:
      'Uno o más tests están fuera de lo esperado. Con tan pocos bytes, una fuente ' +
      'sana también fluctúa, así que un aviso aislado no prueba nada. Míralo con ' +
      'contexto.',
  },
  alert: {
    title: 'Patrón claro detectado',
    body:
      'Se ha encontrado una estructura que una fuente aleatoria sana casi nunca ' +
      'produce (constantes, mitades repetidas, sesgo extremo…). Trata esta semilla ' +
      'como potencialmente comprometida.',
  },
};

export function EntropyAuditor() {
  const [input, setInput] = useState('');
  const [debouncedInput, setDebouncedInput] = useState('');

  // Debounce: reconstruir bits + SHA-256 del checksum es cálculo pesado
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedInput(input), 400);
    return () => clearTimeout(timer);
  }, [input]);

  const parse = useMemo(() => parseMnemonic(debouncedInput), [debouncedInput]);
  const audit = useMemo(
    () => (parse.valid ? auditMnemonic(parse.words) : null),
    [parse],
  );

  return (
    <div className="entropy-auditor">
      <div className="ea-header">
        <h1>Entropy Auditor</h1>
        <p className="ea-subtitle">
          Reconstruye los bits crudos de un mnemónico y aplica tests de aleatoriedad
          "a ojo". Inspirado en el caso ColdCard (2026), donde semillas se generaron
          con ~72 bits de entropía en vez de 128. Todo el cálculo es local — nada sale
          de esta máquina.
        </p>
      </div>

      {/* Descargo de responsabilidad */}
      <div className="ea-disclaimer">
        <span className="ea-disclaimer-tag">⚠️ Herramienta de aprendizaje — sin garantías</span>
        <p>
          Proyecto de aprendizaje, publicado <strong>"tal cual"</strong>, sin garantía de
          ningún tipo y con criptografía no auditada para producción. El autor{' '}
          <strong>no se hace responsable</strong> de ninguna pérdida o daño derivado de su uso.
          Su fin es <strong>entender</strong> cómo se verifica una semilla, no operar en producción.
        </p>
        <p>
          <strong>Nunca introduzcas una seed que custodie fondos reales en un dispositivo
          conectado a internet.</strong> Si aun así te aventuras a usarla con palabras reales,
          tómala <strong>solo como inspiración</strong> para tu propia solución; y si de todos
          modos vas a hacerlo, al menos <strong>audita el código</strong>,{' '}
          <strong>clónalo</strong> y <strong>ejecútalo en un equipo desconectado</strong>{' '}
          (air-gapped). Al usarlo aceptas hacerlo bajo tu entera responsabilidad.
        </p>
      </div>

      {/* Aviso conceptual — la parte más importante */}
      <div className="ea-concept">
        <span className="ea-concept-tag">Antes de empezar — entiende esto</span>
        <p>
          La entropía es una propiedad del <strong>proceso que generó</strong> la
          semilla, no de la semilla en sí. Un valor de 128 bits es idéntico venga de
          un RNG perfecto o de uno roto. Por eso <strong>ningún análisis de una sola
          semilla puede medir cuántos bits de entropía tenía el generador</strong>.
        </p>
        <ul>
          <li>
            <strong>Sí</strong> detecta defectos groseros: patrones fijos, mitades
            repetidas, sesgo extremo — la "firma" que un generador roto podría dejar.
          </li>
          <li>
            <strong>No</strong> certifica seguridad: pasar todos los tests solo
            significa "no se ve nada raro". La reducción sutil tipo ColdCard (72 bits
            con bytes de aspecto aleatorio) <strong>no</strong> es detectable así.
          </li>
        </ul>
      </div>

      {/* Explicación general del caso ColdCard (siempre visible) */}
      <div className="ea-section ea-coldcard">
        <span className="ea-label">El caso ColdCard, y qué puede (y no puede) ver esta herramienta</span>
        <p className="ea-desc">
          Coinkite publicó el mecanismo: un <strong>fallback silencioso a un PRNG
          software</strong>. En marzo de 2021, al migrar a libNgU, el código que debía
          usar el TRNG hardware (<code>ckcc.rng_bytes()</code>) resolvió por error al
          PRNG de MicroPython (<code>ngu.random.bytes()</code>); una guarda de
          preprocesador mal escrita hizo que el <code>#error</code> que debía abortar la
          compilación nunca saltara. Resultado: espacio efectivo de <strong>~40 bits</strong>{' '}
          en Mk3 y <strong>~72 bits</strong> en Mk4/Q/Mk5 (corregido en Mk4/Mk5 v5.6.0 y
          Q v1.5.0Q).
        </p>

        <p className="ea-desc">
          Para entender por qué no se detecta, recuerda la cadena BIP39: la{' '}
          <strong>entropía</strong> (los bits crudos del RNG) se <em>reescribe</em> como{' '}
          <strong>palabras</strong> — las palabras no añaden azar, son la misma entropía
          en otro formato — y de las palabras sale la <strong>semilla</strong> de 512 bits
          (PBKDF2) de la que cuelgan las claves. El bug estaba en el <strong>primer
          eslabón</strong>, la entropía; todo lo demás es determinista y hereda el defecto.
        </p>

        <div className="ea-distinction">
          <div className="ea-dist-item">
            <span className="ea-dist-head ea-dist-head--ok">Sesgo</span>
            <p>
              Unos valores más probables que otros (p. ej. bits pegados a 0). Deja rastro
              estadístico en los bytes → <strong>esto sí lo cazan los tests de esta herramienta</strong>.
            </p>
          </div>
          <div className="ea-dist-item">
            <span className="ea-dist-head ea-dist-head--bad">Espacio reducido — ColdCard</span>
            <p>
              El aparato solo podía producir un <strong>conjunto pequeño</strong> de
              semillas (~2⁷²), pero cada una es de aspecto normal, con palabras repartidas
              por todo el rango 0–2047. <strong>No deja rastro en una sola muestra.</strong>
            </p>
          </div>
        </div>

        <p className="ea-desc">
          Es decir: una semilla de ColdCard es indistinguible de una buena porque el
          defecto no vive en los bytes de <em>tu</em> semilla, sino en el{' '}
          <strong>catálogo de semillas que el aparato podía crear</strong>. Un atacante que
          conoce el PRNG enumera las ~2⁷² alcanzables y las prueba contra la blockchain.
          Solo un análisis forense (reconstruir el PRNG + fuerza bruta) lo detecta — nunca
          la inspección de una semilla.
        </p>

        <p className="ea-desc">
          <strong>Entonces, ¿para qué sirve este auditor?</strong> Para las <em>otras</em>{' '}
          deficiencias de una semilla — las que un RNG roto <strong>sí</strong> imprime en
          los bytes: bits pegados, sesgo, rellenos constantes, mitades duplicadas, baja
          diversidad de bytes. Esos defectos dejan firma y son justo lo que detectan los
          tests al introducir una semilla abajo. ColdCard es el caso que se escapa, no el
          único fallo posible.
        </p>

        <p className="ea-desc">
          Mitigación universal para cualquier RNG dudoso:{' '}
          <strong>añadir entropía propia por fuera</strong> del dispositivo (passphrase
          BIP39 fuerte, o generar la semilla con 50+ tiradas de dados, o{' '}
          <a
            className="ea-link"
            href="https://estudiobitcoin.com/como-calcular-tu-semilla-100-offline/"
            target="_blank"
            rel="noreferrer noopener"
          >
            con una moneda
          </a>).
        </p>
      </div>

      {/* Entrada */}
      <div className="ea-section">
        <span className="ea-label">Introduce el mnemónico</span>
        <p className="ea-desc">
          12, 15, 18, 21 o 24 palabras separadas por espacios. Para un análisis de
          verdad hazlo en una máquina offline / de aire — nunca teclees en un
          dispositivo conectado una semilla que custodie fondos reales.
        </p>
        <textarea
          className="ea-input"
          rows={3}
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
          spellCheck={false}
          autoComplete="off"
        />
        {parse.error && <div className="ea-error">{parse.error}</div>}

        <div className="ea-examples">
          <span className="ea-examples-label">
            ¿Sin semilla a mano? Prueba con un ejemplo (los dos tienen checksum válido; cambia
            la entropía):
          </span>
          <div className="ea-example-btns">
            <button
              type="button"
              className="ea-example-btn ok"
              onClick={() => setInput(EXAMPLE_OK)}
            >
              ✓ Ejemplo que audita OK
            </button>
            <button
              type="button"
              className="ea-example-btn alert"
              onClick={() => setInput(EXAMPLE_ALERT)}
            >
              ✕ Ejemplo con alertas
            </button>
          </div>
        </div>
      </div>

      {audit && (
        <>
          {/* Checksum */}
          <div className="ea-section">
            <span className="ea-label">1 · Checksum BIP39</span>
            <p className="ea-desc">
              Los últimos {audit.decode.checksumBits.length} bits de las palabras son
              un checksum: los primeros bits de <code>SHA-256(entropía)</code>.
              Lo recalculamos con el SHA-256 de la Fase 1.
            </p>
            <div className={`ea-checksum ${audit.decode.checksumValid ? 'valid' : 'invalid'}`}>
              <span className="ea-checksum-icon">
                {audit.decode.checksumValid ? '✓' : '✕'}
              </span>
              <div>
                <strong>
                  {audit.decode.checksumValid ? 'Checksum correcto' : 'Checksum INCORRECTO'}
                </strong>
                <div className="ea-checksum-detail">
                  leído de las palabras: <code>{audit.decode.checksumBits}</code>
                  {' · '}esperado: <code>{audit.decode.expectedChecksum}</code>
                </div>
                {!audit.decode.checksumValid && (
                  <div className="ea-checksum-note">
                    Alguna palabra está mal o fuera de orden. La entropía de abajo no es fiable.
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Entropía reconstruida */}
          <div className="ea-section">
            <span className="ea-label">
              2 · Entropía cruda ({audit.decode.entropy.length * 8} bits)
            </span>
            <p className="ea-desc">
              Cada palabra → su índice (0–2047) → 11 bits. Concatenados y quitando el
              checksum, estos son los bytes que tu generador produjo. Es exactamente lo
              que obtendrías a mano con la hoja BIP39.
            </p>
            <div className="ea-hex">{formatHex(audit.decode.entropyHex)}</div>
            <details className="ea-bits-details">
              <summary>Ver los {audit.decode.allBits.length} bits e índices de palabra</summary>
              <div className="ea-indices">
                {audit.decode.words.map((w, i) => (
                  <div key={i} className="ea-index-row">
                    <span className="ea-idx-num">{i + 1}.</span>
                    <span className="ea-idx-word">{w}</span>
                    <span className="ea-idx-val">#{audit.decode.wordIndices[i]}</span>
                    <span className="ea-idx-bits">
                      {audit.decode.wordIndices[i].toString(2).padStart(11, '0')}
                    </span>
                  </div>
                ))}
              </div>
            </details>
          </div>

          {/* Tests de aleatoriedad */}
          <div className="ea-section">
            <span className="ea-label">3 · Tests de aleatoriedad "a ojo"</span>
            <p className="ea-desc">
              Cada test busca una clase de defecto que un generador roto podría dejar.
              Con tan pocos bytes hay fluctuación natural, así que los umbrales son
              laxos: <span className="ea-chip warn">!</span> = mirar,
              {' '}<span className="ea-chip alert">✕</span> = patrón claro.
            </p>
            <div className="ea-checks">
              {audit.checks.map((c, i) => (
                <div key={i} className={`ea-check ${c.status}`}>
                  <span className={`ea-check-icon ${c.status}`}>{STATUS_ICON[c.status]}</span>
                  <div className="ea-check-body">
                    <div className="ea-check-name">{c.name}</div>
                    <div className="ea-check-obs">{c.observed}</div>
                    <div className="ea-check-exp">esperado: {c.expected}</div>
                    <div className="ea-check-explain">{c.explanation}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Veredicto */}
          <div className={`ea-verdict ${audit.worst}`}>
            <span className="ea-verdict-icon">{STATUS_ICON[audit.worst]}</span>
            <div>
              <strong>{VERDICT_TEXT[audit.worst].title}</strong>
              <p>{VERDICT_TEXT[audit.worst].body}</p>
            </div>
          </div>

        </>
      )}
    </div>
  );
}

/** Agrupa el hex en bloques de 8 para lectura cómoda. */
function formatHex(hex: string): string {
  return (hex.match(/.{1,8}/g) ?? []).join(' ');
}
