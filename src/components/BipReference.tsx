/**
 * BIP Reference — Referencia general
 *
 * Un índice de todos los BIPs (Bitcoin Improvement Proposals) que aparecen en
 * el código de la app, con una frase de qué es cada uno y un enlace al texto
 * oficial. No es interactivo: es el mapa para orientarse entre las siglas que
 * van apareciendo en cada lección.
 *
 * La lista está sacada de los BIPs realmente referenciados en src/ — si añades
 * un BIP nuevo en el código, añádelo también aquí para que el mapa siga fiel.
 */

import './BipReference.css';

interface Bip {
  num: number;
  name: string;
  desc: string;
  /** Dónde se toca en la app (chip informativo) */
  where?: string;
}

interface BipGroup {
  label: string;
  intro: string;
  bips: Bip[];
}

// Agrupados por tema, en el orden en que aparecen a lo largo de las fases.
const GROUPS: BipGroup[] = [
  {
    label: 'HD Wallets y derivación',
    intro: 'Cómo una sola seed se convierte en un árbol infinito de claves y direcciones.',
    bips: [
      { num: 32, name: 'HD Wallets', desc: 'Deriva un árbol jerárquico de claves a partir de una única seed (m/…).', where: 'HD Wallets' },
      { num: 39, name: 'Mnemonic seed phrase', desc: 'Convierte entropía en 12/24 palabras y, junto a un passphrase opcional (la "25ª palabra"), las transforma en la seed vía PBKDF2.', where: 'Seed Manager' },
      { num: 44, name: 'Multi-Account Hierarchy', desc: 'Estructura estándar de la ruta: m/purpose\'/coin\'/account\'/change/index.', where: 'toda la wallet' },
      { num: 48, name: 'Derivación para multisig', desc: 'Rutas m/48\'/coin\'/account\'/script_type\' para las claves de un multisig.', where: 'Multisig' },
      { num: 84, name: 'P2WPKH nativo', desc: 'Ruta m/84\' para direcciones SegWit v0 (bc1q…), lo que usa la wallet.', where: 'Seed Manager' },
      { num: 86, name: 'P2TR (Taproot)', desc: 'Ruta m/86\' para direcciones Taproot key-path (bc1p…).', where: 'HD Wallets' },
    ],
  },
  {
    label: 'Firmas',
    intro: 'Las dos formas de demostrar que controlas una clave sin revelarla.',
    bips: [
      { num: 340, name: 'Firmas Schnorr', desc: 'Esquema de firma sobre secp256k1 que habilita Taproot (más simple que ECDSA).', where: 'Schnorr' },
      { num: 62, name: 'Maleabilidad (low-s)', desc: 'Mitiga la maleabilidad de las firmas; de aquí sale la regla low-s al normalizar s.', where: 'ECDSA' },
    ],
  },
  {
    label: 'SegWit y transacciones',
    intro: 'El testigo separado del cuerpo de la transacción, y las reglas de gasto.',
    bips: [
      { num: 141, name: 'Segregated Witness', desc: 'Separa las firmas (witness) del cuerpo de la tx; arregla la maleabilidad del txid.', where: 'Transacciones' },
      { num: 143, name: 'Sighash SegWit v0', desc: 'Nuevo algoritmo de firma que incluye el valor del input (evita ataques de fee).', where: 'Transacción' },
      { num: 173, name: 'Bech32', desc: 'Codificación de direcciones SegWit v0 (bc1q…), con checksum robusto.', where: 'Dirección' },
      { num: 350, name: 'Bech32m', desc: 'Variante de Bech32 para SegWit v1+ / Taproot (bc1p…).', where: 'Dirección' },
      { num: 125, name: 'Replace-By-Fee (RBF)', desc: 'Reemplaza una tx sin confirmar por otra con más fee (nSequence 0xfffffffd).', where: 'Transacción' },
      { num: 68, name: 'Timelocks relativos', desc: 'Bloquea el gasto hasta que pase un tiempo/altura relativo, vía nSequence.', where: 'Sighash Taproot' },
    ],
  },
  {
    label: 'Taproot',
    intro: 'SegWit v1: un mismo output se gasta por clave o por script, indistinguible.',
    bips: [
      { num: 341, name: 'Taproot', desc: 'SegWit v1: gasto por key-path o script-path, con su propio sighash.', where: 'Sighash Taproot' },
      { num: 342, name: 'Tapscript', desc: 'El lenguaje de script dentro de Taproot; usa OP_CHECKSIGADD en vez de OP_CHECKMULTISIG.', where: 'Taproot Multisig' },
      { num: 371, name: 'Campos Taproot en PSBT', desc: 'Extiende el PSBT con los datos necesarios para firmar inputs Taproot.', where: 'PSBT Explorer' },
    ],
  },
  {
    label: 'PSBT, descriptores y multisig',
    intro: 'Cómo se coordinan varias partes para describir y firmar una wallet compartida.',
    bips: [
      { num: 174, name: 'PSBT', desc: 'Sobre para firmar una tx entre varias partes sin exponer claves privadas.', where: 'PSBT Explorer' },
      { num: 380, name: 'Output Descriptors', desc: 'Describen exactamente qué scripts y claves controla una wallet (con checksum).', where: 'Multisig' },
      { num: 387, name: 'multi_a / sortedmulti_a', desc: 'El fragmento multisig de Tapscript: monta la hoja de script m-de-n en Taproot.', where: 'Taproot Multisig' },
      { num: 67, name: 'Orden de pubkeys', desc: 'Ordena lexicográficamente las claves en un multisig (sortedmulti) para que sea determinista.', where: 'Multisig' },
      { num: 129, name: 'Bitcoin Secure Multisig Setup', desc: 'Proceso estándar (BSMS) para montar una wallet multisig entre dispositivos sin confiar en el canal.', where: 'Multisig (guía)' },
    ],
  },
];

const TOTAL = GROUPS.reduce((n, g) => n + g.bips.length, 0);

function bipUrl(num: number): string {
  const padded = String(num).padStart(4, '0');
  return `https://github.com/bitcoin/bips/blob/master/bip-${padded}.mediawiki`;
}

export function BipReference() {
  return (
    <div className="bipref">
      <header className="bipref-header">
        <span className="bipref-phase-tag">Referencia</span>
        <h1>BIPs usados en la app</h1>
        <p className="bipref-subtitle">
          Un <strong>BIP</strong> (Bitcoin Improvement Proposal) es el documento
          donde se estandariza cada pieza del protocolo. A lo largo de las lecciones
          van apareciendo por número — aquí tienes los {TOTAL} que toca esta app,
          agrupados por tema, con una frase de qué es cada uno y enlace al texto oficial.
        </p>
      </header>

      {GROUPS.map((group) => (
        <section key={group.label} className="bipref-group">
          <span className="bipref-group-label">{group.label}</span>
          <p className="bipref-group-intro">{group.intro}</p>

          <div className="bipref-list">
            {group.bips.map((bip) => (
              <a
                key={bip.num}
                className="bipref-card"
                href={bipUrl(bip.num)}
                target="_blank"
                rel="noreferrer noopener"
              >
                <span className="bipref-num">BIP{bip.num}</span>
                <div className="bipref-body">
                  <div className="bipref-name-row">
                    <span className="bipref-name">{bip.name}</span>
                    {bip.where && <span className="bipref-where">{bip.where}</span>}
                  </div>
                  <p className="bipref-desc">{bip.desc}</p>
                </div>
              </a>
            ))}
          </div>
        </section>
      ))}

      <p className="bipref-footnote">
        Los enlaces apuntan al repositorio oficial{' '}
        <a href="https://github.com/bitcoin/bips" target="_blank" rel="noreferrer noopener">
          bitcoin/bips
        </a>
        . Un BIP no es ley: describe una propuesta que la red adopta (o no) por consenso.
      </p>
    </div>
  );
}
