import { useState } from 'react';
import { Sha256Explorer } from './components/Sha256Explorer';
import { Ripemd160Explorer } from './components/Ripemd160Explorer';
import { Secp256k1Explorer } from './components/Secp256k1Explorer';
import { AddressExplorer } from './components/AddressExplorer';
import { EcdsaExplorer } from './components/EcdsaExplorer';
import { SchnorrExplorer } from './components/SchnorrExplorer';
import { UtxoExplorer } from './components/UtxoExplorer';
import { TransactionExplorer } from './components/TransactionExplorer';
import { ScriptExplorer } from './components/ScriptExplorer';
import { HdWalletExplorer } from './components/HdWalletExplorer';
import { WalletSetup } from './components/WalletSetup';
import { BalanceChecker } from './components/BalanceChecker';
import { TxBuilder } from './components/TxBuilder';
import { EntropyAuditor } from './components/EntropyAuditor';
import { MultisigGuide } from './components/MultisigGuide';
import { MultisigExplorer } from './components/MultisigExplorer';
import { PsbtExplorer } from './components/PsbtExplorer';
import { TaprootMultisigExplorer } from './components/TaprootMultisigExplorer';
import { BipReference } from './components/BipReference';
import { DisclaimerBanner } from './components/DisclaimerBanner';
import './App.css';

type LessonId =
  | 'sha256' | 'ripemd160' | 'secp256k1' | 'address'
  | 'ecdsa' | 'schnorr' | 'utxo' | 'transaction' | 'scripts' | 'hdwallet'
  | 'wallet-setup' | 'balance' | 'tx-builder' | 'entropy-audit'
  | 'multisig-guide' | 'multisig-explorer' | 'psbt-explorer' | 'taproot-multisig'
  | 'bip-reference';

interface Phase {
  id: string;
  label: string;
  lessons: { id: LessonId; label: string; component: React.FC }[];
}

const phases: Phase[] = [
  {
    id: 'phase1',
    label: 'Fase 1: Criptografía',
    lessons: [
      { id: 'sha256', label: 'SHA-256', component: Sha256Explorer },
      { id: 'ripemd160', label: 'RIPEMD-160', component: Ripemd160Explorer },
      { id: 'secp256k1', label: 'secp256k1', component: Secp256k1Explorer },
      { id: 'address', label: 'Dirección', component: AddressExplorer },
    ],
  },
  {
    id: 'phase2',
    label: 'Fase 2: Primitivas Bitcoin',
    lessons: [
      { id: 'ecdsa', label: 'ECDSA', component: EcdsaExplorer },
      { id: 'schnorr', label: 'Schnorr', component: SchnorrExplorer },
      { id: 'utxo', label: 'UTXOs', component: UtxoExplorer },
      { id: 'transaction', label: 'Transacciones', component: TransactionExplorer },
      { id: 'scripts', label: 'Script', component: ScriptExplorer },
      { id: 'hdwallet', label: 'HD Wallets', component: HdWalletExplorer },
      { id: 'multisig-guide', label: 'Multisig (guía)', component: MultisigGuide },
    ],
  },
  {
    id: 'phase3',
    label: 'Fase 3: Wallet',
    lessons: [
      { id: 'wallet-setup', label: 'Seed Manager', component: WalletSetup },
      { id: 'balance', label: 'Balance', component: BalanceChecker },
      { id: 'tx-builder', label: 'Transacción', component: TxBuilder },
      { id: 'entropy-audit', label: 'Entropy Auditor', component: EntropyAuditor },
    ],
  },
  {
    id: 'phase4',
    label: 'Fase 4: UI visual',
    lessons: [
      { id: 'multisig-explorer', label: 'Multisig Explorer', component: MultisigExplorer },
      { id: 'psbt-explorer', label: 'PSBT Explorer', component: PsbtExplorer },
      { id: 'taproot-multisig', label: 'Taproot Multisig', component: TaprootMultisigExplorer },
    ],
  },
  {
    id: 'reference',
    label: 'Referencia',
    lessons: [
      { id: 'bip-reference', label: 'BIPs usados', component: BipReference },
    ],
  },
];

function App() {
  const [activeLesson, setActiveLesson] = useState<LessonId>('sha256');
  const [menuOpen, setMenuOpen] = useState(false);

  const allLessons = phases.flatMap(p => p.lessons);
  const ActiveComponent = allLessons.find(l => l.id === activeLesson)!.component;
  const activeLessonLabel = allLessons.find(l => l.id === activeLesson)!.label;

  return (
    <div className="app">
      <DisclaimerBanner />

      <div className="app-shell">
        {/* Barra lateral vertical — sidebar fija en escritorio, drawer en móvil */}
        <aside className={`app-sidebar ${menuOpen ? 'app-sidebar--open' : ''}`}>
          <div className="sidebar-head">
            <span className="nav-brand">BTC Wallet</span>
            <button
              className="sidebar-close"
              onClick={() => setMenuOpen(false)}
              aria-label="Cerrar menú"
            >
              ✕
            </button>
          </div>
          <nav className="sidebar-nav">
            {phases.map((phase) => (
              <div key={phase.id} className="nav-phase-group">
                <span className="nav-phase">{phase.label}</span>
                <div className="nav-lessons">
                  {phase.lessons.map((lesson) => (
                    <button
                      key={lesson.id}
                      className={`nav-btn ${activeLesson === lesson.id ? 'active' : ''}`}
                      onClick={() => {
                        setActiveLesson(lesson.id);
                        setMenuOpen(false);
                      }}
                    >
                      {lesson.label}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </nav>
        </aside>

        {/* Telón para cerrar el drawer al tocar fuera (solo móvil) */}
        {menuOpen && (
          <div className="sidebar-backdrop" onClick={() => setMenuOpen(false)} />
        )}

        <div className="app-main">
          {/* Barra superior — solo visible en móvil */}
          <div className="app-topbar">
            <button
              className="nav-hamburger"
              onClick={() => setMenuOpen(true)}
              aria-label="Abrir menú"
            >
              <span className="hamburger-icon" />
            </button>
            <span className="nav-brand">BTC Wallet</span>
            <span className="nav-current-label">{activeLessonLabel}</span>
          </div>

          <ActiveComponent />

          <footer className="app-footer">
            <span>Proyecto educativo de código abierto (MIT) ·</span>
            <a
              href="https://github.com/PrvsatsDev/learning-btc-wallet"
              target="_blank"
              rel="noreferrer noopener"
            >
              Ver, clonar o auditar en GitHub
            </a>
          </footer>
        </div>
      </div>
    </div>
  );
}

export default App;
