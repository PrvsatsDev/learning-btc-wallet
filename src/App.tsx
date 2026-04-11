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
import './App.css';

type LessonId =
  | 'sha256' | 'ripemd160' | 'secp256k1' | 'address'
  | 'ecdsa' | 'schnorr' | 'utxo' | 'transaction' | 'scripts' | 'hdwallet';

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
    ],
  },
];

function App() {
  const [activeLesson, setActiveLesson] = useState<LessonId>('sha256');

  const allLessons = phases.flatMap(p => p.lessons);
  const ActiveComponent = allLessons.find(l => l.id === activeLesson)!.component;

  return (
    <div className="app">
      <nav className="app-nav">
        <span className="nav-brand">BTC Wallet</span>
        <div className="nav-phases">
          {phases.map((phase) => (
            <div key={phase.id} className="nav-phase-group">
              <span className="nav-phase">{phase.label}</span>
              <div className="nav-lessons">
                {phase.lessons.map((lesson) => (
                  <button
                    key={lesson.id}
                    className={`nav-btn ${activeLesson === lesson.id ? 'active' : ''}`}
                    onClick={() => setActiveLesson(lesson.id)}
                  >
                    {lesson.label}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      </nav>
      <ActiveComponent />
    </div>
  );
}

export default App;
