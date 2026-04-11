import { useState } from 'react';
import { Sha256Explorer } from './components/Sha256Explorer';
import { Ripemd160Explorer } from './components/Ripemd160Explorer';
import './App.css';

type LessonId = 'sha256' | 'ripemd160';

const lessons: { id: LessonId; label: string; component: React.FC }[] = [
  { id: 'sha256', label: 'SHA-256', component: Sha256Explorer },
  { id: 'ripemd160', label: 'RIPEMD-160', component: Ripemd160Explorer },
];

function App() {
  const [activeLesson, setActiveLesson] = useState<LessonId>('sha256');
  const ActiveComponent = lessons.find(l => l.id === activeLesson)!.component;

  return (
    <div className="app">
      <nav className="app-nav">
        <span className="nav-brand">BTC Wallet</span>
        <span className="nav-separator">|</span>
        <span className="nav-phase">Fase 1: Criptografía</span>
        <div className="nav-lessons">
          {lessons.map((lesson) => (
            <button
              key={lesson.id}
              className={`nav-btn ${activeLesson === lesson.id ? 'active' : ''}`}
              onClick={() => setActiveLesson(lesson.id)}
            >
              {lesson.label}
            </button>
          ))}
        </div>
      </nav>
      <ActiveComponent />
    </div>
  );
}

export default App;
