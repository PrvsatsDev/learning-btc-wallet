/**
 * Banda de aviso global — visible en toda la app.
 *
 * Toda la aplicación es material educativo, así que el descargo no debe vivir
 * solo en una sección. Esta banda fina se muestra sobre la navegación en todas
 * las lecciones; al pulsarla despliega el aviso completo como overlay, sin
 * descolocar el contenido.
 */

import { useState } from 'react';
import './DisclaimerBanner.css';

export function DisclaimerBanner() {
  const [open, setOpen] = useState(false);

  return (
    <div className={`app-disclaimer ${open ? 'open' : ''}`}>
      <button
        className="app-disclaimer-bar"
        onClick={() => setOpen(o => !o)}
        aria-expanded={open}
      >
        <span className="app-disclaimer-icon">⚠️</span>
        <span className="app-disclaimer-short">
          Proyecto educativo · sin garantías · criptografía no auditada · nunca uses una
          seed con fondos reales
        </span>
        <span className="app-disclaimer-toggle">{open ? 'Ocultar ▴' : 'Leer aviso ▾'}</span>
      </button>

      {open && (
        <div className="app-disclaimer-panel">
          <p>
            Toda esta aplicación es <strong>material de aprendizaje</strong> para entender
            cómo funciona Bitcoin por dentro. Se publica <strong>«tal cual»</strong>, sin
            garantía de ningún tipo y con criptografía implementada desde cero,{' '}
            <strong>no auditada para producción</strong>. El autor{' '}
            <strong>no se hace responsable</strong> de ninguna pérdida o daño derivado de su uso.
          </p>
          <p>
            <strong>Nunca introduzcas una seed que custodie fondos reales</strong> en esta ni
            en ninguna app conectada a internet — usa solo semillas de prueba. Distribuido bajo
            licencia MIT.
          </p>
        </div>
      )}
    </div>
  );
}
