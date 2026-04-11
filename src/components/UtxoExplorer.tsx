import { useState, useMemo } from 'react';
import {
  runScenario,
  selectCoins,
  formatSats,
  type UTXO,
} from '../crypto/utxo';
import './UtxoExplorer.css';

type ScenarioId = 'simple' | 'change' | 'consolidation';

const scenarioLabels: Record<ScenarioId, string> = {
  simple: 'Pago simple',
  change: 'Pago con cambio',
  consolidation: 'Consolidación',
};

export function UtxoExplorer() {
  const [scenarioId, setScenarioId] = useState<ScenarioId>('change');
  const [stepIndex, setStepIndex] = useState(0);
  const [showAccounts, setShowAccounts] = useState(false);

  // Coin selection demo
  const [coinSelectTarget, setCoinSelectTarget] = useState('50000');

  const steps = useMemo(() => runScenario(scenarioId), [scenarioId]);

  const currentStep = steps[Math.min(stepIndex, steps.length - 1)];

  const coinSelectResult = useMemo(() => {
    const target = parseInt(coinSelectTarget, 10);
    if (isNaN(target) || target <= 0) return null;
    const demoUtxos: UTXO[] = [
      { txid: 'a'.repeat(64), vout: 0, amount: 100_000, address: 'yo' },
      { txid: 'b'.repeat(64), vout: 0, amount: 25_000, address: 'yo' },
      { txid: 'c'.repeat(64), vout: 0, amount: 50_000, address: 'yo' },
      { txid: 'd'.repeat(64), vout: 0, amount: 10_000, address: 'yo' },
      { txid: 'e'.repeat(64), vout: 0, amount: 75_000, address: 'yo' },
    ];
    try {
      return selectCoins(demoUtxos, target);
    } catch {
      return null;
    }
  }, [coinSelectTarget]);

  return (
    <div className="utxo-explorer">
      <header className="utxo-header">
        <h1>Modelo UTXO</h1>
        <p className="subtitle">
          Bitcoin no usa cuentas con saldo. Rastrea "monedas" individuales llamadas UTXOs
          (Unspent Transaction Outputs). Es como efectivo: no divides un billete, lo gastas
          entero y recibes cambio.
        </p>
      </header>

      {/* Concepto clave */}
      <section className="utxo-section concept-section">
        <label className="section-label">Concepto clave</label>
        <div className="concept-grid">
          <div className="concept-card">
            <h3>Modelo de cuentas (Ethereum)</h3>
            <p>Cada dirección tiene un saldo. Enviar dinero = restar de una cuenta y sumar a otra.</p>
            <div className="concept-example">
              Alice: 1.0 ETH → envía 0.3 → Alice: 0.7, Bob: 0.3
            </div>
          </div>
          <div className="concept-card highlight-card">
            <h3>Modelo UTXO (Bitcoin)</h3>
            <p>No hay "saldos". Hay monedas concretas. Gastar = destruir monedas viejas + crear nuevas.</p>
            <div className="concept-example">
              Alice tiene [1.0 BTC] → gasta → nacen [0.3 Bob] + [0.7 Alice cambio]
            </div>
          </div>
        </div>
      </section>

      {/* Simulador */}
      <section className="utxo-section">
        <label className="section-label">Simulador de UTXOs</label>
        <p className="section-description">
          Selecciona un escenario y avanza paso a paso para ver cómo evolucionan los UTXOs.
        </p>

        <div className="scenario-selector">
          {(Object.keys(scenarioLabels) as ScenarioId[]).map((id) => (
            <button
              key={id}
              className={`scenario-btn ${scenarioId === id ? 'active' : ''}`}
              onClick={() => { setScenarioId(id); setStepIndex(0); }}
            >
              {scenarioLabels[id]}
            </button>
          ))}
        </div>

        {/* Step controls */}
        <div className="step-controls">
          <button
            className="step-btn"
            disabled={stepIndex === 0}
            onClick={() => setStepIndex(stepIndex - 1)}
          >
            ← Anterior
          </button>
          <span className="step-counter">
            Paso {stepIndex + 1} de {steps.length}
          </span>
          <button
            className="step-btn"
            disabled={stepIndex >= steps.length - 1}
            onClick={() => setStepIndex(stepIndex + 1)}
          >
            Siguiente →
          </button>
        </div>

        {/* Step description */}
        <div className={`step-description ${currentStep.type}`}>
          {currentStep.type === 'transaction' && <span className="step-type-badge tx">TX</span>}
          {currentStep.type === 'info' && <span className="step-type-badge info">INFO</span>}
          {currentStep.description}
        </div>

        {/* Transaction details */}
        {currentStep.type === 'transaction' && (
          <div className="tx-details">
            {currentStep.from && currentStep.to && (
              <div className="tx-flow">
                <span className="tx-party">{currentStep.from}</span>
                <span className="tx-arrow">→ {formatSats(currentStep.amount!)} →</span>
                <span className="tx-party">{currentStep.to}</span>
              </div>
            )}
            {currentStep.fee !== undefined && (
              <div className="tx-meta">
                <span>Comisión: {formatSats(currentStep.fee)}</span>
                {currentStep.change !== undefined && (
                  <span>Cambio: {formatSats(currentStep.change)}</span>
                )}
              </div>
            )}
          </div>
        )}

        {/* UTXO visualization */}
        <div className="utxo-state">
          <div className="utxo-column">
            <h3 className="column-title">
              UTXOs activos
              <span className="utxo-count">({currentStep.utxos.length})</span>
            </h3>
            <div className="utxo-list">
              {currentStep.utxos.map((utxo) => {
                const isNew = currentStep.created.some(
                  c => c.txid === utxo.txid && c.vout === utxo.vout
                );
                return (
                  <div key={`${utxo.txid}-${utxo.vout}`} className={`utxo-card ${isNew ? 'new' : ''}`}>
                    <div className="utxo-address">{utxo.address}</div>
                    <div className="utxo-amount">{formatSats(utxo.amount)}</div>
                    <div className="utxo-ref">
                      {utxo.txid.slice(0, 8)}...:{utxo.vout}
                    </div>
                  </div>
                );
              })}
              {currentStep.utxos.length === 0 && (
                <div className="utxo-empty">Sin UTXOs</div>
              )}
            </div>
          </div>

          {currentStep.consumed.length > 0 && (
            <div className="utxo-column consumed-column">
              <h3 className="column-title consumed-title">Consumidos en este paso</h3>
              <div className="utxo-list">
                {currentStep.consumed.map((utxo, i) => (
                  <div key={i} className="utxo-card consumed">
                    <div className="utxo-address">{utxo.address}</div>
                    <div className="utxo-amount">{formatSats(utxo.amount)}</div>
                    <div className="utxo-consumed-badge">GASTADO</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Comparison toggle */}
        <div className="comparison-toggle">
          <button className="toggle-btn" onClick={() => setShowAccounts(!showAccounts)}>
            {showAccounts ? 'Ocultar' : 'Comparar con'} modelo de cuentas
          </button>
        </div>

        {showAccounts && (
          <div className="accounts-view">
            <h3 className="column-title">Vista de cuentas (equivalente)</h3>
            <div className="accounts-list">
              {currentStep.accounts.map((acc, i) => (
                <div key={i} className="account-card">
                  <span className="account-address">{acc.address}</span>
                  <span className="account-balance">{formatSats(acc.balance)}</span>
                </div>
              ))}
            </div>
            <p className="accounts-note">
              En el modelo de cuentas, solo ves saldos. No sabes cuántas "monedas"
              hay detrás ni su origen. Más simple, pero menos transparente.
            </p>
          </div>
        )}
      </section>

      {/* Coin Selection */}
      <section className="utxo-section">
        <label className="section-label">Selección de monedas (coin selection)</label>
        <p className="section-description">
          Cuando quieres pagar, el wallet elige qué UTXOs usar. Es como decidir
          qué billetes sacar de la cartera. Aquí usamos "largest first" (el más grande primero).
        </p>

        <div className="coin-select-demo">
          <div className="coin-select-wallet">
            <h4>Tu cartera (5 UTXOs)</h4>
            <div className="wallet-utxos">
              {[100_000, 75_000, 50_000, 25_000, 10_000].map((amount, i) => (
                <div key={i} className={`wallet-utxo ${
                  coinSelectResult?.selected.some(s => s.amount === amount) ? 'selected' : ''
                }`}>
                  {formatSats(amount)}
                </div>
              ))}
            </div>
          </div>

          <div className="coin-select-input">
            <label className="input-label">Cantidad a enviar (sats)</label>
            <input
              type="text"
              className="utxo-input"
              value={coinSelectTarget}
              onChange={(e) => setCoinSelectTarget(e.target.value.replace(/[^0-9]/g, ''))}
              placeholder="50000"
            />
          </div>

          {coinSelectResult && (
            <div className="coin-select-result">
              <div className="cs-row">
                <span className="cs-label">UTXOs seleccionados</span>
                <span className="cs-value">{coinSelectResult.selected.length} UTXO(s)</span>
              </div>
              <div className="cs-row">
                <span className="cs-label">Total aportado</span>
                <span className="cs-value">{formatSats(coinSelectResult.total)}</span>
              </div>
              <div className="cs-row">
                <span className="cs-label">Envío</span>
                <span className="cs-value">{formatSats(coinSelectResult.target)}</span>
              </div>
              <div className="cs-row">
                <span className="cs-label">Comisión</span>
                <span className="cs-value">{formatSats(coinSelectResult.fee)}</span>
              </div>
              <div className={`cs-row ${coinSelectResult.dust ? 'dust-warning' : ''}`}>
                <span className="cs-label">Cambio</span>
                <span className="cs-value">
                  {coinSelectResult.change <= 0
                    ? 'Sin cambio'
                    : formatSats(coinSelectResult.change)}
                  {coinSelectResult.dust && ' ⚠ DUST'}
                </span>
              </div>
              {coinSelectResult.dust && (
                <div className="dust-note">
                  El cambio es menor que el dust limit (546 sats). No vale la pena
                  crear un UTXO tan pequeño — se "dona" como comisión extra.
                </div>
              )}
            </div>
          )}
        </div>
      </section>

      {/* ¿Por qué UTXOs? */}
      <section className="utxo-section">
        <label className="section-label">¿Por qué Bitcoin usa UTXOs?</label>
        <div className="why-grid">
          {[
            {
              title: 'Paralelismo',
              text: 'Dos UTXOs diferentes se pueden validar y gastar en paralelo. No hay un "saldo global" que bloquear.',
            },
            {
              title: 'Privacidad',
              text: 'Cada UTXO puede estar en una dirección diferente. Nadie sabe cuáles son tuyas (en teoría).',
            },
            {
              title: 'Verificación simple',
              text: 'Para validar una tx, solo hay que comprobar que cada input referencia un UTXO existente y no gastado.',
            },
            {
              title: 'Sin estado global',
              text: 'No hay un "saldo de cuenta" que actualizar atómicamente. Cada UTXO es independiente.',
            },
          ].map((item, i) => (
            <div key={i} className="why-card">
              <h4>{item.title}</h4>
              <p>{item.text}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
