/**
 * Modelo UTXO (Unspent Transaction Output) — el corazón de Bitcoin.
 *
 * Bitcoin NO usa un modelo de "cuentas con saldo" (como un banco o Ethereum).
 * En su lugar, rastrea "monedas" individuales llamadas UTXOs.
 *
 * Piénsalo como efectivo físico:
 *   - No tienes "saldo" — tienes billetes y monedas concretas
 *   - Para pagar 7€, usas un billete de 10€ y recibes 3€ de cambio
 *   - El billete de 10€ deja de existir; nacen dos nuevos: 7€ + 3€
 *
 * Un UTXO es una "moneda" de Bitcoin que:
 *   - Fue creada como output de una transacción anterior
 *   - Aún no ha sido gastada (unspent)
 *   - Tiene un valor en satoshis y una condición de gasto (script)
 *
 * ¿Por qué UTXOs y no cuentas?
 *   1. Paralelismo: dos UTXOs diferentes se pueden gastar en paralelo
 *   2. Privacidad: cada UTXO puede estar en una dirección diferente
 *   3. Verificación simple: solo hay que comprobar que el UTXO existe y no ha sido gastado
 *   4. No hay "estado global": no hay un saldo que actualizar atómicamente
 */

// ─── Tipos ──────────────────────────────────────────────────

/** Un UTXO: una moneda de Bitcoin sin gastar */
export interface UTXO {
  txid: string;       // ID de la transacción que creó este output
  vout: number;       // índice del output dentro de esa transacción (0, 1, 2...)
  amount: number;     // valor en satoshis (1 BTC = 100,000,000 satoshis)
  address: string;    // dirección que controla este UTXO
}

/** Una entrada de un modelo de cuentas (para comparación) */
export interface AccountEntry {
  address: string;
  balance: number;    // saldo en satoshis
}

/** Un paso en la simulación */
export interface SimulationStep {
  description: string;
  type: 'initial' | 'transaction' | 'info';
  from?: string;
  to?: string;
  amount?: number;
  fee?: number;
  // Estado después de este paso
  utxos: UTXO[];
  accounts: AccountEntry[];
  // UTXOs consumidos y creados en este paso
  consumed: UTXO[];
  created: UTXO[];
  change?: number;
}

/** Resultado de la selección de monedas */
export interface CoinSelectionResult {
  selected: UTXO[];
  total: number;       // suma de los UTXOs seleccionados
  target: number;      // cantidad que queremos enviar
  fee: number;         // comisión
  change: number;      // cambio = total - target - fee
  dust: boolean;       // ¿el cambio es tan pequeño que no vale la pena? (<546 sat)
}

// ─── Simulación UTXO ────────────────────────────────────────

let txCounter = 0;
function nextTxId(): string {
  txCounter++;
  // Generar un txid simulado (en realidad es el hash de la transacción)
  return txCounter.toString(16).padStart(64, '0');
}

/**
 * Ejecuta un escenario de transacciones y devuelve la evolución
 * del estado UTXO paso a paso, junto con el estado equivalente
 * en un modelo de cuentas (para comparación visual).
 */
export function runScenario(scenarioId: 'simple' | 'change' | 'consolidation'): SimulationStep[] {
  txCounter = 0;
  const scenarios: Record<string, () => SimulationStep[]> = {
    simple: scenarioSimplePayment,
    change: scenarioChangeOutput,
    consolidation: scenarioConsolidation,
  };
  return scenarios[scenarioId]();
}

/** Escenario 1: Alice recibe una coinbase y paga a Bob */
function scenarioSimplePayment(): SimulationStep[] {
  const steps: SimulationStep[] = [];

  // Estado inicial: Alice recibe 50 BTC de la minería (coinbase)
  const coinbaseTxid = nextTxId();
  const aliceUtxo: UTXO = { txid: coinbaseTxid, vout: 0, amount: 5_000_000_000, address: 'Alice' };

  steps.push({
    description: 'Alice mina un bloque y recibe 50 BTC como recompensa (coinbase)',
    type: 'initial',
    utxos: [aliceUtxo],
    accounts: [{ address: 'Alice', balance: 5_000_000_000 }],
    consumed: [],
    created: [aliceUtxo],
  });

  // Alice envía 50 BTC a Bob (usa todo el UTXO, sin cambio)
  const tx1Id = nextTxId();
  const bobUtxo: UTXO = { txid: tx1Id, vout: 0, amount: 4_999_900_000, address: 'Bob' };
  const fee1 = 100_000;

  steps.push({
    description: 'Alice envía ~50 BTC a Bob. Usa su único UTXO completo. Comisión: 0.001 BTC',
    type: 'transaction',
    from: 'Alice',
    to: 'Bob',
    amount: 4_999_900_000,
    fee: fee1,
    utxos: [bobUtxo],
    accounts: [
      { address: 'Alice', balance: 0 },
      { address: 'Bob', balance: 4_999_900_000 },
    ],
    consumed: [aliceUtxo],
    created: [bobUtxo],
  });

  steps.push({
    description: 'El UTXO de Alice fue destruido. Nació un nuevo UTXO para Bob. La comisión (0.001 BTC) va al minero.',
    type: 'info',
    utxos: [bobUtxo],
    accounts: [
      { address: 'Alice', balance: 0 },
      { address: 'Bob', balance: 4_999_900_000 },
    ],
    consumed: [],
    created: [],
  });

  return steps;
}

/** Escenario 2: Pago con cambio (el caso más común) */
function scenarioChangeOutput(): SimulationStep[] {
  const steps: SimulationStep[] = [];

  // Alice tiene un UTXO de 1 BTC
  const tx0 = nextTxId();
  const aliceUtxo: UTXO = { txid: tx0, vout: 0, amount: 100_000_000, address: 'Alice' };

  steps.push({
    description: 'Alice tiene 1 BTC (100,000,000 satoshis) en un UTXO',
    type: 'initial',
    utxos: [aliceUtxo],
    accounts: [{ address: 'Alice', balance: 100_000_000 }],
    consumed: [],
    created: [aliceUtxo],
  });

  // Alice quiere enviar 0.3 BTC a Bob
  // Como su UTXO es de 1 BTC, necesita cambio
  const tx1 = nextTxId();
  const fee = 10_000;
  const bobOutput: UTXO = { txid: tx1, vout: 0, amount: 30_000_000, address: 'Bob' };
  const changeOutput: UTXO = { txid: tx1, vout: 1, amount: 69_990_000, address: 'Alice' };

  steps.push({
    description: 'Alice quiere enviar 0.3 BTC a Bob. Su UTXO es de 1 BTC — no puede "dividirlo". Debe gastar el UTXO entero y crear cambio.',
    type: 'transaction',
    from: 'Alice',
    to: 'Bob',
    amount: 30_000_000,
    fee,
    change: 69_990_000,
    utxos: [bobOutput, changeOutput],
    accounts: [
      { address: 'Alice', balance: 69_990_000 },
      { address: 'Bob', balance: 30_000_000 },
    ],
    consumed: [aliceUtxo],
    created: [bobOutput, changeOutput],
  });

  steps.push({
    description: 'El UTXO original de 1 BTC fue destruido. Nacieron 2 UTXOs nuevos: 0.3 BTC para Bob + 0.6999 BTC de cambio para Alice. El cambio va a una dirección de Alice (puede ser nueva).',
    type: 'info',
    utxos: [bobOutput, changeOutput],
    accounts: [
      { address: 'Alice', balance: 69_990_000 },
      { address: 'Bob', balance: 30_000_000 },
    ],
    consumed: [],
    created: [],
  });

  return steps;
}

/** Escenario 3: Consolidación de UTXOs */
function scenarioConsolidation(): SimulationStep[] {
  const steps: SimulationStep[] = [];

  // Alice tiene varios UTXOs pequeños (como monedas sueltas)
  const utxos: UTXO[] = [
    { txid: nextTxId(), vout: 0, amount: 50_000, address: 'Alice' },
    { txid: nextTxId(), vout: 0, amount: 30_000, address: 'Alice' },
    { txid: nextTxId(), vout: 0, amount: 80_000, address: 'Alice' },
    { txid: nextTxId(), vout: 0, amount: 20_000, address: 'Alice' },
    { txid: nextTxId(), vout: 0, amount: 60_000, address: 'Alice' },
  ];
  const totalBalance = utxos.reduce((sum, u) => sum + u.amount, 0);

  steps.push({
    description: `Alice tiene 5 UTXOs pequeños (como monedas sueltas). Saldo total: ${formatSats(totalBalance)}`,
    type: 'initial',
    utxos: [...utxos],
    accounts: [{ address: 'Alice', balance: totalBalance }],
    consumed: [],
    created: [...utxos],
  });

  // Consolidar todos en un solo UTXO
  const fee = 15_000; // comisión más alta por tener muchos inputs
  const consolidatedTxid = nextTxId();
  const consolidated: UTXO = {
    txid: consolidatedTxid,
    vout: 0,
    amount: totalBalance - fee,
    address: 'Alice',
  };

  steps.push({
    description: `Consolidación: Alice gasta los 5 UTXOs en una sola transacción que se paga a sí misma. Comisión: ${formatSats(fee)} (más alta porque hay 5 inputs)`,
    type: 'transaction',
    from: 'Alice',
    to: 'Alice',
    amount: consolidated.amount,
    fee,
    utxos: [consolidated],
    accounts: [{ address: 'Alice', balance: consolidated.amount }],
    consumed: [...utxos],
    created: [consolidated],
  });

  steps.push({
    description: `Ahora Alice tiene 1 solo UTXO de ${formatSats(consolidated.amount)}. Más barato de gastar en el futuro (1 input vs 5). La consolidación tiene sentido cuando las comisiones son bajas.`,
    type: 'info',
    utxos: [consolidated],
    accounts: [{ address: 'Alice', balance: consolidated.amount }],
    consumed: [],
    created: [],
  });

  return steps;
}

// ─── Coin Selection ─────────────────────────────────────────
/**
 * Selección de monedas: ¿qué UTXOs uso para pagar una cantidad?
 *
 * Es como pagar en efectivo: si quieres pagar 7€ y tienes
 * billetes de 5€, 2€ y 1€, ¿cuáles usas?
 *
 * Estrategia "largest first": usa los UTXOs más grandes primero.
 * Simple pero no óptima (en producción se usan algoritmos más sofisticados
 * como Branch and Bound o Knapsack).
 *
 * El "dust limit" (546 satoshis para P2PKH) es el mínimo para un UTXO.
 * Si el cambio sería menor que esto, no vale la pena crearlo
 * y es mejor "donarlo" como comisión extra al minero.
 */
export function selectCoins(
  utxos: UTXO[],
  targetAmount: number,
  feePerInput: number = 5_000
): CoinSelectionResult {
  // Ordenar de mayor a menor
  const sorted = [...utxos].sort((a, b) => b.amount - a.amount);
  const selected: UTXO[] = [];
  let total = 0;

  for (const utxo of sorted) {
    selected.push(utxo);
    total += utxo.amount;
    const fee = selected.length * feePerInput;
    if (total >= targetAmount + fee) break;
  }

  const fee = selected.length * feePerInput;
  const change = total - targetAmount - fee;
  const DUST_LIMIT = 546;
  const dust = change > 0 && change < DUST_LIMIT;

  return { selected, total, target: targetAmount, fee, change, dust };
}

// ─── Utilidades ─────────────────────────────────────────────

/** Formatea satoshis para mostrar */
export function formatSats(sats: number): string {
  if (sats >= 100_000_000) {
    return `${(sats / 100_000_000).toFixed(4)} BTC`;
  }
  if (sats >= 1_000) {
    return `${sats.toLocaleString()} sats`;
  }
  return `${sats} sats`;
}
