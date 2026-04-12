/**
 * Cliente de la API de mempool.space
 *
 * mempool.space es un explorador de Bitcoin open-source que expone
 * una API REST pública, sin necesidad de API key.
 *
 * ¿Por qué mempool.space y no un nodo propio?
 *   - Para aprender no necesitamos un full node (170+ GB de blockchain)
 *   - La API nos da todo lo que una wallet necesita: saldo, UTXOs, broadcast
 *   - Es lo mismo que hacen wallets como BlueWallet o Sparrow en modo "público"
 *
 * ¿Qué redes soporta?
 *   - Mainnet: https://mempool.space/api
 *   - Testnet4: https://mempool.space/testnet4/api  (la que usamos para experimentar)
 *   - Signet: https://mempool.space/signet/api
 *
 * Usamos testnet4 por defecto — es la red de pruebas de Bitcoin donde
 * los BTC no tienen valor real. Perfecta para aprender sin riesgo.
 */

// ─── Tipos ──────────────────────────────────────────────

export type Network = 'mainnet' | 'testnet4' | 'signet';

/** Estadísticas de una dirección (confirmadas o en mempool) */
interface AddressStats {
  funded_txo_count: number;   // cuántas veces ha recibido fondos
  funded_txo_sum: number;     // total recibido (satoshis)
  spent_txo_count: number;    // cuántas veces ha gastado
  spent_txo_sum: number;      // total gastado (satoshis)
  tx_count: number;           // número total de transacciones
}

/** Respuesta de GET /api/address/:address */
export interface AddressInfo {
  address: string;
  chain_stats: AddressStats;   // confirmado en blockchain
  mempool_stats: AddressStats; // pendiente en mempool
}

/** Estado de una transacción */
export interface TxStatus {
  confirmed: boolean;
  block_height?: number;
  block_hash?: string;
  block_time?: number;         // Unix timestamp
}

/** Un UTXO — un "billete" que la dirección puede gastar */
export interface UTXO {
  txid: string;                // hash de la transacción que creó este output
  vout: number;                // índice del output dentro de esa transacción
  value: number;               // cantidad en satoshis
  status: TxStatus;
}

/** Entrada de una transacción */
export interface TxInput {
  txid: string;
  vout: number;
  prevout: {
    scriptpubkey: string;
    scriptpubkey_address?: string;
    value: number;
  } | null;
  scriptsig: string;
  witness?: string[];
  sequence: number;
}

/** Salida de una transacción */
export interface TxOutput {
  scriptpubkey: string;
  scriptpubkey_address?: string;
  scriptpubkey_type: string;
  value: number;
}

/** Una transacción completa */
export interface Transaction {
  txid: string;
  version: number;
  locktime: number;
  size: number;
  weight: number;
  fee: number;
  status: TxStatus;
  vin: TxInput[];
  vout: TxOutput[];
}

// ─── Base URLs por red ──────────────────────────────────

const BASE_URLS: Record<Network, string> = {
  mainnet: 'https://mempool.space/api',
  testnet4: 'https://mempool.space/testnet4/api',
  signet: 'https://mempool.space/signet/api',
};

// ─── Cliente API ────────────────────────────────────────

/**
 * Hace un fetch a la API con manejo de errores.
 * La API de mempool.space tiene rate limiting (sin API key),
 * así que si obtenemos un 429 esperamos y reintentamos una vez.
 */
async function apiFetch<T>(network: Network, path: string): Promise<T> {
  const url = `${BASE_URLS[network]}${path}`;
  const response = await fetch(url);

  if (response.status === 429) {
    // Rate limited — esperar 2 segundos y reintentar
    await new Promise(r => setTimeout(r, 2000));
    const retry = await fetch(url);
    if (!retry.ok) throw new Error(`API error ${retry.status}: ${retry.statusText}`);
    return retry.json();
  }

  if (!response.ok) {
    throw new Error(`API error ${response.status}: ${response.statusText}`);
  }

  return response.json();
}

// ─── Funciones públicas ─────────────────────────────────

/**
 * Obtiene información de una dirección: saldo confirmado, pendiente, etc.
 *
 * El saldo se calcula como:
 *   confirmado = chain_stats.funded_txo_sum - chain_stats.spent_txo_sum
 *   pendiente  = mempool_stats.funded_txo_sum - mempool_stats.spent_txo_sum
 */
export async function getAddressInfo(address: string, network: Network = 'testnet4'): Promise<AddressInfo> {
  return apiFetch<AddressInfo>(network, `/address/${address}`);
}

/**
 * Obtiene los UTXOs de una dirección — los "billetes" que puede gastar.
 *
 * Esto es lo más importante para construir transacciones:
 * cada UTXO es un input potencial. La wallet selecciona los UTXOs
 * necesarios para cubrir el monto + fee (coin selection).
 */
export async function getAddressUtxos(address: string, network: Network = 'testnet4'): Promise<UTXO[]> {
  return apiFetch<UTXO[]>(network, `/address/${address}/utxo`);
}

/**
 * Obtiene el historial de transacciones de una dirección.
 * Devuelve las últimas 25 confirmadas + hasta 50 pendientes.
 */
export async function getAddressTxs(address: string, network: Network = 'testnet4'): Promise<Transaction[]> {
  return apiFetch<Transaction[]>(network, `/address/${address}/txs`);
}

/**
 * Obtiene una transacción específica por su txid.
 */
export async function getTransaction(txid: string, network: Network = 'testnet4'): Promise<Transaction> {
  return apiFetch<Transaction>(network, `/tx/${txid}`);
}

/**
 * Emite una transacción a la red (broadcast).
 * Recibe el hex de la transacción serializada.
 * Devuelve el txid si se acepta.
 *
 * Esto se usará en el paso 4 (firma y broadcast).
 */
export async function broadcastTx(txHex: string, network: Network = 'testnet4'): Promise<string> {
  const url = `${BASE_URLS[network]}/tx`;
  const response = await fetch(url, {
    method: 'POST',
    body: txHex,
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Broadcast failed: ${errorText}`);
  }

  return response.text(); // devuelve el txid
}

// ─── Helpers ────────────────────────────────────────────

/** Calcula el saldo de una dirección a partir de su AddressInfo */
export function calculateBalance(info: AddressInfo): { confirmed: number; pending: number; total: number } {
  const confirmed = info.chain_stats.funded_txo_sum - info.chain_stats.spent_txo_sum;
  const pending = info.mempool_stats.funded_txo_sum - info.mempool_stats.spent_txo_sum;
  return { confirmed, pending, total: confirmed + pending };
}

/** Formatea satoshis a BTC con 8 decimales */
export function satsToBtc(sats: number): string {
  return (sats / 100_000_000).toFixed(8);
}

/** Formatea satoshis de forma legible (ej: 1,234,567 sats) */
export function formatSats(sats: number): string {
  return sats.toLocaleString('es-ES') + ' sats';
}
