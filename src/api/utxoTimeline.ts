/**
 * Timeline de UTXOs de una dirección — reconstruida a partir de su historial.
 *
 * Una dirección no tiene "saldo" en ningún sitio de la blockchain. Lo que hay
 * son monedas (UTXOs) que NACEN cuando una tx paga a esa dirección y MUEREN
 * cuando otra tx las usa como entrada. El saldo en cada instante es la suma de
 * las monedas vivas en ese instante:
 *
 *   saldo(t) = Σ valor de las monedas con nacimiento ≤ t < muerte
 *
 * Aquí rehacemos esa película a partir de la lista de transacciones de la
 * dirección: cada salida a la dirección crea una moneda; cada entrada cuyo
 * prevout era de la dirección mata la moneda (txid:vout) a la que apunta. Al
 * final, las monedas sin muerte son exactamente el conjunto de UTXOs actual,
 * algo que se puede COMPROBAR contra /address/:a/utxo, que el servidor calcula
 * por su cuenta (checkAgainstServer).
 */

import {
  getAddressInfo,
  getAddressTxs,
  getAddressTxsChain,
  getAddressUtxos,
  type AddressInfo,
  type Network,
  type UTXO,
} from './mempool';

// ─── Tipos de entrada ───────────────────────────────────

/**
 * Lo mínimo que necesitamos de cada tx. `Transaction` de mempool.ts lo cumple
 * estructuralmente; los fixtures guardan solo estos campos.
 */
export interface TimelineTx {
  txid: string;
  fee?: number;
  status: { confirmed: boolean; block_height?: number; block_time?: number };
  vin: {
    txid: string;
    vout: number;
    prevout: { scriptpubkey_address?: string; value: number } | null;   // null en coinbase
  }[];
  vout: { scriptpubkey_address?: string; scriptpubkey_type: string; value: number }[];
}

// ─── Tipos de salida ────────────────────────────────────

/** Un instante de la película: la tx que lo provoca y cuándo se confirmó */
export interface TimePoint {
  order: number;            // posición de la tx en el orden cronológico (0 = la más antigua)
  height: number | null;    // null = aún en mempool
  time: number | null;      // unix (s) del bloque; null = en mempool
}

export interface Coin {
  id: string;               // "txid:vout" — el outpoint, la identidad de la moneda
  txid: string;
  vout: number;
  value: number;
  /** null = nació antes del historial cargado (historial truncado) */
  born: TimePoint | null;
  spent: { txid: string; vin: number; at: TimePoint } | null;
  dust: boolean;
  lane: number;             // carril en el diagrama (assignLanes)
}

export interface TimelineEvent {
  tx: TimelineTx;
  at: TimePoint;
  created: Coin[];          // monedas que nacen en esta tx
  consumed: Coin[];         // monedas de la dirección que mueren en esta tx
  received: number;         // Σ created
  spentValue: number;       // Σ consumed
  delta: number;            // received − spentValue
  balanceAfter: number;
  /** Entradas de la tx que NO son de esta dirección (heurística de propiedad común) */
  foreignInputs: number;
  /** Gasta y además devuelve dinero a la misma dirección → cambio a dirección reutilizada */
  changeBack: boolean;
  coinbase: boolean;
}

export interface AddressTimeline {
  address: string;
  events: TimelineEvent[];
  coins: Coin[];
  live: Coin[];
  balance: number;          // confirmado + mempool
  confirmedBalance: number;
  lanes: number;
  /** Monedas gastadas que no nacieron en el historial cargado → falta historia */
  orphanSpends: number;
  /** Veces que la dirección recibió fondos en tx distintas (>1 = reutilizada) */
  fundingTxs: number;
  firstTime: number | null;
  lastTime: number | null;
}

/** Umbral orientativo de "polvo" (dust): por debajo cuesta más gastarla que lo que vale */
export const DUST_SATS = 1000;

// ─── Orden cronológico ──────────────────────────────────

/**
 * Ordena las tx de la más antigua a la más nueva.
 *
 * Por altura de bloque, y las de mempool al final. Dentro del mismo bloque el
 * API no nos dice el orden, pero hay una regla que SIEMPRE se cumple: si una tx
 * gasta una salida de otra del mismo bloque, la madre va antes (un bloque no
 * puede gastar algo que aún no existe). Lo resolvemos con un orden topológico.
 */
export function sortChronologically<T extends TimelineTx>(txs: T[]): T[] {
  const key = (t: TimelineTx) => (t.status.confirmed && t.status.block_height != null ? t.status.block_height : Infinity);
  // El API devuelve de más nueva a más antigua: invertir da el desempate natural
  const base = [...txs].reverse();
  const groups = new Map<number, T[]>();
  for (const t of base) {
    const k = key(t);
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k)!.push(t);
  }
  const out: T[] = [];
  for (const k of [...groups.keys()].sort((a, b) => a - b)) {
    const group = groups.get(k)!;
    const ids = new Set(group.map(t => t.txid));
    const placed = new Set<string>();
    const pending = [...group];
    while (pending.length) {
      // primera tx cuyas madres (dentro del grupo) ya están colocadas
      let i = pending.findIndex(t => t.vin.every(v => !ids.has(v.txid) || placed.has(v.txid) || v.txid === t.txid));
      if (i === -1) i = 0; // ciclo imposible en datos válidos: no nos colgamos
      const [t] = pending.splice(i, 1);
      placed.add(t.txid);
      out.push(t);
    }
  }
  return out;
}

// ─── Reconstrucción ─────────────────────────────────────

export function buildTimeline(address: string, txs: TimelineTx[]): AddressTimeline {
  const sorted = sortChronologically(dedupe(txs));
  const coins = new Map<string, Coin>();
  const events: TimelineEvent[] = [];
  let balance = 0;
  let orphanSpends = 0;
  let fundingTxs = 0;

  sorted.forEach((tx, order) => {
    const at: TimePoint = {
      order,
      height: tx.status.confirmed ? tx.status.block_height ?? null : null,
      time: tx.status.confirmed ? tx.status.block_time ?? null : null,
    };

    // 1) Entradas: ¿mata alguna moneda de la dirección?
    const consumed: Coin[] = [];
    let foreignInputs = 0;
    tx.vin.forEach((v, vin) => {
      if (v.prevout?.scriptpubkey_address !== address) {
        foreignInputs++;
        return;
      }
      const id = `${v.txid}:${v.vout}`;
      let coin = coins.get(id);
      if (!coin) {
        // Gasta una moneda cuyo nacimiento no está en lo cargado
        orphanSpends++;
        coin = { id, txid: v.txid, vout: v.vout, value: v.prevout.value, born: null, spent: null, dust: v.prevout.value < DUST_SATS, lane: 0 };
        coins.set(id, coin);
      }
      coin.spent = { txid: tx.txid, vin, at };
      consumed.push(coin);
    });

    // 2) Salidas: ¿nace alguna moneda en la dirección?
    const created: Coin[] = [];
    tx.vout.forEach((o, vout) => {
      if (o.scriptpubkey_address !== address) return;
      const coin: Coin = { id: `${tx.txid}:${vout}`, txid: tx.txid, vout, value: o.value, born: at, spent: null, dust: o.value < DUST_SATS, lane: 0 };
      coins.set(coin.id, coin);
      created.push(coin);
    });
    if (created.length) fundingTxs++;

    const received = sum(created);
    const spentValue = sum(consumed);
    // Las huérfanas no estaban en el saldo que llevamos: no las restamos dos veces
    balance += received - sum(consumed.filter(c => c.born !== null));
    events.push({
      tx, at, created, consumed, received, spentValue,
      delta: received - spentValue,
      balanceAfter: balance,
      foreignInputs: consumed.length ? foreignInputs : 0,
      changeBack: consumed.length > 0 && created.length > 0,
      coinbase: tx.vin.length > 0 && tx.vin.every(v => v.prevout === null),
    });
  });

  const all = [...coins.values()];
  const lanes = assignLanes(all);
  const live = all.filter(c => !c.spent);
  const times = sorted.map(t => t.status.block_time).filter((x): x is number => x != null);
  return {
    address,
    events,
    coins: all,
    live,
    balance: sum(live),
    confirmedBalance: sum(live.filter(c => c.born?.height != null)),
    lanes,
    orphanSpends,
    fundingTxs,
    firstTime: times.length ? Math.min(...times) : null,
    lastTime: times.length ? Math.max(...times) : null,
  };
}

/**
 * Reparte las monedas en carriles horizontales: dos monedas pueden compartir
 * carril si una muere antes (o en la misma tx) de que nazca la otra. Es el
 * clásico "interval partitioning": el número de carriles es el máximo de
 * monedas vivas a la vez.
 */
export function assignLanes(coins: Coin[]): number {
  const start = (c: Coin) => c.born?.order ?? -1;
  const end = (c: Coin) => c.spent?.at.order ?? Infinity;
  const laneEnd: number[] = [];
  for (const c of [...coins].sort((a, b) => start(a) - start(b) || end(a) - end(b))) {
    let lane = laneEnd.findIndex(e => e <= start(c));
    if (lane === -1) lane = laneEnd.length;
    laneEnd[lane] = end(c);
    c.lane = lane;
  }
  return laneEnd.length;
}

// ─── Comprobación independiente ─────────────────────────

export interface ServerCheck {
  utxosMatch: boolean;
  missing: string[];     // el servidor dice que existe y nosotros no la vemos viva
  extra: string[];       // la vemos viva y el servidor no
  balanceMatch: boolean;
  serverBalance: number;
}

/**
 * Compara nuestra reconstrucción con lo que el servidor calcula por separado:
 * la lista de UTXOs (/utxo) y el saldo de sus estadísticas (funded − spent).
 * Si el historial está completo, deben coincidir exactamente.
 */
export function checkAgainstServer(tl: AddressTimeline, utxos: UTXO[], info: AddressInfo): ServerCheck {
  const ours = new Set(tl.live.map(c => c.id));
  const theirs = new Set(utxos.map(u => `${u.txid}:${u.vout}`));
  const missing = [...theirs].filter(id => !ours.has(id));
  const extra = [...ours].filter(id => !theirs.has(id));
  const s = info.chain_stats, m = info.mempool_stats;
  const serverBalance = s.funded_txo_sum - s.spent_txo_sum + m.funded_txo_sum - m.spent_txo_sum;
  return {
    utxosMatch: missing.length === 0 && extra.length === 0,
    missing,
    extra,
    balanceMatch: serverBalance === tl.balance,
    serverBalance,
  };
}

// ─── Descarga del historial ─────────────────────────────

export interface AddressHistory {
  info: AddressInfo;
  utxos: UTXO[];
  txs: TimelineTx[];
  /** Nos paramos por el tope de páginas: falta la parte más antigua */
  truncated: boolean;
}

/** Tope de páginas del historial confirmado (la API pública limita peticiones) */
export const MAX_HISTORY_PAGES = 8;

/**
 * Descarga el historial completo de una dirección.
 *
 * /address/:a/txs da las de mempool + la primera página de confirmadas; las
 * siguientes se piden con /txs/chain/:último_txid, hacia atrás en el tiempo,
 * hasta que una página llega vacía. (El tamaño de página lo decide el servidor:
 * mempool.space devuelve hoy 50, otros Esplora 25; no lo suponemos.)
 */
export async function fetchAddressHistory(
  address: string,
  network: Network,
  onProgress?: (msg: string) => void,
  isCancelled: () => boolean = () => false,
): Promise<AddressHistory | null> {
  onProgress?.('Consultando estadísticas de la dirección…');
  const info = await getAddressInfo(address, network);
  const total = info.chain_stats.tx_count + info.mempool_stats.tx_count;

  onProgress?.(`Descargando historial (0/${total} tx)…`);
  const txs: TimelineTx[] = await getAddressTxs(address, network);
  let page = txs.filter(t => t.status.confirmed);
  let pages = 1;
  let truncated = false;
  while (page.length > 0) {
    if (isCancelled()) return null;
    if (pages >= MAX_HISTORY_PAGES) { truncated = txs.length < total; break; }
    onProgress?.(`Descargando historial (${txs.length}/${total} tx)…`);
    page = await getAddressTxsChain(address, page[page.length - 1].txid, network);
    txs.push(...page);
    pages++;
  }
  if (isCancelled()) return null;

  onProgress?.('Descargando la lista de UTXOs para comprobar…');
  const utxos = await getAddressUtxos(address, network);
  return { info, utxos, txs, truncated };
}

// ─── Utilidades ─────────────────────────────────────────

function sum(coins: Coin[]): number {
  return coins.reduce((a, c) => a + c.value, 0);
}

function dedupe<T extends TimelineTx>(txs: T[]): T[] {
  const seen = new Set<string>();
  return txs.filter(t => (seen.has(t.txid) ? false : (seen.add(t.txid), true)));
}

/** Vida de una moneda en bloques (null si sigue viva o falta un extremo) */
export function lifespanBlocks(c: Coin): number | null {
  const a = c.born?.height, b = c.spent?.at.height;
  return a != null && b != null ? b - a : null;
}

/** Red que implica el prefijo de la dirección (null si no lo sabemos decir) */
export function networkOfAddress(addr: string): 'mainnet' | 'test' | null {
  const a = addr.trim();
  if (/^bc1/i.test(a) || /^[13]/.test(a)) return 'mainnet';
  if (/^tb1/i.test(a) || /^[mn2]/.test(a)) return 'test';
  return null;
}
