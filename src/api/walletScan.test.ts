/**
 * Test del escaneo con gap limit (recepción + cambio) contra un fetch simulado.
 *
 * Simulamos mempool.space: unas direcciones "usadas" (tx_count > 0, con un UTXO)
 * y el resto vírgenes. Comprobamos hasta dónde escanea cada cadena y cuál es
 * la primera dirección de cambio libre.
 *
 * Sin framework: console.log + process.exit(1). Ejecutar bundleando con rolldown.
 */

import { scanWallet } from './walletScan';
import {
  derivePath,
  getAddress,
  getDerivationPath,
  masterKeyFromSeed,
  mnemonicToSeed,
} from '../crypto/hdwallet';

let failed = false;
function check(name: string, cond: boolean, got?: string, want?: string) {
  console.log(`${cond ? '✓' : '✗'} ${name}`);
  if (!cond) {
    failed = true;
    if (got !== undefined) console.log(`    got:  ${got}`);
    if (want !== undefined) console.log(`    want: ${want}`);
  }
}

const words = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'.split(' ');
const master = masterKeyFromSeed(mnemonicToSeed(words));

function addr(change: boolean, i: number): string {
  const { node } = derivePath(master, getDerivationPath(84, 0, change, i, 1));
  return getAddress(node, 84, false);
}

// Recepción: usadas 0, 1 y 3 (con un hueco en la 2). Cambio: usadas 0..6.
const used = new Set<string>([
  addr(false, 0), addr(false, 1), addr(false, 3),
  ...Array.from({ length: 7 }, (_, i) => addr(true, i)),
]);

const requested: string[] = [];
const stats = (n: number) => ({ funded_txo_count: n, funded_txo_sum: n * 1000, spent_txo_count: 0, spent_txo_sum: 0, tx_count: n });

globalThis.fetch = (async (input: string | URL | Request) => {
  const url = String(input);
  requested.push(url);
  const m = url.match(/\/address\/([^/]+)(\/utxo)?$/);
  if (!m) return new Response('not found', { status: 404 });
  const [, address, isUtxo] = m;
  const n = used.has(address) ? 1 : 0;
  const body = isUtxo
    ? Array.from({ length: n }, () => ({ txid: 'ab'.repeat(32), vout: 0, value: 1000, status: { confirmed: true } }))
    : { address, chain_stats: stats(n), mempool_stats: stats(0) };
  return new Response(JSON.stringify(body), { status: 200 });
}) as typeof fetch;

const { receive, change } = await scanWallet(master, 'testnet4');

// Recepción: última usada = 3, luego 5 vírgenes (4..8) → escanea 0..8
check('recepción escanea 0..8 (gap limit 5 tras la última usada)',
  receive.addresses.length === 9, String(receive.addresses.length), '9');
check('el hueco en la 2 no corta el escaneo', receive.addresses[3].used);
check('recepción: primera libre tras la última usada = 4',
  receive.firstUnused === 4, String(receive.firstUnused), '4');

// Cambio: usadas 0..6 → escanea 0..11, siguiente cambio = 7 (más allá del antiguo tope de 5)
check('cambio escanea 0..11', change.addresses.length === 12, String(change.addresses.length), '12');
check('siguiente dirección de cambio = 7', change.firstUnused === 7, String(change.firstUnused), '7');

const utxos = [...receive.addresses, ...change.addresses].flatMap(a => a.utxos);
check('encuentra los 10 UTXOs (3 de recepción + 7 de cambio)', utxos.length === 10, String(utxos.length), '10');

const utxoCalls = requested.filter(u => u.endsWith('/utxo')).length;
check('solo pide /utxo para direcciones usadas', utxoCalls === 10, String(utxoCalls), '10');

if (failed) process.exit(1);
