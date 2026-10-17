/**
 * Escaneo de una wallet BIP84 contra mempool.space con "gap limit" (BIP44).
 *
 * Una cuenta HD tiene DOS cadenas de direcciones:
 *   m/84'/coin'/0'/0/i  → recepción (las que das para que te paguen)
 *   m/84'/coin'/0'/1/i  → cambio    (a donde vuelve el sobrante al gastar)
 *
 * Si solo miramos la de recepción, el cambio de cada envío "desaparece": los
 * fondos siguen siendo tuyos (los controla la seed), pero la wallet no los ve.
 *
 * ¿Hasta qué índice mirar? La blockchain no lo dice. BIP44 propone el gap
 * limit: recorre la cadena y para cuando encuentres N direcciones SEGUIDAS
 * sin historial (N = 20 en BIP44; aquí 5 para no saturar la API pública).
 * "Sin historial" = tx_count 0 (nunca recibió nada), no "saldo 0": una
 * dirección vaciada ya se usó y no se debe reutilizar.
 */

import {
  derivePath,
  getAddress,
  getDerivationPath,
  type HDNode,
} from '../crypto/hdwallet';
import {
  getAddressInfo,
  getAddressUtxos,
  type AddressInfo,
  type Network,
  type UTXO,
} from './mempool';

export interface ScannedAddress {
  path: string;
  address: string;
  change: boolean;
  index: number;
  info: AddressInfo;
  utxos: UTXO[];
  used: boolean;   // ¿ha tenido alguna transacción (confirmada o en mempool)?
}

export interface ChainScan {
  addresses: ScannedAddress[];
  firstUnused: number;   // primer índice sin historial — el siguiente a usar
}

const DEFAULT_GAP_LIMIT = 5;
const MAX_INDEX = 100;   // tope de seguridad para no hacer peticiones sin fin

async function scanAddress(master: HDNode, network: Network, change: boolean, index: number): Promise<ScannedAddress> {
  const coinType = network === 'mainnet' ? 0 : 1;
  const path = getDerivationPath(84, 0, change, index, coinType);
  const { node } = derivePath(master, path);
  const address = getAddress(node, 84, network === 'mainnet');

  const info = await getAddressInfo(address, network);
  const used = info.chain_stats.tx_count + info.mempool_stats.tx_count > 0;
  // Una dirección nunca usada no puede tener UTXOs: nos ahorramos la petición
  const utxos = used ? await getAddressUtxos(address, network) : [];

  return { path, address, change, index, info, utxos, used };
}

/**
 * Recorre una cadena (recepción o cambio) hasta encontrar `gapLimit`
 * direcciones seguidas sin usar. Consulta en lotes de `gapLimit` en paralelo.
 */
export async function scanChain(
  master: HDNode,
  network: Network,
  change: boolean,
  gapLimit = DEFAULT_GAP_LIMIT,
): Promise<ChainScan> {
  const addresses: ScannedAddress[] = [];
  let gap = 0;
  let firstUnused = -1;

  for (let start = 0; gap < gapLimit && start < MAX_INDEX; start += gapLimit) {
    const batch = await Promise.all(
      Array.from({ length: gapLimit }, (_, k) => scanAddress(master, network, change, start + k)),
    );
    for (const a of batch) {
      if (gap >= gapLimit) break;
      addresses.push(a);
      if (a.used) {
        gap = 0;
        firstUnused = -1;   // un hueco seguido de una usada no cuenta como "siguiente"
      } else {
        if (firstUnused === -1) firstUnused = a.index;
        gap++;
      }
    }
  }

  return { addresses, firstUnused: firstUnused === -1 ? addresses.length : firstUnused };
}

/** Escanea recepción y cambio de la cuenta 0. */
export async function scanWallet(master: HDNode, network: Network, gapLimit = DEFAULT_GAP_LIMIT) {
  const [receive, change] = await Promise.all([
    scanChain(master, network, false, gapLimit),
    scanChain(master, network, true, gapLimit),
  ]);
  return { receive, change };
}
