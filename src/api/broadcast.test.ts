/**
 * Test de la barrera anti-mainnet de broadcastTx.
 *
 * La wallet es didáctica: nunca debe emitir en mainnet. El tipo
 * BroadcastNetwork ya lo impide al compilar, pero aquí forzamos 'mainnet'
 * con un cast (como haría un `any` olvidado) y comprobamos que la función
 * lo rechaza SIN hacer ninguna petición. Simulamos fetch para contarlas.
 *
 * Sin framework: console.log + process.exit(1). Ejecutar bundleando con rolldown.
 */

import { broadcastTx, BROADCAST_NETWORKS, type BroadcastNetwork } from './mempool';

let failed = false;
function check(name: string, cond: boolean, got?: string) {
  console.log(`${cond ? '✓' : '✗'} ${name}`);
  if (!cond) {
    failed = true;
    if (got !== undefined) console.log(`    got:  ${got}`);
  }
}

const requested: string[] = [];
globalThis.fetch = (async (url: string | URL | Request) => {
  requested.push(String(url));
  return new Response('f'.repeat(64), { status: 200 });
}) as typeof fetch;

// 1. Mainnet forzado con cast → error y cero peticiones
let error = '';
try {
  await broadcastTx('00', 'mainnet' as BroadcastNetwork);
} catch (e) {
  error = e instanceof Error ? e.message : String(e);
}
check('mainnet forzado lanza error', error.includes('Broadcast bloqueado'), error);
check('mainnet forzado no hace ninguna petición', requested.length === 0, requested.join(', '));

// 2. Cualquier otro valor raro, también fuera
requested.length = 0;
error = '';
try {
  await broadcastTx('00', 'regtest' as BroadcastNetwork);
} catch (e) {
  error = e instanceof Error ? e.message : String(e);
}
check('red desconocida lanza error', error.includes('Broadcast bloqueado'), error);
check('red desconocida no hace ninguna petición', requested.length === 0);

// 3. Las redes de prueba siguen funcionando, cada una contra su endpoint
check('solo testnet4 y signet permitidas', BROADCAST_NETWORKS.join(',') === 'testnet4,signet');
for (const n of BROADCAST_NETWORKS) {
  requested.length = 0;
  const txid = await broadcastTx('00', n);
  check(`${n}: devuelve el txid`, txid === 'f'.repeat(64));
  check(`${n}: POST a /${n}/api/tx`, requested[0] === `https://mempool.space/${n}/api/tx`, requested[0]);
}

if (failed) {
  console.log('\nFALLOS');
  process.exit(1);
}
console.log('\nTodo OK');
