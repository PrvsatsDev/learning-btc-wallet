/**
 * Test de timelocks (BIP65 OP_CLTV / BIP68+BIP112 OP_CSV) y bóveda Liana.
 *
 * Dos niveles:
 *   1) INTÉRPRETE — OP_CHECKSEQUENCEVERIFY / OP_CHECKLOCKTIMEVERIFY / OP_DROP,
 *      con todos sus modos de fallo (version, retardo insuficiente, tipos
 *      incompatibles, bit de desactivación, nSequence=final).
 *   2) BÓVEDA LIANA — árbol Taproot con hoja primaria + hoja de recuperación con
 *      retardo. La primaria gasta siempre; la recuperación solo si el nSequence
 *      del input aporta suficiente maduración. Firmas Schnorr reales, witness
 *      ejecutado con el intérprete.
 */

import { executeScript, encodeScriptNumFull, OP } from './script';
import {
  buildLianaVault, spendVault, csvRecoveryLeaf, encodeRelativeBlocks, encodeRelativeTime,
} from './timelock';
import { getPublicKey } from './secp256k1';

let failures = 0;
function check(name: string, cond: boolean, got?: string, want?: string) {
  console.log(`${cond ? 'OK  ' : 'FAIL'} ${name}`);
  if (!cond) { failures++; if (got !== undefined) { console.log('  got :', got); console.log('  want:', want); } }
}

function to32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = n;
  for (let i = 31; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}
function xonly(priv: bigint): Uint8Array { return to32(getPublicKey(priv)!.x); }

// ─── 1) INTÉRPRETE: OP_CSV ──────────────────────────────────
// Script mínimo: <N> OP_CSV OP_DROP OP_1  (deja true si el timelock pasa)

function csvScript(n: number): Uint8Array {
  const val = encodeScriptNumFull(n);
  return new Uint8Array([val.length, ...val, OP.OP_CHECKSEQUENCEVERIFY, OP.OP_DROP, OP.OP_1]);
}

{
  // relative locktime de 6 bloques
  const script = csvScript(6);

  // input aporta 6 → cumple
  check('[csv] input madura 6 ≥ exigido 6 → válido',
    executeScript(script, undefined, { txVersion: 2, nSequence: 6 }).success);
  // input aporta 10 → cumple de sobra
  check('[csv] input madura 10 ≥ exigido 6 → válido',
    executeScript(script, undefined, { txVersion: 2, nSequence: 10 }).success);
  // input aporta 5 → NO cumple
  check('[csv] input madura 5 < exigido 6 → inválido',
    !executeScript(script, undefined, { txVersion: 2, nSequence: 5 }).success);
  // tx version 1 → BIP68 no aplica → falla
  check('[csv] tx version 1 → falla (BIP68 exige v≥2)',
    !executeScript(script, undefined, { txVersion: 1, nSequence: 6 }).success);
  // nSequence con bit de desactivación (0x80000000 | 6) → el input NO opta al relative locktime
  check('[csv] input con bit de desactivación → falla',
    !executeScript(script, undefined, { txVersion: 2, nSequence: 0x80000000 | 6 }).success);
  // tipos incompatibles: script pide bloques, input aporta "tiempo" (type flag)
  check('[csv] tipos incompatibles (bloques vs tiempo) → falla',
    !executeScript(script, undefined, { txVersion: 2, nSequence: 0x00400000 | 6 }).success);
}

// ─── 1b) INTÉRPRETE: OP_CLTV ────────────────────────────────
// Script: <height> OP_CLTV OP_DROP OP_1

function cltvScript(h: number): Uint8Array {
  const val = encodeScriptNumFull(h);
  return new Uint8Array([val.length, ...val, OP.OP_CHECKLOCKTIMEVERIFY, OP.OP_DROP, OP.OP_1]);
}

{
  const script = cltvScript(800000); // altura de bloque

  check('[cltv] nLockTime 800000 ≥ exigido → válido',
    executeScript(script, undefined, { nLockTime: 800000, nSequence: 0 }).success);
  check('[cltv] nLockTime 900000 ≥ exigido → válido',
    executeScript(script, undefined, { nLockTime: 900000, nSequence: 0 }).success);
  check('[cltv] nLockTime 799999 < exigido → inválido',
    !executeScript(script, undefined, { nLockTime: 799999, nSequence: 0 }).success);
  // nSequence=final deshabilita nLockTime → falla aunque la altura baste
  check('[cltv] nSequence=0xffffffff deshabilita nLockTime → falla',
    !executeScript(script, undefined, { nLockTime: 800000, nSequence: 0xffffffff }).success);
  // mezclar altura (script) con timestamp (nLockTime ≥ 5e8) → falla
  check('[cltv] mezclar altura de bloque con timestamp → falla',
    !executeScript(script, undefined, { nLockTime: 1_700_000_000, nSequence: 0 }).success);
}

// ─── 1c) BIP68: codificación de nSequence ───────────────────
{
  check('[bip68] 6 bloques → 0x000006', encodeRelativeBlocks(6) === 6);
  check('[bip68] 65535 bloques ok', encodeRelativeBlocks(65535) === 65535);
  // 1024 s = 2 unidades de 512 s, con type flag (bit 22)
  check('[bip68] 1024 s → 2 unidades + type flag', encodeRelativeTime(1024) === (0x00400000 | 2));
  let threw = false;
  try { encodeRelativeBlocks(70000); } catch { threw = true; }
  check('[bip68] > 65535 bloques lanza error', threw);
}

// ─── 2) BÓVEDA LIANA end-to-end ─────────────────────────────
{
  const primaryPriv = 0x1111111111111111111111111111111111111111111111111111111111111111n;
  const recoveryPriv = 0x2222222222222222222222222222222222222222222222222222222222222222n;
  const TIMELOCK = 6; // bloques

  const vault = buildLianaVault({
    primaryXonly: xonly(primaryPriv),
    recoveryXonly: xonly(recoveryPriv),
    timelockBlocks: TIMELOCK,
    mainnet: true,
  });

  check('[liana] genera dirección Taproot bc1p', vault.address.startsWith('bc1p'));
  check('[liana] descriptor estilo Liana con older()',
    vault.descriptor.includes(`older(${TIMELOCK})`) && vault.descriptor.startsWith('tr('));
  check('[liana] las dos hojas tienen hash distinto',
    vault.primaryLeafHash.join(',') !== vault.recoveryLeafHash.join(','));

  // La ruta PRIMARIA gasta siempre (sin importar el timelock)
  const primarySpend = spendVault({ vault, path: 'primary', privateKey: primaryPriv });
  check('[liana] ruta primaria firma y valida (sin timelock)', primarySpend.valid, primarySpend.error);

  // La primaria NO puede gastar con la clave de recuperación (firma no coincide)
  const wrongKey = spendVault({ vault, path: 'primary', privateKey: recoveryPriv });
  check('[liana] ruta primaria con clave equivocada → inválido', !wrongKey.valid);

  // La ruta de RECUPERACIÓN con maduración suficiente (nSequence = TIMELOCK) → válida
  const recoverOk = spendVault({ vault, path: 'recovery', privateKey: recoveryPriv, nSequence: TIMELOCK });
  check('[liana] recuperación con nSequence ≥ retardo → válida', recoverOk.valid, recoverOk.error);

  // La ruta de RECUPERACIÓN sin maduración suficiente (nSequence = TIMELOCK-1) → falla el CSV
  const recoverEarly = spendVault({ vault, path: 'recovery', privateKey: recoveryPriv, nSequence: TIMELOCK - 1 });
  check('[liana] recuperación demasiado pronto (nSequence < retardo) → inválida', !recoverEarly.valid);

  // La recuperación con tx version 1 falla (BIP68)
  const recoverV1 = spendVault({ vault, path: 'recovery', privateKey: recoveryPriv, nSequence: TIMELOCK, txVersion: 1 });
  check('[liana] recuperación con tx version 1 → inválida (BIP68)', !recoverV1.valid);

  // La recuperación firmada con la clave primaria (equivocada) → inválida
  const recoverWrong = spendVault({ vault, path: 'recovery', privateKey: primaryPriv, nSequence: TIMELOCK });
  check('[liana] recuperación con clave equivocada → inválida', !recoverWrong.valid);

  // Propiedad: reordenar no aplica (dos hojas fijas), pero el control block de cada
  // hoja debe reconstruir la misma output key (comprobado implícitamente al validar).
  check('[liana] la tx de recuperación es SegWit v1 (version 2)', recoverOk.txVersion === 2);
}

// ─── 3) csvRecoveryLeaf: forma del script ───────────────────
{
  const leaf = csvRecoveryLeaf(6, xonly(3n));
  // <push 01><06> CSV(0xb2) DROP(0x75) <push 20><32B> CHECKSIG(0xac)
  check('[leaf] empieza con push del valor 6', leaf[0] === 0x01 && leaf[1] === 0x06);
  check('[leaf] contiene OP_CSV y OP_DROP', leaf[2] === 0xb2 && leaf[3] === 0x75);
  check('[leaf] termina en push32 + OP_CHECKSIG', leaf[4] === 0x20 && leaf[leaf.length - 1] === 0xac);
}

console.log(failures === 0 ? '\nTODO OK ✓' : `\n${failures} FALLO(S) ✗`);
if (failures > 0) process.exit(1);
