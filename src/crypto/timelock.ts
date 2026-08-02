/**
 * Timelocks estilo Liana — bóveda Taproot con ruta de recuperación con retardo.
 *
 * La idea de Liana: una llave PRIMARIA que gasta siempre, y una llave de
 * RECUPERACIÓN que solo funciona pasado un timelock. Es un "dead man's switch"
 * on-chain: si pierdes la primaria, tras el retardo recuperas los fondos.
 *
 * Se apoya en dos timelocks de Bitcoin:
 *   · ABSOLUTO   — OP_CHECKLOCKTIMEVERIFY (BIP65) contra nLockTime de la tx.
 *                  "No antes del bloque/fecha X."
 *   · RELATIVO   — OP_CHECKSEQUENCEVERIFY (BIP112) contra nSequence (BIP68).
 *                  "No antes de N bloques/tiempo desde que se confirmó el UTXO."
 *                  Es el que usa Liana para el retardo de recuperación.
 *
 * En Taproot, cada ruta de gasto es una HOJA del árbol. La bóveda es un árbol
 * con dos hojas y nadie ve la ruta que no usas:
 *
 *        TapTree
 *       /        \
 *   PRIMARIA      RECUPERACIÓN
 *   <pk> CHECKSIG   <N> CSV DROP <pk_rec> CHECKSIG
 *
 * Clave interna NUMS (sin dueño) → el key-path queda inutilizado y solo se puede
 * gastar cumpliendo una de las dos hojas por script-path.
 *
 * Reutiliza tapscript.ts (árbol, control blocks, tweak) y el intérprete de
 * script.ts (que ahora entiende OP_CSV/OP_CLTV/OP_DROP con contexto de tx).
 */

import { OP, encodeScriptNumFull, createP2TR, addressP2TR, executeScript } from './script';
import { tapLeafHash, taprootScriptOutput, TAPROOT_LEAF_VERSION, type TapTree } from './tapscript';
import { NUMS_H, descriptorChecksum } from './descriptor';
import { computeSighashTaproot } from './sighash-taproot';
import { schnorrSign, schnorrVerify } from './schnorr';
import { bytesToBigint, bytesToHex } from './hmac';
import { serializeWitness, type Transaction, type TxOutput } from './transaction';

// ─── BIP68: codificar el nSequence relativo ─────────────────

const SEQUENCE_TYPE_FLAG = 0x00400000;  // bit 22: cuenta tiempo (512s) en vez de bloques

/**
 * Codifica un retardo relativo en BLOQUES como valor de nSequence (BIP68).
 * Con el type flag a 0, el valor es simplemente el nº de bloques (máx. 65535).
 */
export function encodeRelativeBlocks(blocks: number): number {
  if (blocks < 0 || blocks > 0xffff) throw new Error('BIP68: bloques fuera de rango (0..65535)');
  return blocks;
}

/**
 * Codifica un retardo relativo en TIEMPO como valor de nSequence (BIP68).
 * La unidad es de 512 segundos, con el type flag (bit 22) puesto.
 */
export function encodeRelativeTime(seconds: number): number {
  const units = Math.ceil(seconds / 512);
  if (units < 0 || units > 0xffff) throw new Error('BIP68: tiempo fuera de rango');
  return SEQUENCE_TYPE_FLAG | units;
}

// ─── Hojas de script ────────────────────────────────────────

function push(data: Uint8Array): number[] {
  if (data.length > 0x4b) throw new Error('push demasiado grande para este demo');
  return [data.length, ...data];
}

/** Hoja PRIMARIA de clave única: `<pk> OP_CHECKSIG`. */
export function singleKeyLeaf(xonly: Uint8Array): Uint8Array {
  if (xonly.length !== 32) throw new Error('la clave debe ser x-only (32 bytes)');
  return new Uint8Array([0x20, ...xonly, OP.OP_CHECKSIG]);
}

/**
 * Hoja de RECUPERACIÓN con retardo relativo:
 *   `<N> OP_CHECKSEQUENCEVERIFY OP_DROP <pk_rec> OP_CHECKSIG`
 *
 * El `<N>` es el nSequence codificado (bloques o tiempo). OP_CSV lo verifica sin
 * sacarlo, OP_DROP lo retira, y luego se comprueba la firma de recuperación.
 */
export function csvRecoveryLeaf(sequenceValue: number, recoveryXonly: Uint8Array): Uint8Array {
  if (recoveryXonly.length !== 32) throw new Error('la clave debe ser x-only (32 bytes)');
  const n = encodeScriptNumFull(sequenceValue);
  return new Uint8Array([
    ...push(n),
    OP.OP_CHECKSEQUENCEVERIFY,
    OP.OP_DROP,
    0x20, ...recoveryXonly,
    OP.OP_CHECKSIG,
  ]);
}

/**
 * Hoja de recuperación con timelock ABSOLUTO (variante con OP_CLTV):
 *   `<height> OP_CHECKLOCKTIMEVERIFY OP_DROP <pk_rec> OP_CHECKSIG`
 */
export function cltvRecoveryLeaf(locktime: number, recoveryXonly: Uint8Array): Uint8Array {
  if (recoveryXonly.length !== 32) throw new Error('la clave debe ser x-only (32 bytes)');
  const n = encodeScriptNumFull(locktime);
  return new Uint8Array([
    ...push(n),
    OP.OP_CHECKLOCKTIMEVERIFY,
    OP.OP_DROP,
    0x20, ...recoveryXonly,
    OP.OP_CHECKSIG,
  ]);
}

// ─── Bóveda Liana ───────────────────────────────────────────

export interface LianaVault {
  primaryLeaf: Uint8Array;
  recoveryLeaf: Uint8Array;
  primaryLeafHash: Uint8Array;
  recoveryLeafHash: Uint8Array;
  primaryControlBlock: Uint8Array;
  recoveryControlBlock: Uint8Array;
  merkleRoot: Uint8Array;
  outputKey: bigint;         // Q.x
  scriptPubKey: Uint8Array;
  address: string;
  descriptor: string;        // estilo miniscript de Liana
  timelockBlocks: number;
}

export interface BuildVaultParams {
  primaryXonly: Uint8Array;   // clave primaria (gasta siempre)
  recoveryXonly: Uint8Array;  // clave de recuperación (solo tras el retardo)
  timelockBlocks: number;     // retardo relativo en bloques (BIP68)
  mainnet?: boolean;
  internalXonly?: Uint8Array; // clave interna (por defecto NUMS)
}

function to32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = n;
  for (let i = 31; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  return bytes;
}

/**
 * Construye la bóveda Liana: un output Taproot con dos hojas (primaria +
 * recuperación con retardo) y clave interna NUMS.
 */
export function buildLianaVault(params: BuildVaultParams): LianaVault {
  const { primaryXonly, recoveryXonly, timelockBlocks, mainnet = true } = params;
  const internalXonly = params.internalXonly ?? hexToBytes(NUMS_H);

  const primaryLeaf = singleKeyLeaf(primaryXonly);
  const seq = encodeRelativeBlocks(timelockBlocks);
  const recoveryLeaf = csvRecoveryLeaf(seq, recoveryXonly);

  // El orden de las hojas en el árbol: [primaria, recuperación].
  const tree: TapTree = [{ script: primaryLeaf }, { script: recoveryLeaf }];
  const out = taprootScriptOutput(bytesToBigint(internalXonly), tree);

  // taprootScriptOutput preserva el orden de las hojas en out.leaves.
  const primaryInfo = out.leaves[0];
  const recoveryInfo = out.leaves[1];

  const outputKeyBytes = to32(out.outputKey);
  const scriptPubKey = createP2TR(outputKeyBytes);
  const address = addressP2TR(outputKeyBytes, mainnet);

  const internalHex = bytesToHex(internalXonly);
  const primaryHex = bytesToHex(primaryXonly);
  const recoveryHex = bytesToHex(recoveryXonly);
  // Descriptor estilo Liana (miniscript): pk primaria O (older(N) Y pk recuperación).
  const body = `tr(${internalHex},{pk(${primaryHex}),and_v(v:older(${timelockBlocks}),pk(${recoveryHex}))})`;

  return {
    primaryLeaf,
    recoveryLeaf,
    primaryLeafHash: primaryInfo.leafHash,
    recoveryLeafHash: recoveryInfo.leafHash,
    primaryControlBlock: out.controlBlocks[0],
    recoveryControlBlock: out.controlBlocks[1],
    merkleRoot: out.merkleRoot,
    outputKey: out.outputKey,
    scriptPubKey,
    address,
    descriptor: `${body}#${descriptorChecksum(body)}`,
    timelockBlocks,
  };
}

// ─── Gastar la bóveda (firmar + montar witness + verificar) ─

export interface WitnessRow { label: string; hex: string; kind: 'sig' | 'script' | 'control' }
export interface SpendResult {
  path: 'primary' | 'recovery';
  valid: boolean;
  witness: WitnessRow[];
  txHex: string;
  txid: string;
  nSequence: number;
  txVersion: number;
  error?: string;
}

export interface SpendParams {
  vault: LianaVault;
  path: 'primary' | 'recovery';
  privateKey: bigint;   // clave que firma (primaria o recuperación)
  amount?: bigint;      // valor del UTXO (sats)
  nSequence?: number;   // nSequence del input (para la ruta de recuperación)
  txVersion?: number;   // version de la tx (recuperación exige >= 2)
}

/**
 * Firma un gasto de la bóveda por la ruta elegida y VERIFICA el witness
 * ejecutándolo con el intérprete (que aplica el timelock). Devuelve el veredicto
 * y la tx cruda. Si el timelock no se cumple, el intérprete devuelve valid=false.
 */
export function spendVault(params: SpendParams): SpendResult {
  const { vault, path, privateKey } = params;
  const amount = params.amount ?? 100_000n;
  const isRecovery = path === 'recovery';
  // Por defecto, la recuperación aporta justo el retardo exigido; la primaria no
  // necesita relative locktime (nSequence final).
  const nSequence = params.nSequence ?? (isRecovery ? vault.timelockBlocks : 0xffffffff);
  const txVersion = params.txVersion ?? 2;

  const leaf = isRecovery ? vault.recoveryLeaf : vault.primaryLeaf;
  const leafHash = isRecovery ? vault.recoveryLeafHash : vault.primaryLeafHash;
  const controlBlock = isRecovery ? vault.recoveryControlBlock : vault.primaryControlBlock;

  // Destino de prueba: un P2WPKH cualquiera.
  const dest = hexToBytes('0014751e76e8199196d454941c45d1b3a323f1433bd6');
  const unsigned: Transaction = {
    version: txVersion,
    inputs: [{ prevTxId: '00'.repeat(31) + '01', prevVout: 0, scriptSig: new Uint8Array(0), sequence: nSequence }],
    outputs: [{ value: amount - 2000n, scriptPubKey: dest }],
    locktime: 0,
  };
  const prevout: TxOutput = { value: amount, scriptPubKey: vault.scriptPubKey };

  // Sighash BIP341 script-path (compromete la hoja) → firma Schnorr con la clave
  // SIN ajustar (el tweak es solo para key-path).
  const sighash = computeSighashTaproot(unsigned, 0, [prevout], { ext: { tapLeafHash: leafHash } }).sigHash;
  const sig = hexToBytes(schnorrSign(sighash, privateKey).signatureHex);

  // Witness script-path: [<sig>, script, controlBlock].
  const witnessStack = [sig, leaf, controlBlock];
  unsigned.witnesses = [witnessStack];
  const ser = serializeWitness(unsigned);

  // Verificamos ejecutando <sig> + leaf con Schnorr real y el contexto de tx.
  const checkSig = (s: Uint8Array, pub: Uint8Array): boolean => {
    if (s.length !== 64) return false;
    return schnorrVerify(sighash,
      { r: bytesToBigint(s.slice(0, 32)), s: bytesToBigint(s.slice(32, 64)) },
      bytesToBigint(pub)).valid;
  };
  const scriptBytes = new Uint8Array([sig.length, ...sig, ...leaf]);
  const exec = executeScript(scriptBytes, checkSig, { txVersion, nSequence, nLockTime: 0 });

  const witness: WitnessRow[] = [
    { label: 'firma Schnorr', hex: bytesToHex(sig), kind: 'sig' },
    { label: isRecovery ? 'script (hoja recuperación + CSV)' : 'script (hoja primaria)', hex: bytesToHex(leaf), kind: 'script' },
    { label: 'control block', hex: bytesToHex(controlBlock), kind: 'control' },
  ];

  return {
    path,
    valid: exec.success,
    witness,
    txHex: ser.hex,
    txid: ser.txid,
    nSequence,
    txVersion,
    error: exec.error,
  };
}

export { tapLeafHash, TAPROOT_LEAF_VERSION };
