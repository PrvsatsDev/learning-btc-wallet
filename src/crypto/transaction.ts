/**
 * Estructura de una transacción Bitcoin — implementada desde cero.
 *
 * Una transacción es el mensaje fundamental de Bitcoin: "mueve valor de aquí a allí".
 * Internamente es una secuencia de bytes con una estructura precisa:
 *
 *   [version 4B] [inputs...] [outputs...] [locktime 4B]
 *
 * Con SegWit (BIP141), se añaden marker, flag y witness:
 *   [version 4B] [marker 0x00] [flag 0x01] [inputs...] [outputs...] [witness...] [locktime 4B]
 *
 * El TxID es el doble-SHA256 de la serialización LEGACY (sin witness).
 * Esto es lo que resolvió el problema de maleabilidad de transacciones.
 *
 * Todo en Bitcoin está en little-endian, excepto cuando no lo está.
 * Los hashes se muestran en byte-reversed order (por razones históricas).
 */

import { sha256 } from './sha256';

// ─── Tipos ──────────────────────────────────────────────────

export interface TxInput {
  prevTxId: string;       // hash de la transacción previa (32 bytes, hex)
  prevVout: number;       // índice del output que gastamos (uint32)
  scriptSig: Uint8Array;  // script de desbloqueo (vacío en SegWit)
  sequence: number;       // número de secuencia (uint32, normalmente 0xffffffff)
}

export interface TxOutput {
  value: bigint;              // cantidad en satoshis (int64)
  scriptPubKey: Uint8Array;   // script de bloqueo (condiciones de gasto)
}

export interface Transaction {
  version: number;            // versión (uint32, normalmente 1 o 2)
  inputs: TxInput[];
  outputs: TxOutput[];
  locktime: number;           // bloque o timestamp mínimo para incluir la tx (uint32)
  witnesses?: Uint8Array[][]; // datos witness por input (SegWit)
}

/** Un campo anotado de la serialización (para visualización) */
export interface TxField {
  name: string;
  bytes: Uint8Array;
  description: string;
  color: string;
}

/** Resultado de serializar con anotaciones */
export interface TxSerializationResult {
  raw: Uint8Array;          // bytes crudos
  hex: string;              // hex string
  fields: TxField[];        // campos desglosados
  txid: string;             // TxID (doble SHA-256, byte-reversed)
  size: number;             // tamaño en bytes
  isSegwit: boolean;
}

// ─── VarInt ─────────────────────────────────────────────────
/**
 * VarInt (Variable-length Integer) de Bitcoin.
 *
 * Bitcoin usa un formato compacto para codificar enteros:
 *   - 0x00-0xfc: 1 byte (el valor directamente)
 *   - 0xfd + 2 bytes LE: para valores 0xfd-0xffff
 *   - 0xfe + 4 bytes LE: para valores 0x10000-0xffffffff
 *   - 0xff + 8 bytes LE: para valores mayores
 *
 * Se usa para codificar la cantidad de inputs, outputs, y longitudes de scripts.
 */
export function serializeVarInt(n: number): Uint8Array {
  if (n < 0xfd) {
    return new Uint8Array([n]);
  } else if (n <= 0xffff) {
    const buf = new Uint8Array(3);
    buf[0] = 0xfd;
    buf[1] = n & 0xff;
    buf[2] = (n >> 8) & 0xff;
    return buf;
  } else if (n <= 0xffffffff) {
    const buf = new Uint8Array(5);
    buf[0] = 0xfe;
    buf[1] = n & 0xff;
    buf[2] = (n >> 8) & 0xff;
    buf[3] = (n >> 16) & 0xff;
    buf[4] = (n >> 24) & 0xff;
    return buf;
  }
  throw new Error('VarInt > 32 bits no soportado en esta implementación');
}

export function parseVarInt(data: Uint8Array, offset: number): { value: number; bytesRead: number } {
  const first = data[offset];
  if (first < 0xfd) return { value: first, bytesRead: 1 };
  if (first === 0xfd) {
    const value = data[offset + 1] | (data[offset + 2] << 8);
    return { value, bytesRead: 3 };
  }
  if (first === 0xfe) {
    const value = data[offset + 1] | (data[offset + 2] << 8) |
                  (data[offset + 3] << 16) | (data[offset + 4] << 24);
    return { value: value >>> 0, bytesRead: 5 };
  }
  throw new Error('VarInt de 8 bytes no soportado');
}

// ─── Serialización ──────────────────────────────────────────

/** Serializa uint32 en little-endian */
function uint32LE(n: number): Uint8Array {
  const buf = new Uint8Array(4);
  buf[0] = n & 0xff;
  buf[1] = (n >> 8) & 0xff;
  buf[2] = (n >> 16) & 0xff;
  buf[3] = (n >> 24) & 0xff;
  return buf;
}

/** Serializa int64 en little-endian (para valores de satoshis) */
function int64LE(n: bigint): Uint8Array {
  const buf = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    buf[i] = Number((n >> BigInt(i * 8)) & 0xffn);
  }
  return buf;
}

/** Convierte hex string a bytes (byte-reversed para txids) */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Convierte bytes a hex string */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Reverse bytes (para txids: stored internal byte order → display byte order) */
function reverseBytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array([...bytes].reverse());
}

/** Concatena múltiples arrays */
function concat(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Serializa una transacción en formato legacy (sin witness).
 * Este es el formato que se usa para calcular el TxID.
 */
export function serializeLegacy(tx: Transaction): TxSerializationResult {
  const fields: TxField[] = [];

  // Version
  const versionBytes = uint32LE(tx.version);
  fields.push({
    name: 'Version',
    bytes: versionBytes,
    description: `Versión ${tx.version} — indica qué reglas aplican`,
    color: '#a78bfa', // purple
  });

  // Input count
  const inputCount = serializeVarInt(tx.inputs.length);
  fields.push({
    name: 'Input count',
    bytes: inputCount,
    description: `${tx.inputs.length} input(s) — cuántos UTXOs se gastan`,
    color: '#fbbf24', // amber
  });

  // Each input
  tx.inputs.forEach((input, i) => {
    // Previous tx hash (reversed in serialization)
    const prevHash = reverseBytes(hexToBytes(input.prevTxId));
    fields.push({
      name: `Input ${i}: prevTxId`,
      bytes: prevHash,
      description: `Hash de la tx que creó el UTXO (reversed)`,
      color: '#f87171', // red
    });

    // Previous output index
    const voutBytes = uint32LE(input.prevVout);
    fields.push({
      name: `Input ${i}: vout`,
      bytes: voutBytes,
      description: `Output #${input.prevVout} de esa transacción`,
      color: '#fb923c', // orange
    });

    // ScriptSig
    const scriptLen = serializeVarInt(input.scriptSig.length);
    fields.push({
      name: `Input ${i}: scriptSig len`,
      bytes: scriptLen,
      description: `${input.scriptSig.length} bytes de script de desbloqueo`,
      color: '#38bdf8', // sky
    });
    if (input.scriptSig.length > 0) {
      fields.push({
        name: `Input ${i}: scriptSig`,
        bytes: input.scriptSig,
        description: 'Script que prueba el derecho a gastar el UTXO',
        color: '#38bdf8',
      });
    }

    // Sequence
    const seqBytes = uint32LE(input.sequence);
    fields.push({
      name: `Input ${i}: sequence`,
      bytes: seqBytes,
      description: input.sequence === 0xffffffff ? 'Sin RBF, sin timelock relativo' : `Sequence: 0x${input.sequence.toString(16)}`,
      color: '#94a3b8', // gray
    });
  });

  // Output count
  const outputCount = serializeVarInt(tx.outputs.length);
  fields.push({
    name: 'Output count',
    bytes: outputCount,
    description: `${tx.outputs.length} output(s) — cuántos UTXOs nuevos se crean`,
    color: '#fbbf24',
  });

  // Each output
  tx.outputs.forEach((output, i) => {
    // Value
    const valueBytes = int64LE(output.value);
    fields.push({
      name: `Output ${i}: value`,
      bytes: valueBytes,
      description: `${output.value.toLocaleString()} satoshis (${(Number(output.value) / 1e8).toFixed(8)} BTC)`,
      color: '#4ade80', // green
    });

    // ScriptPubKey
    const spkLen = serializeVarInt(output.scriptPubKey.length);
    fields.push({
      name: `Output ${i}: scriptPubKey len`,
      bytes: spkLen,
      description: `${output.scriptPubKey.length} bytes de script de bloqueo`,
      color: '#2dd4bf', // teal
    });
    fields.push({
      name: `Output ${i}: scriptPubKey`,
      bytes: output.scriptPubKey,
      description: 'Condiciones que deben cumplirse para gastar este UTXO',
      color: '#2dd4bf',
    });
  });

  // Locktime
  const locktimeBytes = uint32LE(tx.locktime);
  fields.push({
    name: 'Locktime',
    bytes: locktimeBytes,
    description: tx.locktime === 0
      ? 'Sin restricción temporal'
      : tx.locktime < 500_000_000
        ? `Válida desde bloque ${tx.locktime}`
        : `Válida desde timestamp ${new Date(tx.locktime * 1000).toISOString()}`,
    color: '#c084fc', // violet
  });

  // Construir raw bytes
  const raw = concat(...fields.map(f => f.bytes));
  const hex = bytesToHex(raw);

  // TxID = double SHA-256, byte-reversed
  const hash1 = hexToBytes(sha256(raw).hash);
  const hash2 = hexToBytes(sha256(hash1).hash);
  const txid = bytesToHex(reverseBytes(hash2));

  return { raw, hex, fields, txid, size: raw.length, isSegwit: false };
}

/**
 * Serializa una transacción en formato SegWit (con witness).
 *
 * SegWit (Segregated Witness, BIP141) separa las firmas ("witness data")
 * del cuerpo de la transacción. Esto soluciona:
 *   1. Maleabilidad de transacciones (las firmas ya no afectan al TxID)
 *   2. Más capacidad por bloque (los datos witness se descuentan)
 *
 * El marker (0x00) y flag (0x01) indican que es una tx SegWit.
 * El TxID se calcula SIN los datos witness (formato legacy).
 */
export function serializeWitness(tx: Transaction): TxSerializationResult {
  if (!tx.witnesses || tx.witnesses.length === 0) {
    return serializeLegacy(tx);
  }

  const fields: TxField[] = [];

  // Version
  fields.push({
    name: 'Version',
    bytes: uint32LE(tx.version),
    description: `Versión ${tx.version}`,
    color: '#a78bfa',
  });

  // Marker + Flag (SegWit indicators)
  fields.push({
    name: 'Marker',
    bytes: new Uint8Array([0x00]),
    description: 'Indica que hay datos witness (siempre 0x00)',
    color: '#e879f9', // fuchsia
  });
  fields.push({
    name: 'Flag',
    bytes: new Uint8Array([0x01]),
    description: 'Flag SegWit (siempre 0x01)',
    color: '#e879f9',
  });

  // Input count + inputs (same as legacy)
  fields.push({
    name: 'Input count',
    bytes: serializeVarInt(tx.inputs.length),
    description: `${tx.inputs.length} input(s)`,
    color: '#fbbf24',
  });

  tx.inputs.forEach((input, i) => {
    fields.push({
      name: `Input ${i}: prevTxId`,
      bytes: reverseBytes(hexToBytes(input.prevTxId)),
      description: 'Hash de la tx anterior (reversed)',
      color: '#f87171',
    });
    fields.push({
      name: `Input ${i}: vout`,
      bytes: uint32LE(input.prevVout),
      description: `Output #${input.prevVout}`,
      color: '#fb923c',
    });
    const scriptLen = serializeVarInt(input.scriptSig.length);
    fields.push({
      name: `Input ${i}: scriptSig len`,
      bytes: scriptLen,
      description: `${input.scriptSig.length} bytes (vacío en SegWit nativo)`,
      color: '#38bdf8',
    });
    if (input.scriptSig.length > 0) {
      fields.push({
        name: `Input ${i}: scriptSig`,
        bytes: input.scriptSig,
        description: 'Script de desbloqueo',
        color: '#38bdf8',
      });
    }
    fields.push({
      name: `Input ${i}: sequence`,
      bytes: uint32LE(input.sequence),
      description: `Sequence: 0x${input.sequence.toString(16).padStart(8, '0')}`,
      color: '#94a3b8',
    });
  });

  // Output count + outputs (same as legacy)
  fields.push({
    name: 'Output count',
    bytes: serializeVarInt(tx.outputs.length),
    description: `${tx.outputs.length} output(s)`,
    color: '#fbbf24',
  });

  tx.outputs.forEach((output, i) => {
    fields.push({
      name: `Output ${i}: value`,
      bytes: int64LE(output.value),
      description: `${output.value.toLocaleString()} satoshis`,
      color: '#4ade80',
    });
    fields.push({
      name: `Output ${i}: scriptPubKey len`,
      bytes: serializeVarInt(output.scriptPubKey.length),
      description: `${output.scriptPubKey.length} bytes`,
      color: '#2dd4bf',
    });
    fields.push({
      name: `Output ${i}: scriptPubKey`,
      bytes: output.scriptPubKey,
      description: 'Script de bloqueo',
      color: '#2dd4bf',
    });
  });

  // Witness data
  tx.witnesses.forEach((witnessItems, i) => {
    fields.push({
      name: `Witness ${i}: item count`,
      bytes: serializeVarInt(witnessItems.length),
      description: `${witnessItems.length} item(s) de witness para input ${i}`,
      color: '#e879f9',
    });
    witnessItems.forEach((item, j) => {
      fields.push({
        name: `Witness ${i}[${j}]: len`,
        bytes: serializeVarInt(item.length),
        description: `${item.length} bytes`,
        color: '#e879f9',
      });
      fields.push({
        name: `Witness ${i}[${j}]: data`,
        bytes: item,
        description: j === 0 ? 'Firma (DER + sighash type)' : 'Clave pública',
        color: '#e879f9',
      });
    });
  });

  // Locktime
  fields.push({
    name: 'Locktime',
    bytes: uint32LE(tx.locktime),
    description: tx.locktime === 0 ? 'Sin restricción temporal' : `Locktime: ${tx.locktime}`,
    color: '#c084fc',
  });

  const raw = concat(...fields.map(f => f.bytes));
  const hex = bytesToHex(raw);

  // TxID = doble SHA-256 de la serialización LEGACY (sin witness)
  const legacy = serializeLegacy(tx);
  const txid = legacy.txid;

  return { raw, hex, fields, txid, size: raw.length, isSegwit: true };
}

// ─── Parser de transacciones ────────────────────────────────

/**
 * Parsea una transacción desde hex crudo.
 * Detecta automáticamente si es legacy o SegWit.
 */
export function parseTxHex(hex: string): Transaction {
  const data = hexToBytes(hex);
  let offset = 0;

  // Version
  const version = data[offset] | (data[offset + 1] << 8) |
                  (data[offset + 2] << 16) | (data[offset + 3] << 24);
  offset += 4;

  // Detectar SegWit: marker=0x00, flag=0x01
  let isSegwit = false;
  if (data[offset] === 0x00 && data[offset + 1] === 0x01) {
    isSegwit = true;
    offset += 2;
  }

  // Input count
  const { value: inputCount, bytesRead: inputCountBytes } = parseVarInt(data, offset);
  offset += inputCountBytes;

  // Inputs
  const inputs: TxInput[] = [];
  for (let i = 0; i < inputCount; i++) {
    const prevTxId = bytesToHex(reverseBytes(data.slice(offset, offset + 32)));
    offset += 32;

    const prevVout = data[offset] | (data[offset + 1] << 8) |
                     (data[offset + 2] << 16) | (data[offset + 3] << 24);
    offset += 4;

    const { value: scriptLen, bytesRead: scriptLenBytes } = parseVarInt(data, offset);
    offset += scriptLenBytes;
    const scriptSig = data.slice(offset, offset + scriptLen);
    offset += scriptLen;

    const sequence = (data[offset] | (data[offset + 1] << 8) |
                      (data[offset + 2] << 16) | (data[offset + 3] << 24)) >>> 0;
    offset += 4;

    inputs.push({ prevTxId, prevVout, scriptSig, sequence });
  }

  // Output count
  const { value: outputCount, bytesRead: outputCountBytes } = parseVarInt(data, offset);
  offset += outputCountBytes;

  // Outputs
  const outputs: TxOutput[] = [];
  for (let i = 0; i < outputCount; i++) {
    let value = 0n;
    for (let j = 0; j < 8; j++) {
      value |= BigInt(data[offset + j]) << BigInt(j * 8);
    }
    offset += 8;

    const { value: spkLen, bytesRead: spkLenBytes } = parseVarInt(data, offset);
    offset += spkLenBytes;
    const scriptPubKey = data.slice(offset, offset + spkLen);
    offset += spkLen;

    outputs.push({ value, scriptPubKey });
  }

  // Witness (if SegWit)
  let witnesses: Uint8Array[][] | undefined;
  if (isSegwit) {
    witnesses = [];
    for (let i = 0; i < inputCount; i++) {
      const { value: itemCount, bytesRead: itemCountBytes } = parseVarInt(data, offset);
      offset += itemCountBytes;
      const items: Uint8Array[] = [];
      for (let j = 0; j < itemCount; j++) {
        const { value: itemLen, bytesRead: itemLenBytes } = parseVarInt(data, offset);
        offset += itemLenBytes;
        items.push(data.slice(offset, offset + itemLen));
        offset += itemLen;
      }
      witnesses.push(items);
    }
  }

  // Locktime
  const locktime = (data[offset] | (data[offset + 1] << 8) |
                    (data[offset + 2] << 16) | (data[offset + 3] << 24)) >>> 0;

  return { version, inputs, outputs, locktime, witnesses };
}

// ─── Transacciones de ejemplo ───────────────────────────────

/** Transacción legacy simple (P2PKH) */
export function exampleLegacyTx(): Transaction {
  return {
    version: 1,
    inputs: [{
      // Un UTXO ficticio
      prevTxId: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
      prevVout: 0,
      scriptSig: hexToBytes(
        '47304402207e2c1eb23f7b7d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e' +
        '02201a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b01' +
        '2103deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef01'
      ),
      sequence: 0xffffffff,
    }],
    outputs: [
      {
        value: 50000n,          // 0.0005 BTC
        scriptPubKey: hexToBytes('76a914' + '89abcdef0123456789abcdef0123456789abcdef' + '88ac'),
      },
      {
        value: 49000n,          // cambio
        scriptPubKey: hexToBytes('76a914' + 'fedcba9876543210fedcba9876543210fedcba98' + '88ac'),
      },
    ],
    locktime: 0,
  };
}

/** Transacción SegWit simple (P2WPKH) */
export function exampleSegwitTx(): Transaction {
  return {
    version: 2,
    inputs: [{
      prevTxId: 'b1a2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
      prevVout: 1,
      scriptSig: new Uint8Array(0), // vacío en SegWit nativo
      sequence: 0xfffffffe,         // RBF habilitado
    }],
    outputs: [
      {
        value: 100000n,
        scriptPubKey: hexToBytes('0014' + '751e76e8199196d454941c45d1b3a323f1433bd6'),
      },
      {
        value: 80000n,
        scriptPubKey: hexToBytes('0014' + '89abcdef0123456789abcdef0123456789abcdef'),
      },
    ],
    locktime: 800000,
    witnesses: [
      [
        // Firma (simulada)
        hexToBytes('304402207e2c1eb23f7b7d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e02201a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b01'),
        // Clave pública (simulada)
        hexToBytes('0303deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef'),
      ],
    ],
  };
}
