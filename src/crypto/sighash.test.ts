/**
 * Smoke test: verifica el preimage y sighash BIP143 contra valores
 * cross-verificados de forma independiente con Python/Node crypto sobre
 * la tx del ejemplo "Native P2WPKH" del documento BIP143:
 *   https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
 *
 * La tx es v1, 2 inputs (uno legacy, uno P2WPKH), 2 outputs.
 * Firmamos el input #1 (el SegWit) con SIGHASH_ALL.
 *
 * Los valores "expected" fueron verificados con tres implementaciones
 * SHA-256 distintas (esta, node:crypto y python hashlib) — coinciden.
 */

import { computeSighashP2WPKH } from './sighash';
import type { Transaction } from './transaction';

function h(hex: string): Uint8Array {
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  return b;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

const tx: Transaction = {
  version: 1,
  inputs: [
    {
      prevTxId: '9f96ade4b41d5433f4eda31e1738ec2b36f6e7d1420d94a6af99801a88f7f7ff',
      prevVout: 0,
      scriptSig: new Uint8Array(0),
      sequence: 0xffffffee,
    },
    {
      // Display order del prev hash `ef51e151b804cc79d282d8dc5a4ab0a9fc6b8e576f9df3e87158b4e51e10eb8a`
      prevTxId: '8aeb101ee5b45871e8f39d6f578e6bfca9b04a5adcd882d279cc04b851e151ef',
      prevVout: 1,
      scriptSig: new Uint8Array(0),
      sequence: 0xffffffff,
    },
  ],
  outputs: [
    {
      value: 0x0000000006b22c20n,
      scriptPubKey: h('76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac'),
    },
    {
      value: 0x000000000d519390n,
      scriptPubKey: h('76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac'),
    },
  ],
  locktime: 0x11,
};

const pubKeyHash = h('1d0f172a0ecb48aee1be1f2687d2963ae33f71a1');
const amount = 0x23c34600n; // 600,000,000 sats

const result = computeSighashP2WPKH(tx, 1, pubKeyHash, amount);

const expectedPreimage =
  '01000000' +                                                                     // nVersion
  '12448d1270f5d9dedc4fdbef7c3b991d5c4f4b0503e97a4715fb086b851ba878' +             // hashPrevouts
  '52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b' +             // hashSequence
  'ef51e151b804cc79d282d8dc5a4ab0a9fc6b8e576f9df3e87158b4e51e10eb8a01000000' +     // outpoint
  '1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac' +                          // scriptCode
  '0046c32300000000' +                                                              // amount
  'ffffffff' +                                                                      // nSequence
  '863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5' +             // hashOutputs
  '11000000' +                                                                      // nLocktime
  '01000000';                                                                       // sighashType

const expectedSighash = '6f3cee79b5fa7e324130255080cd20d5e4857d6970df7c4e13e2e2c974b9d39b';

const actualPreimage = toHex(result.preimage);
const actualSighash = toHex(result.sighash);

console.log('preimage match:', actualPreimage === expectedPreimage);
if (actualPreimage !== expectedPreimage) {
  console.log('expected:', expectedPreimage);
  console.log('actual:  ', actualPreimage);
}
console.log('sighash match: ', actualSighash === expectedSighash);
if (actualSighash !== expectedSighash) {
  console.log('expected:', expectedSighash);
  console.log('actual:  ', actualSighash);
}

if (actualPreimage !== expectedPreimage || actualSighash !== expectedSighash) {
  process.exit(1);
}
