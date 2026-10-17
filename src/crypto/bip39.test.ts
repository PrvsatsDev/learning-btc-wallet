/**
 * Test de BIP39 mnemonicToSeed: vector oficial + normalización NFKD.
 *
 * Vector: https://github.com/trezor/python-mnemonic/blob/master/vectors.json
 * (entropía 00…00, passphrase "TREZOR").
 *
 * Sin framework: console.log + process.exit(1). Ejecutar bundleando con rolldown.
 */

import { mnemonicToSeed } from './hdwallet';

let failed = false;
function check(name: string, cond: boolean, got?: string, want?: string) {
  console.log(`${cond ? '✓' : '✗'} ${name}`);
  if (!cond) {
    failed = true;
    if (got !== undefined) console.log(`    got:  ${got}`);
    if (want !== undefined) console.log(`    want: ${want}`);
  }
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

const words = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'.split(' ');

// 1. Vector oficial
const seed = bytesToHex(mnemonicToSeed(words, 'TREZOR'));
const want = 'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04';
check('vector Trezor (passphrase "TREZOR")', seed === want, seed, want);

// 2. NFKD: "ñ" compuesta (U+00F1) y descompuesta (n + U+0303) → misma seed
const composed = 'contraseña';
const decomposed = 'contraseña';
check('las dos "ñ" son strings distintos antes de normalizar', composed !== decomposed);
const a = bytesToHex(mnemonicToSeed(words, composed));
const b = bytesToHex(mnemonicToSeed(words, decomposed));
check('passphrase con "ñ" compuesta y descompuesta da la misma seed', a === b, b, a);

// 3. NFKD también pliega compatibilidades: "ﬁ" (ligadura U+FB01) → "fi"
const lig = bytesToHex(mnemonicToSeed(words, 'ﬁ'));
const plain = bytesToHex(mnemonicToSeed(words, 'fi'));
check('ligadura "ﬁ" equivale a "fi" (la K de NFKD)', lig === plain, lig, plain);

if (failed) process.exit(1);
