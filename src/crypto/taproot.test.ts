/**
 * Test del tweak Taproot (BIP341), verificado contra el vector OFICIAL
 * (key-path only, sin árbol de scripts) de:
 *   https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json
 *
 *   internalPubkey : d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d
 *   tweak          : b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70
 *   tweakedPubkey  : 53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343
 *   scriptPubKey   : 512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343
 *   bip350Address  : bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5
 *
 * Además: consistencia clave-privada ↔ clave-pública (ajustar la privada y firmar
 * produce una firma Schnorr válida contra la output key ajustada).
 */

import { tapTweak, tweakPublicKey, p2trScriptPubKey, p2trAddress, keyPathSign, bytesToHex } from './taproot';
import { schnorrVerify } from './schnorr';
import { getPublicKey } from './secp256k1';

let failures = 0;
function check(name: string, cond: boolean, got?: string, want?: string) {
  console.log(`${cond ? 'OK  ' : 'FAIL'} ${name}`);
  if (!cond) { failures++; if (got !== undefined) { console.log('  got :', got); console.log('  want:', want); } }
}

function toHex32(n: bigint): string {
  return n.toString(16).padStart(64, '0');
}

// ─── Vector oficial BIP341 (key-path only) ──────────────────

const internalX = 0xd6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961dn;
const wantTweak = 'b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70';
const wantOutput = '53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343';
const wantSpk = '512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343';
const wantAddr = 'bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5';

const { tweak } = tapTweak(internalX);
check('tweak coincide con BIP341', bytesToHex(tweak) === wantTweak, bytesToHex(tweak), wantTweak);

const { outputKey } = tweakPublicKey(internalX);
check('output key (Q.x) coincide con BIP341', toHex32(outputKey) === wantOutput, toHex32(outputKey), wantOutput);

check('scriptPubKey coincide (OP_1 <32B>)',
  bytesToHex(p2trScriptPubKey(internalX)) === wantSpk, bytesToHex(p2trScriptPubKey(internalX)), wantSpk);

check('dirección bech32m coincide',
  p2trAddress(internalX, true) === wantAddr, p2trAddress(internalX, true), wantAddr);

// ─── Consistencia privada ↔ pública + firma key-path ────────

const priv = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefn;
const P = getPublicKey(priv)!;
const internalX2 = P.x; // clave interna x-only de nuestra propia clave

const { outputKey: out2 } = tweakPublicKey(internalX2);
const message = new Uint8Array(32).fill(0xab); // "sighash" ficticio de 32 bytes
const signed = keyPathSign(message, priv);

check('la privada ajustada firma como la output key ajustada',
  toHex32(signed.outputKey) === toHex32(out2), toHex32(signed.outputKey), toHex32(out2));

const verify = schnorrVerify(message, signed.schnorr.signature, out2);
check('la firma Schnorr key-path verifica contra Q ✓', verify.valid);

// ─── Veredicto ──────────────────────────────────────────────

console.log(failures === 0 ? '\nTODO OK ✓' : `\n${failures} FALLO(S) ✗`);
if (failures > 0) process.exit(1);
