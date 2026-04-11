# Learning BTC Wallet

Wallet de Bitcoin didáctica construida desde cero para aprender criptografía y el protocolo Bitcoin paso a paso.

Inspirada en [Sparrow Wallet](https://sparrowwallet.com/) y [Liana Wallet](https://wizardsardine.com/liana/).

## Stack

- **TypeScript + React** — frontend interactivo con tipado explícito
- **Tauri** — runtime nativo (Rust), mucho más ligero que Electron
- **Criptografía propia** — todo implementado desde cero, sin librerías externas

## Qué hay implementado

### Fase 1 — Fundamentos criptográficos

Cada módulo tiene su implementación desde cero y un explorador visual interactivo:

| Módulo | Descripción | Archivo |
|--------|-------------|---------|
| **SHA-256** | Padding, message schedule, 64 rondas de compresión, efecto avalancha | `src/crypto/sha256.ts` |
| **RIPEMD-160** | Dos líneas paralelas de compresión, modo Hash160 | `src/crypto/ripemd160.ts` |
| **secp256k1** | Curva elíptica, aritmética modular, point addition, double-and-add | `src/crypto/secp256k1.ts` |
| **Base58Check** | Codificación de direcciones, checksum, validador | `src/crypto/base58.ts` |

Flujo completo implementado:

```
clave privada (256 bits)
  → × G (secp256k1)
  → clave pública
  → SHA-256
  → RIPEMD-160
  → Base58Check
  → dirección Bitcoin
```

### Fase 2 — Primitivas Bitcoin

6 lecciones con criptografía implementada desde cero y exploradores interactivos:

| Módulo | Descripción | Archivos |
|--------|-------------|----------|
| **ECDSA** | Firmas RFC 6979, codificación DER, demo reutilización de k | `src/crypto/ecdsa.ts` |
| **Schnorr** | BIP340, tagged hashes, x-only pubkeys, comparativa con ECDSA | `src/crypto/schnorr.ts` |
| **UTXO** | Simulador de UTXOs, coin selection, comparativa con modelo de cuentas | `src/crypto/utxo.ts` |
| **Transacciones** | Serialización legacy/SegWit, hex coloreado por campo, cálculo de TxID | `src/crypto/transaction.ts` |
| **Bitcoin Script** | Intérprete de pila (~10 opcodes), P2PKH/P2WPKH/P2TR, Bech32/Bech32m | `src/crypto/script.ts` |
| **HD Wallets** | BIP39 mnemónico, BIP32 derivación, BIP44/84/86, PBKDF2-HMAC-SHA512 | `src/crypto/hdwallet.ts` |

Módulos de soporte: SHA-512 (`sha512.ts`), HMAC-SHA256/512 (`hmac.ts`), wordlist BIP39 (`bip39-wordlist.ts`).

## Desarrollo

```bash
# Instalar dependencias
npm install

# Servidor de desarrollo (frontend)
npm run dev

# Aplicación nativa (requiere Rust)
npm run tauri dev
```

## Hoja de ruta

- [x] **Fase 1** — Fundamentos criptográficos (SHA-256, RIPEMD-160, secp256k1, Base58Check)
- [x] **Fase 2** — Primitivas Bitcoin (firmas, UTXOs, transacciones, scripts, HD Wallets)
- [ ] **Fase 3** — Wallet funcional (seed phrase, derivación, conexión a red, broadcast)
- [ ] **Fase 4** — UI visual estilo Sparrow/Liana
