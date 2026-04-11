# Learning BTC Wallet

Wallet de Bitcoin didáctica construida desde cero para aprender criptografía y el protocolo Bitcoin paso a paso.

Inspirada en [Sparrow Wallet](https://sparrowwallet.com/) y [Liana Wallet](https://wizardsardine.com/liana/).

## Stack

- **TypeScript + React** — frontend interactivo con tipado explícito
- **Tauri** — runtime nativo (Rust), mucho más ligero que Electron
- **Criptografía propia** — SHA-256, RIPEMD-160, secp256k1 y Base58 implementados desde cero, sin librerías externas

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

- [x] **Fase 1** — Fundamentos criptográficos
- [ ] **Fase 2** — Bitcoin primitives (UTXOs, transacciones, scripts, HD Wallets)
- [ ] **Fase 3** — Wallet funcional (seed phrase, derivación, broadcast)
- [ ] **Fase 4** — UI visual estilo Sparrow/Liana
