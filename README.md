# Learning BTC Wallet

Wallet de Bitcoin didáctica construida desde cero para aprender criptografía y el protocolo Bitcoin paso a paso.

Inspirada en [Sparrow Wallet](https://sparrowwallet.com/) y [Liana Wallet](https://wizardsardine.com/liana/).

## ⚠️ Aviso — herramienta de aprendizaje, sin garantías

Este es un **proyecto de aprendizaje**. Todo el código se publica "TAL CUAL" (*as is*),
**sin garantía de ningún tipo** y con criptografía implementada desde cero con fines
didácticos, no auditada para producción. **El autor no se hace responsable** de ninguna
pérdida, daño o consecuencia derivada de su uso.

Su propósito es **entender** cómo funciona una wallet Bitcoin por dentro — no custodiar
fondos ni operar en producción. **No introduzcas nunca una seed phrase que custodie fondos
reales en un dispositivo conectado a internet**, ni aquí ni en ninguna otra web o app.

En particular, la herramienta **Entropy Auditor** es material didáctico. Si aun así alguien
se aventura a usarla con palabras reales, tómala **solo como inspiración** para tu propia
solución; y si de todos modos vas a ejecutarla con una semilla real, hazlo como mínimo así:

1. **Revisa y audita el código tú mismo** antes de confiar en él.
2. **Clona el repositorio** y ejecútalo desde la fuente que has revisado.
3. **Hazlo en un equipo desconectado** (*air-gapped*) — ver
   [Uso en equipo air-gapped](#uso-en-equipo-air-gapped).

Al usar este software aceptas que lo haces **bajo tu entera responsabilidad**. Se distribuye
bajo licencia [MIT](LICENSE), que incluye la cláusula estándar de exención de garantías y
responsabilidad.

## Stack

- **TypeScript + React** — frontend interactivo con tipado explícito
- **Tauri** — andamiaje presente para empaquetado nativo futuro (opcional, requiere Rust; la app corre en el navegador sin él)
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

La app corre en el navegador con Vite — no necesitas nada más para usarla:

```bash
# Instalar dependencias
npm install

# Servidor de desarrollo (abre en el navegador)
npm run dev
```

### Fase 3 — Wallet funcional

| Módulo | Descripción | Archivos |
|--------|-------------|----------|
| **Seed Manager** | Generar/importar mnemónico 12/24 palabras, backup, derivar direcciones | `src/components/WalletSetup.tsx` |
| **Balance Checker** | Consulta de UTXOs y saldo vía API mempool.space | `src/components/BalanceChecker.tsx`, `src/api/mempool.ts` |
| **Transaction Builder** | Selección de UTXOs, construcción de tx, firma BIP143 + ECDSA, broadcast | `src/components/TxBuilder.tsx`, `src/crypto/sighash.ts` |
| **Entropy Auditor** | Reconstruye la entropía cruda de un mnemónico offline, verifica checksum y aplica tests "a ojo" de aleatoriedad (inspirado en el caso ColdCard 2026) | `src/components/EntropyAuditor.tsx`, `src/crypto/entropy-audit.ts` |

El Transaction Builder cubre el flujo completo end-to-end:

1. **Inputs** — carga UTXOs de la wallet vía API, selección manual o automática (largest-first).
2. **Outputs** — dirección destino (bech32/bech32m) + cambio con dust limit.
3. **Fee** — estimación en vB con fee rate ajustable.
4. **Firma BIP143** — cálculo del preimage SegWit v0 paso a paso (hashPrevouts, hashSequence, scriptCode P2WPKH, amount, hashOutputs) y firma ECDSA (RFC 6979, low-s, DER) con visualización del preimage anotado.
5. **Broadcast** — POST del hex firmado al endpoint `/tx` de mempool.space; enlace al explorador para ver la tx resultante.

Sanity check del sighash cross-verificado con Python/Node crypto: `src/crypto/sighash.test.ts`.

#### Entropy Auditor

Herramienta nacida a raíz del caso **ColdCard (2026)**, donde Coinkite avisó de semillas
generadas con **~72 bits de entropía en vez de 128**. Reconstruye offline los bits crudos
de un mnemónico (palabra → índice → 11 bits → entropía + checksum), verifica el checksum
BIP39 con el SHA-256 de la Fase 1, y aplica una batería de tests estadísticos.

**Qué SÍ hace:** detectar defectos *groseros* — constantes, mitades repetidas, sesgo de
bits extremo, baja diversidad de bytes. La clase de "firma" que un generador roto podría
dejar.

**Qué NO hace:** medir ni certificar la entropía. La entropía es una propiedad del
*proceso que generó* la semilla, no de la semilla en sí — un valor de 128 bits es idéntico
venga de un RNG perfecto o de uno roto. **Pasar todos los tests no prueba que una semilla
sea segura**, y la reducción sutil tipo ColdCard (bytes de aspecto aleatorio pero de un
espacio pequeño) **no es detectable** analizando una sola semilla.

**El caso ColdCard, técnicamente:** fue un fallback silencioso a un PRNG software — el
firmware debía usar el TRNG hardware (`ckcc.rng_bytes()`) pero, tras migrar a libNgU en
2021, el símbolo resolvió al PRNG de MicroPython (`ngu.random.bytes()`); una guarda de
preprocesador mal escrita impidió que el build abortara. Espacio efectivo resultante:
~40 bits en Mk3, ~72 bits en Mk4/Q/Mk5 (corregido en Mk4/Mk5 v5.6.0 y Q v1.5.0Q). Como
el PRNG produce salida de ancho completo, **no deja firma en los bytes** y solo se
detectaría reconstruyendo el PRNG y buscando por fuerza bruta en su espacio reducido — de
ahí que Coinkite no dé un método de verificación. Referencias:
[aviso Mk3](https://blog.coinkite.com/coldcard-mk3-seed-generation-warning/) ·
[backgrounder técnico](https://blog.coinkite.com/entropy-technical-backgrounder/).

> Recuerda el **aviso** del principio: es material didáctico; para palabras reales, tómalo
> como inspiración y, en su caso, sigue el
> [uso en equipo air-gapped](#uso-en-equipo-air-gapped).

### Fase 4 — UI visual, multisig y Taproot

Herramientas interactivas estilo Sparrow/Liana. Toda la criptografía sigue implementada
desde cero y verificada contra vectores oficiales (BIP32 / BIP341 / BIP342 / BIP350 / BIP387).

| Módulo | Descripción | Archivos |
|--------|-------------|----------|
| **PSBT (BIP174)** | Sobre de firma parcial: los 6 roles (creator → extractor), recorrido visual paso a paso mostrando cómo "firmar = añadir pares clave-valor" | `src/crypto/psbt.ts`, `src/components/PsbtExplorer.tsx` |
| **Multisig P2WSH** | `wsh(sortedmulti(m,n))`, descriptores + checksum (BIP380), direcciones, modo watch-only (pegar xpubs, CKDpub) | `src/crypto/descriptor.ts`, `src/components/MultisigExplorer.tsx` |
| **Taproot** | Tweak key-path (BIP341), script-path (BIP342: TapTree, control block, `OP_CHECKSIGADD`), sighash BIP341, firmas Schnorr | `src/crypto/taproot.ts`, `src/crypto/tapscript.ts`, `src/crypto/sighash-taproot.ts` |
| **Taproot Multisig** | `tr(NUMS, sortedmulti_a(m,…))` watch-only: pega tus xpubs, deriva por rama/índice (CKDpub) y consulta el **saldo real** vía mempool.space | `src/components/TaprootMultisigExplorer.tsx` |
| **MuSig2 (BIP327)** | Firma Schnorr agregada n-de-n: agregación de claves con coeficientes (defensa rogue-key), dos nonces + coef `b` (las 2 rondas), firmas parciales → una sola firma | `src/crypto/musig2.ts`, `src/components/MuSig2Explorer.tsx` |
| **Timelocks (Liana)** | `OP_CHECKSEQUENCEVERIFY`/`OP_CHECKLOCKTIMEVERIFY` en el intérprete (BIP68/112/65) y bóveda Taproot con ruta de recuperación con retardo | `src/crypto/timelock.ts`, `src/components/TimelockExplorer.tsx` |

Además: una sección de **Referencia** con todos los BIPs usados en la app (`src/components/BipReference.tsx`).

Cada explorador hace algo real y verificable: montar el descriptor y las direcciones, firmar
un gasto Taproot script-path y ejecutar el witness con el intérprete, o agregar n firmas
MuSig2 y comprobar que verifican como una sola firma Schnorr.

## Uso en equipo air-gapped

La herramienta **Entropy Auditor** funciona 100% en local: no hace ninguna llamada de red,
no carga recursos externos (fuentes, analytics, CDN) y todo el cálculo usa criptografía
propia con la wordlist BIP39 embebida en el bundle. Aun siendo una herramienta de
aprendizaje, si alguien la ejecuta con una semilla real debe hacerlo en un equipo
desconectado. Como `npm install` sí necesita red, el flujo es:

```bash
# 1) En una máquina CON red:
git clone https://github.com/PrvsatsDev/learning-btc-wallet.git && cd learning-btc-wallet
npm ci            # instala las versiones EXACTAS del package-lock.json

# 2) Copia la carpeta ENTERA (incluido node_modules) por USB al equipo air-gapped.

# 3) En el equipo desconectado, sin red:
npm run dev       # servidor local en localhost, sin telemetría
```

`npm ci` (en vez de `npm install`) instala exactamente lo fijado en el lockfile, sin
resolver versiones nuevas — reproducible y auditable.

**Verificación que puedes hacer tú mismo, sin leer una línea de código:**

- Abre las **DevTools del navegador → pestaña Network** y usa el Auditor: al teclear la
  semilla no debe aparecer **ninguna** petición (0 requests). Es la prueba definitiva de
  que nada sale de la máquina.
- No necesitas Tauri (la capa Rust): con `npm run dev` en el navegador basta, y hay menos
  superficie que auditar.
- Evita clicar los enlaces externos (mempool.space, referencias) mientras la semilla esté
  en pantalla — son navegaciones que sí saldrían a Internet si hubiera red.

**Sobre dependencias de terceros:** el código propio no hace ninguna llamada de red, y las
dependencias directas (React, react-dom, Tauri) tampoco lo hacen en el navegador. Nadie
puede garantizar al 100% el árbol transitivo entero de npm, pero el air-gap es precisamente
la garantía: sin red, aunque algo lo intentara, nada puede salir.

## Hoja de ruta

- [x] **Fase 1** — Fundamentos criptográficos (SHA-256, RIPEMD-160, secp256k1, Base58Check)
- [x] **Fase 2** — Primitivas Bitcoin (firmas, UTXOs, transacciones, scripts, HD Wallets)
- [x] **Fase 3** — Wallet funcional (seed phrase, derivación, conexión a red, firma BIP143 y broadcast)
- [ ] **Fase 4** — UI visual estilo Sparrow/Liana *(en curso)*
  - [x] PSBT (BIP174) y multisig P2WSH con descriptores watch-only
  - [x] Taproot completo (key-path, script-path, sighash BIP341) y multisig `tr(NUMS, sortedmulti_a)`
  - [x] MuSig2 (BIP327): firma Schnorr agregada n-de-n
  - [x] Timelocks `OP_CSV`/`OP_CLTV` y bóveda de recuperación estilo Liana
  - [x] Taproot Multisig watch-only con tus xpubs + saldo real vía mempool.space
  - [ ] Visualizador navegable del árbol de derivación BIP32
  - [ ] Vista inputs → outputs de una transacción
  - [ ] Timeline de UTXOs por dirección

## Licencia

[MIT](LICENSE) © 2026 psatsdev. Software libre, sin garantías (ver el **aviso** al principio
del README).
