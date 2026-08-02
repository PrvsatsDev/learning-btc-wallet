# Bitcoin Wallet — Proyecto de Aprendizaje

## Qué es esto

Una wallet de Bitcoin didáctica, visualmente rica, inspirada en Sparrow y Liana.
El objetivo NO es solo construirla — es entender cada concepto mientras la construimos.

**Stack elegido:** TypeScript + React + Tauri
- Tauri: runtime nativo (Rust bajo el capó), mucho más ligero que Electron
- React: UI visual e interactiva
- TypeScript: tipado explícito que hace los conceptos Bitcoin tangibles
- `bitcoinjs-lib`: librería Bitcoin madura para Node/TS

## Filosofía del proyecto

1. Cada módulo nuevo va acompañado de su explicación conceptual
2. Construimos una guía visual paralela al código
3. Usamos Claude Code (agents, skills, slash commands, hooks) como parte del proceso
4. Primero entendemos, luego implementamos

---

## Hoja de ruta

### Fase 1 — Fundamentos criptográficos ✅
- [x] SHA-256 y RIPEMD-160 (implementación manual + explicación)
- [x] Curvas elípticas secp256k1
- [x] Clave privada → clave pública → dirección Bitcoin

### Fase 2 — Primitivas Bitcoin ✅
- [x] Firmas: ECDSA (RFC 6979, DER) y Schnorr (BIP340, tagged hashes)
- [x] UTXO model (vs account model), coin selection
- [x] Estructura de una transacción (legacy + SegWit, serialización, TxID)
- [x] Scripts: P2PKH, P2WPKH, P2TR (Taproot), Bech32/Bech32m
- [x] HD Wallets: BIP32 / BIP39 / BIP44 / BIP84 / BIP86 (con SHA-512, HMAC, PBKDF2)

### Fase 3 — La wallet funcional ✅
- [x] Generar e importar seed phrase (12/24 palabras)
- [x] Derivar árbol de cuentas y direcciones
- [x] Conectar a nodo vía mempool.space API (saldos + UTXOs)
- [x] Construir transacciones (selección de UTXOs, fees, cambio)
- [x] Firmar con BIP143 sighash + ECDSA y broadcast a la red

### Fase 4 — UI visual (Sparrow/Liana-style) 🚧 en curso
- [x] Multisig P2WSH + PSBT (BIP174) con descriptores watch-only
- [x] Taproot completo (key-path, script-path, sighash BIP341) + `tr(NUMS, sortedmulti_a)`
- [x] MuSig2 (BIP327): firma Schnorr agregada n-de-n
- [x] Timelocks OP_CSV/OP_CLTV + bóveda de recuperación estilo Liana
- [x] Taproot Multisig watch-only con xpubs del usuario + saldo real vía mempool.space
- [ ] Visualizador del árbol de derivación de claves (BIP32 tree)
- [ ] Vista de transacción: inputs → outputs con amounts
- [ ] Timeline de UTXOs por dirección

---

## Claude Code — Cosas a explorar juntos

- **Slash commands**: `/derive-key`, `/decode-tx`, `/explain-script`
- **Agents**: un agente que reciba un tx hex y lo explique en lenguaje natural
- **Hooks**: ejecutar tests automáticamente al modificar código criptográfico
- **Skills**: generar diagramas de flujo de transacciones
- **MCP servers**: integración con mempool.space u otras herramientas externas

---

## Primer paso al volver

Fase 4 muy avanzada: ya hay exploradores de multisig P2WSH, PSBT, Taproot
(key/script-path), Taproot Multisig watch-only (xpubs propias + saldo real vía
mempool.space), MuSig2 y timelocks estilo Liana — toda la cripto desde cero y
verificada contra vectores. Lo que **queda de Fase 4** es la parte más "visual
Sparrow/Liana": árbol de derivación BIP32 navegable, vista inputs→outputs de una
tx, y timeline de UTXOs por dirección.

---

## Referencias

- [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) — HD Wallets
- [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) — Mnemonic seed phrases
- [bitcoinjs-lib](https://github.com/bitcoinjs/bitcoinjs-lib) — Librería TS/JS
- [Sparrow Wallet](https://sparrowwallet.com/) — Inspiración UI (transactions, UTXOs)
- [Liana Wallet](https://wizardsardine.com/liana/) — Inspiración (timelocks, multisig visual)
- [mempool.space API](https://mempool.space/docs/api) — Para conectar a la red sin nodo propio
