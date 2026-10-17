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

## Límites deliberados (wallet didáctica, no de producción)

- **Nunca gasta fondos reales**: firmar y emitir solo en testnet4/signet. Mainnet
  es de solo lectura (saldos, vista de tx, timeline, watch-only).
- **La seed nunca se guarda**: vive solo en memoria mientras la pestaña está
  abierta. Cargar una seed real es posible (offline, bajo responsabilidad del
  usuario) para *ver* derivaciones, pero no se persiste ni se cifra en disco.
- Cualquier funcionalidad nueva que "gaste" (RBF, CPFP, bóveda Liana…) se
  prueba en signet/testnet4.

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

### Fase 4 — UI visual (Sparrow/Liana-style) ✅
- [x] Multisig P2WSH + PSBT (BIP174) con descriptores watch-only
- [x] Taproot completo (key-path, script-path, sighash BIP341) + `tr(NUMS, sortedmulti_a)`
- [x] MuSig2 (BIP327): firma Schnorr agregada n-de-n
- [x] Timelocks OP_CSV/OP_CLTV + bóveda de recuperación estilo Liana
- [x] Taproot Multisig watch-only con xpubs del usuario + saldo real vía mempool.space
- [x] Visualizador del árbol de derivación de claves (BIP32 tree) navegable, con frontera watch-only
- [x] Vista de transacción: inputs → outputs con amounts (importes verificados contra la tx previa)
- [x] Timeline de UTXOs por dirección (reconstruida del historial y comprobada contra /utxo del servidor)

### Fase 5 — Miniscript, gestión de fees y Claude Code
- [x] **0. Hacer cumplir los límites deliberados**: `TxBuilder` solo ofrece
  testnet4/signet (coin_type 1', rechaza direcciones bc1…) y `broadcastTx` solo
  acepta `BroadcastNetwork` + comprobación en runtime (test `broadcast.test.ts`).
  La seed no se persiste en ningún sitio (no hay localStorage/sessionStorage).
- [ ] **1. Miniscript + bóveda Liana de punta a punta**: políticas legibles →
  Script, análisis de condiciones de gasto, y construir/firmar el gasto de la
  rama de recuperación al vencer el timelock (en signet/testnet4).
- [ ] **2. RBF / CPFP + coin control estilo Sparrow**: acelerar tx atascadas
  (nSequence, reglas de reemplazo, mercado de fees) y elegir UTXOs a mano
  viendo el impacto en privacidad (en signet/testnet4).
- [ ] **3. Claude Code**: hook que lance los tests al tocar `src/crypto/`, y
  slash command `/decode-tx` (después `/explain-script` y el agente explicador).
- [ ] Limpieza: pendientes de la revisión de seguridad (7: CSP de Tauri, 8: menores).

### Ideas para una Fase 6
- Silent Payments (BIP352) — ECDH sobre secp256k1
- Etiquetas BIP329 (import/export)
- Análisis de privacidad (reutilización, heurísticas de cambio)
- Intercambio de PSBT air-gapped (fichero / QR animado UR/BBQr)
- Servidor MCP de mempool.space

---

## Claude Code — Cosas a explorar juntos

- **Slash commands**: `/derive-key`, `/decode-tx`, `/explain-script`
- **Agents**: un agente que reciba un tx hex y lo explique en lenguaje natural
- **Hooks**: ejecutar tests automáticamente al modificar código criptográfico
- **Skills**: generar diagramas de flujo de transacciones
- **MCP servers**: integración con mempool.space u otras herramientas externas

---

## Primer paso al volver

Fase 4 completa: exploradores de multisig P2WSH, PSBT, Taproot (key/script-path),
Taproot Multisig watch-only, MuSig2, timelocks estilo Liana, árbol BIP32
navegable, vista inputs→outputs de una tx (importes verificados contra la tx
previa) y timeline de UTXOs por dirección — toda la cripto desde cero y
verificada contra vectores o contra datos reales de mainnet.

Fase 5 en marcha (2026-10-17). Punto 0 hecho: ya no se puede firmar ni emitir
en mainnet. Siguiente: Miniscript + bóveda Liana, RBF/CPFP + coin control, y
los hooks/slash commands de Claude Code.

---

## Referencias

- [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) — HD Wallets
- [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) — Mnemonic seed phrases
- [bitcoinjs-lib](https://github.com/bitcoinjs/bitcoinjs-lib) — Librería TS/JS
- [Sparrow Wallet](https://sparrowwallet.com/) — Inspiración UI (transactions, UTXOs)
- [Liana Wallet](https://wizardsardine.com/liana/) — Inspiración (timelocks, multisig visual)
- [mempool.space API](https://mempool.space/docs/api) — Para conectar a la red sin nodo propio
