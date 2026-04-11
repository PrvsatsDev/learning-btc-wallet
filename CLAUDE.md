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

### Fase 1 — Fundamentos criptográficos
- [ ] SHA-256 y RIPEMD-160 (implementación manual + explicación)
- [ ] Curvas elípticas secp256k1
- [ ] Clave privada → clave pública → dirección Bitcoin

### Fase 2 — Bitcoin primitives
- [ ] UTXO model (vs account model)
- [ ] Estructura de una transacción
- [ ] Scripts: P2PKH, P2WPKH, P2TR (Taproot)
- [ ] Firmas: ECDSA y Schnorr
- [ ] HD Wallets: BIP32 / BIP39 / BIP44 / BIP84 / BIP86

### Fase 3 — La wallet funcional
- [ ] Generar e importar seed phrase (12/24 palabras)
- [ ] Derivar árbol de cuentas y direcciones
- [ ] Conectar a nodo vía Electrum protocol o mempool.space API
- [ ] Construir, firmar y broadcast de transacciones

### Fase 4 — UI visual (Sparrow/Liana-style)
- [ ] Visualizador del árbol de derivación de claves (BIP32 tree)
- [ ] Vista de transacción: inputs → outputs con amounts
- [ ] Timeline de UTXOs por dirección
- [ ] Multisig y timelocks (inspirado en Liana)

---

## Claude Code — Cosas a explorar juntos

- **Slash commands**: `/derive-key`, `/decode-tx`, `/explain-script`
- **Agents**: un agente que reciba un tx hex y lo explique en lenguaje natural
- **Hooks**: ejecutar tests automáticamente al modificar código criptográfico
- **Skills**: generar diagramas de flujo de transacciones
- **MCP servers**: integración con mempool.space u otras herramientas externas

---

## Primer paso al volver

Arrancar con **Fase 1**: scaffold del proyecto (Tauri + React + TS) y primera lección:
SHA-256 implementado a mano en TypeScript, con su visualización en la UI.

Comando de inicio sugerido:
```bash
npm create tauri-app@latest btc-wallet -- --template react-ts
```

---

## Referencias

- [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) — HD Wallets
- [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) — Mnemonic seed phrases
- [bitcoinjs-lib](https://github.com/bitcoinjs/bitcoinjs-lib) — Librería TS/JS
- [Sparrow Wallet](https://sparrowwallet.com/) — Inspiración UI (transactions, UTXOs)
- [Liana Wallet](https://wizardsardine.com/liana/) — Inspiración (timelocks, multisig visual)
- [mempool.space API](https://mempool.space/docs/api) — Para conectar a la red sin nodo propio
