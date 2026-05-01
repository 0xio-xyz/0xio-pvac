# @0xio/pvac

PVAC-HFHE privacy primitives for Octra Network. FHE encryption, range proofs, bound proofs, and cipher arithmetic for building privacy-aware DApps.

**Browser only (WASM).** This package runs in browsers, browser extensions, and web workers. For native mobile (React Native) or desktop (Tauri/Rust), use the `pvac-rs` crate directly via FFI or as a Rust dependency.

| Platform | Use |
|---|---|
| Web DApps / Browser | `@0xio/pvac` (this package) |
| Browser Extension | `@0xio/pvac` or bundled WASM directly |
| React Native (mobile) | `pvac-rs` native FFI (.so/.dylib) |
| Tauri / Desktop | `pvac-rs` Rust crate |
| Node.js server | Not supported (no WASM threading) |

## When to Use

Use this package if you're building a **browser-based** DApp that needs to work with encrypted balances on Octra — private DEX, lending protocol, or any contract that operates on FHE ciphertexts.

For basic wallet operations (send, receive, check balance), use `@0xio/sdk` instead.

## Installation

```bash
npm install @0xio/pvac
```

WASM module is bundled — no extra setup needed.

## Quick Start

```typescript
import { PvacContext, initPvac, buildEncryptPayload, buildDecryptPayload } from '@0xio/pvac';

// 1. Load WASM (bundled in the package)
const wasm = await initPvac();

// 2. Create context (32-byte seed from wallet key derivation)
const ctx = await PvacContext.create(seed, wasm, {
  preWarm: true,
  threads: navigator.hardwareConcurrency,
});

// 3. Encrypt a value
const result = ctx.fullEncrypt(1000000); // 1 OCT
console.log(result.cipherB64);  // hfhe_v1|<base64>
console.log(result.boundProofEncoded); // zkzp_v2|<base64>

// 4. Decrypt
const value = ctx.decrypt(result.cipher);
console.log(value); // 1000000n

// 5. Cipher arithmetic
const sum = ctx.ctAdd(cipherA, cipherB);
const diff = ctx.ctSub(cipherA, cipherB);

// 6. Build transaction payloads
const encryptTxData = buildEncryptPayload(ctx, 1000000);
const decryptTxData = await buildDecryptPayload(ctx, 500000, currentCipher, currentBalance);
```

## API Reference

### `PvacContext`

| Method | Description | Speed |
|---|---|---|
| `encrypt(value)` | FHE encrypt a value | <1ms |
| `encryptSeeded(value, seed)` | Deterministic encryption | <1ms |
| `encryptZero()` | Encrypt zero | <1ms |
| `decrypt(cipher)` | Decrypt to plaintext | 0.5-5s |
| `ctAdd(a, b)` | Homomorphic addition | <1ms |
| `ctSub(a, b)` | Homomorphic subtraction | <1ms |
| `makeRangeProof(cipher, value)` | Prove value ≥ 0 | 30-60s |
| `makeRangeProofParallel(cipher, value)` | Parallel range proof (rayon) | 15-30s |
| `makeBoundProof(cipher, value, blinding)` | Prove cipher matches commitment | <1s |
| `pedersenCommit(value, blinding)` | Pedersen commitment | <1ms |
| `verifyRangeProof(cipher, proof)` | Verify range proof | <1s |
| `verifyBoundProof(cipher, proof, commitment)` | Verify bound proof | <1ms |
| `fullEncrypt(value)` | Encrypt + bound proof in one call | <1s |
| `serializePubkey()` | Serialize public key (~3-4MB) | 5-15s |

### Encoding

| Function | Description |
|---|---|
| `encodeCipher(bytes)` | → `hfhe_v1\|<base64>` |
| `decodeCipher(str)` | → raw bytes |
| `encodeProof(bytes)` | → `zkzp_v2\|<base64>` |
| `decodeProof(str)` | → raw bytes |

### Transaction Payloads

| Function | Description |
|---|---|
| `buildEncryptPayload(ctx, amount)` | Build encrypted_data for encrypt TX |
| `buildDecryptPayload(ctx, amount, currentCipher, currentBalance)` | Build encrypted_data for decrypt TX (slow — range proof) |

## Private DEX Integration

For a DEX operating on encrypted balances:

```typescript
// User wants to swap 100 OCT for token X

// 1. Encrypt the swap amount
const swapCipher = ctx.encrypt(100_000_000); // 100 OCT in microOCT

// 2. Prove the amount is valid (bound proof)
const blinding = crypto.getRandomValues(new Uint8Array(32));
const { proof, commitment } = ctx.makeBoundProof(swapCipher, 100_000_000, blinding);

// 3. Update pool reserves (cipher arithmetic)
const newPoolOCT = ctx.ctSub(poolOCTCipher, swapCipher);  // pool loses OCT
const newPoolX = ctx.ctAdd(poolXCipher, outputCipher);      // pool gains token X

// 4. Range proof: prove pool still has non-negative OCT
const rangeProof = await ctx.makeRangeProofParallel(newPoolOCT, newPoolValue);

// 5. Submit to DEX contract with all proofs
```

## Requirements

- **Browser only** — Chrome, Firefox, Edge, Brave (no Node.js, no React Native)
- WebAssembly support (all modern browsers)
- SharedArrayBuffer + COOP/COEP headers (for rayon thread pool parallelism)
- ~100MB RAM for PVAC context initialization
- WASM module is bundled (3.2MB) — no external setup needed

## License

MIT License. Copyright 2026 0xio Labs.
