# @0xio/pvac

Privacy primitives for Octra Network. FHE encryption, stealth addresses, confidential tokens, compliance proofs, Groth16 ZK verification, and Web Worker offloading.

**Browser only (WASM).** Runs in browsers, extensions, and web workers.

| Platform | Use |
|---|---|
| Web DApps / Browser | `@0xio/pvac` (this package) |
| Browser Extension | `@0xio/pvac` or bundled WASM directly |
| React Native (mobile) | `pvac-rs` native FFI (.so/.dylib) |
| Tauri / Desktop | `pvac-rs` Rust crate |

## Installation

```bash
npm install @0xio/pvac
```

WASM module is bundled — no extra setup needed.

## Modules

| Module | Description | Speed |
|---|---|---|
| `PvacContext` | Core FHE: encrypt, decrypt, cipher arithmetic, proofs | varies |
| `PrivateTransfer` | One-call encrypt/decrypt with progress callbacks | encrypt ~1s, decrypt 30-60s |
| `ConfidentialBalance` | Fetch + decrypt + cache + format encrypted balances | ~2s (cached: instant) |
| `StealthAddress` | Stealth payments: generate, send, scan, claim | ~5ms per output |
| `ConfidentialToken` | ORC20 token with encrypted balances | ~1s per tx |
| `ComplianceProof` | Prove balance ≥/≤/in-range without revealing value | 30-60s |
| `ProofWorker` | Web Worker offload — proofs don't freeze UI | same, off-thread |
| `Groth16` | BN254 ZK proof generation + on-chain verification | ~2-5s |

---

## Quick Start

```typescript
import { PvacContext, initPvac, PrivateTransfer } from '@0xio/pvac';

// 1. Load WASM
const wasm = await initPvac();

// 2. Create context from wallet seed
const ctx = await PvacContext.create(seed, wasm, {
  preWarm: true,
  threads: navigator.hardwareConcurrency,
});

// 3. Encrypt 1 OCT into private balance (one call, ~1s)
const tx = PrivateTransfer.encrypt(ctx, 1_000_000n, (phase, pct) => {
  console.log(`${phase}: ${pct}%`);
});
// tx.encrypted_data is ready for SDK callContract

// 4. Decrypt back to public (one call, 30-60s with range proof)
const dtx = PrivateTransfer.decrypt(ctx, 500_000n, currentCipher, currentBalance, (phase, pct) => {
  progressBar.value = pct;
});
```

---

## Private Transfers

Encrypt/decrypt in one call with progress tracking.

```typescript
import { PrivateTransfer } from '@0xio/pvac';

// Public → Private (fast, ~1s)
const encryptTx = PrivateTransfer.encrypt(ctx, 1_000_000n, (phase, pct) => {
  // phase: 'generating-seed' | 'encrypting' | 'commitment' | 'bound-proof' | 'encoding' | 'done'
  updateUI(phase, pct);
});

// Private → Public (slow, 30-60s — range proof)
const decryptTx = PrivateTransfer.decrypt(
  ctx,
  500_000n,         // amount to decrypt
  currentCipher,     // current encrypted balance (raw bytes)
  currentBalance,    // current decrypted value
  (phase, pct) => {
    // phase: 'range-proof' at pct 30 = the slow part
    progressBar.value = pct;
  },
);

// Submit via SDK
await wallet.callContract({
  contract: 'self',
  method: encryptTx.op_type,
  params: [],
  encrypted_data: encryptTx.encrypted_data,
});
```

---

## Confidential Balance

Fetch, decrypt, cache, and display encrypted balances.

```typescript
import { ConfidentialBalance } from '@0xio/pvac';

const balance = new ConfidentialBalance(ctx, 'http://YOUR_OCTRA_RPC:8080');

// Subscribe to updates
balance.onUpdate((snapshot) => {
  const formatted = ConfidentialBalance.format(snapshot, octPrice);
  console.log(`Public: ${formatted.public} OCT`);
  console.log(`Private: ${formatted.private} OCT`);
  console.log(`Total: ${formatted.total} OCT ($${formatted.totalUsd})`);
});

// Fetch + decrypt (cached on second call)
const snapshot = await balance.fetch(myAddress, async (address) => {
  // Sign the RPC auth challenge
  const sig = wallet.signMessage(address);
  return { signature: sig, publicKey: myPubKey };
});

// After encrypt/decrypt tx, invalidate cache
balance.invalidate(myAddress);
```

---

## Stealth Addresses

Send private payments that only the recipient can detect.

```typescript
import { StealthAddress } from '@0xio/pvac';

// === Sender ===

// 1. Create a stealth output for the recipient
const { output, ephSk } = await StealthAddress.createOutput(
  recipientViewPub,  // recipient's view public key (32 bytes)
  1_000_000n,        // 1 OCT
  blinding,          // 32-byte blinding factor
);
// output = { ephPub, tag, encAmount } — include in the transaction

// === Recipient ===

// 2. Derive view keypair from wallet
const { viewSk, viewPub } = await StealthAddress.deriveViewKeypair(privateKeyB64);

// 3. Scan chain outputs to find payments addressed to you
const mine = await StealthAddress.scan(chainOutputs, viewSk, myAddress);
for (const m of mine) {
  console.log(`Found ${m.amount} microOCT at index ${m.index}`);
  // m.claimSecret — use to claim/spend the funds
  // m.blinding — use for proof generation
}

// 4. Compute claim public key for spending
const claimPub = await StealthAddress.computeClaimPub(m.claimSecret, myAddress);
```

---

## Confidential Token

ORC20 tokens with encrypted balances.

```typescript
import { ConfidentialToken } from '@0xio/pvac';

const token = new ConfidentialToken(ctx, 'octTokenContractAddress...');

// Get token info (cached)
const info = await token.info();
console.log(`${info.symbol} (${info.decimals} decimals)`);

// Check balance
const bal = await token.balanceOf(myAddress);
console.log(`Balance: ${await token.formatAmount(bal)}`);

// Build a private transfer
const tx = token.buildTransfer(recipientAddress, 500_000n, (phase, pct) => {
  console.log(`${phase}: ${pct}%`);
});
// tx = { contract, method, args, encrypted_data } — ready for SDK

// Approve + transferFrom
const approveTx = token.buildApprove(spenderAddress, 1_000_000n);
const fromTx = token.buildTransferFrom(ownerAddress, toAddress, 500_000n);
```

---

## Compliance Proofs

Prove properties about encrypted balances without revealing them. For DeFi collateral checks, regulatory compliance, AML thresholds.

```typescript
import { ComplianceProof } from '@0xio/pvac';

// Prove: "my encrypted balance ≥ 100 OCT" (without revealing actual balance)
const proof = ComplianceProof.balanceAbove(
  ctx,
  encryptedCipher,    // your encrypted balance
  actualBalance,       // known plaintext (for proof generation)
  100_000_000n,        // 100 OCT threshold
  (phase, pct) => progressBar.value = pct,
);

// Verify (on-chain or off-chain)
const valid = ComplianceProof.verify(ctx, proof.shiftedCipher, proof.rangeProof);

// Prove: "my balance ≤ 10,000 OCT" (for regulatory limits)
const limitProof = ComplianceProof.balanceBelow(ctx, cipher, balance, 10_000_000_000n);

// Prove: "my balance is between 100 and 10,000 OCT"
const rangeProof = ComplianceProof.balanceInRange(ctx, cipher, balance, 100_000_000n, 10_000_000_000n);
```

---

## Web Worker Offload

Range proofs take 30-60s. Don't freeze the UI.

```typescript
import { ProofWorker } from '@0xio/pvac';

// Create worker (loads WASM in background thread)
const worker = new ProofWorker('/wasm/pvac_rs_bg.wasm');
await worker.createContext(seed);

// Encrypt — fast, but still off-thread
const enc = await worker.encrypt(1_000_000n, {
  onProgress: (phase, pct) => console.log(`${phase}: ${pct}%`),
});

// Decrypt — the slow one, now off main thread
const dec = await worker.decrypt(500_000n, currentCipher, currentBalance, {
  onProgress: (phase, pct) => {
    progressBar.value = pct;
    statusText.textContent = phase === 'range-proof' ? 'Generating proof...' : phase;
  },
});

// enc.encrypted_data / dec.encrypted_data — ready for chain

// Cleanup
worker.terminate();
```

---

## Groth16 ZK Proofs (BN254)

Generate and verify Groth16 zero-knowledge proofs on Octra. Uses the on-chain verifier at `oct3rzJZucw9BsS7LRWBNoKRoaBsXAhhSK4LmfRvg45ppSs`.

```typescript
import { Groth16, loadCircuit } from '@0xio/pvac';

// Load circuit (requires snarkjs as peer dep)
const circuit = await loadCircuit('/circuits/MyCircuit');

// Generate proof
const { proofB64, inputsB64 } = await Groth16.prove(circuit, {
  publicInput1: 42n,
  publicInput2: recipientField,
  privateWitness: secretValue,
});

// Verify on Octra (calls on-chain BN254 verifier)
const valid = await Groth16.verifyOnChain(proofB64, inputsB64, callerAddress);

// Or verify locally (off-chain)
const localValid = await Groth16.verifyLocal(circuit, proof, publicSignals);
```

Peer dependency for proof generation:
```bash
npm install snarkjs
```

---

## Core FHE API

Low-level FHE operations for advanced use cases.

```typescript
import { PvacContext, initPvac } from '@0xio/pvac';

const wasm = await initPvac();
const ctx = await PvacContext.create(seed, wasm, { preWarm: true, threads: 8 });

// Encrypt / Decrypt
const cipher = ctx.encrypt(1_000_000n);
const value = ctx.decrypt(cipher);                      // → 1000000n

// Cipher arithmetic (homomorphic)
const sum = ctx.ctAdd(cipherA, cipherB);                // enc(a + b)
const diff = ctx.ctSub(cipherA, cipherB);               // enc(a - b)

// Proofs
const rangeProof = ctx.makeRangeProofParallel(cipher, value);   // 15-30s
const boundProof = ctx.makeBoundProof(cipher, value, blinding); // <1s
const commitment = ctx.pedersenCommit(value, blinding);         // <1ms

// Verification
ctx.verifyRangeProof(cipher, rangeProof);               // → boolean
ctx.verifyBoundProof(cipher, proof, commitment);         // → boolean

// Full encrypt (encrypt + bound proof + encode in one call)
const result = ctx.fullEncrypt(1_000_000n);
// result = { cipher, cipherB64, boundProof, boundProofEncoded }

// Serialization (for PVAC registration)
const pubkey = ctx.serializePubkey();                    // ~3MB, 5-15s

// Encoding
ctx.encodeCipher(cipher);       // → 'hfhe_v1|<base64>'
ctx.encodeRangeProof(proof);    // → 'rp_v1|<base64>'
ctx.encodeZeroProof(proof);     // → 'zkzp_v2|<base64>'
```

---

## Requirements

- **Browser only** — Chrome, Firefox, Edge, Brave
- WebAssembly support
- SharedArrayBuffer + COOP/COEP headers (for rayon thread parallelism)
- ~100MB RAM for PVAC context
- WASM module is bundled (3.2MB)

## License

MIT License. Copyright 2026 0xio Labs.
