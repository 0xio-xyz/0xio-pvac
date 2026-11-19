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

The WASM module is bundled. `StealthAddress` needs `tweetnacl` (optional peer dependency) on browsers without SubtleCrypto X25519 import, and always for view keypair derivation:

```bash
npm install tweetnacl
```

## Threaded and single builds

Two pvac-rs builds ship in `wasm/`. `initPvac()` picks one at runtime:

| Build | Loads when | Encrypt | Decrypt |
|---|---|---|---|
| `wasm/threaded/` | the page is cross-origin isolated | about 3 s | about 10 s |
| `wasm/single/` | anywhere else | about 35 s | about 110 s |

Times are on an Apple M3 (single build measured in Node 22, V8).

To get threads, serve the page with both headers:

```
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```

```typescript
import { initPvac, pvacMode } from '@0xio/pvac';

const wasm = await initPvac();                  // mode: 'auto'
pvacMode();                                     // 'threaded' or 'single'

await initPvac({ mode: 'single' });             // force a build ('threaded' throws off isolation)
await initPvac({ wasmBase: '/pvac/' });         // self-hosted copy of the wasm/ folder
```

Unbundled ESM (a CDN such as jsDelivr, or the files served as published) finds `wasm/` beside `dist/`. A bundler that moves the module does not copy `wasm/`: copy `node_modules/@0xio/pvac/wasm` to your public folder and pass `wasmBase`. On the single build, `threads` is ignored and `makeRangeProofParallel` proves serially.

## Modules

| Module | Description |
|---|---|
| `PvacContext` | Core FHE: encrypt, decrypt, cipher arithmetic, proofs |
| `readProofPolicy` | Network proof policy every proof is built under |
| `PrivateTransfer` | One-call encrypt/decrypt with progress callbacks |
| `ConfidentialBalance` | Fetch, decrypt, cache and format encrypted balances |
| `StealthAddress` | Stealth payments: generate, send, scan, claim |
| `ConfidentialToken` | ORC20 token with encrypted balances |
| `ComplianceProof` | Prove balance above, below or in a range without revealing it |
| `ProofWorker` | Web Worker offload so proofs don't freeze the UI |
| `Groth16` | BN254 ZK proof generation and on-chain verification |

With threads on an M3, an encrypt takes about 3 s and a decrypt about 10 s (see [Threaded and single builds](#threaded-and-single-builds)).

## Proof policy

Every proof is built under the network proof policy (bit 0 wide reduction, bit 1 bound to the registered key), announced by `octra_pvacMigrationStatus`. Read it before proving and again right before submitting. A proof made under one policy fails under another, so if the policy moved, build the transaction again.

```typescript
import { readProofPolicy, requireProofPolicy, ProofPolicyError } from '@0xio/pvac';

const policy = await readProofPolicy(rpcUrl, myAddress);   // throws ProofPolicyError if unannounced
const tx = PrivateTransfer.encrypt(ctx, 1_000_000n, policy);
await requireProofPolicy(policy, rpcUrl, myAddress);       // throws PROOF_POLICY_CHANGED if it moved
// sign and submit
```

When the policy binds the key, a key_switch also needs `ctx.makeKeyOwnerProof(address, policy)` merged into its `encrypted_data`.

---

## Quick Start

```typescript
import { PvacContext, initPvac, PrivateTransfer, readProofPolicy } from '@0xio/pvac';

// 1. Load WASM
const wasm = await initPvac();

// 2. Create context from wallet seed
const ctx = await PvacContext.create(seed, wasm, {
  preWarm: true,
  threads: navigator.hardwareConcurrency,
});

// 3. Read the network proof policy
const policy = await readProofPolicy(rpcUrl, myAddress);

// 4. Encrypt 1 OCT into private balance
const tx = PrivateTransfer.encrypt(ctx, 1_000_000n, policy, (phase, pct) => {
  console.log(`${phase}: ${pct}%`);
});
// tx.encrypted_data is ready for SDK callContract

// 5. Decrypt back to public (bound range proof on the remaining balance)
const dtx = PrivateTransfer.decrypt(ctx, 500_000n, currentCipher, currentBalance, policy, (phase, pct) => {
  progressBar.value = pct;
});
```

---

## Private Transfers

Encrypt/decrypt in one call with progress tracking.

```typescript
import { PrivateTransfer } from '@0xio/pvac';

// Public to private
const encryptTx = PrivateTransfer.encrypt(ctx, 1_000_000n, policy, (phase, pct) => {
  // phase: 'generating-seed' | 'encrypting' | 'commitment' | 'bound-proof' | 'encoding' | 'done'
  updateUI(phase, pct);
});

// Private to public (bound range proof)
const decryptTx = PrivateTransfer.decrypt(
  ctx,
  500_000n,         // amount to decrypt
  currentCipher,     // encrypted balance freshly read from chain (raw bytes)
  currentBalance,    // that cipher decrypted
  policy,
  (phase, pct) => {
    // phase: 'range-proof' at pct 30 is the slow part
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
// output = { ephPub, tag, encAmount }: include in the transaction

// === Recipient ===

// 2. Derive view keypair from wallet
const { viewSk, viewPub } = await StealthAddress.deriveViewKeypair(privateKeyB64);

// 3. Scan chain outputs to find payments addressed to you
const mine = await StealthAddress.scan(chainOutputs, viewSk, myAddress);
for (const m of mine) {
  console.log(`Found ${m.amount} microOCT at index ${m.index}`);
  // m.claimSecret: use to claim or spend the funds
  // m.blinding: use for proof generation
}

// 4. Compute claim public key for spending
const claimPub = await StealthAddress.computeClaimPub(m.claimSecret, myAddress);
```

---

## Confidential Token

ORC20 tokens with encrypted balances.

```typescript
import { ConfidentialToken } from '@0xio/pvac';

const token = new ConfidentialToken(ctx, 'octTokenContractAddress...', rpcUrl);

// Get token info (cached)
const info = await token.info();
console.log(`${info.symbol} (${info.decimals} decimals)`);

// Check balance
const bal = await token.balanceOf(myAddress);
console.log(`Balance: ${await token.formatAmount(bal)}`);

// Build a private transfer
const tx = token.buildTransfer(recipientAddress, 500_000n, policy, (phase, pct) => {
  console.log(`${phase}: ${pct}%`);
});
// tx = { contract, method, args, encrypted_data }: ready for SDK

// Approve + transferFrom
const approveTx = token.buildApprove(spenderAddress, 1_000_000n);
const fromTx = token.buildTransferFrom(ownerAddress, toAddress, 500_000n);
```

---

## Compliance Proofs

Prove properties about encrypted balances without revealing them. For DeFi collateral checks, regulatory compliance, AML thresholds.

```typescript
import { ComplianceProof } from '@0xio/pvac';

// Prove: "my encrypted balance >= 100 OCT" (without revealing actual balance)
const proof = ComplianceProof.balanceAbove(
  ctx,
  encryptedCipher,    // your encrypted balance
  actualBalance,       // known plaintext (for proof generation)
  100_000_000n,        // 100 OCT threshold
  policy,
  (phase, pct) => progressBar.value = pct,
);

// Verify under the same policy
const valid = ComplianceProof.verify(ctx, proof.shiftedCipher, proof.rangeProof, proof.commitment, policy);

// Prove: "my balance <= 10,000 OCT" (for regulatory limits)
const limitProof = ComplianceProof.balanceBelow(ctx, cipher, balance, 10_000_000_000n, policy);

// Prove: "my balance is between 100 and 10,000 OCT"
const rangeProof = ComplianceProof.balanceInRange(ctx, cipher, balance, 100_000_000n, 10_000_000_000n, policy);
```

---

## Web Worker Offload

Proofs take seconds. Keep them off the UI thread.

```typescript
import { ProofWorker } from '@0xio/pvac';

// Create worker (loads the bundled build in a background thread, or pass a pvac_rs.js glue URL)
const worker = new ProofWorker();
await worker.createContext(seed);

// Encrypt
const enc = await worker.encrypt(1_000_000n, policy, {
  onProgress: (phase, pct) => console.log(`${phase}: ${pct}%`),
});

// Decrypt
const dec = await worker.decrypt(500_000n, currentCipher, currentBalance, policy, {
  onProgress: (phase, pct) => {
    progressBar.value = pct;
    statusText.textContent = phase === 'range-proof' ? 'Generating proof...' : phase;
  },
});

// enc.encrypted_data and dec.encrypted_data are ready for chain

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
import { PvacContext, initPvac, ProofKind } from '@0xio/pvac';

const wasm = await initPvac();
const ctx = await PvacContext.create(seed, wasm, { preWarm: true, threads: 8 });

// Encrypt / Decrypt
const cipher = ctx.encrypt(1_000_000n);
const value = ctx.decrypt(cipher);                      // 1000000n, throws when out of range
ctx.decryptSafe(cipher);                                // 0n instead of throwing
ctx.decryptLegacy(cipher);                              // read-only, for balances from pvac-rs before 0.2

// Cipher arithmetic (homomorphic)
const sum = ctx.ctAdd(cipherA, cipherB);                // enc(a + b)
const diff = ctx.ctSub(cipherA, cipherB);               // enc(a - b)

// Proofs (all under the network proof policy)
const bound = ctx.makeBoundProof(cipher, value, blinding, policy);  // { proof, commitment, blinding }
const range = ctx.makeBoundRangeProof(cipher, value, policy);       // decrypt's range_proof_balance
const proof = ctx.proveAmount(cipher, value, blinding, ProofKind.refresh, policy);
const commitment = ctx.pedersenCommit(value, blinding);

// Verification
ctx.verifyBoundProof(cipher, bound.proof, bound.commitment, policy);
ctx.verifyAmount(cipher, range.proof, range.commitment, ProofKind.range, policy);

// key_switch helpers
ctx.makeKeyOwnerProof(address, policy);                  // { owner_cipher, owner_proof }
ctx.buildCipherProofMigration(oldPubkey, source, amount, policy);
ctx.checkBoundProvable(cipher);                          // { provable, reason, base_layers, canonical_r_com }
ctx.matchesSecretProfile(registeredPubkey);              // is this registered key ours

// Full encrypt (encrypt + bound proof + encode in one call)
const result = ctx.fullEncrypt(1_000_000n, policy);
// result = { cipher, cipherB64, boundProof, boundProofEncoded }

// Serialization (for PVAC registration)
const pubkey = ctx.serializePubkey();                    // ~3MB

// pvac-rs sanity bounds in microOCT; read the live op fee from the network
ctx.limits();                                            // { minFee, maxFee, minBalance, maxBalance }

// Encoding
ctx.encodeCipher(cipher);       // 'hfhe_v1|<base64>'
ctx.encodeRangeProof(proof);    // 'rp_v1|<base64>'
ctx.encodeZeroProof(proof);     // 'zkzp_v2|<base64>'
```

The secret key never leaves the context: there is no secret key export.

---

## Requirements

- **Browser only**: Chrome, Firefox, Edge, Brave
- WebAssembly support
- Threads need SharedArrayBuffer and COOP/COEP headers; other pages get the single build
- Several hundred MB of RAM while a proof runs (the generator table alone is about 84 MB)
- WASM is bundled (pvac-rs 0.3.0: threaded 3.0 MB, single 0.6 MB)

## License

MIT License. Copyright 2026 0xio Labs.
