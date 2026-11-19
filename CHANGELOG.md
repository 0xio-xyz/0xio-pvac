# Changelog

## 2.0.0 (2026-11-19)

Breaking: every proof takes the network proof policy, and secret key export is gone.

### Security

- Removed `PvacContext.serializeSeckey` (pvac-rs no longer exports the secret key)
- Proofs follow the network proof policy (wide reduction, key binding) from `octra_pvacMigrationStatus`
- Policy outside 0..3 is refused before any proof runs

### Fixed

- Decrypt `range_proof_balance` is the bound range proof the chain accepts (was the per-bit range proof)
- Compliance proofs use bound range proofs and verify against their commitment
- `preWarm` builds the full proof generator table (`pvac_prewarm_generators`)
- `ProofWorker` decrypt refuses a zero amount or one above the balance before proving
- Typecheck passes again (`BufferSource` casts in stealth, `tweetnacl` declared)
- Package loads on pages that are not cross-origin isolated (single build fallback)
- `initPvac` resolves `wasm/` from the module URL, not the page URL, and no longer needs `eval`
- Rayon workers start when the package is served from another origin (CDN)
- `PvacContext.create` and `ProofWorker` skip `threads` on the single build instead of crashing

### Added

- `readProofPolicy(rpcUrl, address)`, `requireProofPolicy`, `PROOF_WIDE`, `PROOF_BIND_KEY`, `ProofKind`, `ProofPolicyError`
- `PvacContext.proveAmount`, `verifyAmount`, `makeBoundRangeProof`
- `PvacContext.makeKeyOwnerProof`, `buildCipherProofMigration`, `checkBoundProvable`, `matchesSecretProfile`
- `PvacContext.decryptSafe`, `decryptLegacy`
- `PvacContext.limits()`: pvac-rs fee and balance bounds
- Single-threaded build in `wasm/single/`, picked when the page cannot run threads
- `initPvac({ mode, wasmBase })`, `pvacMode()`, `pvacGlueUrl()`, `canUseThreads()`
- `ProofWorker` glue URL is optional (defaults to the bundled build)
- `tweetnacl` as optional peer dependency (stealth view keys)

### Changed

- Bundled WASM is pvac-rs 0.3.0 (canonical parity, proof policy, faster proofs)
- Threaded build moved to `wasm/threaded/`
- `policy` argument added (before `onProgress` or options) to `buildEncryptPayload`, `buildDecryptPayload`, `PrivateTransfer.encrypt`, `PrivateTransfer.decrypt`, `ConfidentialToken.buildTransfer`, `ComplianceProof.*`, `ProofWorker.encrypt`, `ProofWorker.decrypt`, `PvacContext.makeBoundProof`, `verifyBoundProof`, `fullEncrypt`
- `ComplianceResult` carries `commitment` and `commitmentB64`; `ComplianceProof.verify` takes the commitment and policy
- `makeRangeProof`, `makeRangeProofParallel` and `makeAggregatedRangeProof` stay for off-chain use only

## 1.0.1 (2026-05-05)

### New Modules

- **PrivateTransfer** — one-call encrypt/decrypt with progress callbacks
  - `PrivateTransfer.encrypt()`: encrypt + bound proof + payload (~1s)
  - `PrivateTransfer.decrypt()`: full flow with range proof (30-60s)
  - Progress callbacks for UI feedback (`onProgress: (phase, pct) => ...`)

- **ConfidentialBalance** — fetch, decrypt, cache, and display encrypted balances
  - Decryption result cached by cipher hash (skip re-decrypt on refetch)
  - `onUpdate()` listener for reactive UI
  - `ConfidentialBalance.format()` with USD conversion

- **StealthAddress** — stealth payment lifecycle
  - `deriveViewKeypair()`: Ed25519 seed → x25519 view keypair
  - `createOutput()`: ephemeral ECDH + stealth tag + AES-encrypted amount
  - `scan()`: detect incoming stealth payments
  - `computeClaimPub()`: derive claim key for spending
  - Uses SubtleCrypto X25519 with tweetnacl fallback

- **ConfidentialToken** — ORC20 token with encrypted balances
  - Token metadata query with caching
  - `buildTransfer()`: encrypt + proof + ready-to-submit payload
  - `buildApprove()`, `buildTransferFrom()` for allowance flows

- **ComplianceProof** — prove balance properties without revealing values
  - `balanceAbove()`: prove balance >= threshold
  - `balanceBelow()`: prove balance <= limit
  - `balanceInRange()`: prove balance in [min, max]
  - Use cases: DeFi collateral checks, AML thresholds, regulatory compliance

- **ProofWorker** — Web Worker offload for proof generation
  - Range proofs run off the main thread (no UI freeze)
  - `encrypt()` and `decrypt()` with progress callbacks
  - Inline worker blob (no separate file needed)

- **Groth16** — BN254 ZK proof generation + on-chain verification
  - `Groth16.prove()`: generate proofs via snarkjs (dynamic import)
  - `Groth16.verifyOnChain()`: call Octra BN254 verifier contract
  - `Groth16.verifyLocal()`: off-chain verification with vkey
  - Octra binary format encoding (OG16P1/OG16V1)
  - snarkjs is optional peer dependency

### Fixes

- **wasm-bindgen-rayon worker helpers** now included in npm tarball
  - `wasm/snippets/` directory was missing, causing import errors
- **No hardcoded RPC URLs** — all modules require explicit `rpcUrl` param

## 1.0.0 (2026-05-01)

### Initial Release

- `PvacContext` — core FHE context (encrypt, decrypt, cipher arithmetic)
- Range proofs (standard, parallel, aggregated)
- Bound proofs + Pedersen commitments
- Encoding helpers (`hfhe_v1|`, `zkzp_v2|`)
- Transaction payload builders (`buildEncryptPayload`, `buildDecryptPayload`)
- Bundled pvac-rs WASM (3.2MB)
