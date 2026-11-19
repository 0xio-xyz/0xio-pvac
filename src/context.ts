/**
 * PvacContext: High-level wrapper around pvac-rs WASM
 *
 * Handles initialization, encryption, decryption, proof generation,
 * and cipher arithmetic for FHE operations on Octra.
 *
 * All value parameters use bigint (microOCT). Use BigInt(amount) to convert.
 */

import type {
  Cipher,
  RangeProof,
  BoundProof,
  PedersenCommitment,
  EncryptResult,
  PvacWasmModule,
  PvacWasmContext,
} from './types';
import { encodeCipher, encodeProof } from './encoding';
import { ProofKind, assertProofPolicy } from './policy';

const OWN_KEY = new Uint8Array(0);

/** key_switch owner fields for a network whose policy binds the key */
export interface KeyOwnerProof {
  owner_cipher: string;
  owner_proof: string;
}

/** cipher_proof migration fields to merge into a key_switch encrypted_data */
export interface CipherProofMigration {
  migration_mode: string;
  source_cipher_hash: string;
  new_cipher: string;
  old_zero_proof: string;
  new_range_proof: string;
  amount_commitment: string;
}

/** Private-spend readiness of a cipher */
export interface BoundProvable {
  provable: boolean;
  reason: string;
  base_layers: number;
  canonical_r_com: boolean;
}

/** pvac-rs fee and balance bounds in microOCT */
export interface PvacLimits {
  minFee: bigint;
  maxFee: bigint;
  minBalance: bigint;
  maxBalance: bigint;
}

export class PvacContext {
  private _wasm: PvacWasmContext;
  private _module: PvacWasmModule;

  private constructor(wasm: PvacWasmContext, module: PvacWasmModule) {
    this._wasm = wasm;
    this._module = module;
  }

  /**
   * Create a new PVAC context from a 32-byte seed.
   * The seed derives the FHE keypair (public + secret key).
   *
   * @param seed - 32 bytes (e.g., HMAC-SHA512("Octra seed", mnemonic)[0:32])
   * @param wasmModule - WASM module from initPvac()
   * @param options.preWarm - Build the proof generator table now (faster first proof)
   * @param options.threads - Init rayon thread pool for parallel proofs (ignored by the single build)
   */
  static async create(
    seed: Uint8Array,
    wasmModule: PvacWasmModule,
    options?: { preWarm?: boolean; threads?: number }
  ): Promise<PvacContext> {
    if (seed.length !== 32) throw new Error('Seed must be 32 bytes');

    if (options?.threads && wasmModule.initThreadPool) {
      await wasmModule.initThreadPool(options.threads);
    }

    if (options?.preWarm) {
      wasmModule.pvac_prewarm_generators();
    }

    const ctx = new wasmModule.PvacContext(seed);
    return new PvacContext(ctx, wasmModule);
  }

  // Encryption / Decryption

  /** Encrypt a value in microOCT. Returns raw cipher bytes. */
  encrypt(value: bigint): Cipher {
    return this._wasm.encrypt(value);
  }

  /** Encrypt with a specific 32-byte seed (deterministic). */
  encryptSeeded(value: bigint, seed: Uint8Array): Cipher {
    return this._wasm.encrypt_seeded(value, seed);
  }

  /** Encrypt zero, used for padding/dummy operations. */
  encryptZero(): Cipher {
    return this._wasm.encrypt_zero();
  }

  /** Encrypt zero with a specific seed. */
  encryptZeroSeeded(seed: Uint8Array): Cipher {
    return this._wasm.encrypt_zero_seeded(seed);
  }

  /** Decrypt a cipher to its plaintext value (microOCT as bigint). Throws when out of range. */
  decrypt(cipher: Cipher): bigint {
    return this._wasm.decrypt(cipher);
  }

  /** Decrypt without throwing: 0n when the cipher cannot be read. */
  decryptSafe(cipher: Cipher): bigint {
    return this._wasm.decryptSafe(cipher);
  }

  /**
   * Read-only decrypt with the pre canonical parity keys, for balances written by
   * pvac-rs builds before 0.2. A success means the balance must be re-encrypted
   * before any private op touches it.
   */
  decryptLegacy(cipher: Cipher): bigint {
    return this._wasm.decryptLegacy(cipher);
  }

  // Cipher Arithmetic

  /** Add two ciphertexts homomorphically: result encrypts (a + b). */
  ctAdd(a: Cipher, b: Cipher): Cipher {
    return this._wasm.ct_add(a, b);
  }

  /** Subtract two ciphertexts homomorphically: result encrypts (a - b). */
  ctSub(a: Cipher, b: Cipher): Cipher {
    return this._wasm.ct_sub(a, b);
  }

  // Proofs

  /**
   * Proof of `kind` under the network proof `policy` (see readProofPolicy).
   * Kind range returns the bound range envelope, other kinds raw zero proof bytes.
   * Pass `pubkey` to prove under a registered key instead of this context's own.
   */
  proveAmount(
    cipher: Cipher,
    amount: bigint,
    blinding: Uint8Array,
    kind: ProofKind,
    policy: number,
    pubkey: Uint8Array = OWN_KEY,
  ): Uint8Array {
    return this._wasm.proveAmount(pubkey, cipher, amount, blinding, kind, assertProofPolicy(policy));
  }

  /** Verify a proveAmount proof against its 32-byte commitment under the same kind and policy. */
  verifyAmount(
    cipher: Cipher,
    proof: Uint8Array,
    commitment: Uint8Array,
    kind: ProofKind,
    policy: number,
    pubkey: Uint8Array = OWN_KEY,
  ): boolean {
    return this._wasm.verifyAmount(pubkey, cipher, proof, commitment, kind, assertProofPolicy(policy));
  }

  /**
   * Bound proof: proves the cipher encrypts a value matching the Pedersen commitment.
   *
   * @param cipher - The FHE ciphertext
   * @param value - The plaintext value (must match what was encrypted)
   * @param blinding - 32-byte random blinding factor
   * @param policy - Network proof policy (readProofPolicy)
   */
  makeBoundProof(cipher: Cipher, value: bigint, blinding: Uint8Array, policy: number): BoundProof {
    const proof = this.proveAmount(cipher, value, blinding, ProofKind.amount, policy);
    const commitment = this._wasm.pedersen_commit(value, blinding);
    return { proof, commitment, blinding };
  }

  /**
   * Bound range proof: proves the cipher encrypts `value` and that it is non-negative.
   * This is the range_proof_balance the chain accepts for decrypt.
   */
  makeBoundRangeProof(cipher: Cipher, value: bigint, policy: number): BoundProof {
    const blinding = crypto.getRandomValues(new Uint8Array(32));
    const proof = this.proveAmount(cipher, value, blinding, ProofKind.range, policy);
    const commitment = this._wasm.pedersen_commit(value, blinding);
    return { proof, commitment, blinding };
  }

  /**
   * Legacy per-bit range proof: proves the encrypted value >= 0.
   * The chain no longer accepts it for decrypt; use makeBoundRangeProof.
   */
  makeRangeProof(cipher: Cipher, value: bigint): RangeProof {
    return this._wasm.make_range_proof(cipher, value);
  }

  /**
   * Parallel range proof using rayon threads.
   * Requires initThreadPool() in create options; the single build proves serially.
   */
  makeRangeProofParallel(cipher: Cipher, value: bigint): RangeProof {
    return this._wasm.make_range_proof_parallel
      ? this._wasm.make_range_proof_parallel(cipher, value)
      : this._wasm.make_range_proof(cipher, value);
  }

  /**
   * Aggregated range proof: smaller proof size but slower generation.
   * Better for server-side verification, worse for client generation.
   */
  makeAggregatedRangeProof(cipher: Cipher, value: bigint): RangeProof {
    return this._wasm.make_aggregated_range_proof(cipher, value);
  }

  /** key_switch owner_cipher and owner_proof, required when the policy binds the key. */
  makeKeyOwnerProof(address: string, policy: number): KeyOwnerProof {
    return JSON.parse(this._wasm.makeKeyOwnerProof(address, assertProofPolicy(policy)));
  }

  /**
   * cipher_proof migration fields for a proven balance on a historical registered key.
   * `source` is the on-chain "hfhe_v1|..." string, `amount` its value.
   */
  buildCipherProofMigration(
    oldPubkey: Uint8Array,
    source: string,
    amount: bigint,
    policy: number,
  ): CipherProofMigration {
    return JSON.parse(
      this._wasm.buildCipherProofMigration(oldPubkey, source, amount, assertProofPolicy(policy)),
    );
  }

  /** Pedersen commitment: commit(value, blinding) -> deterministic 32-byte commitment. */
  pedersenCommit(value: bigint, blinding: Uint8Array): PedersenCommitment {
    const commitment = this._wasm.pedersen_commit(value, blinding);
    return { commitment, blinding };
  }

  // Verification

  /** Verify a range proof (auto-detects standard vs aggregated format). */
  verifyRangeProof(cipher: Cipher, proof: RangeProof): boolean {
    return this._wasm.verify_range_any(cipher, proof);
  }

  /** Verify a bound proof against a commitment under the network proof policy. */
  verifyBoundProof(cipher: Cipher, proof: Uint8Array, commitment: Uint8Array, policy: number): boolean {
    return this.verifyAmount(cipher, proof, commitment, ProofKind.amount, policy);
  }

  /** Whether a balance cipher can carry a private spend, and its base layer count. */
  checkBoundProvable(cipher: Cipher): BoundProvable {
    return JSON.parse(this._wasm.check_bound_provable(cipher));
  }

  /** Whether a registered pubkey (from octra_pvacPubkey) belongs to this secret key. */
  matchesSecretProfile(pubkey: Uint8Array): boolean {
    return this._wasm.matchesSecretProfile(pubkey);
  }

  // Key Serialization

  /** Serialize public key (~3-4MB compressed). Needed for PVAC registration. */
  serializePubkey(): Uint8Array {
    return this._wasm.serialize_pubkey();
  }

  // Diagnostics

  /** Debug info about a proof (format, size, validity hints). */
  diagnoseProof(proof: Uint8Array): string {
    return this._wasm.diagnose_proof(proof);
  }

  /** Debug info about a cipher (size, format). */
  diagnoseCipher(cipher: Uint8Array): string {
    return this._wasm.diagnose_cipher(cipher);
  }

  // Encoding Helpers

  /** Encode cipher to Octra wire format: hfhe_v1|<base64> */
  encodeCipher(cipher: Cipher): string {
    return this._module.pvac_encode_cipher(cipher);
  }

  /** Encode range proof to wire format: rp_v1|<base64> */
  encodeRangeProof(proof: RangeProof): string {
    return this._module.pvac_encode_range_proof(proof);
  }

  /** Encode zero/bound proof to wire format: zkzp_v2|<base64> */
  encodeZeroProof(proof: Uint8Array): string {
    return this._module.pvac_encode_zero_proof(proof);
  }

  /** Compute AES KAT (Key Agreement Test), needed for PVAC registration. */
  computeAesKat(): string {
    return this._module.pvac_compute_aes_kat();
  }

  /** Sanity bounds built into pvac-rs, in microOCT. Read the live op fee from the network. */
  limits(): PvacLimits {
    return {
      minFee: this._module.pvac_min_fee_raw(),
      maxFee: this._module.pvac_max_fee_raw(),
      minBalance: this._module.pvac_min_balance_raw(),
      maxBalance: this._module.pvac_max_balance_raw(),
    };
  }

  // High-Level Helpers

  /**
   * Full encrypt flow: encrypt + bound proof + encode.
   * Returns everything needed for an encrypt transaction.
   *
   * @param value - Amount in microOCT (as bigint)
   * @param policy - Network proof policy (readProofPolicy)
   */
  fullEncrypt(value: bigint, policy: number): EncryptResult {
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const blinding = crypto.getRandomValues(new Uint8Array(32));

    const cipher = this.encryptSeeded(value, seed);
    const boundProof = this.makeBoundProof(cipher, value, blinding, policy);

    return {
      cipher,
      cipherB64: encodeCipher(cipher),
      boundProof,
      boundProofEncoded: encodeProof(boundProof.proof),
    };
  }

  /** Release WASM memory. Call when done with this context. */
  free(): void {
    this._wasm.free();
  }
}
