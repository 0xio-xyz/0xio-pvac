/** Raw FHE ciphertext bytes */
export type Cipher = Uint8Array;

/** Range proof: proves value >= 0 without revealing it */
export type RangeProof = Uint8Array;

/** Bound proof: proves ciphertext encrypts a specific committed value */
export interface BoundProof {
  proof: Uint8Array;
  commitment: Uint8Array;
  blinding: Uint8Array;
}

/** Pedersen commitment to a value */
export interface PedersenCommitment {
  commitment: Uint8Array;
  blinding: Uint8Array;
}

/** Result of encrypting a value */
export interface EncryptResult {
  cipher: Cipher;
  cipherB64: string;
  boundProof: BoundProof;
  boundProofEncoded: string;
}

/** JSON payload for encrypt transaction (matches Octra consensus) */
export interface EncryptPayload {
  cipher: string;
  amount_commitment: string;
  zero_proof: string;
  blinding: string;
}

/** JSON payload for decrypt transaction (matches Octra consensus) */
export interface DecryptPayload {
  cipher: string;
  amount_commitment: string;
  zero_proof: string;
  blinding: string;
  range_proof_balance: string;
}

/**
 * WASM module interface: matches pvac_rs.d.ts exports.
 * Obtained via: const wasm = await initPvac();
 */
export interface PvacWasmModule {
  PvacContext: new (seed: Uint8Array) => PvacWasmContext;
  initThreadPool(num_threads: number): Promise<any>;
  pvac_pre_warm_generators(n: number): void;
  pvac_prewarm_generators(): void;
  pvac_prewarm_heap(bytes: number): boolean;
  pvac_min_fee_raw(): bigint;
  pvac_max_fee_raw(): bigint;
  pvac_min_balance_raw(): bigint;
  pvac_max_balance_raw(): bigint;
  sha256Hex(data: Uint8Array): string;
  pvac_encode_cipher(cipher_bytes: Uint8Array): string;
  pvac_encode_range_proof(proof_bytes: Uint8Array): string;
  pvac_encode_zero_proof(proof_bytes: Uint8Array): string;
  pvac_compute_aes_kat(): string;
  pvac_deserialize_pubkey(data: Uint8Array): Uint8Array;
}

/**
 * PvacContext instance: matches the WASM class methods exactly.
 * All value params are bigint (not number).
 */
export interface PvacWasmContext {
  free(): void;
  encrypt(value: bigint): Uint8Array;
  encrypt_seeded(value: bigint, seed: Uint8Array): Uint8Array;
  encrypt_zero(): Uint8Array;
  encrypt_zero_seeded(seed: Uint8Array): Uint8Array;
  decrypt(cipher_bytes: Uint8Array): bigint;
  decryptSafe(cipher_bytes: Uint8Array): bigint;
  decryptLegacy(cipher_bytes: Uint8Array): bigint;
  commit(cipher_bytes: Uint8Array): Uint8Array;
  ct_add(a: Uint8Array, b: Uint8Array): Uint8Array;
  ct_sub(a: Uint8Array, b: Uint8Array): Uint8Array;
  serialize_pubkey(): Uint8Array;
  matchesSecretProfile(candidate_bytes: Uint8Array): boolean;
  check_bound_provable(cipher_bytes: Uint8Array): string;
  make_range_proof(cipher_bytes: Uint8Array, value: bigint): Uint8Array;
  make_range_proof_parallel(cipher_bytes: Uint8Array, value: bigint): Uint8Array;
  make_aggregated_range_proof(cipher_bytes: Uint8Array, value: bigint): Uint8Array;
  make_bound_proof(cipher_bytes: Uint8Array, amount: bigint, blinding: Uint8Array): Uint8Array;
  makeBoundRangeProof(cipher_bytes: Uint8Array, value: bigint): Uint8Array;
  makeBoundProofWithPubkey(pubkey_bytes: Uint8Array, cipher_bytes: Uint8Array, amount: bigint, blinding: Uint8Array): Uint8Array;
  makeBoundKeySwitchProof(cipher_bytes: Uint8Array, amount: bigint, blinding: Uint8Array): Uint8Array;
  makeBoundKeySwitchProofWithPubkey(pubkey_bytes: Uint8Array, cipher_bytes: Uint8Array, amount: bigint, blinding: Uint8Array): Uint8Array;
  proveAmount(pubkey_bytes: Uint8Array, cipher_bytes: Uint8Array, amount: bigint, blinding: Uint8Array, kind: number, policy: number): Uint8Array;
  verifyAmount(pubkey_bytes: Uint8Array, cipher_bytes: Uint8Array, proof_bytes: Uint8Array, commitment: Uint8Array, kind: number, policy: number): boolean;
  makeKeyOwnerProof(address: string, policy: number): string;
  buildCipherProofMigration(pubkey_bytes: Uint8Array, source: string, amount: bigint, policy: number): string;
  pedersen_commit(amount: bigint, blinding: Uint8Array): Uint8Array;
  verify_range_proof(cipher_bytes: Uint8Array, proof_bytes: Uint8Array): boolean;
  verify_range_any(cipher_bytes: Uint8Array, proof_bytes: Uint8Array): boolean;
  verify_aggregated_range_proof(cipher_bytes: Uint8Array, proof_bytes: Uint8Array): boolean;
  verify_bound_proof(cipher_bytes: Uint8Array, proof_bytes: Uint8Array, commitment: Uint8Array): boolean;
  verifyBoundProofWithPubkey(pubkey_bytes: Uint8Array, cipher_bytes: Uint8Array, proof_bytes: Uint8Array, commitment: Uint8Array): boolean;
  verifyBoundKeySwitchProof(cipher_bytes: Uint8Array, proof_bytes: Uint8Array, commitment: Uint8Array): boolean;
  verifyBoundKeySwitchProofWithPubkey(pubkey_bytes: Uint8Array, cipher_bytes: Uint8Array, proof_bytes: Uint8Array, commitment: Uint8Array): boolean;
  diagnose_proof(proof_bytes: Uint8Array): string;
  diagnose_cipher(cipher_bytes: Uint8Array): string;
}
