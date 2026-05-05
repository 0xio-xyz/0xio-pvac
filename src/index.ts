/**
 * @0xio/pvac — Privacy Primitives for Octra Network
 *
 * FHE encryption, range proofs, stealth addresses, confidential tokens,
 * compliance proofs, Groth16 ZK verification, and Web Worker offloading.
 *
 * Usage:
 *   import { PvacContext, PrivateTransfer, StealthAddress } from '@0xio/pvac';
 */

// Core FHE context
export { PvacContext } from './context';
export type {
  Cipher,
  RangeProof,
  BoundProof,
  PedersenCommitment,
  EncryptResult,
  DecryptPayload,
  EncryptPayload,
} from './types';

// Encoding
export { encodeCipher, decodeCipher, encodeProof, decodeProof, uint8ToBase64, base64ToUint8, uint8ToHex, hexToUint8 } from './encoding';

// Low-level payloads
export { buildEncryptPayload, buildDecryptPayload } from './payloads';

// WASM loader
export { initPvac } from './wasm';

// High-level: Private transfers (encrypt/decrypt in one call)
export { PrivateTransfer } from './transfer';
export type { TransferResult, ProgressCallback } from './transfer';

// High-level: Confidential balance (fetch, decrypt, cache, display)
export { ConfidentialBalance } from './balance';
export type { BalanceSnapshot, BalanceFormatted, BalanceSigner } from './balance';

// Stealth addresses (generate, send, scan, claim)
export { StealthAddress } from './stealth';
export type { ViewKeypair, EphemeralKeypair, StealthOutput, ScannedOutput } from './stealth';

// Confidential token (ORC20 with privacy)
export { ConfidentialToken } from './token';
export type { TokenInfo, TokenBalance, TokenTxPayload } from './token';

// Compliance proofs (balance above/below/in-range)
export { ComplianceProof } from './compliance';
export type { ComplianceResult } from './compliance';

// Web Worker offload (proof generation off main thread)
export { ProofWorker } from './worker';
export type { WorkerOptions, WorkerResult } from './worker';

// Groth16 BN254 ZK proofs
export {
  Groth16,
  loadCircuit,
  encodeProof as encodeGroth16Proof,
  encodeInputs as encodeGroth16Inputs,
  encodeVKey as encodeGroth16VKey,
  GROTH16_VERIFIER,
} from './groth16';
export type { Circuit, Groth16Proof, SnarkjsProof, VerificationKey } from './groth16';
