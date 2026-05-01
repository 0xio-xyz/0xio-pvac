/**
 * @0xio/pvac — PVAC-HFHE Privacy Primitives for Octra Network
 *
 * Provides FHE encryption, range proofs, bound proofs, and cipher arithmetic
 * for building privacy-aware DApps on Octra (DEX, lending, etc.)
 *
 * Usage:
 *   import { PvacContext } from '@0xio/pvac';
 *   const ctx = await PvacContext.create(seed);
 *   const cipher = ctx.encrypt(1000000);  // 1 OCT in microOCT
 *
 * Requires pvac-rs WASM module. See README for setup.
 */

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
export { encodeCipher, decodeCipher, encodeProof, decodeProof } from './encoding';
export { buildEncryptPayload, buildDecryptPayload } from './payloads';
export { initPvac } from './wasm';
