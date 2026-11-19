/**
 * ComplianceProof: prove properties about encrypted balances without revealing them.
 *
 * Use cases:
 * - Prove balance >= threshold (for DeFi collateral, lending, staking)
 * - Prove balance <= limit (for regulatory compliance, AML)
 * - Prove balance is in range [min, max]
 * - Prove total volume is under a threshold (aggregate proof)
 *
 * All proofs are zero-knowledge: the verifier learns only that the
 * statement is true, not the actual balance value.
 *
 * Usage:
 *   const proof = ComplianceProof.balanceAbove(ctx, cipher, balance, threshold, policy);
 *   const valid = ComplianceProof.verify(ctx, proof.shiftedCipher, proof.rangeProof, proof.commitment, policy);
 */

import type { PvacContext } from './context';
import type { Cipher, RangeProof } from './types';
import { uint8ToBase64 } from './encoding';
import { ProofKind } from './policy';
import type { ProgressCallback } from './transfer';

export interface ComplianceResult {
  /** Whether the statement is provably true */
  valid: boolean;
  /** Bound range proof envelope */
  rangeProof: RangeProof;
  /** Pedersen commitment the range proof carries, needed for verification */
  commitment: Uint8Array;
  /** The shifted cipher (cipher - threshold), needed for verification */
  shiftedCipher: Cipher;
  /** Base64 encoded proof for transmission */
  proofB64: string;
  /** Base64 encoded shifted cipher for transmission */
  shiftedCipherB64: string;
  /** Base64 encoded commitment for transmission */
  commitmentB64: string;
  /** Generation time in ms */
  elapsed_ms: number;
}

export const ComplianceProof = {
  /**
   * Prove encrypted balance >= threshold, without revealing the balance.
   *
   * Method: encrypt(threshold), compute cipher_shifted = cipher - enc(threshold),
   * then prove cipher_shifted >= 0 via range proof.
   *
   * @param ctx - PvacContext
   * @param cipher - Current encrypted balance (raw bytes)
   * @param balance - Known plaintext balance (for proof generation)
   * @param threshold - Minimum balance to prove
   * @param policy - Network proof policy (readProofPolicy)
   * @param onProgress - Progress callback
   */
  balanceAbove(
    ctx: PvacContext,
    cipher: Cipher,
    balance: bigint,
    threshold: bigint,
    policy: number,
    onProgress?: ProgressCallback,
  ): ComplianceResult {
    if (balance < threshold) {
      throw new Error(`Balance ${balance} is below threshold ${threshold}: cannot prove`);
    }
    const t0 = performance.now();

    onProgress?.('encrypting-threshold', 10);
    const thresholdCipher = ctx.encrypt(threshold);

    onProgress?.('computing-shifted', 20);
    const shiftedCipher = ctx.ctSub(cipher, thresholdCipher);
    const shiftedValue = balance - threshold;

    onProgress?.('range-proof', 30);
    const { proof: rangeProof, commitment } = ctx.makeBoundRangeProof(shiftedCipher, shiftedValue, policy);

    onProgress?.('done', 100);
    return {
      valid: true,
      rangeProof,
      commitment,
      shiftedCipher,
      proofB64: uint8ToBase64(rangeProof),
      shiftedCipherB64: uint8ToBase64(shiftedCipher),
      commitmentB64: uint8ToBase64(commitment),
      elapsed_ms: performance.now() - t0,
    };
  },

  /**
   * Prove encrypted balance <= limit, without revealing the balance.
   *
   * Method: compute cipher_shifted = enc(limit) - cipher,
   * then prove cipher_shifted >= 0 via range proof.
   */
  balanceBelow(
    ctx: PvacContext,
    cipher: Cipher,
    balance: bigint,
    limit: bigint,
    policy: number,
    onProgress?: ProgressCallback,
  ): ComplianceResult {
    if (balance > limit) {
      throw new Error(`Balance ${balance} exceeds limit ${limit}: cannot prove`);
    }
    const t0 = performance.now();

    onProgress?.('encrypting-limit', 10);
    const limitCipher = ctx.encrypt(limit);

    onProgress?.('computing-shifted', 20);
    const shiftedCipher = ctx.ctSub(limitCipher, cipher);
    const shiftedValue = limit - balance;

    onProgress?.('range-proof', 30);
    const { proof: rangeProof, commitment } = ctx.makeBoundRangeProof(shiftedCipher, shiftedValue, policy);

    onProgress?.('done', 100);
    return {
      valid: true,
      rangeProof,
      commitment,
      shiftedCipher,
      proofB64: uint8ToBase64(rangeProof),
      shiftedCipherB64: uint8ToBase64(shiftedCipher),
      commitmentB64: uint8ToBase64(commitment),
      elapsed_ms: performance.now() - t0,
    };
  },

  /**
   * Prove encrypted balance is in range [min, max].
   * Generates two range proofs: one for >= min, one for <= max.
   */
  balanceInRange(
    ctx: PvacContext,
    cipher: Cipher,
    balance: bigint,
    min: bigint,
    max: bigint,
    policy: number,
    onProgress?: ProgressCallback,
  ): { above: ComplianceResult; below: ComplianceResult } {
    if (balance < min || balance > max) {
      throw new Error(`Balance ${balance} is not in range [${min}, ${max}]`);
    }
    onProgress?.('proving-above', 10);
    const above = this.balanceAbove(ctx, cipher, balance, min, policy, (phase, pct) => {
      onProgress?.(phase, pct * 0.5);
    });
    onProgress?.('proving-below', 50);
    const below = this.balanceBelow(ctx, cipher, balance, max, policy, (phase, pct) => {
      onProgress?.(phase, 50 + pct * 0.5);
    });
    onProgress?.('done', 100);
    return { above, below };
  },

  /**
   * Verify a compliance proof under the policy it was made with.
   * Returns true if the shifted cipher holds a non-negative value.
   */
  verify(
    ctx: PvacContext,
    shiftedCipher: Cipher,
    rangeProof: RangeProof,
    commitment: Uint8Array,
    policy: number,
  ): boolean {
    return ctx.verifyAmount(shiftedCipher, rangeProof, commitment, ProofKind.range, policy);
  },
};
