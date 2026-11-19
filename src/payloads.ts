/**
 * Build transaction payloads for encrypt/decrypt operations.
 * These match the exact JSON format expected by Octra consensus.
 *
 * CANONICAL FORMAT (all platforms must match):
 *   { cipher, amount_commitment, zero_proof, blinding [, range_proof_balance] }
 *
 * Every proof takes the network proof policy from readProofPolicy.
 */

import type { PvacContext } from './context';
import type { Cipher } from './types';
import { uint8ToBase64 } from './encoding';

/**
 * Build the encrypted_data JSON for an encrypt transaction.
 *
 * @param ctx - Initialized PvacContext
 * @param amount - Amount in microOCT as bigint (e.g., 1000000n = 1 OCT)
 * @param policy - Network proof policy (readProofPolicy)
 * @returns JSON string ready for encrypted_data field
 */
export function buildEncryptPayload(ctx: PvacContext, amount: bigint, policy: number): string {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const blinding = crypto.getRandomValues(new Uint8Array(32));

  const cipher = ctx.encryptSeeded(amount, seed);
  const { commitment } = ctx.pedersenCommit(amount, blinding);
  const { proof } = ctx.makeBoundProof(cipher, amount, blinding, policy);

  return JSON.stringify({
    cipher: ctx.encodeCipher(cipher),
    amount_commitment: uint8ToBase64(commitment),
    zero_proof: ctx.encodeZeroProof(proof),
    blinding: uint8ToBase64(blinding),
  });
}

/**
 * Build the encrypted_data JSON for a decrypt transaction.
 * The bound range proof takes about 10 s threaded on an M3.
 *
 * @param ctx - Initialized PvacContext
 * @param amount - Amount to decrypt in microOCT as bigint
 * @param currentCipher - Current encrypted balance (raw bytes, no prefix), freshly read from chain
 * @param currentBalance - That cipher decrypted, in microOCT as bigint
 * @param policy - Network proof policy (readProofPolicy)
 * @returns JSON string ready for encrypted_data field
 */
export function buildDecryptPayload(
  ctx: PvacContext,
  amount: bigint,
  currentCipher: Cipher,
  currentBalance: bigint,
  policy: number,
): string {
  if (amount <= 0n) throw new Error('Amount must be positive');
  if (amount > currentBalance) {
    throw new Error(`Insufficient encrypted balance: have ${currentBalance}, need ${amount}`);
  }
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const blinding = crypto.getRandomValues(new Uint8Array(32));

  const cipher = ctx.encryptSeeded(amount, seed);
  const { commitment } = ctx.pedersenCommit(amount, blinding);
  const { proof } = ctx.makeBoundProof(cipher, amount, blinding, policy);

  const newBalanceCipher = ctx.ctSub(currentCipher, cipher);
  const newBalanceValue = currentBalance - amount;
  const { proof: rangeProof } = ctx.makeBoundRangeProof(newBalanceCipher, newBalanceValue, policy);

  return JSON.stringify({
    cipher: ctx.encodeCipher(cipher),
    amount_commitment: uint8ToBase64(commitment),
    zero_proof: ctx.encodeZeroProof(proof),
    blinding: uint8ToBase64(blinding),
    range_proof_balance: ctx.encodeRangeProof(rangeProof),
  });
}
