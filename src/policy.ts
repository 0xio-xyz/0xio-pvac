/**
 * Network proof policy, read exactly as the Octra reference client does.
 *
 * Bit 0 picks the wide challenge reduction, bit 1 binds every proof to the
 * registered public key. Networks announce it via octra_pvacMigrationStatus
 * (proof_math, proof_key). Read it once before proving and again right
 * before submitting; if it moved, prepare the transaction again.
 *
 * Usage:
 *   const policy = await readProofPolicy(rpcUrl, address);
 *   const data = buildEncryptPayload(ctx, 1_000_000n, policy);
 *   await requireProofPolicy(policy, rpcUrl, address);
 */

/** Bit 0: wide (512-bit) challenge reduction */
export const PROOF_WIDE = 1;
/** Bit 1: proofs bound to the registered key */
export const PROOF_BIND_KEY = 2;

/** Proof kinds for proveAmount / verifyAmount */
export const ProofKind = {
  amount: 0,
  refresh: 1,
  range: 2,
  history: 3,
} as const;
export type ProofKind = (typeof ProofKind)[keyof typeof ProofKind];

export const PROOF_POLICY_UNAVAILABLE = 'Network proof arithmetic is unavailable';
export const PROOF_KEY_POLICY_UNAVAILABLE = 'Network proof key policy is unavailable';
export const PROOF_POLICY_UNREACHABLE = 'Network proof rules could not be read';
export const PROOF_POLICY_CHANGED =
  'Proof policy changed. Nothing sent. Prepare the transaction again.';

export class ProofPolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProofPolicyError';
  }
}

const RUNTIME_PROFILES = new Set([
  '86a3e354b18cad2cd2ec35c63a61924aa78363fef2e93e1b5f5b37badd7d0c0c',
  '1d46b19e336be6978b7a27b3fc04eda930cd58114858fd8a822c29c2e96ff13a',
]);

const isObject = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === 'object' && !Array.isArray(v);

/** Throws unless `policy` is an integer in 0..3. */
export function assertProofPolicy(policy: number): number {
  if (!Number.isInteger(policy) || policy < 0 || policy > 3) {
    throw new ProofPolicyError('proof policy must be 0..3');
  }
  return policy;
}

export const bindsKey = (policy: number) => (policy & PROOF_BIND_KEY) !== 0;

/** Policy from an octra_pvacMigrationStatus result that carries proof_math. */
export function policyFromStatus(status: Record<string, unknown>): number {
  const key = 'proof_key' in status ? status.proof_key : false;
  if (typeof key !== 'boolean') throw new ProofPolicyError(PROOF_KEY_POLICY_UNAVAILABLE);
  const math = status.proof_math;
  if (math !== 'wide' && math !== 'prior') throw new ProofPolicyError(PROOF_POLICY_UNAVAILABLE);
  return (math === 'wide' ? PROOF_WIDE : 0) | (key ? PROOF_BIND_KEY : 0);
}

/** Fallback for a status without proof_math: only the pinned devnet runtime implies wide. */
export function policyFromRuntime(runtime: unknown): number {
  if (
    isObject(runtime) &&
    runtime.schema === 'octra-runtime-release-v1' &&
    runtime.chain_id === 'octra-devnet-9871-cluster' &&
    runtime.consensus_rules_id === 'finalized_rejection_commitment' &&
    runtime.consensus_profile === 16 &&
    typeof runtime.runtime_profile_hash === 'string' &&
    RUNTIME_PROFILES.has(runtime.runtime_profile_hash)
  ) {
    return PROOF_WIDE;
  }
  throw new ProofPolicyError(PROOF_POLICY_UNAVAILABLE);
}

class RpcError extends Error {}

async function rpc(rpcUrl: string, method: string, params: unknown[]): Promise<unknown> {
  const res = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const data = await res.json();
  if (data?.error) {
    const err = data.error;
    throw new RpcError(`${err.code ?? ''} ${err.message ?? JSON.stringify(err)}`);
  }
  return data?.result;
}

const isMethodMissing = (e: unknown) =>
  e instanceof RpcError && /method not found|-32601/i.test(e.message);

/**
 * Read the proof policy for `address` from the node at `rpcUrl`.
 * Throws ProofPolicyError when the network announces no policy or cannot be read;
 * a private op must not be built in that case.
 */
export async function readProofPolicy(rpcUrl: string, address: string): Promise<number> {
  let status: unknown;
  try {
    status = await rpc(rpcUrl, 'octra_pvacMigrationStatus', [address]);
  } catch (e) {
    throw new ProofPolicyError(isMethodMissing(e) ? PROOF_POLICY_UNAVAILABLE : PROOF_POLICY_UNREACHABLE);
  }
  if (!status || typeof status !== 'object') throw new ProofPolicyError(PROOF_POLICY_UNREACHABLE);
  if (!isObject(status) || status.address !== address) {
    throw new ProofPolicyError(PROOF_POLICY_UNAVAILABLE);
  }
  if ('proof_math' in status) return policyFromStatus(status);
  let runtime: unknown;
  try {
    runtime = await rpc(rpcUrl, 'octra_runtimeVersion', []);
  } catch (e) {
    throw new ProofPolicyError(isMethodMissing(e) ? PROOF_POLICY_UNAVAILABLE : PROOF_POLICY_UNREACHABLE);
  }
  return policyFromRuntime(runtime);
}

/** Read the policy again right before submit; throws PROOF_POLICY_CHANGED if it moved. */
export async function requireProofPolicy(prepared: number, rpcUrl: string, address: string): Promise<void> {
  const current = await readProofPolicy(rpcUrl, address);
  if (current !== prepared) throw new ProofPolicyError(PROOF_POLICY_CHANGED);
}
