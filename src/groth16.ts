/**
 * Groth16 BN254 proof generation and encoding for Octra Network.
 *
 * Generates and encodes Groth16 zero-knowledge proofs compatible with
 * the on-chain verifier at oct3rzJZucw9BsS7LRWBNoKRoaBsXAhhSK4LmfRvg45ppSs.
 *
 * Uses snarkjs for proof generation, and encodes to Octra's binary format
 * (OG16V1/OG16P1 magic bytes + BN254 big-endian points).
 *
 * Usage:
 *   import { Groth16, loadCircuit } from '@0xio/pvac/groth16';
 *   const circuit = await loadCircuit('/circuits/CrossChainFill');
 *   const { proofB64, inputsB64 } = await Groth16.prove(circuit, publicInputs, privateInputs);
 *   const valid = await Groth16.verifyOnChain(proofB64, inputsB64, callerAddress);
 */

// BN254 curve constants
const BN254_P = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47n;
const BN254_R = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;
const FE_SIZE = 32;
const MAGIC_PROOF = 'OG16P1';
const MAGIC_VK = 'OG16V1';

/** Default Groth16 verifier contract on Octra */
export const GROTH16_VERIFIER = 'oct3rzJZucw9BsS7LRWBNoKRoaBsXAhhSK4LmfRvg45ppSs';

/** Loaded circuit files (WASM + zkey + vkey) */
export interface Circuit {
  wasmPath: string;
  zkeyPath: string;
  vkey: VerificationKey;
}

/** snarkjs verification key format */
export interface VerificationKey {
  protocol: string;
  curve: string;
  nPublic: number;
  vk_alpha_1: string[];
  vk_beta_2: string[][];
  vk_gamma_2: string[][];
  vk_delta_2: string[][];
  IC: string[][];
}

/** snarkjs proof format */
export interface SnarkjsProof {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol: string;
  curve: string;
}

/** Encoded proof ready for Octra verifier */
export interface Groth16Proof {
  proofB64: string;
  inputsB64: string;
  publicSignals: string[];
}

/**
 * Load a circuit from a base path.
 * Expects: {basePath}.wasm, {basePath}_final.zkey, {basePath}_vkey.json
 */
export async function loadCircuit(basePath: string): Promise<Circuit> {
  const vkeyResp = await fetch(`${basePath}_vkey.json`);
  if (!vkeyResp.ok) throw new Error(`Failed to load vkey: ${vkeyResp.status}`);
  const vkey = await vkeyResp.json();
  return {
    wasmPath: `${basePath}.wasm`,
    zkeyPath: `${basePath}_final.zkey`,
    vkey,
  };
}

/** Encode a bigint as a BN254 field element (32 bytes big-endian). */
function fieldToBytes(n: bigint, modulus: bigint = BN254_R): Uint8Array {
  if (n < 0n) throw new Error('Negative field elements not allowed');
  if (n >= modulus) throw new Error(`Field element ${n} exceeds modulus`);
  const hex = n.toString(16).padStart(FE_SIZE * 2, '0');
  const bytes = new Uint8Array(FE_SIZE);
  for (let i = 0; i < FE_SIZE; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Encode a G1 point [x, y] as 64 bytes (big-endian). */
function encodeG1(point: string[]): Uint8Array {
  const x = fieldToBytes(BigInt(point[0]), BN254_P);
  const y = fieldToBytes(BigInt(point[1]), BN254_P);
  const out = new Uint8Array(64);
  out.set(x, 0);
  out.set(y, 32);
  return out;
}

/** Encode a G2 point [[x0,x1],[y0,y1]] as 128 bytes (big-endian). */
function encodeG2(point: string[][]): Uint8Array {
  const x0 = fieldToBytes(BigInt(point[0][0]), BN254_P);
  const x1 = fieldToBytes(BigInt(point[0][1]), BN254_P);
  const y0 = fieldToBytes(BigInt(point[1][0]), BN254_P);
  const y1 = fieldToBytes(BigInt(point[1][1]), BN254_P);
  const out = new Uint8Array(128);
  out.set(x0, 0);
  out.set(x1, 32);
  out.set(y0, 64);
  out.set(y1, 96);
  return out;
}

/**
 * Encode a snarkjs proof into Octra's binary format (OG16P1 + BN254 points).
 */
export function encodeProof(proof: SnarkjsProof): string {
  const magic = new TextEncoder().encode(MAGIC_PROOF);
  const a = encodeG1(proof.pi_a);
  const b = encodeG2(proof.pi_b);
  const c = encodeG1(proof.pi_c);
  const buf = new Uint8Array(magic.length + a.length + b.length + c.length);
  let offset = 0;
  buf.set(magic, offset); offset += magic.length;
  buf.set(a, offset); offset += a.length;
  buf.set(b, offset); offset += b.length;
  buf.set(c, offset);
  return btoa(String.fromCharCode(...buf));
}

/**
 * Encode public signals as field elements for Octra verifier.
 */
export function encodeInputs(publicSignals: string[]): string {
  const parts: Uint8Array[] = publicSignals.map(s => fieldToBytes(BigInt(s)));
  const total = parts.reduce((s, p) => s + p.length, 0);
  const buf = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    buf.set(part, offset);
    offset += part.length;
  }
  return btoa(String.fromCharCode(...buf));
}

/**
 * Encode a verification key for on-chain storage (OG16V1 format).
 */
export function encodeVKey(vkey: VerificationKey): string {
  const magic = new TextEncoder().encode(MAGIC_VK);
  const nPublic = new Uint8Array(4);
  new DataView(nPublic.buffer).setUint32(0, vkey.nPublic);

  const alpha = encodeG1(vkey.vk_alpha_1);
  const beta = encodeG2(vkey.vk_beta_2);
  const gamma = encodeG2(vkey.vk_gamma_2);
  const delta = encodeG2(vkey.vk_delta_2);

  const icParts = vkey.IC.map(ic => encodeG1(ic));
  const icTotal = icParts.reduce((s, p) => s + p.length, 0);

  const total = magic.length + 4 + alpha.length + beta.length + gamma.length + delta.length + icTotal;
  const buf = new Uint8Array(total);
  let offset = 0;
  buf.set(magic, offset); offset += magic.length;
  buf.set(nPublic, offset); offset += 4;
  buf.set(alpha, offset); offset += alpha.length;
  buf.set(beta, offset); offset += beta.length;
  buf.set(gamma, offset); offset += gamma.length;
  buf.set(delta, offset); offset += delta.length;
  for (const ic of icParts) {
    buf.set(ic, offset);
    offset += ic.length;
  }
  return btoa(String.fromCharCode(...buf));
}

/**
 * Groth16 — high-level interface for proof generation and verification.
 */
export const Groth16 = {
  /**
   * Generate a Groth16 proof.
   * Requires snarkjs loaded globally or as ESM import.
   *
   * @param circuit - Loaded circuit (wasm + zkey + vkey)
   * @param inputs - All inputs (public + private) as a flat object
   * @returns Encoded proof + inputs ready for Octra verifier
   */
  async prove(circuit: Circuit, inputs: Record<string, bigint | string | number>): Promise<Groth16Proof> {
    // Dynamic import snarkjs (peer dep — install separately)
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    let snarkjs: any;
    try { snarkjs = await (Function('return import("snarkjs")')() as Promise<any>); }
    catch { throw new Error('@0xio/pvac: snarkjs not installed. Run: npm install snarkjs'); }
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      inputs,
      circuit.wasmPath,
      circuit.zkeyPath,
    );
    return {
      proofB64: encodeProof(proof),
      inputsB64: encodeInputs(publicSignals),
      publicSignals,
    };
  },

  /**
   * Verify a proof locally (off-chain) using the verification key.
   */
  async verifyLocal(circuit: Circuit, proof: SnarkjsProof, publicSignals: string[]): Promise<boolean> {
    let snarkjs: any;
    try { snarkjs = await (Function('return import("snarkjs")')() as Promise<any>); }
    catch { throw new Error('@0xio/pvac: snarkjs not installed. Run: npm install snarkjs'); }
    return snarkjs.groth16.verify(circuit.vkey, publicSignals, proof);
  },

  /**
   * Verify a proof on-chain via the Octra Groth16 verifier contract.
   *
   * @param proofB64 - Encoded proof (OG16P1 format)
   * @param inputsB64 - Encoded public inputs
   * @param caller - Caller address for the view call
   * @param options.verifier - Override verifier contract address
   * @param options.rpcUrl - Octra RPC URL
   */
  async verifyOnChain(
    proofB64: string,
    inputsB64: string,
    caller: string,
    options?: { verifier?: string; rpcUrl?: string }
  ): Promise<boolean> {
    const verifier = options?.verifier || GROTH16_VERIFIER;
    if (!options?.rpcUrl) throw new Error('rpcUrl is required for on-chain verification');
    const rpcUrl = options.rpcUrl;

    const res = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'contract_call',
        params: [verifier, 'verify', [proofB64, inputsB64], caller],
      }),
    });
    const data = await res.json();
    return data?.result?.result === true || data?.result?.result === 'true';
  },

  /** Encode proof for Octra format */
  encodeProof,
  /** Encode public inputs for Octra format */
  encodeInputs,
  /** Encode verification key for on-chain storage */
  encodeVKey,
};
