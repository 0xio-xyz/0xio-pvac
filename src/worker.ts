/**
 * ProofWorker: offload slow proof generation to a Web Worker.
 *
 * Proofs take seconds and freeze the UI thread. This module
 * runs them in a dedicated worker with progress reporting.
 *
 * Usage:
 *   const worker = new ProofWorker();
 *   await worker.createContext(seed);
 *   const policy = await readProofPolicy(rpcUrl, address);
 *   const result = await worker.decrypt(amount, currentCipher, currentBalance, policy, {
 *     onProgress: (pct) => console.log(`${pct}%`),
 *   });
 *   worker.terminate();
 *
 * Threads need a cross-origin isolated page (COOP/COEP headers); elsewhere the
 * single build proves serially.
 */

import { assertProofPolicy } from './policy';
import { canUseThreads, pvacGlueUrl } from './wasm';

export interface WorkerOptions {
  onProgress?: (phase: string, pct: number) => void;
  threads?: number;
}

export interface WorkerResult {
  encrypted_data: string;
  elapsed_ms: number;
}

type PendingJob = {
  resolve: (result: WorkerResult) => void;
  reject: (error: Error) => void;
  onProgress?: (phase: string, pct: number) => void;
};

export class ProofWorker {
  private worker: Worker | null = null;
  private pending: Map<number, PendingJob> = new Map();
  private nextId = 1;
  private ready: Promise<void>;
  private wasmUrl: string;

  /**
   * @param wasmUrl - URL to the pvac_rs.js glue (pvac_rs_bg.wasm beside it); default picks the bundled build
   * @param threads - Number of rayon threads (default: navigator.hardwareConcurrency)
   */
  constructor(wasmUrl?: string, threads?: number) {
    this.wasmUrl = wasmUrl ?? pvacGlueUrl(canUseThreads() ? 'threaded' : 'single');
    this.ready = this.init(threads ?? navigator.hardwareConcurrency);
  }

  private async init(threads: number): Promise<void> {
    // Create worker from inline blob so no separate worker file is needed
    const workerCode = `
      let wasm = null;
      let ctx = null;
      const OWN_KEY = new Uint8Array(0);
      const KIND_AMOUNT = 0;
      const KIND_RANGE = 2;
      const policyArg = (p) => {
        if (!Number.isInteger(p) || p < 0 || p > 3) throw new Error('proof policy must be 0..3');
        return p;
      };

      self.onmessage = async (e) => {
        const { id, type, payload } = e.data;
        try {
          if (type === 'init') {
            const mod = await import(payload.wasmUrl);
            await mod.default();
            if (mod.initThreadPool) await mod.initThreadPool(payload.threads);
            mod.pvac_prewarm_generators();
            wasm = mod;
            self.postMessage({ id, type: 'ready' });
            return;
          }

          if (type === 'create-ctx') {
            ctx = new wasm.PvacContext(new Uint8Array(payload.seed));
            self.postMessage({ id, type: 'ok' });
            return;
          }

          if (type === 'encrypt') {
            self.postMessage({ id, type: 'progress', phase: 'encrypting', pct: 10 });
            const seed = crypto.getRandomValues(new Uint8Array(32));
            const blinding = crypto.getRandomValues(new Uint8Array(32));
            const cipher = ctx.encrypt_seeded(BigInt(payload.amount), seed);
            self.postMessage({ id, type: 'progress', phase: 'commitment', pct: 40 });
            const commitment = ctx.pedersen_commit(BigInt(payload.amount), blinding);
            const proof = ctx.proveAmount(OWN_KEY, cipher, BigInt(payload.amount), blinding, KIND_AMOUNT, policyArg(payload.policy));
            self.postMessage({ id, type: 'progress', phase: 'encoding', pct: 80 });
            const result = JSON.stringify({
              cipher: wasm.pvac_encode_cipher(cipher),
              amount_commitment: btoa(String.fromCharCode(...commitment)),
              zero_proof: wasm.pvac_encode_zero_proof(proof),
              blinding: btoa(String.fromCharCode(...blinding)),
            });
            self.postMessage({ id, type: 'progress', phase: 'done', pct: 100 });
            self.postMessage({ id, type: 'result', encrypted_data: result, elapsed_ms: 0 });
            return;
          }

          if (type === 'decrypt') {
            const t0 = performance.now();
            self.postMessage({ id, type: 'progress', phase: 'encrypting', pct: 5 });
            const seed = crypto.getRandomValues(new Uint8Array(32));
            const blinding = crypto.getRandomValues(new Uint8Array(32));
            const cipher = ctx.encrypt_seeded(BigInt(payload.amount), seed);
            self.postMessage({ id, type: 'progress', phase: 'commitment', pct: 10 });
            const commitment = ctx.pedersen_commit(BigInt(payload.amount), blinding);
            const proof = ctx.proveAmount(OWN_KEY, cipher, BigInt(payload.amount), blinding, KIND_AMOUNT, policyArg(payload.policy));
            self.postMessage({ id, type: 'progress', phase: 'balance-cipher', pct: 15 });
            const currentCipher = new Uint8Array(payload.currentCipher);
            const newCipher = ctx.ct_sub(currentCipher, cipher);
            const newValue = BigInt(payload.currentBalance) - BigInt(payload.amount);
            self.postMessage({ id, type: 'progress', phase: 'range-proof', pct: 20 });
            const rangeBlinding = crypto.getRandomValues(new Uint8Array(32));
            const rangeProof = ctx.proveAmount(OWN_KEY, newCipher, newValue, rangeBlinding, KIND_RANGE, policyArg(payload.policy));
            self.postMessage({ id, type: 'progress', phase: 'encoding', pct: 95 });
            const result = JSON.stringify({
              cipher: wasm.pvac_encode_cipher(cipher),
              amount_commitment: btoa(String.fromCharCode(...commitment)),
              zero_proof: wasm.pvac_encode_zero_proof(proof),
              blinding: btoa(String.fromCharCode(...blinding)),
              range_proof_balance: wasm.pvac_encode_range_proof(rangeProof),
            });
            self.postMessage({ id, type: 'progress', phase: 'done', pct: 100 });
            self.postMessage({ id, type: 'result', encrypted_data: result, elapsed_ms: performance.now() - t0 });
            return;
          }
        } catch (err) {
          self.postMessage({ id, type: 'error', message: err.message || String(err) });
        }
      };
    `;

    const blob = new Blob([workerCode], { type: 'application/javascript' });
    this.worker = new Worker(URL.createObjectURL(blob), { type: 'module' });

    this.worker.onmessage = (e) => {
      const { id, type } = e.data;
      const job = this.pending.get(id);
      if (!job) return;

      if (type === 'progress') {
        job.onProgress?.(e.data.phase, e.data.pct);
      } else if (type === 'result') {
        this.pending.delete(id);
        job.resolve({ encrypted_data: e.data.encrypted_data, elapsed_ms: e.data.elapsed_ms });
      } else if (type === 'error') {
        this.pending.delete(id);
        job.reject(new Error(e.data.message));
      } else if (type === 'ready' || type === 'ok') {
        this.pending.delete(id);
        job.resolve(e.data);
      }
    };

    // Init WASM in worker
    await this.send('init', { wasmUrl: this.wasmUrl, threads });
  }

  private send(type: string, payload: any): Promise<any> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.worker!.postMessage({ id, type, payload });
    });
  }

  /** Initialize context in the worker with a seed */
  async createContext(seed: Uint8Array): Promise<void> {
    await this.ready;
    await this.send('create-ctx', { seed: Array.from(seed) });
  }

  /**
   * Encrypt (public -> private) in the worker thread.
   * Fast: no range proof.
   *
   * @param policy - Network proof policy (readProofPolicy)
   */
  async encrypt(amount: bigint, policy: number, options?: WorkerOptions): Promise<WorkerResult> {
    assertProofPolicy(policy);
    await this.ready;
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject, onProgress: options?.onProgress });
      this.worker!.postMessage({ id, type: 'encrypt', payload: { amount: amount.toString(), policy } });
    });
  }

  /**
   * Decrypt (private -> public) in the worker thread.
   * Runs the bound range proof off the main thread.
   *
   * @param policy - Network proof policy (readProofPolicy)
   */
  async decrypt(
    amount: bigint,
    currentCipher: Uint8Array,
    currentBalance: bigint,
    policy: number,
    options?: WorkerOptions,
  ): Promise<WorkerResult> {
    assertProofPolicy(policy);
    if (amount <= 0n) throw new Error('Amount must be positive');
    if (amount > currentBalance) {
      throw new Error(`Insufficient encrypted balance: have ${currentBalance}, need ${amount}`);
    }
    await this.ready;
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject, onProgress: options?.onProgress });
      this.worker!.postMessage({
        id,
        type: 'decrypt',
        payload: {
          amount: amount.toString(),
          currentCipher: Array.from(currentCipher),
          currentBalance: currentBalance.toString(),
          policy,
        },
      });
    });
  }

  /** Terminate the worker */
  terminate() {
    this.worker?.terminate();
    this.worker = null;
    for (const [id, job] of this.pending) {
      job.reject(new Error('Worker terminated'));
    }
    this.pending.clear();
  }
}
