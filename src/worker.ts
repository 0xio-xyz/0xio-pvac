/**
 * ProofWorker — offload slow proof generation to a Web Worker.
 *
 * Range proofs take 30-60s and freeze the UI thread. This module
 * runs them in a dedicated worker with progress reporting.
 *
 * Usage:
 *   const worker = new ProofWorker(wasmUrl);
 *   const result = await worker.decrypt(seed, amount, currentCipher, currentBalance, {
 *     onProgress: (pct) => console.log(`${pct}%`),
 *   });
 *   worker.terminate();
 *
 * Requirements:
 * - SharedArrayBuffer (COOP/COEP headers)
 * - WASM module URL accessible from worker
 */

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
   * @param wasmUrl - URL to the pvac_rs_bg.wasm file
   * @param threads - Number of rayon threads (default: navigator.hardwareConcurrency)
   */
  constructor(wasmUrl: string, threads?: number) {
    this.wasmUrl = wasmUrl;
    this.ready = this.init(threads ?? navigator.hardwareConcurrency);
  }

  private async init(threads: number): Promise<void> {
    // Create worker from inline blob — avoids needing a separate worker file
    const workerCode = `
      let wasm = null;
      let ctx = null;

      self.onmessage = async (e) => {
        const { id, type, payload } = e.data;
        try {
          if (type === 'init') {
            const mod = await import(payload.wasmUrl);
            await mod.default();
            await mod.initThreadPool(payload.threads);
            mod.pvac_pre_warm_generators(64);
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
            const proof = ctx.make_bound_proof(cipher, BigInt(payload.amount), blinding);
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
            const proof = ctx.make_bound_proof(cipher, BigInt(payload.amount), blinding);
            self.postMessage({ id, type: 'progress', phase: 'balance-cipher', pct: 15 });
            const currentCipher = new Uint8Array(payload.currentCipher);
            const newCipher = ctx.ct_sub(currentCipher, cipher);
            const newValue = BigInt(payload.currentBalance) - BigInt(payload.amount);
            self.postMessage({ id, type: 'progress', phase: 'range-proof', pct: 20 });
            const rangeProof = ctx.make_range_proof_parallel(newCipher, newValue);
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
   * Encrypt (public → private) in the worker thread.
   * Fast — no range proof.
   */
  async encrypt(amount: bigint, options?: WorkerOptions): Promise<WorkerResult> {
    await this.ready;
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject, onProgress: options?.onProgress });
      this.worker!.postMessage({ id, type: 'encrypt', payload: { amount: amount.toString() } });
    });
  }

  /**
   * Decrypt (private → public) in the worker thread.
   * SLOW — runs range proof off the main thread.
   */
  async decrypt(
    amount: bigint,
    currentCipher: Uint8Array,
    currentBalance: bigint,
    options?: WorkerOptions,
  ): Promise<WorkerResult> {
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
