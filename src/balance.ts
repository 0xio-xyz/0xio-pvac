/**
 * ConfidentialBalance — fetch, decrypt, cache, and display encrypted balances.
 *
 * Handles the full lifecycle of an encrypted balance on Octra:
 * - Fetch cipher from RPC (octra_encryptedBalance)
 * - Decrypt using PvacContext
 * - Cache results (avoid re-decrypting same cipher)
 * - Format for display (microOCT → OCT)
 *
 * Usage:
 *   const balance = new ConfidentialBalance(ctx);
 *   const { public, private, total } = await balance.fetch(address, signer);
 *   balance.onUpdate((b) => console.log('Balance:', b.total));
 */

import type { PvacContext } from './context';
import { decodeCipher } from './encoding';

const MICRO_OCT = 1_000_000n;

export interface BalanceSnapshot {
  /** Public (unencrypted) balance in microOCT */
  public: bigint;
  /** Private (encrypted) balance in microOCT, null if not yet decrypted */
  private: bigint | null;
  /** Total balance (public + private), null if private unknown */
  total: bigint | null;
  /** Whether decryption permanently failed (key mismatch) */
  decryptFailed: boolean;
  /** Timestamp of this snapshot */
  timestamp: number;
  /** Time taken to decrypt in ms (0 if cached) */
  decryptMs: number;
}

export interface BalanceFormatted {
  public: string;
  private: string | null;
  total: string | null;
  publicUsd: string | null;
  totalUsd: string | null;
}

type BalanceListener = (balance: BalanceSnapshot) => void;

/** RPC signer function — signs a challenge for octra_encryptedBalance auth */
export type BalanceSigner = (challenge: string) => Promise<{ signature: string; publicKey: string }>;

export class ConfidentialBalance {
  private ctx: PvacContext;
  private cache: Map<string, { cipher: string; value: bigint }> = new Map();
  private listeners: Set<BalanceListener> = new Set();
  private lastSnapshot: BalanceSnapshot | null = null;
  private rpcUrl: string;

  constructor(ctx: PvacContext, rpcUrl: string) {
    this.ctx = ctx;
    this.rpcUrl = rpcUrl;
  }

  /** Subscribe to balance updates */
  onUpdate(cb: BalanceListener): () => void {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }

  /** Get the last known balance without fetching */
  get current(): BalanceSnapshot | null {
    return this.lastSnapshot;
  }

  /**
   * Fetch and decrypt the full balance for an address.
   *
   * @param address - Octra address (oct...)
   * @param signer - Signs the RPC auth challenge
   * @param octPrice - Optional OCT/USD price for USD formatting
   */
  async fetch(address: string, signer: BalanceSigner, octPrice?: number): Promise<BalanceSnapshot> {
    // 1. Get public balance
    const pubResult = await this.rpc('octra_balance', [address]);
    const publicBalance = BigInt(pubResult?.balance ?? pubResult?.balance_in_microunits ?? 0);

    // 2. Get encrypted balance (requires auth signature)
    let privateBalance: bigint | null = null;
    let decryptFailed = false;
    let decryptMs = 0;

    try {
      const { signature, publicKey } = await signer(address);
      const encResult = await this.rpc('octra_encryptedBalance', [address, signature, publicKey]);

      if (encResult?.cipher) {
        const cipherStr = encResult.cipher as string;
        // Check cache — same cipher = same value
        const cached = this.cache.get(address);
        if (cached && cached.cipher === cipherStr) {
          privateBalance = cached.value;
        } else {
          const t0 = performance.now();
          try {
            const rawCipher = decodeCipher(cipherStr);
            const decrypted = this.ctx.decrypt(rawCipher);
            privateBalance = decrypted;
            decryptMs = performance.now() - t0;
            this.cache.set(address, { cipher: cipherStr, value: decrypted });
          } catch {
            decryptFailed = true;
          }
        }
      }
    } catch {
      // Encrypted balance not available — public only
    }

    const snapshot: BalanceSnapshot = {
      public: publicBalance,
      private: privateBalance,
      total: privateBalance !== null ? publicBalance + privateBalance : null,
      decryptFailed,
      timestamp: Date.now(),
      decryptMs,
    };

    this.lastSnapshot = snapshot;
    this.listeners.forEach(cb => cb(snapshot));
    return snapshot;
  }

  /** Clear the decrypt cache (e.g., after encrypt/decrypt tx changes balance) */
  invalidate(address?: string) {
    if (address) this.cache.delete(address);
    else this.cache.clear();
  }

  /** Format a balance for display */
  static format(snapshot: BalanceSnapshot, octPrice?: number, decimals = 6): BalanceFormatted {
    const fmt = (v: bigint) => {
      const whole = v / MICRO_OCT;
      const frac = v % MICRO_OCT;
      const fracStr = frac.toString().padStart(6, '0').slice(0, decimals);
      const raw = `${whole}.${fracStr}`;
      return parseFloat(raw).toString();
    };

    const fmtUsd = (v: bigint, price: number) => {
      const oct = Number(v) / Number(MICRO_OCT);
      return `$${(oct * price).toFixed(2)}`;
    };

    return {
      public: fmt(snapshot.public),
      private: snapshot.private !== null ? fmt(snapshot.private) : null,
      total: snapshot.total !== null ? fmt(snapshot.total) : null,
      publicUsd: octPrice ? fmtUsd(snapshot.public, octPrice) : null,
      totalUsd: snapshot.total !== null && octPrice ? fmtUsd(snapshot.total, octPrice) : null,
    };
  }

  private async rpc(method: string, params: unknown[]): Promise<any> {
    const res = await fetch(this.rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    });
    const data = await res.json();
    if (data.error) throw new Error(data.error.message || JSON.stringify(data.error));
    return data.result;
  }
}
