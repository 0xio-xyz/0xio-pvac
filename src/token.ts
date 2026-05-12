/**
 * ConfidentialToken — OAT token with encrypted balances.
 *
 * High-level interface for interacting with privacy-preserving tokens on Octra:
 * - Query encrypted balance and decrypt
 * - Build private transfer transactions (sender encrypts, proves, sends)
 * - Build private approve/transferFrom flows
 *
 * Usage:
 *   const token = new ConfidentialToken(ctx, tokenAddress, rpcUrl);
 *   const balance = await token.balance(myAddress, signer);
 *   const tx = await token.transfer(to, 1_000_000n, currentCipher, currentBalance);
 */

import type { PvacContext } from './context';
import type { Cipher } from './types';
import { uint8ToBase64, decodeCipher } from './encoding';
import type { ProgressCallback } from './transfer';

export interface TokenInfo {
  address: string;
  name: string;
  symbol: string;
  decimals: number;
  totalSupply: bigint;
}

export interface TokenBalance {
  /** Public (unencrypted) token balance */
  public: bigint;
  /** Private (encrypted) token balance, null if cipher unavailable */
  private: bigint | null;
  /** Raw cipher bytes (for building transactions) */
  cipher: Cipher | null;
}

/** Transaction payload ready for SDK callContract */
export interface TokenTxPayload {
  contract: string;
  method: string;
  args: string[];
  encrypted_data?: string;
}

export class ConfidentialToken {
  private ctx: PvacContext;
  readonly address: string;
  private rpcUrl: string;
  private infoCache: TokenInfo | null = null;

  constructor(ctx: PvacContext, tokenAddress: string, rpcUrl: string) {
    this.ctx = ctx;
    this.address = tokenAddress;
    this.rpcUrl = rpcUrl;
  }

  /** Fetch token metadata (cached after first call) */
  async info(): Promise<TokenInfo> {
    if (this.infoCache) return this.infoCache;
    const [name, symbol, decimals, totalSupply] = await Promise.all([
      this.view('name', []),
      this.view('symbol', []),
      this.view('decimals', []),
      this.view('total_supply', []),
    ]);
    this.infoCache = {
      address: this.address,
      name: String(name),
      symbol: String(symbol),
      decimals: Number(decimals),
      totalSupply: BigInt(totalSupply),
    };
    return this.infoCache;
  }

  /** Get public balance of an address (uses fast tokensByAddress RPC with balance_of fallback) */
  async balanceOf(address: string): Promise<bigint> {
    try {
      const res = await fetch(this.rpcUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0', id: 1,
          method: 'octra_tokensByAddress',
          params: [address],
        }),
      });
      const data = await res.json();
      const tokens: any[] = data?.result?.tokens || [];
      const match = tokens.find((t: any) =>
        (t.contract_address || t.contractAddress || t.address) === this.address
      );
      if (match) return BigInt(match.balance ?? 0);
    } catch { /* fallback below */ }
    const result = await this.view('balance_of', [address]);
    return BigInt(result ?? 0);
  }

  /** Get allowance */
  async allowance(owner: string, spender: string): Promise<bigint> {
    const result = await this.view('allowance', [owner, spender]);
    return BigInt(result ?? 0);
  }

  /**
   * Build a private transfer payload.
   * Encrypts the amount, generates bound proof, and returns ready-to-submit data.
   */
  buildTransfer(
    to: string,
    amount: bigint,
    onProgress?: ProgressCallback,
  ): TokenTxPayload {
    if (amount <= 0n) throw new Error('Amount must be positive');

    onProgress?.('encrypting', 20);
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const blinding = crypto.getRandomValues(new Uint8Array(32));
    const cipher = this.ctx.encryptSeeded(amount, seed);

    onProgress?.('commitment', 40);
    const { commitment } = this.ctx.pedersenCommit(amount, blinding);

    onProgress?.('bound-proof', 60);
    const { proof } = this.ctx.makeBoundProof(cipher, amount, blinding);

    onProgress?.('encoding', 90);
    const encrypted_data = JSON.stringify({
      cipher: this.ctx.encodeCipher(cipher),
      amount_commitment: uint8ToBase64(commitment),
      zero_proof: this.ctx.encodeZeroProof(proof),
      blinding: uint8ToBase64(blinding),
    });

    onProgress?.('done', 100);
    return {
      contract: this.address,
      method: 'transfer',
      args: [to, amount.toString()],
      encrypted_data,
    };
  }

  /** Build an approve payload */
  buildApprove(spender: string, amount: bigint): TokenTxPayload {
    return {
      contract: this.address,
      method: 'approve',
      args: [spender, amount.toString()],
    };
  }

  /** Build a transferFrom payload */
  buildTransferFrom(from: string, to: string, amount: bigint): TokenTxPayload {
    return {
      contract: this.address,
      method: 'transfer_from',
      args: [from, to, amount.toString()],
    };
  }

  /** Format amount with token decimals */
  async formatAmount(amount: bigint): Promise<string> {
    const { decimals, symbol } = await this.info();
    const divisor = 10n ** BigInt(decimals);
    const whole = amount / divisor;
    const frac = (amount % divisor).toString().padStart(decimals, '0');
    return `${parseFloat(`${whole}.${frac}`)} ${symbol}`;
  }

  private async view(method: string, args: string[]): Promise<any> {
    const res = await fetch(this.rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0', id: 1,
        method: 'contract_call',
        params: [this.address, method, args, this.address],
      }),
    });
    const data = await res.json();
    return data?.result?.result;
  }
}
