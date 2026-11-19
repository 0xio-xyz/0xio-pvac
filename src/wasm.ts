/**
 * Load the pvac-rs WASM module.
 *
 *   import { initPvac, pvacMode } from '@0xio/pvac';
 *   const wasm = await initPvac();
 *   if (pvacMode() === 'single') showSlowerProofs();
 *
 * Two builds ship in wasm/: threaded (needs a cross-origin isolated page)
 * and single (runs anywhere, proofs take longer).
 */

export type PvacMode = 'threaded' | 'single';

export interface InitPvacOptions {
  /** 'auto' (default) picks threaded on cross-origin isolated pages, single elsewhere */
  mode?: 'auto' | PvacMode;
  /** URL of a self-hosted copy of the package's wasm/ folder (holding threaded/ and single/) */
  wasmBase?: string | URL;
}

// Kept out of the new URL('...', import.meta.url) form so bundlers do not try to emit the folder
const MODULE_URL = import.meta.url;

let loadedMode: PvacMode | null = null;

/** True when this context can run the threaded build (SharedArrayBuffer and cross-origin isolation). */
export function canUseThreads(): boolean {
  return (globalThis as any).crossOriginIsolated === true && typeof SharedArrayBuffer === 'function';
}

/** The build initPvac loaded, or null before it ran. */
export function pvacMode(): PvacMode | null {
  return loadedMode;
}

/** URL of the pvac_rs.js glue for a build. */
export function pvacGlueUrl(mode: PvacMode, wasmBase?: string | URL): string {
  const base = wasmBase ? new URL(String(wasmBase).replace(/\/?$/, '/'), globalThis.location?.href) : new URL('../wasm/', MODULE_URL);
  return new URL(`${mode}/pvac_rs.js`, base).href;
}

export async function initPvac(options: InitPvacOptions = {}): Promise<any> {
  const requested = options.mode ?? 'auto';
  const mode: PvacMode = requested === 'auto' ? (canUseThreads() ? 'threaded' : 'single') : requested;
  if (mode === 'threaded' && !canUseThreads()) {
    throw new Error('Threaded PVAC needs a cross-origin isolated page (Cross-Origin-Opener-Policy: same-origin, Cross-Origin-Embedder-Policy: require-corp)');
  }
  const url = pvacGlueUrl(mode, options.wasmBase);
  const mod = await import(/* webpackIgnore: true */ /* @vite-ignore */ url);
  await mod.default();
  loadedMode = mode;
  return mod;
}
