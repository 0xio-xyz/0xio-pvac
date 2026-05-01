/**
 * Re-export the pvac-rs WASM module for convenience.
 * Consumers can import directly:
 *   import { initPvac } from '@0xio/pvac';
 *   const wasm = await initPvac();
 */

// Dynamic import path — NOT resolved by rollup at build time
const WASM_PATH = '../wasm/pvac_rs.js';

export async function initPvac(): Promise<any> {
  // Use Function constructor to prevent rollup from resolving the import
  const dynamicImport = new Function('p', 'return import(p)');
  const mod = await dynamicImport(WASM_PATH);
  await mod.default(); // calls wasm init
  return mod;
}
