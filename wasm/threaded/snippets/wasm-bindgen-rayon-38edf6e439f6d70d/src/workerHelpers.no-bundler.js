/*
 * Copyright 2022 Google Inc. All Rights Reserved.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// This file is kept similar to workerHelpers.js, but intended to be used in
// a bundlerless ES module environment (which has a few differences).

function waitForMsgType(target, type) {
  return new Promise(resolve => {
    target.addEventListener('message', function onMsg({ data }) {
      if (data == null || data.type !== type) return;
      target.removeEventListener('message', onMsg);
      resolve(data);
    });
  });
}

// We need to wait for a specific message because this file is used both
// as a Worker and as a regular script, so it might receive unrelated
// messages on the page.
waitForMsgType(self, 'wasm_bindgen_worker_init').then(async data => {
  const pkg = await import(data.mainJS);
  await pkg.default({ module_or_path: data.module, memory: data.memory });
  postMessage({ type: 'wasm_bindgen_worker_ready' });
  pkg.wbg_rayon_start_worker(data.receiver);
});

// Note: this is never used, but necessary to prevent a bug in Firefox
// (https://bugzilla.mozilla.org/show_bug.cgi?id=1702191) where it collects
// Web Workers that have a shared WebAssembly memory with the main thread,
// but are not explicitly rooted via a `Worker` instance.
//
// By storing them in a variable, we can keep `Worker` objects around and
// prevent them from getting GC-d.
let _workers;

export async function startWorkers(module, memory, builder) {
  if (builder.numThreads() === 0) {
    throw new Error(`num_threads must be > 0.`);
  }

  // Track sub-worker health on the calling context's global (pvac-worker.js's self)
  self.__rayonSubWorkersCrashed = 0;
  self.__rayonSubWorkersTotal = builder.numThreads();

  const sameOrigin = new URL(import.meta.url).origin === self.location.origin;
  // Only a worker reports crashes: on a page, postMessage would reach the page's own listeners
  const inWorker = typeof WorkerGlobalScope !== 'undefined' && self instanceof WorkerGlobalScope;

  const workerInit = {
    type: 'wasm_bindgen_worker_init',
    module,
    memory,
    receiver: builder.receiver(),
    mainJS: builder.mainJS()
  };

  _workers = await Promise.all(
    Array.from({ length: builder.numThreads() }, async () => {
      // Same origin (extension, self-hosted): spawn this file directly, since
      // extension CSP blocks blob: workers. Cross-origin (CDN): browsers refuse
      // the script URL, so a blob module worker imports it instead.
      const blobUrl = sameOrigin ? null : URL.createObjectURL(
        new Blob([`import ${JSON.stringify(import.meta.url)};`], { type: 'text/javascript' })
      );
      const worker = new Worker(blobUrl || import.meta.url, {
        type: 'module'
      });
      worker.onerror = (e) => {
        // Sub-worker crashed: likely Atomics.wait() is blocked in this context.
        // wbg_rayon_start_worker() calls Atomics.wait() after sending 'ready'.
        self.__rayonSubWorkersCrashed = (self.__rayonSubWorkersCrashed || 0) + 1;
        if (inWorker) {
          self.postMessage({ id: 0, log: `[rayon sub-worker] CRASHED: ${e.message} (${self.__rayonSubWorkersCrashed}/${self.__rayonSubWorkersTotal} dead)` });
        }
      };
      worker.postMessage(workerInit);
      await waitForMsgType(worker, 'wasm_bindgen_worker_ready');
      if (blobUrl) URL.revokeObjectURL(blobUrl);
      return worker;
    })
  );
  builder.build();
}
