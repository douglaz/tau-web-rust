// The harness worker (STA-1): it loads the wasm module, takes the store's writer lock and opens
// the store. Keys, pins and the journal live in the module. The page sends one message per
// create or unlock, the passphrase's UTF-8 bytes, which the module zero-fills; the module's
// `run_command` is called in this worker's own context, and only the tracer does so, over the
// DevTools protocol.
import init, { spec_commit, open, create, unlock } from './pkg/tau_web.js';

try {
  await init();
  postMessage({ ready: spec_commit() });
} catch (error) {
  postMessage({ error: String(error) });
  throw error;
}

// STA-1 and STA-7: one writer. The lock is exclusive and store-wide, taken before the store is
// read and held for this worker's whole life; while another worker holds it, this one queues.
const held = (options) =>
  new Promise((acquired) =>
    navigator.locks.request('tau-web-store', options, (lock) => {
      acquired(lock !== null);
      return lock && new Promise(() => {});
    }));
if (!(await held({ ifAvailable: true }))) {
  postMessage({ store: { state: 'in-use' } });
  await held({});
}
onmessage = async ({ data }) => {
  const report = data.create ? create(data.create) : unlock(data.unlock);
  postMessage({ store: JSON.parse(await report) });
};
postMessage({ store: JSON.parse(await open()) });
