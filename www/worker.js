// The harness worker (STA-1): it loads the wasm module and reports that it is up. Keys, pins and
// the journal live in the module. Nothing here takes a request: the module's `run_command` is
// called in this worker's own context, and only the tracer does so, over the DevTools protocol.
import init, { spec_commit } from './pkg/tau_web.js';

try {
  await init();
  postMessage({ ready: spec_commit() });
} catch (error) {
  postMessage({ error: String(error) });
}
