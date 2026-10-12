// The page is a bootstrap: it starts the harness worker (STA-1), which holds every key, pin and
// record, and shows whether the worker came up. It defines no global and passes the worker no
// request.
const status = document.getElementById('status');
const show = (state, text) => {
  status.dataset.state = state;
  status.textContent = text;
};
const worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
worker.onmessage = ({ data }) =>
  data.ready ? show('ready', `Harness ready (spec ${data.ready}).`) : show('failed', `Harness failed: ${data.error}`);
worker.onerror = (event) => show('failed', `Harness failed: ${event.message ?? 'the worker did not load'}`);
