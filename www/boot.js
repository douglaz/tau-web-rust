// The page: it starts the harness worker (STA-1), which holds every key, pin and record, and shows
// whether it came up, the store's one state, and the persistent-storage request's outcome. It
// defines no global. A passphrase goes to the worker once, as UTF-8 bytes in one create or unlock
// message, and its fields are cleared at once; nothing is submitted anywhere (STG-10).
const $ = (id) => document.getElementById(id);
const status = $('status');
const show = (state, text) => {
  status.dataset.state = state;
  status.textContent = text;
};

const texts = {
  starting: 'Opening the local store…',
  working: 'Working…',
  'in-use': 'Waiting for the local store: another tab, or this page\'s previous harness worker, still holds it.',
  none: 'There is no local store yet.',
  locked: 'The local store is locked.',
  unlocked: 'The local store is unlocked.',
};
const render = (store) => {
  const { state } = store;
  $('store').dataset.state = state;
  $('store-state').textContent = state === 'refused'
    ? `The local store is refused: ${store.reason}. Reload the page to try again.`
    : [texts[state] ?? state, store.error].filter(Boolean).join(' ');
  $('create-help').hidden = $('confirm-field').hidden = $('create').hidden = state !== 'none';
  $('passphrase-field').hidden = state !== 'none' && state !== 'locked';
  $('passphrase').autocomplete = state === 'none' ? 'new-password' : 'current-password';
  $('unlock').hidden = state !== 'locked';
  $('lock').hidden = state !== 'unlocked';
};

let worker;
const start = () => {
  show('starting', 'Starting the harness…');
  render({ state: 'starting' });
  worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
  worker.onmessage = ({ data }) => {
    if (data.ready) show('ready', `Harness ready (spec ${data.ready}).`);
    else if (data.store) render(data.store);
    else show('failed', `Harness failed: ${data.error}`);
  };
  worker.onerror = (event) => show('failed', `Harness failed: ${event.message ?? 'the worker did not load'}`);
};

// STA-23: explicit lock, page hide and a back/forward-cache restore each end the harness worker,
// and with it everything inside it: its keys, its channels and any work in flight. A fresh one
// starts locked. No grace timer, and nothing is journaled here. Text typed but not submitted goes
// too (SEC-5 row 18: the passphrase is in the input UI briefly).
const lock = () => {
  worker.terminate();
  $('passphrase').value = '';
  $('confirm').value = '';
  start();
};
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden') lock();
});
addEventListener('pagehide', lock);
addEventListener('pageshow', (event) => {
  if (event.persisted) lock();
});
$('lock').addEventListener('click', lock);

const send = (kind) => {
  const passphrase = $('passphrase');
  const confirm = $('confirm');
  const differ = kind === 'create' && passphrase.value !== confirm.value;
  const bytes = differ ? null : new TextEncoder().encode(passphrase.value);
  passphrase.value = '';
  confirm.value = '';
  if (differ) {
    render({ state: 'none', error: 'The two passphrases differ.' });
    return;
  }
  render({ state: 'working' });
  worker.postMessage({ [kind]: bytes }, [bytes.buffer]);
};
$('create').addEventListener('click', () => send('create'));
$('unlock').addEventListener('click', () => send('unlock'));

// STA-23: "The browser MUST request persistent storage and visibly report a refusal." Asked once
// per load, unless already granted.
const persist = $('persist');
const request = async () => {
  try {
    return (await navigator.storage.persisted()) || (await navigator.storage.persist());
  } catch {
    return false;
  }
};
request().then((granted) => {
  persist.dataset.state = granted ? 'granted' : 'refused';
  persist.textContent = `${granted
    ? 'Persistent storage is granted.'
    : 'Persistent storage: the browser refused the request.'} This is a request, not a guarantee: eviction, device loss or corruption can still lose the local store, so the seed backup and recovery remain necessary.`;
});

start();
