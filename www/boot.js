// The page sends passphrase and re-entry bytes once and clears fields immediately. The only
// mnemonic display is the dedicated seed-backup ceremony; lock removes its words and inputs.
const $ = (id) => document.getElementById(`tau-${id}`);
const status = $('status');
const show = (state, text) => {
  status.dataset.state = state === 'ready' ? 'harness-ready' : state;
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
const clearWords = () => $('seed-backup-words-slot').replaceChildren();
let redisplay = false;
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
  const stage = store.seed_backup_stage;
  const active = state === 'unlocked' && stage !== 'inactive';
  clearWords();
  $('seed-backup').hidden = !active;
  $('seed-backup-answer').hidden = stage !== 'showing_words';
  $('seed-backup-entry').hidden = stage !== 'answering';
  $('redisplay').hidden = state !== 'unlocked' || active;
  const completion = store.seed_backup_completion;
  if (state === 'unlocked' && completion) {
    $('store-state').textContent += completion === 'full_reentry'
      ? ' Seed-backup record: all twelve words re-entered.'
      : ' Seed-backup record: re-entry check skipped.';
  }
  $('seed-backup-state').textContent = active
    ? ['Seed-backup ceremony.', store.seed_backup_owed
      ? 'New machines, relay passes and handoffs are refused until the seed backup is recorded.'
      : stage !== 'append_failed' && 'Re-display: record a new full re-entry or skip.',
    'Dispatch is stopped.', store.error].filter(Boolean).join(' ')
    : '';
  if (state === 'locked' && redisplay) $('store-state').textContent += ' Enter the local passphrase again to show the seed backup.';
};

let worker;
const start = () => {
  show('starting', 'Starting the harness…');
  render({ state: 'starting' });
  worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
  const current = worker;
  worker.onmessage = ({ data }) => {
    if (worker !== current) return;
    if (data.harness_ready) show('ready', `Harness ready (spec ${data.harness_ready}).`);
    else if (data.store) {
      const { store_state: state, store_error: error, store_reason: reason, ...rest } = data.store;
      render({ state, error, reason, ...rest });
    }
    else if (Object.keys(data).length === 1 && typeof data.seed_backup_display === 'string') {
      clearWords();
      const list = document.createElement('ol');
      list.id = 'tau-seed-backup-words';
      for (const word of data.seed_backup_display.split(' ')) {
        const item = document.createElement('li');
        item.textContent = word;
        list.append(item);
      }
      $('seed-backup-words-slot').append(list);
    }
    else show('failed', `Harness failed: ${data.harness_error}`);
  };
  worker.onerror = (event) => {
    if (worker !== current) return;
    clearWords();
    $('seed-backup-input').value = '';
    show('failed', `Harness failed: ${event.message ?? 'the worker did not load'}`);
  };
};

// STA-23: explicit lock, page hide and a back/forward-cache restore each end the harness worker,
// and with it everything inside it: its keys, its channels and any work in flight. A fresh one
// starts locked. No grace timer, and nothing is journaled here. Text typed but not submitted goes
// too (SEC-5 row 18: the passphrase is in the input UI briefly).
const lock = () => {
  worker.terminate();
  clearWords();
  $('seed-backup-input').value = '';
  redisplay = false;
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
  const operation = kind === 'unlock' && redisplay ? 'seed_backup_redisplay' : kind;
  redisplay = false;
  worker.postMessage({ [operation]: bytes }, [bytes.buffer]);
};
$('create').addEventListener('click', () => send('create'));
$('unlock').addEventListener('click', () => send('unlock'));

$('redisplay').addEventListener('click', () => {
  lock();
  redisplay = true;
});
$('seed-backup-answer').addEventListener('click', () => {
  clearWords();
  worker.postMessage({ seed_backup_answer: true });
});
$('seed-backup-check').addEventListener('click', () => {
  const field = $('seed-backup-input');
  const bytes = new TextEncoder().encode(field.value);
  field.value = '';
  worker.postMessage({ seed_backup_reentry: bytes }, [bytes.buffer]);
});
$('seed-backup-skip').addEventListener('click', () => {
  $('seed-backup-input').value = '';
  worker.postMessage({ seed_backup_skip: true });
});

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
