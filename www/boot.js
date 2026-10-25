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
  renderSetup(store);
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

// Fixture wording until the signed bundle supplies it. No message supplies question text.
const classQuestion = "Will this machine serve people you have never met, for example by renting out space on it or hosting other people's accounts?";
const classHelp = "If you are not sure, the machine is treated as serving people you have never met: it never holds spendable keys and is always bound alone.";
const answers = [['yes', 'Yes'], ['no', 'No, only me and people I know'], ['not_sure', 'Not sure']];
const paragraph = (parent, text) => {
  const p = document.createElement('p');
  p.textContent = text;
  parent.append(p);
};
const renderSetup = (store) => {
  const slot = $('setup');
  slot.replaceChildren();
  slot.hidden = store.state !== 'unlocked' || store.seed_backup_stage !== 'inactive';
  if (slot.hidden) return;
  const approved = store.setup ?? [];
  const entries = approved.length ? approved.map(m => m.entry) : store.setup_offer ?? [];
  if (!entries.length) return;
  paragraph(slot, approved.length ? 'Approved setup' : 'Approve the setup');
  paragraph(slot, "Prices are fixture data, not a vendor's price.");
  for (const entry of entries) {
    paragraph(slot, `${entry.machine}: ${entry.vendor}; ${entry.product}; ${entry.region}; ${entry.cost.amount} ${entry.cost.unit} per ${entry.cost.period}.`);
  }
  const monthly = entries.reduce((sum, entry) => sum + BigInt(entry.cost.amount), 0n);
  paragraph(slot, `Setup total: ${monthly} sat per month; ${monthly * 12n} sat per year.`);
  paragraph(slot, 'Each machine will be bound alone in its own session.');
  paragraph(slot, "Recurring means each machine is billed by its vendor every month from the moment it is created until it is destroyed or abandoned, whether or not setup finishes. tau-web never pays for a machine and cannot stop a vendor's billing; only you can.");
  if (!approved.length) {
    const button = document.createElement('button');
    button.type = 'button';
    button.id = 'tau-setup-approve';
    button.textContent = 'Approve setup';
    button.addEventListener('click', () => {
      button.disabled = true;
      worker.postMessage({ setup_approve: true });
    });
    slot.append(button);
    return;
  }
  for (const machine of approved) {
    const section = document.createElement('section');
    section.dataset.machine = machine.entry.machine;
    paragraph(section, `${machine.entry.machine}: ${machine.family} index ${machine.index}.`);
    if (machine.class === null) {
      paragraph(section, `Machine class for ${machine.entry.machine}.`);
      paragraph(section, classQuestion);
      paragraph(section, classHelp);
      const controls = document.createElement('div');
      controls.dataset.classAnswers = '';
      for (const [answer, label] of answers) {
        const button = document.createElement('button');
        button.type = 'button';
        button.dataset.answer = answer;
        button.textContent = label;
        button.addEventListener('click', () => {
          for (const control of controls.children) control.disabled = true;
          worker.postMessage({ setup_answer: { machine: machine.entry.machine, answer } });
        });
        controls.append(button);
      }
      section.append(controls);
    } else {
      paragraph(section, `Answer: ${machine.answer}; class: ${machine.class}.`);
    }
    const access = machine.access;
    if (access) paragraph(section, `Access model: ${access.model}; profile ${access.profile}, revision ${access.revision}.`);
    const installation = (store.installations ?? []).find(i => i.machine === machine.entry.machine);
    if (installation) paragraph(section, `Installation: ${installation.installation}.`);
    const session = (store.sessions ?? []).find(s => s.bound_set.includes(machine.entry.machine));
    if (session) {
      paragraph(section, `Session ${session.identity}: bound set ${session.bound_set.join(', ')}.`);
      const card = document.createElement('section');
      card.dataset.goalCard = session.identity;
      paragraph(card, 'Goal for this session');
      if (session.goal) {
        paragraph(card, session.goal.text);
        paragraph(card, `Source: ${session.goal.source}.`);
        if (session.goal.document_source) paragraph(card, `Document source: ${session.goal.document_source}.`);
        if (!(session.standing_modes ?? []).includes('Acting on a goal with no brief')) {
          paragraph(card, 'No brief is available.');
          const accept = document.createElement('button');
          accept.type = 'button';
          accept.dataset.goalAccept = session.identity;
          accept.textContent = 'Acting on a goal with no brief';
          accept.addEventListener('click', () => {
            accept.disabled = true;
            worker.postMessage({ goal_accept: { session: session.identity } });
          });
          card.append(accept);
        }
      } else {
        const words = document.createElement('textarea');
        words.dataset.goalText = '';
        words.setAttribute('aria-label', 'Your goal in your own words');
        const source = document.createElement('input');
        source.type = 'url';
        source.dataset.documentSource = '';
        source.setAttribute('aria-label', 'Optional document source (https URL)');
        const enter = document.createElement('button');
        enter.type = 'button';
        enter.dataset.goalEnter = session.identity;
        enter.textContent = 'Set goal';
        enter.addEventListener('click', () => {
          const text = words.value;
          const document_source = source.value || null;
          words.value = source.value = '';
          enter.disabled = true;
          worker.postMessage({ goal: { session: session.identity, text, document_source } });
        });
        card.append(words, source, enter);
      }
      if (store.goal_outcome?.session === session.identity) {
        const outcome = store.goal_outcome.outcome;
        const status = document.createElement('p');
        status.dataset.goalOutcome = session.identity;
        status.textContent = outcome.done === true ? 'Goal loop ended: done.'
          : outcome.unresolved === true ? 'Goal loop ended: inference request unresolved.'
          : outcome.refused ? `Goal loop ended: ${outcome.refused}.`
          : outcome.finished === true ? `Goal loop ended: inference request finished with status ${outcome.status}.`
          : 'Goal loop ended.';
        card.append(status);
      }
      section.append(card);
      const spend = session.unaccounted_spend;
      if (spend?.count) paragraph(section, `${spend.count} unresolved inference requests: unaccounted spend against cap ${spend.cap}.`);
      for (const label of session.standing_modes ?? []) paragraph(section, `Standing mode: ${label}.`);
    }
    else if (machine.class !== null && access) {
      const button = document.createElement('button');
      button.type = 'button';
      button.dataset.bind = machine.entry.machine;
      button.textContent = `Bind ${machine.entry.machine}`;
      button.addEventListener('click', () => {
        button.disabled = true;
        worker.postMessage({ bind: { machine: machine.entry.machine } });
      });
      section.append(button);
    }
    slot.append(section);
  }
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

// Stop dispatch and clear the page at once. The worker drops session holdings, records each
// revoke and answers; termination follows that answer or this implementation bound. Expiry
// and the next-unlock sweep cover a killed worker without relying on an unload append.
const END_SESSIONS_BOUND_MS = 5000;
const endingWorkers = new WeakSet();
const lock = () => {
  const previous = worker;
  if (!endingWorkers.has(previous)) {
    endingWorkers.add(previous);
    const timer = setTimeout(() => previous.terminate(), END_SESSIONS_BOUND_MS);
    previous.addEventListener('message', ({ data }) => {
      if (data?.sessions_ended === true && Object.keys(data).length === 1) {
        clearTimeout(timer);
        previous.terminate();
      }
    });
    previous.postMessage({ end_sessions: true });
  }
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
