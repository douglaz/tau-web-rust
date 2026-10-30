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
let ceremony = false;
let suspended = false;
const goalOutcomes = new Map();
const render = (store) => {
  const { state } = store;
  $('store-state').dataset.lifecycle = store.lifecycle_state ?? '';
  if (store.seed_backup_stage !== undefined) ceremony = state === 'unlocked' && store.seed_backup_stage !== 'inactive';
  if (['locked', 'none', 'refused'].includes(state)) ceremony = false;
  renderSetup(store);
  $('store').dataset.state = state;
  $('store-state').textContent = state === 'refused'
    ? `The local store is refused: ${store.reason}. Reload the page to try again.`
    : [texts[state] ?? state, store.error].filter(Boolean).join(' ');
  if (store.lifecycle_state) $('store-state').textContent += ` Session state: ${store.lifecycle_state}.`;
  $('create-help').hidden = $('confirm-field').hidden = $('create').hidden = state !== 'none';
  $('passphrase-field').hidden = state !== 'none' && state !== 'locked';
  $('passphrase').autocomplete = state === 'none' ? 'new-password' : 'current-password';
  $('unlock').hidden = state !== 'locked';
  $('lock').hidden = state !== 'unlocked';
  const stage = store.seed_backup_stage;
  const active = state === 'unlocked' && typeof stage === 'string' && stage !== 'inactive';
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
const renderDeclaration = (parent, d) => {
  paragraph(parent, `Delivery declaration version ${d.version}.`);
  const list = (label, value, empty, entry) => {
    if (value === 'unspecified') paragraph(parent, `${label}: unspecified (not stated).`);
    else if (!value.length) paragraph(parent, `${label}: explicit empty set; ${empty}.`);
    else for (const e of value) paragraph(parent, `${label}: ${entry(e)}.`);
  };
  list('Inbound listeners', d.listeners.inbound, 'no listener may be present', e => `${e.proto} port ${e.port} from ${e.from}`);
  list('Outbound restrictions', d.listeners.outbound, 'no restriction declared', e => `${e.proto} host ${e.host} port ${e.port}`);
  list('Services', d.services, 'no service obligation declared', e => `${e.name}, ${e.scope.kind}${e.scope.kind === 'user' ? ` account ${e.scope.account}` : ' (no account)'}, ${e.lifecycle === 'running-at-delivery' ? 'running at delivery' : 'enabled and survives reboot'}`);
  paragraph(parent, `Spendable tenant material: ${d.key_material.spendable === 'unspecified' ? 'unspecified (not stated)' : d.key_material.spendable ? 'permitted' : 'forbidden'}.`);
  list('Permitted tenant material', d.key_material.permitted, 'no tenant material may be present; application secrets are classified separately', e => `${e.kind} at ${e.where}`);
  list('Drift checks on re-entry', d.drift_checks, 'no re-entry checks declared', e => JSON.stringify(e));
  list('Required checks', d.required, 'no delivery checks declared', e => JSON.stringify(e));
  if (d.default_credentials === 'none') paragraph(parent, 'Default credentials: none.');
  else list('Default credentials to change', d.default_credentials, 'none declared', e => e);
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
    if (store.lifecycle_state === 'ended') return;
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
    if (machine.declaration) renderDeclaration(section, machine.declaration);
    renderDelivery(section, machine.entry.machine, store);
    for (const approval of (store.reinstall_approvals ?? []).filter(a => a.entry === machine.entry.machine)) {
      paragraph(section, `Dedicated reinstall reset ${approval.reset}: ${approval.state}; rendering session ${approval.session}.`);
      if (approval.state === 'no longer usable') paragraph(section, 'Approve again in this session to proceed; the new reset requires a newer rescue activation and a confirming read.');
      if (approval.withdrawal_offer) {
        paragraph(section, 'A standing destructive reinstall disposition still opens the installation through its own reset. Withdrawal of this approval does not withdraw that disposition. An eligible approved reset can run while hidden; there is no guaranteed withdrawal interval.');
        const withdraw = document.createElement('button');
        withdraw.type = 'button'; withdraw.dataset.withdrawReinstall = String(approval.approval);
        withdraw.textContent = `Withdraw approval for ${approval.reset}`;
        withdraw.addEventListener('click', () => { withdraw.disabled = true; worker.postMessage({ withdraw_reinstall: { approval: approval.approval, reset: approval.reset, entry: approval.entry } }); });
        section.append(withdraw);
      }
    }
    for (const approval of machine.requirements ?? []) {
      if (approval.proposal.kind === 'tighten_class') paragraph(section, 'Approved tightening: single-purpose to multi-tenant. The original class answer is retained.');
    }
    const installation = (store.installations ?? []).find(i => i.machine === machine.entry.machine);
    if (installation) paragraph(section, `Installation: ${installation.installation}.`);
    for (const ended of (store.sessions ?? []).filter(s => s.session_state === 'ended' && s.bound_set.includes(machine.entry.machine))) paragraph(section, `Session ${ended.identity}: ${ended.inference_limits?.state ?? 'ended'}. Approvals from this session are no longer usable.`);
    const session = (store.sessions ?? []).find(s => s.session_state !== 'ended' && s.bound_set.includes(machine.entry.machine));
    if (session) {
      paragraph(section, `Session ${session.identity}: bound set ${session.bound_set.join(', ')}; ${session.inference_limits?.state ?? session.session_state ?? 'running'}.`);
      const limits = session.inference_limits;
      if (limits) {
        paragraph(section, `Confirmed limit: ${(BigInt(limits.confirmed.cap_hundredths) / 100n)}.${String(BigInt(limits.confirmed.cap_hundredths) % 100n).padStart(2, '0')} ${limits.confirmed.unit}; lifetime ${limits.confirmed.lifetime_seconds / 60} minutes. No renewal; observed spend ${limits.observed_spend}. Unaccounted spend is not zero or refunded.`);
        paragraph(section, limits.original_expiry ? `Original requested expiry: ${new Date(limits.original_expiry * 1000).toISOString()} (UTC). All delays and hidden or frozen time consume this lifetime.` : 'Lifetime has not started.');
        if (limits.state === 'clock-withheld') paragraph(section, 'Clock validity unknown; verification required. The original expiry has not changed.');
      }
      if (limits?.state === 'clock-withheld') {
        if (session.goal) paragraph(section, session.goal.text);
        const verify = document.createElement('button');
        verify.type = 'button'; verify.dataset.verifyClock = session.identity;
        verify.textContent = 'Verify issuer clock';
        verify.addEventListener('click', () => { verify.disabled = true; worker.postMessage({ verify_clock: session.identity }); });
        section.append(verify); slot.append(section); continue;
      }
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
      const pending = session.pending_requirements;
      if (pending) {
        const approval = document.createElement('section');
        approval.dataset.requirementsCard = session.identity;
        paragraph(approval, `Approve intended requirements for ${pending.proposal.machine}. These are proposed requirements, not measured results.`);
        if (pending.proposal.kind === 'declaration') renderDeclaration(approval, pending.proposal.declaration);
        else paragraph(approval, 'Tighten this machine from single-purpose to multi-tenant. It must remain bound alone and cannot hold spendable or private tenant material.');
        for (const [decision, text] of [['approve', 'Approve these requirements'], ['reject', 'Reject these requirements']]) {
          const button = document.createElement('button');
          button.type = 'button';
          button.dataset.requirementsDecision = decision;
          button.textContent = text;
          button.addEventListener('click', () => {
            for (const b of approval.querySelectorAll('button')) b.disabled = true;
            worker.postMessage({ requirements_answer: { session: session.identity, machine: pending.proposal.machine, candidate: pending.candidate, decision } });
          });
          approval.append(button);
        }
        card.append(approval);
      }
      const outcome = goalOutcomes.get(session.identity);
      if (outcome) {
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
  if (store.lifecycle_state === 'ended') {
    for (const control of slot.querySelectorAll('button, input, textarea')) control.remove();
  }
};

const renderDelivery = (section, machine, store) => {
  const delivery = (store.delivery ?? []).find(d => d.machine === machine);
  if (!delivery) return;
  const card = document.createElement('section');
  card.dataset.deliveryCard = machine;
  paragraph(card, delivery.fixture_limit);
  const verdict = document.createElement('p');
  verdict.dataset.deliveryVerdict = machine;
  verdict.textContent = delivery.verdict;
  if (delivery.verdict_is_historical && delivery.last_completed_check) paragraph(card, 'The last completed result is historical; a final demonstration is still needed.');
  card.append(verdict);
  paragraph(card, 'Delivered covers the declared machine state and the fixed lockdown checks.');
  if (delivery.last_completed_check) {
    paragraph(card, 'Last recorded check against its journaled declaration:');
    paragraph(card, delivery.verdict_is_historical ? 'Last completed check (historical result):' : 'Last completed check:');
    paragraph(card, delivery.last_completed_check.result.delivered ? 'Delivered' : 'handed over with findings');
    for (const note of delivery.last_completed_check.result.notes) paragraph(card, note.service.name + ': ' + note.text);
    if (!delivery.completed_declaration_current) paragraph(card, 'The current declaration needs a re-check; the completed check used earlier values.');
  }
  if (delivery.last_check) {
    if (!delivery.last_check.result.complete) paragraph(card, 'Latest attempt incomplete; no final demonstration recorded.');
    for (const note of delivery.last_check.result.notes) {
      if (!delivery.last_check.result.complete) paragraph(card, note.service.name + ': ' + note.text);
    }
    for (const result of delivery.last_check.result.fields) paragraph(card, result.field + ': ' + result.status);
    if (!delivery.last_check.result.complete) paragraph(card, 'Latest attempt measurements: ' + JSON.stringify(delivery.last_check.measurements));
  }
  if (delivery.findings_unknown) paragraph(card, 'Findings unknown until a complete re-check.');
  for (const finding of delivery.findings ?? []) paragraph(card, finding.class + ': ' + finding.detail);
  for (const name of delivery.applications ?? []) {
    const application = document.createElement('section');
    application.dataset.deliveryApplication = '';
    paragraph(application, `${name} is an AI that acts on this server by itself. tau-web's promises cover what tau-web's AI does, not what ${name} does.`);
    paragraph(application, `It does not mean ${name} works`);
    card.append(application);
  }
  for (const session of delivery.subsequent_placement_sessions ?? []) paragraph(card, 'Placement since the last check in session ' + session + '; final lifecycle demonstration not supplied.');
  if (delivery.reports?.length) {
    paragraph(card, delivery.report_label);
    for (const report of delivery.reports) paragraph(card, JSON.stringify(report));
  }
  const session = (store.sessions ?? []).find(s => s.session_state !== 'ended' && s.bound_set.includes(machine));
  if (session && session.inference_limits?.state !== 'clock-withheld') {
    const button = document.createElement('button');
    button.type = 'button';
    button.dataset.deliveryCheck = machine;
    button.textContent = 'Check delivery (fixture evidence only)';
    button.addEventListener('click', () => {
      button.disabled = true;
      worker.postMessage({ delivery: { action: 'check', session: session.identity, machine } });
    });
    card.append(button);
  }
  section.append(card);
};
let worker;
const start = () => {
  goalOutcomes.clear();
  show('starting', 'Starting the harness…');
  render({ state: 'starting' });
  suspended = false;
  ceremony = false;
  worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
  const current = worker;
  worker.onmessage = ({ data }) => {
    if (data.requirements_store) {
      const { state, error, reason, ...rest } = JSON.parse(data.requirements_store);
      data = { store: { store_state: state, ...(error ? { store_error: error } : {}), ...(reason ? { store_reason: reason } : {}), ...rest } };
    }
    if (worker !== current) return;
    if (data.harness_ready) show('ready', `Harness ready (spec ${data.harness_ready}).`);
    else if (data.store) {
      const { store_state: state, store_error: error, store_reason: reason, ...rest } = data.store;
      if (rest.goal_outcome) goalOutcomes.set(rest.goal_outcome.session, rest.goal_outcome.outcome);
      render({ state, error, reason, ...rest });
    }
    else if (Object.keys(data).length === 1 && typeof data.seed_backup_display === 'string') {
      if (document.visibilityState === 'hidden') { lock(); return; }
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
    current.terminate();
    clearWords();
    $('seed-backup-input').value = '';
    $('passphrase').value = $('confirm').value = '';
    render({ state: 'lost' });
    show('failed', `Harness lost: ${event.message ?? 'the worker did not load'}. Reload to reopen locked.`);
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
  const hidden = document.visibilityState === 'hidden';
  if (hidden && ceremony) { lock(); return; }
  worker.postMessage({ lifecycle: hidden ? 'hidden' : 'visible' });
});
document.addEventListener('freeze', () => {
  if (ceremony) { lock(); return; }
  suspended = true;
  worker.postMessage({ lifecycle: 'freeze' });
});
document.addEventListener('resume', () => {
  if (suspended) { suspended = false; worker.postMessage({ lifecycle: 'resume' }); }
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
