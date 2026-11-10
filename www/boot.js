// The page sends passphrase and re-entry bytes once and clears fields immediately. The only
// mnemonic display is the dedicated seed-backup ceremony; lock removes its words and inputs.
const $ = (id) => document.getElementById(`tau-${id}`);
const status = $('status');
const show = (state, text) => {
  status.dataset.state = state === 'ready' ? 'harness-ready' : state;
  status.textContent = text;
};

// One same-directory object is validated before any value is applied.
const defaultsFields = ['provider_origin', 'relay_url', 'chat_endpoint', 'model', 'topup_sat'];
const defaultsInputs = ['provider-origin', 'provider-relay', 'poc-relay', 'poc-endpoint', 'poc-model', 'credit-amount'];
const defaultsEdited = new Set();
for (const id of defaultsInputs) $(id).addEventListener('input', () => defaultsEdited.add(id));
const validDefaults = value => {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== defaultsFields.length || !defaultsFields.every(k => Object.hasOwn(value, k))) return false;
  const ipv4 = host => host.split('.').length === 4 && host.split('.').every(p => /^(0|[1-9][0-9]{0,2})$/.test(p) && Number(p) <= 255);
  const dns = host => host.length > 0 && host.length <= 253 && host.split('.').every(p =>
    p.length <= 63 && /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(p));
  const url = (text, kind) => {
    const prefix = kind === 'relay' ? 'wss://' : 'https://';
    if (typeof text !== 'string' || !text.startsWith(prefix) || text.length > (kind === 'provider' ? 320 : 2048) || /[^\x21-\x7e]|[\\?@#%]/.test(text)) return false;
    const rest = text.slice(prefix.length), slash = rest.indexOf('/');
    const authority = slash < 0 ? rest : rest.slice(0, slash), path = slash < 0 ? '' : rest.slice(slash);
    let host, port;
    if (kind === 'provider' && authority.startsWith('[')) {
      const match = authority.match(/^(\[[0-9a-fA-F:.]+\])(?::([0-9]+))?$/);
      if (!match) return false;
      [, host, port] = match;
    } else {
      const match = authority.match(/^([^:]+)(?::([0-9]+))?$/);
      if (!match) return false;
      [, host, port] = match;
      const name = kind === 'provider' ? host.replace(/\.$/, '') : host;
      if (!dns(name)) return false;
      if (kind === 'provider') {
        const last = name.split('.').at(-1).toLowerCase();
        if ((/^[0-9]+$/.test(last) || /^0x[0-9a-f]*$/.test(last)) && (!ipv4(host) || host !== name)) return false;
      } else if (kind === 'chat' && (name.split('.').some(p => p.toLowerCase().startsWith('xn--')) || (!ipv4(name) && !/^[A-Za-z]/.test(name.split('.').at(-1))))) return false;
    }
    if (port !== undefined && (Number(port) > 65535 || (kind !== 'provider' && Number(port) === 0))) return false;
    if (kind === 'provider' && path !== '' && path !== '/') return false;
    if (kind === 'relay' && (!path.endsWith('/') || path.split('/').some(p => p === '.' || p === '..' || !/^[A-Za-z0-9_.-]*$/.test(p)))) return false;
    if (kind === 'chat' && !/^[A-Za-z0-9/\-._~!$&'()*+,;=:]*$/.test(path)) return false;
    try { return new URL(text).protocol === (kind === 'relay' ? 'wss:' : 'https:'); } catch { return false; }
  };
  return url(value.provider_origin, 'provider') && url(value.relay_url, 'relay') &&
    url(value.chat_endpoint, 'chat') && typeof value.model === 'string' && value.model.trim() === value.model &&
    value.model.length > 0 && value.model.length <= 128 && /^[A-Za-z0-9._/:\-]+$/.test(value.model) &&
    Number.isInteger(value.topup_sat) && value.topup_sat >= 100 && value.topup_sat <= 5000;
};
const loadDefaults = async () => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3000);
  try {
    const response = await fetch(new URL('poc-defaults.json', location.href), {credentials: 'omit', cache: 'no-store', redirect: 'error', signal: controller.signal});
    if (!response.ok || new URL(response.url).origin !== location.origin) throw Error();
    const reader = response.body.getReader();
    const chunks = []; let size = 0;
    while (true) {
      const {done, value} = await reader.read(); if (done) break;
      size += value.byteLength; if (size > 16384) { controller.abort(); throw Error(); } chunks.push(value);
    }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const value = JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(bytes));
    if (!validDefaults(value)) throw Error();
    for (const [id, field] of [['provider-origin', 'provider_origin'], ['provider-relay', 'relay_url'], ['poc-relay', 'relay_url'], ['poc-endpoint', 'chat_endpoint'], ['poc-model', 'model'], ['credit-amount', 'topup_sat']]) {
      if ($(id) && !defaultsEdited.has(id) && !providerReviewToken) $(id).value = value[field];
    }
    $('defaults-status').textContent = 'Deployment defaults loaded. Public fields remain editable; review and approval use the displayed values.';
  } catch {
    $('defaults-status').textContent = 'Deployment defaults are missing or invalid. All fallback values remain in use.';
  } finally { clearTimeout(timer); }
};
void loadDefaults();

const texts = {
  starting: 'Opening the local store…',
  working: 'Working…',
  'in-use': 'Waiting for the local store: another tab, or this page\'s previous harness worker, still holds it.',
  none: 'There is no local store yet.',
  locked: 'The local store is locked.',
  locking: 'Locking: waiting for the worker to finish any begun write and clear working secrets…',
  unlocked: 'The local store is unlocked.',
};
const clearWords = () => $('seed-backup-words-slot').replaceChildren();
let redisplay = false;
let ceremony = false;
let suspended = false;
const goalOutcomes = new Map();
const pocDeclarationDrafts = new Map();
const creditGoalDrafts = new Map();
const snapshotWorker = () => {
  const current = worker;
  const generation = current?.generation;
  return { postMessage: (data, transfer) => current?.sendAt ? current.sendAt(data, transfer, generation) : current?.postMessage(data, transfer) };
};
const render = (store) => {
  const { state } = store;
  if (state !== 'unlocked') $('task-results')?.replaceChildren();
  $('store-state').dataset.lifecycle = store.lifecycle_state ?? '';
  if (store.seed_backup_stage !== undefined) ceremony = state === 'unlocked' && store.seed_backup_stage !== 'inactive';
  if (['locked', 'none', 'refused'].includes(state)) ceremony = false;
  renderSetup(store);
  renderPoc(store);
  renderTasks(store);
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
  const worker = snapshotWorker();
  const slot = $('setup');
  slot.replaceChildren();
  slot.hidden = store.state !== 'unlocked' || store.seed_backup_stage !== 'inactive';
  if (slot.hidden) return;
  const addEnd = (parent, identity) => {
    const end = document.createElement('button');
    end.type = 'button'; end.textContent = 'End session'; end.dataset.endSession = identity;
    end.addEventListener('click', () => { end.disabled = true; worker.postMessage({task: {action: 'end-session', session: identity}}); });
    parent.append(end);
  };
  if (store.lifecycle_state === 'reconciling') {
    for (const session of store.endable_sessions ?? []) {
      paragraph(slot, `Session ${session.identity}: waiting for revalidation; bound machine ${session.bound_set.join(', ')}.`);
      addEnd(slot, session.identity);
    }
    return;
  }
  const approved = store.setup ?? [];
  const entries = approved.length ? approved.map(m => m.entry) : store.setup_offer ?? [];
  if (!entries.length) return;
  paragraph(slot, approved.length ? 'Approved setup' : 'Approve the setup');
  const purchase = Boolean(store.procurement?.phase);
  if (!purchase) paragraph(slot, "Prices are fixture data, not a vendor's price.");
  for (const entry of entries) {
    const billing = entry.cost.period.billing;
    const period = billing ? `${billing.count} ${billing.interval}` : entry.cost.period;
    paragraph(slot, `${entry.machine}: ${entry.vendor}; ${entry.product}; ${entry.region}; ${entry.cost.amount} ${entry.cost.unit} per ${period}.`);
  }
  if (!purchase) {
    const monthly = entries.reduce((sum, entry) => sum + BigInt(entry.cost.amount), 0n);
    paragraph(slot, `Setup total: ${monthly} sat per month; ${monthly * 12n} sat per year.`);
  }
  paragraph(slot, 'Each machine will be bound alone in its own session.');
  paragraph(slot, purchase ? 'The purchase card records the approved billing interval and currency. App Lock and Stop task do not cancel the VM or its billing. Payment remains external, and this page does not change automatic renewal.' : "Recurring means each machine is billed by its vendor every month from the moment it is created until it is destroyed or abandoned, whether or not setup finishes. tau-web never pays for a machine and cannot stop a vendor's billing; only you can.");
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
      if (session.readiness_reason) paragraph(section, session.readiness_reason);
      paragraph(section, `Inference model: ${session.inference_configuration?.model ?? 'unavailable'}; machine: ${machine.entry.machine}.`);
      addEnd(section, session.identity);
      const limits = session.inference_limits;
      if (limits && !session.credit_backed) {
        paragraph(section, `Confirmed limit: ${(BigInt(limits.confirmed.cap_hundredths) / 100n)}.${String(BigInt(limits.confirmed.cap_hundredths) % 100n).padStart(2, '0')} ${limits.confirmed.unit}; lifetime ${limits.confirmed.lifetime_seconds / 60} minutes. No renewal; observed spend ${limits.observed_spend}. Unaccounted spend is not zero or refunded.`);
        paragraph(section, limits.original_expiry ? `Original requested expiry: ${new Date(limits.original_expiry * 1000).toISOString()} (UTC). All delays and hidden or frozen time consume this lifetime.` : 'Lifetime has not started.');
        if (limits.state === 'clock-withheld') paragraph(section, 'Clock validity unknown; verification required. The original expiry has not changed.');
      }
      if (limits?.state === 'clock-withheld' && !session.credit_backed) {
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
        const accepted = (session.standing_modes ?? []).includes('Acting on a goal with no brief');
        const started = (store.tasks ?? []).find(task => task.start_session === session.identity);
        if (started) {
          paragraph(card, `Session task ${started.id}. Use Resume on that task.`);
        } else if (!accepted || !started) {
          paragraph(card, accepted ? 'Start was accepted. Continue with verification commands for this same goal and machine.' : 'No brief is available.');
          const checks = document.createElement('textarea');
          checks.setAttribute('aria-label', 'Verification commands, one per line');
          paragraph(card, 'Verification commands, one per line. Choose checks that establish the requested service is working. Empty checks cannot establish success.');
          card.append(checks);
          const accept = document.createElement('button');
          accept.type = 'button';
          accept.dataset.goalAccept = session.identity;
          accept.dataset.pocAccept = session.identity;
          accept.textContent = accepted ? 'Continue accepted task start' : 'Acting on a goal with no brief';
          accept.addEventListener('click', () => {
            accept.disabled = true;
            worker.postMessage({ goal_accept: { session: session.identity, checks: checks.value.split('\n').filter(line => line.trim()) } });
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
    else if (machine.class !== null && access && store.fixture_admission) {
      const button = document.createElement('button');
      button.type = 'button';
      button.dataset.bind = machine.entry.machine;
      button.textContent = `Start session ${machine.entry.machine}`;
      button.addEventListener('click', () => {
        button.disabled = true;
        worker.postMessage({ bind: { machine: machine.entry.machine, inference_approval: store.fixture_admission } });
      });
      section.append(button);
    }
    slot.append(section);
  }
  if (store.lifecycle_state === 'ended') {
    for (const control of slot.querySelectorAll('button, input, textarea')) control.remove();
  }
};

// Terminal results arrive individually so a large history cannot suppress a new result.
const renderCommandResult = (result) => {
  if ($('store').dataset.state !== 'unlocked') return;
  let slot = $('task-results');
  if (!slot) {
    slot = document.createElement('section'); slot.id = 'tau-task-results';
    $('setup').after(slot);
  }
  const card = document.createElement('section');
  card.dataset.commandResult = String(result.call);
  paragraph(card, `Recorded call ${result.call}; job ${result.job}; exit ${result.exit_status ?? 'unknown'}.${result.historical ? ' Historical result; no current action authority.' : ''}`);
  for (const field of ['stdout', 'stderr']) {
    paragraph(card, field);
    const output = document.createElement('pre'); output.textContent = result[field] ?? ''; card.append(output);
  }
  const previous = slot.querySelector(`[data-command-result="${Number(result.call)}"]`);
  if (previous) previous.replaceWith(card); else slot.append(card);
};

const renderTasks = (store) => {
  const worker = snapshotWorker();
  let slot = $('tasks');
  if (!slot) {
    slot = document.createElement('section');
    slot.id = 'tau-tasks';
    $('setup').after(slot);
  }
  slot.replaceChildren();
  slot.hidden = store.state !== 'unlocked' || store.seed_backup_stage !== 'inactive';
  if (slot.hidden) return;
  for (const task of store.tasks ?? []) {
    const card = document.createElement('section');
    card.dataset.task = task.id;
    paragraph(card, `Task ${task.id}: ${task.status}; machine ${task.machine}.`);
    paragraph(card, task.goal);
    paragraph(card, `Requests ${task.requests}/${task.limits.requests}; steps ${task.steps}/${task.limits.steps}. Verification commands count as steps.`);
    for (const [id, tool, outcome] of task.completed) paragraph(card, `${id}: ${JSON.stringify(tool)} → ${JSON.stringify(outcome)}`);
    if (task.proposal) paragraph(card, `Next ${task.proposal.call_id}: ${JSON.stringify(task.proposal.tool)}`);
    if (task.pending) paragraph(card, `Pending job ${task.pending.job}; journal call ${task.pending.call}. Resume inspects this job without launching it again.`);
    if (task.pause_reason) paragraph(card, task.pause_reason);
    for (const check of task.verification) paragraph(card, `Verification: ${check.command}; job ${check.job}; exit ${check.exit_status ?? 'unknown'}; ${check.excerpt}`);
    if (['complete', 'abandoned'].includes(task.status)) { slot.append(card); continue; }
    const session = (store.sessions ?? []).find(s => s.identity === task.start_session && s.session_state !== 'ended' && s.bound_set.length === 1 && s.bound_set[0] === task.machine);
    paragraph(card, 'This task retains its original session, machine, approvals and budgets. Eligible interrupted work continues after unlock and any required key resupply. Resume continues a genuine pause.');
    const action = (text, request) => {
      const button = document.createElement('button');
      button.type = 'button'; button.textContent = text;
      button.addEventListener('click', () => { button.disabled = true; worker.postMessage({ task: { id: task.id, ...request } }); });
      card.append(button);
    };
    if (session && store.lifecycle_state !== 'ended') {
      action('Resume', { action: 'resume', session: session.identity });
    } else if ((store.sessions ?? []).some(s => s.identity === task.start_session && s.session_state === 'ended')) paragraph(card, `Session ${task.start_session} is ended. This task remains history and cannot continue.`);
    else paragraph(card, `Unlock to restore session ${task.start_session}.`);
    if (session && task.verification.some(check => check.exit_status !== null && check.exit_status !== 0)) {
      action('Prepare verification retry', { action: 'retry-checks', session: session.identity });
    }
    paragraph(card, 'Stop task stops local orchestration; remote effects and billing continue.');
    action('Stop task', { action: 'abandon' });
    const requests = document.createElement('input'); requests.type = 'number'; requests.min = task.limits.requests; requests.max = 1000; requests.value = task.limits.requests; requests.setAttribute('aria-label', 'Task request limit');
    const steps = document.createElement('input'); steps.type = 'number'; steps.min = task.limits.steps; steps.max = 2000; steps.value = task.limits.steps; steps.setAttribute('aria-label', 'Task step limit');
    const raise = document.createElement('button'); raise.type = 'button'; raise.textContent = 'Raise limits';
    raise.addEventListener('click', () => { raise.disabled = true; worker.postMessage({ task: { action: 'raise', id: task.id, limits: { requests: Number(requests.value), steps: Number(steps.value) } } }); });
    card.append(requests, steps, raise);
    slot.append(card);
  }
};

const renderDelivery = (section, machine, store) => {
  const worker = snapshotWorker();
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
const invoiceControls = (parent, savedInvoice, expires) => {
  const wallet = document.createElement('a'); wallet.textContent = 'Open in wallet'; wallet.href = `lightning:${savedInvoice}`;
  const copy = document.createElement('button'); copy.type = 'button'; copy.textContent = 'Copy';
  copy.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(savedInvoice); copy.textContent = 'Copied'; }
    catch { copy.textContent = 'Copy unavailable'; }
  });
  const remaining = document.createElement('span'); remaining.dataset.invoiceExpires = String(expires);
  remaining.textContent = `${Math.max(0, Math.ceil((expires - Date.now() / 1000) / 60))} minutes left`;
  parent.append(wallet, ' ', copy, ' ', remaining);
};
setInterval(() => {
  for (const node of document.querySelectorAll('[data-invoice-expires]')) node.textContent = `${Math.max(0, Math.ceil((Number(node.dataset.invoiceExpires) - Date.now() / 1000) / 60))} minutes left`;
}, 1000);
const renderCredit = (store, enabled) => {
  const credit = store.credit;
  const invoices = credit?.invoices ?? [];
  const latest = invoices.at(-1);
  const unresolved = latest && !['paid', 'expired_unpaid', 'abandoned'].includes(latest.outcome);
  $('credit-status').textContent = store.credit_error || credit?.balance_text || (!credit?.account ? 'No inference credit yet.' : 'Inference credit balance not read yet.');
  $('credit-invoice').disabled = !enabled || Boolean(unresolved);
  $('credit-invoice').textContent = ['expired_unpaid','abandoned'].includes(latest?.outcome) ? 'New invoice' : credit?.account ? 'Add credit' : 'Get an invoice';
  $('credit-check').hidden = !credit?.account;
  $('credit-check').disabled = !enabled;
  $('credit-configure').disabled = !enabled || !credit?.can_start;
  $('credit-details').textContent = latest ? `Last saved status: ${latest.last_status}` : '';
  const slot = $('credit-invoices'); slot.replaceChildren();
  for (const invoice of invoices) {
    const row = document.createElement('section'); row.dataset.creditInvoice = invoice.id;
    paragraph(row, `${invoice.amount_sat} sat. ${({abandoned:'Invoice marked abandoned.',pending:'Waiting for external payment.',paid:'Payment seen; inference credit read.',expired_unpaid:'This invoice expired unpaid, according to the credit service.',unknown:'Payment status unknown.',seen:'Payment seen; balance not read yet.'})[invoice.outcome]}`);
    invoiceControls(row, invoice.bolt11, invoice.expires_at); slot.append(row);
  }
};
$('credit-invoice').addEventListener('click', () => {
  $('credit-invoice').disabled = true;
  worker.postMessage({credit_request:{action:'invoice',amount:Number($('credit-amount').value)}});
});
$('credit-check').addEventListener('click', () => worker.postMessage({credit_request:{action:'check'}}));
$('credit-configure').addEventListener('click', () => worker.postMessage({credit_request:{action:'configure',endpoint:$('poc-endpoint').value,model:$('poc-model').value}}));

let providerCatalogue = null;
let providerSelectionDirty = true;
let providerReviewToken = null;
let providerDisplayedBilling = null;
let providerDisplayedSelection = null;
let providerDisplayedOrigin = null;
const providerRequest = action => worker.postMessage({provider_request: action});
const renderProvider = (store, enabled) => {
  const worker = snapshotWorker();
  $('provider-key-status').textContent = store.provider_configuration?.key_set ? 'Provider key set.' : 'Provider key unset; re-entry is required.';
  const purchase = store.procurement ?? {};
  if (!$('provider-origin').value && (store.provider_configuration?.origin ?? purchase.origin)) $('provider-origin').value = store.provider_configuration?.origin ?? purchase.origin;
  providerDisplayedOrigin = purchase.origin ?? null;
  providerDisplayedBilling = purchase.billing ? structuredClone(purchase.billing) : null;
  providerDisplayedSelection = purchase.selection ? structuredClone(purchase.selection) : null;
  const renewal = purchase.phase === 'terms_changed';
  const reviewToken = purchase.selection ? JSON.stringify([purchase.origin, purchase.selection]) : null;
  if (providerReviewToken !== reviewToken) {
    $('provider-approve-charge').checked = false;
    $('provider-approve-access').checked = false;
    providerReviewToken = reviewToken;
  }
  if (renewal) {
    $('provider-machine').value = purchase.machine;
    $('provider-relay').value = purchase.relay;
    $('provider-class').value = purchase.class_answer;
  }
  if (store.provider_catalogue) {
    providerCatalogue = store.provider_catalogue;
    const catalogue = $('provider-catalogue-view'); catalogue.replaceChildren();
    const offerSelect = $('provider-offer'); offerSelect.replaceChildren(new Option('Choose a fetched offer', ''));
    for (const [kind, offers] of [['fixed', providerCatalogue.offers.templates], ['custom', providerCatalogue.offers.custom_template ?? []]]) {
      for (const offer of offers) {
        const terms = offer.cost_plan ?? offer;
        const hourly = terms.interval_type === 'hour';
        const label = `${kind}: ${offer.name}; ${offer.region?.name}; ${kind === 'fixed' ? `${offer.cpu} CPU, ${offer.memory} memory bytes, ${offer.disk_size} disk bytes; ${terms.amount} ${terms.currency} smallest units; ` : 'choose resources and request price; '}${terms.interval_amount} ${terms.interval_type}${hourly ? ' — unsupported credit-only hourly plan' : ''}`;
        paragraph(catalogue, label);
        const option = new Option(label, `${kind}:${offer.id}`); option.disabled = hourly; offerSelect.add(option);
        if (kind === 'custom') { const bounds = document.createElement('pre'); bounds.textContent = JSON.stringify(offer, null, 2); catalogue.append(bounds); }
      }
    }
    const images = $('provider-image'); images.replaceChildren(new Option('Choose a fetched image', ''));
    for (const image of providerCatalogue.images) {
      const unsupported = image.encrypted || image.distribution !== 'archlinux' || (image.default_username && image.default_username !== 'arch');
      const label = `${image.distribution} ${image.flavour} ${image.version}${unsupported ? ' — unsupported (requires unencrypted Arch without console unlock)' : ''}`;
      const option = new Option(label, String(image.id)); option.disabled = unsupported; images.add(option);
    }
    providerSelectionDirty = true; $('provider-approve-charge').checked = false;
  }
  if (store.provider_selection_reviewed || renewal) providerSelectionDirty = false;
  const selection = $('provider-selection-view'); selection.replaceChildren();
  if (purchase.selection) {
    paragraph(selection, `Provider origin: ${purchase.origin}`);
    const c = purchase.selection.charge;
    paragraph(selection, `Recurring charge: ${c.amount} ${c.currency === 'BTC' ? 'millisats' : c.currency + ' cents'} per ${c.interval_amount} ${c.interval_type}. Tax and processing fee are shown on the initial invoice.`);
    const exact = document.createElement('pre'); exact.textContent = JSON.stringify(purchase.selection, null, 2); selection.append(exact);
  }
  const progress = $('provider-progress'); progress.replaceChildren();
  if (purchase.closed) paragraph(progress, purchase.closed);
  if (purchase.phase) {
    paragraph(progress, `Saved purchase ${purchase.machine}: ${purchase.phase}. VM ${purchase.vm_id ?? 'not associated'}; SSH registration ${purchase.ssh_key_id ?? 'not established'}.`);
    paragraph(progress, `Bound provider origin: ${purchase.origin}`);
    paragraph(progress, `Provider account public identity: ${purchase.account}`);
    paragraph(progress, `Provider auto-renewal policy: ${purchase.auto_renewal_enabled === true ? 'enabled' : purchase.auto_renewal_enabled === false ? 'disabled' : 'unknown'}. This page does not change that policy.`);
    if (purchase.billing) {
      const quote = purchase.billing.terms;
      paragraph(progress, `Initial Lightning quote for VM ${purchase.billing.vm_id}: amount ${quote.amount}, tax ${quote.tax}, processing fee ${quote.processing_fee} (${quote.currency === 'BTC' ? 'millisats' : quote.currency + ' cents'}); ${quote.time} seconds for one approved billing period. Review these exact terms before issuing. Refresh may update this quote before issuance.`);
    }
    if (purchase.payment) {
      const pay = purchase.payment;
      paragraph(progress, `Payment ${pay.id} for VM ${pay.vm_id}: ${pay.is_paid ? 'paid' : 'payment pending'}; expires ${pay.expires}. Amount ${pay.amount}, tax ${pay.tax}, processing fee ${pay.processing_fee} (${pay.currency === 'BTC' ? 'millisats' : pay.currency + ' cents'}).`);
      invoiceControls(progress, pay.data.lightning, Math.floor(Date.parse(pay.expires) / 1000));
      const check = document.createElement('button'); check.type = 'button'; check.textContent = 'Check now'; check.disabled = !enabled;
      check.addEventListener('click', () => providerRequest({action:'payment_check'})); progress.append(check);
    }
    if (purchase.public_keys) {
      paragraph(progress, 'Relay public key — enroll this separately with the relay operator:');
      const publicKey = document.createElement('pre'); publicKey.textContent = purchase.public_keys.relay_pubkey; progress.append(publicKey);
    }
    if (purchase.target) paragraph(progress, `Published pin saved for VM ${purchase.vm_id}: ${purchase.target.pin}. Bind ${purchase.machine} below to use the existing configuration runner.`);
  }
  const canReview = !purchase.phase || ['approved', 'registered', 'terms_changed'].includes(purchase.phase);
  for (const control of $('provider-selection-form').elements) control.disabled = !enabled || !canReview;
  for (const control of $('provider-approval-form').elements) control.disabled = !enabled || (Boolean(purchase.phase) && !renewal) || providerSelectionDirty || !purchase.selection;
  if (renewal) {
    for (const name of ['provider-machine', 'provider-relay', 'provider-class']) $(name).disabled = true;
  }
  const closeEligible = Boolean(purchase.vm_id) && !purchase.target && (!purchase.payment || (purchase.payment.is_paid === false && Math.floor(Date.parse(purchase.payment.expires) / 1000) <= Math.floor(Date.now() / 1000)));
  $('provider-close').hidden = !closeEligible;
  $('provider-close').disabled = !enabled || !closeEligible;
  $('provider-resume').disabled = !enabled || !purchase.phase;
  $('provider-invoice').disabled = !enabled || purchase.phase !== 'initial_invoice' || !purchase.billing;
};
$('provider-key-form').addEventListener('submit', event => {
  event.preventDefault();
  const field = $('provider-key'), bytes = new TextEncoder().encode(field.value); field.value = '';
  const origin = $('provider-origin').value; $('provider-origin').value = '';
  try { worker.postMessage({provider_configure: {key: bytes, origin}}, [bytes.buffer]); }
  finally { if (bytes.byteLength) bytes.fill(0); }
});
$('provider-catalogue').addEventListener('click', () => providerRequest({action: 'catalogue'}));
$('provider-selection-form').addEventListener('input', () => {
  providerSelectionDirty = true; $('provider-approve-charge').checked = false;
  for (const control of $('provider-approval-form').elements) control.disabled = true;
});
$('provider-selection-form').addEventListener('submit', event => {
  event.preventDefault();
  try {
    const [kind, id] = $('provider-offer').value.split(':');
    providerRequest({action: 'select', choice: {offer_id: Number(id), image_id: Number($('provider-image').value), resources: kind === 'custom' ? JSON.parse($('provider-resources').value) : null}});
  } catch { paragraph($('provider-selection-view'), 'Enter valid custom resource JSON.'); }
});
$('provider-approval-form').addEventListener('submit', event => {
  event.preventDefault(); if (providerSelectionDirty) return;
  providerRequest({action: 'approve', selection: providerDisplayedSelection, approval: {origin: providerDisplayedOrigin, machine: $('provider-machine').value, relay: $('provider-relay').value, class_answer: $('provider-class').value, approve_charge: $('provider-approve-charge').checked, approve_maintained_access: $('provider-approve-access').checked}});
});
$('provider-close').addEventListener('click', () => providerRequest({action: 'close'}));
$('provider-resume').addEventListener('click', () => providerRequest({action: 'resume'}));
$('provider-invoice').addEventListener('click', () => providerRequest({action: 'initial_invoice', billing: providerDisplayedBilling}));
const clearPocInputs = () => {
  providerCatalogue = null;
  providerSelectionDirty = true;
  providerReviewToken = null;
  providerDisplayedBilling = null;
  providerDisplayedSelection = null;
  $('provider-catalogue-view').replaceChildren();
  $('provider-selection-view').replaceChildren();
  $('provider-progress').replaceChildren();
  $('provider-key').value = '';
  pocDeclarationDrafts.clear();
  creditGoalDrafts.clear();
  for (const field of $('poc').querySelectorAll('input')) {
    if (field.type === 'checkbox') field.checked = false;
    else if (!defaultsInputs.includes(field.id.replace('tau-', ''))) field.value = '';
  }
  $('poc-elevation').value = $('poc-class').value = '';
  $('poc-public-keys').replaceChildren();
};
const renderPoc = (store) => {
  if (typeof store.credit_started_machine === 'string') creditGoalDrafts.delete(store.credit_started_machine);
  const worker = snapshotWorker();
  const enabled = store.state === 'unlocked' && !ceremony &&
    !['suspended', 'reconciling', 'ended'].includes(store.lifecycle_state);
  $('poc').hidden = store.state !== 'unlocked';
  for (const control of $('poc').querySelectorAll('input, select, button')) control.disabled = !enabled;
  renderProvider(store, enabled);
  renderCredit(store, enabled);
  const restored = (store.sessions ?? []).find(s => s.session_state !== 'ended')?.inference_configuration;
  if (restored && store.poc_configuration?.key_set !== true) { $('poc-endpoint').value = restored.endpoint; $('poc-model').value = restored.model; }
  $('poc-key-status').textContent = store.poc_configuration?.key_set === true ? 'Key set.' : store.poc_configuration?.key_set === false ? 'Key unset.' : 'Key status unavailable.';
  if (['locked', 'none', 'refused', 'lost', 'starting'].includes(store.state) || store.lifecycle_state === 'ended') clearPocInputs();
  // Working/lifecycle reports can omit sessions. Prune only a full unlocked report;
  // a surviving suspended worker retains the same session's unsubmitted text.
  if (store.state === 'unlocked' && Array.isArray(store.sessions)) {
    const live = new Set(store.sessions.filter(s => s.session_state !== 'ended').map(s => s.identity));
    for (const identity of pocDeclarationDrafts.keys()) {
      if (!live.has(identity)) pocDeclarationDrafts.delete(identity);
    }
  }
  const targets = $('poc-targets');
  targets.replaceChildren();
  for (const target of store.poc_targets ?? []) {
    const row = document.createElement('section');
    paragraph(row, `${target.machine}: relay profile ${target.profile}; elevation ${target.elevation}.`);
    paragraph(row, `Host ${target.host}, port ${target.port}, user ${target.user}; relay ${target.relay}.`);
    paragraph(row, `Independent host pin: ${target.pin}`);
    const useCredit = store.credit?.can_start && (store.credit.selected || !store.poc_configuration?.key_set);
    paragraph(row, useCredit ? `Start session approves the endpoint and model shown above for ${target.machine}.` : `Start session approves inference using ${store.poc_configuration?.configuration?.model || 'the configured model'} on ${target.machine}.`);
    let creditGoal;
    if (useCredit) {
      creditGoal = document.createElement('textarea'); creditGoal.dataset.creditGoal = target.machine;
      creditGoal.setAttribute('aria-label', 'Goal before Start session'); creditGoal.value = creditGoalDrafts.get(target.machine) ?? '';
      creditGoal.addEventListener('input', () => creditGoalDrafts.set(target.machine, creditGoal.value)); row.append(creditGoal);
      paragraph(row, store.credit.disclosure);
    }
    for (const [kind, label] of [['poc_bind', 'Start session'], ['poc_public_keys', 'Show public keys']]) {
      const button = document.createElement('button');
      button.type = 'button';
      button.disabled = !enabled || (kind === 'poc_bind' && !useCredit && !store.poc_configuration?.configuration);
      button.textContent = `${label} ${target.machine}`;
      button.addEventListener('click', () => {
        button.disabled = true;
        if (kind === 'poc_bind' && useCredit) worker.postMessage({credit_request:{action:'start',machine:target.machine,goal:creditGoal.value,endpoint:$('poc-endpoint').value,model:$('poc-model').value}});
        else worker.postMessage({ [kind]: { machine: target.machine } });
      });
      row.append(button);
    }
    for (const session of store.sessions ?? []) {
      if (!session.credit_backed || session.session_state === 'ended' || !(session.bound_set ?? []).includes(target.machine)) continue;
      const button = document.createElement('button'); button.type = 'button'; button.textContent = 'New key'; button.dataset.creditNewKey = session.identity; button.disabled = !enabled;
      button.addEventListener('click', () => { button.disabled = true; worker.postMessage({credit_request: {action:'new_key', session:session.identity}}); });
      row.append(button);
    }
    for (const session of store.sessions ?? []) {
      if (session.session_state === 'ended' || !(session.bound_set ?? []).includes(target.machine) || !session.goal) continue;
      if (!(session.standing_modes ?? []).includes('Acting on a goal with no brief')) continue;
      paragraph(row, 'Declaration candidate: edit the JSON for your intended installation, then propose it. The next card requires explicit approval; these are requirements, not measurements.');
      const declaration = document.createElement('textarea');
      declaration.dataset.pocDeclaration = session.identity;
      declaration.setAttribute('aria-label', 'Installation declaration candidate JSON');
      declaration.disabled = !enabled;
      declaration.value = pocDeclarationDrafts.get(session.identity) ?? JSON.stringify(store.poc_declaration_candidate, null, 2);
      declaration.addEventListener('input', () => pocDeclarationDrafts.set(session.identity, declaration.value));
      const propose = document.createElement('button');
      propose.type = 'button'; propose.disabled = !enabled;
      propose.dataset.pocPropose = session.identity;
      propose.textContent = 'Propose installation declaration';
      propose.addEventListener('click', () => {
        try {
          pocDeclarationDrafts.set(session.identity, declaration.value);
          worker.postMessage({poc_propose_requirements: {session: session.identity,
            proposal: {kind: 'declaration', machine: target.machine, declaration: JSON.parse(declaration.value)}}});
        } catch { paragraph(row, 'Declaration must be valid JSON.'); }
      });
      row.append(declaration, propose);
    }
    targets.append(row);
  }
  if (store.poc_keys && enabled) {
    const slot = $('poc-public-keys');
    slot.replaceChildren();
    if (store.poc_keys.refused) paragraph(slot, store.poc_keys.refused);
    else {
      paragraph(slot, `Public keys for ${store.poc_keys.machine}`);
      for (const [field, label] of [['authorized_keys', 'SSH authorized_keys line'], ['relay_pubkey', 'Relay AUTH public key']]) {
        const value = String(store.poc_keys[field] ?? '');
        paragraph(slot, label);
        const text = document.createElement('pre');
        text.textContent = value;
        const copy = document.createElement('button');
        copy.type = 'button';
        copy.textContent = `Copy ${label}`;
        copy.addEventListener('click', async () => {
          try { await navigator.clipboard.writeText(value); copy.textContent = 'Copied'; }
          catch { copy.textContent = 'Select and copy the text above'; }
        });
        slot.append(text, copy);
      }
    }
  } else if (!enabled) $('poc-public-keys').replaceChildren();
};
$('poc-inference-form').addEventListener('submit', event => {
  event.preventDefault();
  const field = $('poc-key');
  const bytes = new TextEncoder().encode(field.value);
  field.value = '';
  try {
    worker.postMessage({ poc_configure: {
      endpoint: $('poc-endpoint').value,
      model: $('poc-model').value,
      key: bytes,
    } }, [bytes.buffer]);
  } finally {
    if (bytes.byteLength) bytes.fill(0);
  }
});
$('poc-target-form').addEventListener('submit', event => {
  event.preventDefault();
  worker.postMessage({ poc_enroll: {
    target: {
      machine: $('poc-machine').value, relay: $('poc-relay').value,
      profile: $('poc-profile').value, host: $('poc-host').value,
      port: Number($('poc-port').value), user: $('poc-user').value,
      elevation: $('poc-elevation').value, pin: $('poc-pin').value,
    },
    approve_existing: $('poc-approve-existing').checked,
    class_answer: $('poc-class').value,
    approve_maintained_access: $('poc-approve-access').checked,
  } });
});
let worker;

const start = () => {
  goalOutcomes.clear();
  show('starting', 'Starting the harness…');
  render({ state: 'starting' });
  suspended = false;
  ceremony = false;
  worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
  const current = worker;
  const incarnation = crypto.randomUUID();
  current.generation = '0';
  const nativePost = current.postMessage.bind(current);
  current.sendAt = (request, transfer, generation) => nativePost({incarnation, generation, request}, transfer);
  current.postMessage = (request, transfer) => current.sendAt(request, transfer, current.generation);
  nativePost({initialize: incarnation});
  worker.onmessage = ({ data }) => {
    if (worker !== current) return;
    if (data.requirements_store) {
      const { state, error, reason, ...rest } = JSON.parse(data.requirements_store);
      data = { store: { store_state: state, ...(error ? { store_error: error } : {}), ...(reason ? { store_reason: reason } : {}), ...rest } };
    }
    if (worker !== current) return;
    if (typeof data.store?.lifecycle_generation === 'string') current.generation = data.store.lifecycle_generation;
    if (data.harness_ready) show('ready', `Harness ready (spec ${data.harness_ready}).`);
    else if (data.store) {
      const { store_state: state, store_error: error, store_reason: reason, ...rest } = data.store;
      if (rest.goal_outcome) goalOutcomes.set(rest.goal_outcome.session, rest.goal_outcome.outcome);
      render({ state, error, reason, ...rest });
    }
    else if (data.command_result) renderCommandResult(data.command_result);
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

// Retirement acknowledges only after a begun append and secret disposal finish.
const RETIRE_EXPLANATION_MS = 5000;
const lock = () => {
  const previous = worker;
  if (!previous) return;
  worker = undefined;
  clearWords();
  clearPocInputs();
  $('seed-backup-input').value = '';
  redisplay = false;
  $('passphrase').value = '';
  $('confirm').value = '';
  render({state: 'locking'});
  const timer = setTimeout(() => {
    if (!worker) $('store-state').textContent = 'Still locking while the worker finishes a write. You can reload or close the page to stop it and recover at the next unlock.';
  }, RETIRE_EXPLANATION_MS);
  previous.addEventListener('message', ({data}) => {
    if (data?.runtime_retired === true) {
      clearTimeout(timer);
      previous.terminate();
      start();
    }
  });
  previous.postMessage({retire_runtime: true});
};
document.addEventListener('visibilitychange', () => {
  const hidden = document.visibilityState === 'hidden';
  if (hidden && ceremony) { lock(); return; }
  worker?.postMessage({ lifecycle: hidden ? 'hidden' : 'visible' });
});
document.addEventListener('freeze', () => {
  if (ceremony) { lock(); return; }
  suspended = true;
  worker?.postMessage({ lifecycle: 'freeze' });
});
document.addEventListener('resume', () => {
  if (suspended) { suspended = false; worker?.postMessage({ lifecycle: 'resume' }); }
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
