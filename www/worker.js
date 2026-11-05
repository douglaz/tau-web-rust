// The harness worker alone holds the seed and keys. Only the dedicated seed-backup display
// carries words to the page; re-entry and passphrase buffers are zero-filled by the module.
import init, { spec_commit, open, create, unlock, seed_backup_display, seed_backup_answer, seed_backup_reentry, seed_backup_skip, seed_backup_redisplay, setup_approve, setup_answer, bind, goal_request, goal_accept, run_goal, requirements_answer, delivery_request, end_sessions, sweep_inference, lifecycle_transition, publication_generation, publish_report, verify_inference_clock, withdraw_reinstall } from './pkg/tau_web.js';
import { poc_configure, poc_key_is_set, poc_enroll, poc_bind, poc_public_keys, poc_accept, poc_propose_requirements } from './pkg/tau_web.js';

try {
  await init();
  postMessage({ harness_ready: spec_commit() });
} catch (error) {
  postMessage({ harness_error: String(error) });
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
  postMessage({ store: { store_state: 'in-use' } });
  await held({});
}
const reportStore = (report, generation = publication_generation(), session = '') => {
  const value = JSON.parse(report);
  value.poc_configuration = { key_set: poc_key_is_set() };
  return publish_report(generation, session, JSON.stringify(value));
};
const exactMembers = (value, names) => value && typeof value === 'object' &&
  !Array.isArray(value) && Object.keys(value).length === names.length &&
  names.every(name => Object.hasOwn(value, name));

onmessage = async ({ data }) => {
  if (!data || typeof data !== 'object' || Object.keys(data).length !== 1) {
    if (data?.poc_configure?.key instanceof Uint8Array) data.poc_configure.key.fill(0);
    return;
  }
  if (data.end_sessions === true) {
    await end_sessions();
    postMessage({ sessions_ended: true });
    return;
  }
  if (typeof data.lifecycle === 'string') {
    await reportStore(await lifecycle_transition(data.lifecycle));
    return;
  }
  const generation = publication_generation();
  let report;
  const session = data.goal?.session ?? data.goal_accept?.session ?? data.requirements_answer?.session ?? data.delivery?.session ?? '';
  if (data.create instanceof Uint8Array) report = await create(data.create);
  else if (data.unlock instanceof Uint8Array) report = await unlock(data.unlock);
  else if (data.seed_backup_redisplay instanceof Uint8Array) report = await seed_backup_redisplay(data.seed_backup_redisplay);
  else if (data.seed_backup_reentry instanceof Uint8Array) report = await seed_backup_reentry(data.seed_backup_reentry);
  else if (data.seed_backup_answer === true) report = await seed_backup_answer();
  else if (data.seed_backup_skip === true) report = await seed_backup_skip();
  else if (data.poc_configure && typeof data.poc_configure === 'object') {
    const config = data.poc_configure;
    try {
      if (exactMembers(config, ['endpoint', 'model', 'key']) &&
          typeof config.endpoint === 'string' && typeof config.model === 'string' &&
          config.key instanceof Uint8Array) {
        report = await poc_configure(config.endpoint, config.model, config.key);
      } else {
        const current = JSON.parse(await open());
        current.error = 'Invalid inference configuration.';
        report = JSON.stringify(current);
      }
    } finally {
      if (config.key instanceof Uint8Array) config.key.fill(0);
      delete config.key;
    }
  }
  else if (data.poc_enroll !== undefined) {
    if (exactMembers(data.poc_enroll, ['target', 'approve_existing', 'class_answer', 'approve_maintained_access']) &&
        exactMembers(data.poc_enroll.target, ['machine', 'relay', 'profile', 'host', 'port', 'user', 'elevation', 'pin'])) {
      report = await poc_enroll(JSON.stringify(data.poc_enroll));
    } else {
      const current = JSON.parse(await open());
      current.error = 'Invalid existing-machine enrollment.';
      report = JSON.stringify(current);
    }
  }
  else if (exactMembers(data.poc_bind, ['machine']) && typeof data.poc_bind.machine === 'string') report = await poc_bind(data.poc_bind.machine);
  else if (exactMembers(data.poc_public_keys, ['machine']) && typeof data.poc_public_keys.machine === 'string') report = await poc_public_keys(data.poc_public_keys.machine);
  else if (exactMembers(data.poc_accept, ['session']) && typeof data.poc_accept.session === 'string') report = await poc_accept(JSON.stringify(data.poc_accept));
  else if (exactMembers(data.poc_propose_requirements, ['session', 'proposal']) && typeof data.poc_propose_requirements.session === 'string') report = await poc_propose_requirements(JSON.stringify(data.poc_propose_requirements));
  else if (data.setup_approve === true) report = await setup_approve();
  else if (data.setup_answer && typeof data.setup_answer === 'object') report = await setup_answer(JSON.stringify(data.setup_answer));
  else if (data.bind && typeof data.bind === 'object') report = await bind(JSON.stringify(data.bind));
  else if (typeof data.verify_clock === 'string') {
    const result = JSON.parse(await verify_inference_clock(data.verify_clock));
    const current = JSON.parse(await open());
    if (result.refused) current.error = result.refused;
    report = JSON.stringify(current);
  }
  else if (data.withdraw_reinstall && typeof data.withdraw_reinstall === 'object') {
    const { approval, reset, entry } = data.withdraw_reinstall;
    let error;
    try { await withdraw_reinstall(String(approval), reset, entry); } catch (e) { error = String(e); }
    const current = JSON.parse(await open());
    if (error) current.error = error;
    report = JSON.stringify(current);
  }
  else if (data.goal && typeof data.goal === 'object') report = await goal_request(JSON.stringify(data.goal));
  else if (data.requirements_answer && typeof data.requirements_answer === 'object') report = await requirements_answer(JSON.stringify(data.requirements_answer));
  else if (data.delivery && typeof data.delivery === 'object') report = await delivery_request(JSON.stringify(data.delivery));
  else if (data.goal_accept && typeof data.goal_accept === 'object') {
    report = await goal_accept(JSON.stringify(data.goal_accept));
    await reportStore(report, generation, session);
    if (!JSON.parse(report).error) {
      const outcome = JSON.parse(await run_goal(data.goal_accept.session));
      const finalGeneration = publication_generation();
      const current = JSON.parse(await open());
      current.goal_outcome = { session: data.goal_accept.session, outcome };
      await reportStore(JSON.stringify(current), finalGeneration, data.goal_accept.session);
    }
    return;
  }
  else return;
  await reportStore(report, generation, session);
  if (data.unlock instanceof Uint8Array || data.seed_backup_redisplay instanceof Uint8Array) {
    setTimeout(() => sweep_inference(), 0);
  }
  const display = JSON.parse(await seed_backup_display());
  if (display) postMessage(display);
};
await reportStore(await open());
