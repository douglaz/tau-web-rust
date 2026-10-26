// The harness worker alone holds the seed and keys. Only the dedicated seed-backup display
// carries words to the page; re-entry and passphrase buffers are zero-filled by the module.
import init, { spec_commit, open, create, unlock, seed_backup_display, seed_backup_answer, seed_backup_reentry, seed_backup_skip, seed_backup_redisplay, setup_approve, setup_answer, bind, goal_request, goal_accept, run_goal, requirements_answer, end_sessions, sweep_inference } from './pkg/tau_web.js';

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
const reportStore = (report) => {
  const { state, error, reason, ...rest } = JSON.parse(report);
  postMessage({ store: { store_state: state, ...(error ? { store_error: error } : {}),
    ...(reason ? { store_reason: reason } : {}), ...rest } });
};
onmessage = async ({ data }) => {
  if (!data || typeof data !== 'object' || Object.keys(data).length !== 1) return;
  if (data.end_sessions === true) {
    await end_sessions();
    postMessage({ sessions_ended: true });
    return;
  }
  let report;
  if (data.create instanceof Uint8Array) report = await create(data.create);
  else if (data.unlock instanceof Uint8Array) report = await unlock(data.unlock);
  else if (data.seed_backup_redisplay instanceof Uint8Array) report = await seed_backup_redisplay(data.seed_backup_redisplay);
  else if (data.seed_backup_reentry instanceof Uint8Array) report = await seed_backup_reentry(data.seed_backup_reentry);
  else if (data.seed_backup_answer === true) report = await seed_backup_answer();
  else if (data.seed_backup_skip === true) report = await seed_backup_skip();
  else if (data.setup_approve === true) report = await setup_approve();
  else if (data.setup_answer && typeof data.setup_answer === 'object') report = await setup_answer(JSON.stringify(data.setup_answer));
  else if (data.bind && typeof data.bind === 'object') report = await bind(JSON.stringify(data.bind));
  else if (data.goal && typeof data.goal === 'object') report = await goal_request(JSON.stringify(data.goal));
  else if (data.requirements_answer && typeof data.requirements_answer === 'object') report = await requirements_answer(JSON.stringify(data.requirements_answer));
  else if (data.goal_accept && typeof data.goal_accept === 'object') {
    report = await goal_accept(JSON.stringify(data.goal_accept));
    reportStore(report);
    if (!JSON.parse(report).error) {
      const outcome = JSON.parse(await run_goal(data.goal_accept.session));
      const current = JSON.parse(await open());
      current.goal_outcome = { session: data.goal_accept.session, outcome };
      reportStore(JSON.stringify(current));
    }
    return;
  }
  else return;
  reportStore(report);
  if (data.unlock instanceof Uint8Array || data.seed_backup_redisplay instanceof Uint8Array) {
    setTimeout(() => sweep_inference(), 0);
  }
  const display = JSON.parse(await seed_backup_display());
  if (display) postMessage(display);
};
reportStore(await open());
