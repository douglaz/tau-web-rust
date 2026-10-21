// The harness worker alone holds the seed and keys. Only the dedicated seed-backup display
// carries words to the page; re-entry and passphrase buffers are zero-filled by the module.
import init, { spec_commit, open, create, unlock, seed_backup_display, seed_backup_answer, seed_backup_reentry, seed_backup_skip, seed_backup_redisplay } from './pkg/tau_web.js';

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
  let report;
  if (data.create) report = await create(data.create);
  else if (data.unlock) report = await unlock(data.unlock);
  else if (data.seed_backup_redisplay) report = await seed_backup_redisplay(data.seed_backup_redisplay);
  else if (data.seed_backup_reentry) report = await seed_backup_reentry(data.seed_backup_reentry);
  else if (data.seed_backup_answer === true) report = await seed_backup_answer();
  else if (data.seed_backup_skip === true) report = await seed_backup_skip();
  else return;
  reportStore(report);
  const display = JSON.parse(await seed_backup_display());
  if (display) postMessage(display);
};
reportStore(await open());
