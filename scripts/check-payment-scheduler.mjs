import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

// Execute the worker's actual scheduler with a controlled clock and timer queue.
const worker = readFileSync(new URL('../www/worker.js', import.meta.url), 'utf8');
const source = worker.slice(worker.indexOf('let paymentTimer ='), worker.indexOf('const refreshPayments ='));
const run = async ({arm = 59000, fire = 64000, change = '', credit = false, duringCredit = ''} = {}) => {
  let clock = arm, timer, reads = 0, polls = 0;
  const context = vm.createContext({
    Date: {now: () => clock, parse: Date.parse},
    provider_key_is_set: () => true,
    publication_generation: () => 1n,
    setTimeout: (callback, delay) => { assert.equal(delay, 5000); timer = callback; return 1; },
    provider_request: async request => { assert.deepEqual(JSON.parse(request), {action:'payment_check'}); reads++; return '{}'; },
    credit_request: async request => { assert.deepEqual(JSON.parse(request), {action:'poll'}); polls++; vm.runInContext(duringCredit, context); return '{}'; },
    reportStore: async () => {},
    retirementRequested: false,
  });
  vm.runInContext(source + `
    lastReport = {state:'unlocked', lifecycle_state:'running', procurement:{payment:{id:'saved-payment',is_paid:false,expires:'1970-01-01T00:00:00Z'}},credit:{invoices:${credit ? "[{id:'credit-invoice',outcome:'pending',expires_at:120}]" : '[]'}}};
    schedulePayments();`, context);
  assert.equal(typeof timer, 'function');
  const fired = timer; timer = undefined; clock = fire;
  vm.runInContext(change, context);
  await fired();
  return {reads, polls};
};
assert.deepEqual(await run(), {reads:0,polls:0}, 'a timer crossing expiry plus sixty sends nothing');
assert.deepEqual(await run({arm:50000,fire:55000}), {reads:1,polls:0}, 'eligible timer only reads the saved payment');
for (const change of [
  'lastReport.procurement.payment.is_paid = true;',
  "lastReport.procurement.payment.id = 'replacement-payment';",
  'lastReport.procurement.payment = null;',
  'lastReport.procurement.target = {};',
  'retirementRequested = true;',
  'pageVisible = false;',
  "lastReport.state = 'locked';",
  "lastReport.lifecycle_state = 'reconciling';",
  "lastReport.lifecycle_state = 'ended';",
]) assert.equal((await run({arm:50000, fire:55000, change})).reads, 0, change);
for (const duringCredit of [
  'Date.now = () => 64000;',
  'lastReport.procurement.payment.is_paid = true;',
  "lastReport.procurement.payment.id = 'replacement-payment';",
  'retirementRequested = true;',
  'pageVisible = false;',
  "lastReport.lifecycle_state = 'reconciling';",
]) assert.deepEqual(await run({arm:50000,fire:55000,credit:true,duringCredit}), {reads:0,polls:1}, 'machine eligibility is checked again after awaited credit work: '+duringCredit);
console.log('payment scheduler: cutoff, current identity, lifecycle and post-credit dispatch checks passed');
