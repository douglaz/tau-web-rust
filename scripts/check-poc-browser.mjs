import { createServer } from 'node:http';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { join } from 'node:path';

// Separate fresh workers exercise the public release boundary and the real registration lock.
async function releaseCases(api, init, name) {
  const checks = [], events = [];
  const check = (ok, label) => { if (!ok) throw Error(label + ' ' + JSON.stringify(events)); checks.push(label); };
  const encode = value => new TextEncoder().encode(value);
  const localFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = (input, options) => {
    const url = input instanceof Request ? input.url : new URL(input, location.href).href;
    if (!url.startsWith(location.origin + '/')) throw Error('external request refused');
    return localFetch(input, options);
  };
  const configure = key => api.poc_configure('https://inference.invalid/v1/chat/completions', 'model-a', encode(key));
  await init(); await api.open();
  check(JSON.parse(await api.create(encode('fixture release passphrase'))).state === 'unlocked', 'fresh store created');
  await api.seed_backup_answer(); await api.seed_backup_skip();
  const secret = 'unsupported-key-4827';
  const target = {machine:'machine-a',relay:'wss://relay.invalid/',profile:name.startsWith('b1') ? name.endsWith('encoded') ? btoa(secret).replace(/=+$/, '') : secret : 'v1',
    host:'192.0.2.1',port:22,user:'arch',elevation:'none',
    pin:'SHA256:' + btoa(String.fromCharCode(...new Uint8Array(32).fill(7))).replace(/=+$/, '')};
  check(!JSON.parse(await api.poc_enroll(JSON.stringify({target,approve_existing:true,class_answer:'no',approve_maintained_access:true}))).error, 'target enrolled before configuration');
  let contacts = 0;
  globalThis.WebSocket = class { constructor() { contacts++; throw Error('unexpected relay contact'); } };
  if (name.startsWith('b1')) {
    check(!JSON.parse(await configure(secret)).error && api.poc_key_is_set(), 'profile configured as key after enrollment');
    const outputs = [];
    for (const operation of ['run_command','collect_jobs']) {
      const raw = await api[operation](JSON.stringify({machine:'machine-a',command:'true'}));
      const result = JSON.parse(raw);
      outputs.push({operation,raw});
      check(result.outcome?.refused?.includes('unsupported relay profile'), operation + ' concrete unsupported-profile refusal: ' + raw);
    }
    check(contacts === 0, 'resolver refuses before relay contact');
    check(outputs.every(({raw}) => !raw.includes(secret) && !raw.includes(target.profile)), 'poc resolver refusals protect credentials configured after enrollment');
    return {checks,events};
  }
  const normal = 'normal-synthetic-key-482700';
  const rotation = name.includes('rotation') || name.includes('echo');
  if (rotation) check(!JSON.parse(await configure(normal)).error && api.poc_key_is_set(), 'initial credential configured');
  const packageOutput = size => 'Package abc012345 xyz789 installed successfully.\n'.repeat(Math.ceil(size/47)).slice(0,size);
  const hex = value => [...encode(value)].map(b=>b.toString(16).padStart(2,'0')).join('');
  const output = name.includes('echo') ? packageOutput(65536) + normal : rotation ? hex(packageOutput(170000)) : packageOutput(2097152);
  const expectedOutput = name.includes('echo') ? '<redacted>' : output;
  await api.test_poc_prepare_release(output, name.endsWith('held'));
  const keys = rotation ? ['previous-normal-key-482700','third-normal-key-482700','fourth-normal-key-482700'] : [normal];
  let releaseAppend, appendSeen, appendFailed, releaseFinal, finalSeen;
  const appendReady = new Promise((resolve,reject) => { appendSeen = resolve; appendFailed = reject; });
  const finalReady = new Promise(resolve => { finalSeen = resolve; });
  api.test_hold_session_point('poc_terminal_append', new Promise(resolve => { releaseAppend = resolve; }), () => { events.push('append held after preflight'); appendSeen(); });
  if (!name.endsWith('append-error')) api.test_hold_session_point('command_release_writer', new Promise(resolve => { releaseFinal = resolve; }), () => { events.push('final release reached'); finalSeen(); });
  const collect = name.endsWith('collection');
  const command = api[collect ? 'collect_jobs' : 'run_command'](JSON.stringify({machine:'machine-a',command:'true',fail_append:name.endsWith('append-error')}));
  command.then(value => appendFailed(Error("command ended before append hold: " + value)), appendFailed);
  await appendReady;
  const configurations = keys.map(key => configure(key));
  events.push('configuration queued on production writer');
  const transition = name.endsWith('freeze') ? api.lifecycle_transition('freeze') :
    name.endsWith('end') ? api.end_sessions() : undefined;
  if (transition) events.push('lifecycle requested while append pending');
  releaseAppend();
  if (name.endsWith('append-error')) {
    let failed = false;
    try { await command; } catch { failed = true; }
    const outcomes = await Promise.all(configurations);
    const counts = JSON.parse(await api.test_poc_release_counts());
    check(failed && counts.terminals === 0 && counts.collectable === 1 && counts.launches === 1,
      'failed terminal append stays collectable without another launch');
    check(outcomes.every(text => JSON.parse(text).error?.includes('command response pending')) && api.poc_key_is_set() === rotation,
      'queued configuration reports busy truthfully during failed append cleanup');
    check(!JSON.parse(await configure(keys.at(-1))).error && api.poc_key_is_set(),
      'failed request drops reservation and subsequent configuration completes');
    return {checks,events};
  }
  await finalReady;
  const outcomes = await Promise.all(configurations);
  if (transition) await transition;
  events.push('configuration completed before final release');
  const counts = JSON.parse(await api.test_poc_release_counts());
  const custody = api.poc_key_is_set();
  let malformedRefused = false;
  try { await api.run_command('{'); } catch { malformedRefused = true; }
  check(malformedRefused, 'concurrent malformed request exits without losing pending reservation');
  if (!transition) check(JSON.parse(await configure(keys.at(-1))).error?.includes('command response pending'),
    'another request error cannot release the active response reservation');
  releaseFinal();
  const result = JSON.parse(await command);
  events.push({counts,configuration:outcomes.map(text=>({error:JSON.parse(text).error})),custody});
  const value = collect ? result.outcome?.collected?.[0] : name.endsWith('held') ? result.outcome?.calls?.[0]?.dispatch_result : result.outcome;
  check(counts.terminals === 1 && counts.collectable === 0 && counts.launches === 1, 'exactly one terminal, no collectable call, no second launch');
  check(value?.stdout === expectedOutput && value?.stderr === '' && value?.exit_status === 7 &&
    (value.record ?? value.job_record?.record)?.stdout === hex(expectedOutput),
    'poc late ' + (rotation ? 'rotation' : 'first-key') + ' preserves useful full final response: ' + (result.outcome?.refused ?? 'complete output'));
  const reason = transition ? name.endsWith('end') ? 'ended' : 'reconciliation' : 'command response pending';
  check(outcomes.every(text => JSON.parse(text).error?.toLowerCase().includes(reason)) && custody === (rotation && !name.endsWith('end')),
    'configuration truthfully refuses and retains current key custody');
  if (transition) {
    check(value.historical === true && value.actionable === false && value.done !== true,
      'interrupted terminal remains historical with full useful output');
  }
  for (const key of keys) {
    const probe = {stdout:key};
    check(await api.test_poc_protect_output(JSON.stringify(probe)) === JSON.stringify(probe), 'refused configuration leaves protection inventory unchanged');
  }
  if (rotation) {
    const protectedValue = await api.test_poc_protect_output(JSON.stringify({stdout:normal}));
    check(!protectedValue.includes(normal), 'current credential protects release inventory');
  }
  if (name.endsWith('end')) {
    check(JSON.parse(await configure(keys.at(-1))).error?.includes('ended') && !api.poc_key_is_set(),
      'queued and subsequent configuration cannot resurrect ended key authority');
    return {checks,events};
  }
  if (transition) await api.lifecycle_transition('resume');
  check(!JSON.parse(await configure(keys.at(-1))).error && api.poc_key_is_set(), 'configuration succeeds after response release');
  check(!(await api.test_poc_protect_output(JSON.stringify({stdout:keys.at(-1)}))).includes(keys.at(-1)), 'new credential protected after release');
  check(contacts === 0, 'settlement fixture needs no relay contact');
  return {checks,events};
}

async function cases(api, init) {
  const checks = [];
  const check = (value, name) => {
    if (!value) throw new Error(name);
    checks.push(name);
  };
  const key = 'fixture-browser-key-4827';
  let expectedKey = key;
  const originalFetch = globalThis.fetch.bind(globalThis);
  const originalTimeout = globalThis.setTimeout.bind(globalThis);
  const delay = ms => new Promise(resolve => originalTimeout(resolve, ms));
  let accelerate = false, timerSeen = false, mode, pending, aborted = 0;
  const requests = [];
  globalThis.setTimeout = (callback, ms, ...args) => {
    if (ms === 60000) timerSeen = true;
    return originalTimeout(callback, accelerate && ms === 60000 ? 500 : ms, ...args);
  };
  const response = (name = 'exec', command = 'printf ok', id = 'call-a') => ({
    choices: [{ finish_reason: 'tool_calls', message: { role: 'assistant', content: null,
      tool_calls: [{ id, type: 'function', function: { name, arguments: JSON.stringify(
        name === 'done' ? { machine: 'machine-a' } : { machine: 'machine-a', command }) } }] } }],
  });
  const good = () => new Response(JSON.stringify(response()), { status: 200 });
  globalThis.fetch = async (input, options) => {
    const request = input instanceof Request ? input : new Request(input, options);
    if (request.url.startsWith(location.origin + '/')) return originalFetch(request);
    if (request.url !== 'https://inference.invalid/v1/chat/completions') {
      throw new Error('external request refused');
    }
    const text = await request.clone().text();
    const body = JSON.parse(text);
    requests.push({
      transport: request.mode === 'cors' && request.credentials === 'omit' &&
        request.cache === 'no-store' && request.redirect === 'error' &&
        request.headers.get('authorization') === 'Bearer ' + expectedKey,
      bodySafe: !text.includes(key) && !text.includes(btoa(key)) && !text.includes(expectedKey), body,
    });
    if (mode?.network) throw new Error('simulated network loss');
    if (mode?.pending) return new Promise((resolve, reject) => {
      pending = { resolve };
      const ignore = mode.ignoreAbort;
      request.signal.addEventListener('abort', () => {
        aborted++;
        if (!ignore) reject(new DOMException('stopped', 'AbortError'));
      }, { once: true });
    });
    if (mode?.stalledBody) return new Response(new ReadableStream(), { status: mode.status });
    return new Response(mode?.body ?? JSON.stringify(response()), { status: mode?.status ?? 200 });
  };
  let watchId = 0;
  const measured = async (label, action, lifecycle = '') => {
    const id = ++watchId, start = performance.now();
    postMessage({start: {id, label, lifecycle}});
    try { return await action(); }
    finally {
      const ms = performance.now() - start;
      postMessage({timing: {id, label, ms, completedAt:performance.timeOrigin + performance.now()}});
      check(ms < 15000, label + ' completes within 15 seconds');
    }
  };
  const next = async (steps = [], goal = 'Inspect the machine') => measured('inference', async () =>
    JSON.parse(await api.test_poc_next(goal, 'machine-a', JSON.stringify(steps))));
  const awaitPending = async () => {
    for (let i = 0; i < 200 && !pending; i++) await delay(5);
    check(Boolean(pending), 'request reached transport');
  };
  await init();
  await api.open();
  const created = JSON.parse(await api.create(new TextEncoder().encode('fixture passphrase for browser checks')));
  check(created.state === 'unlocked', 'store created');
  await api.seed_backup_answer();
  await api.seed_backup_skip();
  check((await next()).pause?.includes('endpoint missing'), 'configuration missing pauses');
  const empty = new Uint8Array();
  await api.poc_configure('https://inference.invalid/v1/chat/completions', 'model-a', empty);
  check(!api.poc_key_is_set(), 'empty key refused');
  const configure = value => api.poc_configure('https://inference.invalid/v1/chat/completions',
    'model-a', new TextEncoder().encode(value));
  const shortKey = 'short-key-12';
  const shortRefusal = JSON.parse(await configure(shortKey));
  check(shortRefusal.error?.includes('at least 16 bytes') && !JSON.stringify(shortRefusal).includes(shortKey) &&
    !api.poc_key_is_set(), 'poc accepted-short-key refuses before usable custody');
  const shortProbe = {stdout:shortKey};
  check(JSON.stringify(JSON.parse(await api.test_poc_protect_output(JSON.stringify(shortProbe)))) ===
    JSON.stringify(shortProbe), 'refused key adds no protection inventory');
  const boundaryKey = 'boundary-key-123';
  check(new TextEncoder().encode(boundaryKey).length === 16, 'boundary key has exactly 16 bytes');
  check(!JSON.parse(await configure(boundaryKey)).error && api.poc_key_is_set(), '16-byte key accepted');
  const failedReplacement = JSON.parse(await configure(shortKey));
  check(failedReplacement.error?.includes('at least 16 bytes') && api.poc_key_is_set(),
    'short replacement preserves prior usable custody');
  expectedKey = boundaryKey;
  check((await next()).tool?.name === 'exec' && requests.at(-1).transport,
    'refused replacement leaves original authorization active');
  check(JSON.stringify(JSON.parse(await api.test_poc_protect_output(JSON.stringify(shortProbe)))) ===
    JSON.stringify(shortProbe), 'failed replacement adds no protection inventory');
  expectedKey = key;
  const bytes = new TextEncoder().encode(key);
  await api.poc_configure('https://inference.invalid/v1/chat/completions', 'model-a', bytes);
  check(bytes.every(byte => byte === 0) && api.poc_key_is_set(), 'key transfer cleared');

  const target = {machine:'machine-a',relay:'wss://relay.invalid/base/',profile:'v1',host:'192.0.2.1',port:22,user:'arch',elevation:'sudo -n',pin:'SHA256:' + btoa(String.fromCharCode(...new Uint8Array(32).fill(7))).replace(/=+$/, '')};
  const enroll = candidate => api.poc_enroll(JSON.stringify({target:candidate,approve_existing:true,class_answer:'no',approve_maintained_access:true}));
  const journal = async () => JSON.parse(await api.test_poc_journal(key));
  const beforeAdmission = await journal();
  for (const candidate of [{...target,machine:key}, {...target,user:key},
    {...target,relay:'wss://relay.invalid/' + key + '/'},
    {...target,machine:btoa(key).replace(/=+$/,'').replaceAll('+','-').replaceAll('/','_')}]) {
    const refused = JSON.parse(await enroll(candidate));
    check(Boolean(refused.error), 'configure then credential enrollment refused');
    check(JSON.stringify(await journal()) === JSON.stringify(beforeAdmission), 'enrollment refusal leaves authenticated journal/allocation untouched');
  }
  expectedKey = 'rotated-browser-key-9751';
  await api.poc_configure('https://inference.invalid/v1/chat/completions','model-a',new TextEncoder().encode(expectedKey));
  check(Boolean(JSON.parse(await enroll({...target,machine:key})).error), 'previous configured key cannot become authority');
  check(JSON.stringify(await journal()) === JSON.stringify(beforeAdmission), 'rotation refusal has zero durable mutation');
  expectedKey = key;
  await api.poc_configure('https://inference.invalid/v1/chat/completions','model-a',new TextEncoder().encode(key));

  for (const status of [401, 403, 402, 429]) {
    for (const body of ['', 'plain refusal', '<html>refused</html>']) {
      mode = { status, body };
      const result = await next();
      const category = status === 401 || status === 403 ? 'key refused' :
        status === 402 ? 'provider limit' : 'provider rate limit';
      check(result.pause?.includes(category), `HTTP ${status} body classification`);
      check(!JSON.stringify(result).includes(key), `HTTP ${status} output protected`);
    }
  }
  for (const status of [401, 403]) {
    mode = { status, body: 'x'.repeat(300000) };
    check((await next()).pause?.includes('key refused'), 'authentication status precedes body size');
    mode = { status, stalledBody: true };
    accelerate = true;
    check((await next()).pause?.includes('key refused'), 'authentication status precedes stalled body');
    accelerate = false;
  }
  for (const status of [402, 429]) {
    mode = { status, body: JSON.stringify({ error: { message: 'limit echo ' + key } }) };
    const result = await next();
    check(result.pause?.includes('limit') && !result.pause.includes(key), 'provider echo protected');
  }
  const embedded = btoa('x' + key);
  for (const text of [embedded + '\n', 'echo: ' + embedded, 'printf %s ' + embedded + ' | base64 -d']) {
    mode = { status: 429, body: JSON.stringify({ error: { message: text } }) };
    const limit = await next();
    check(limit.pause?.includes('rate limit') && !limit.pause.includes(embedded), 'embedded provider echo protected');
    mode = { body: JSON.stringify(response('exec', text)) };
    check((await next()).pause?.includes('protected'), 'embedded proposal refused');
    const output = JSON.parse(await api.test_poc_protect_output(JSON.stringify({ stdout: text, nested: JSON.stringify({ key }) })));
    check(!JSON.stringify(output).includes(embedded) && !JSON.stringify(output).includes(key), 'store boundary protects configured key');
  }
  const pct = text => [...new TextEncoder().encode(text)].map(b => '%' + b.toString(16).padStart(2,'0')).join('');
  const independentForms = ['=' + embedded, '==' + embedded,
    embedded.slice(0,12) + '\n' + embedded.slice(12),
    embedded.slice(0,17) + '\r\n\t ' + embedded.slice(17),
    pct(key), pct(embedded), btoa(pct(key)),
    JSON.stringify({nested:pct(key)}), btoa(btoa('xy'+key)),
    btoa(String.fromCharCode(251,255)+key).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'')];
  for (const text of independentForms) {
    check(!text.includes(key), 'isolated encoding excludes raw key');
    for (const status of [402,429]) {
      mode = {status,body:JSON.stringify({error:{message:text}})};
      const result = await next();
      const category = status === 402 ? 'provider limit' : 'provider rate limit';
      check(typeof result.pause === 'string' && result.pause.includes(category) &&
        !result.pause.includes(key) && !result.pause.includes(text), 'isolated encoded HTTP excerpt protected with category');
    }
    mode = {body:JSON.stringify(response('exec',text))};
    check((await next()).pause?.includes('protected'), 'isolated encoded executable proposal refused');
    const output = JSON.parse(await api.test_poc_protect_output(JSON.stringify({stdout:text})));
    check(!JSON.stringify(output).includes(text), 'isolated encoded durable-output boundary protected');
    mode = undefined;
    const r = await next([['prior',{name:'done',arguments:{machine:'machine-a'}},{stdout:text}]],text);
    check(r.tool?.name === 'exec' && !JSON.stringify(requests.at(-1).body).includes(text), 'encoded goal and completed outcome protected');
  }
  const mixedAlphabet = 'trace-' + btoa(String.fromCharCode(251) + key);
  for (const text of [mixedAlphabet, 'x" y "\\u' + key.charCodeAt(0).toString(16).padStart(4, '0') + key.slice(1) + '"', '\\u' + key.charCodeAt(0).toString(16).padStart(4, '0') + key.slice(1)]) {
    mode = { status: 429, body: JSON.stringify({ error: { message: text } }) };
    const result = await next();
    check(typeof result.pause === 'string' && result.pause.includes('provider rate limit') &&
      !result.pause.includes(key) && !result.pause.includes(text), 'mixed-alphabet and escaped error protected with category');
    mode = { body: JSON.stringify(response('exec', text)) };
    check((await next()).pause?.includes('protected'), 'mixed-alphabet and escaped proposal refused');
    const safe = JSON.parse(await api.test_poc_protect_output(JSON.stringify({ stdout: text })));
    check(!JSON.stringify(safe).includes(text), 'mixed-alphabet and escaped store output protected');
  }
  expectedKey = 'z~'.repeat(8);
  await api.poc_configure('https://inference.invalid/v1/chat/completions', 'model-a', new TextEncoder().encode(expectedKey));
  const oddHex = 'a' + '7A7e'.repeat(8);
  mode = { status: 429, body: JSON.stringify({ error: { message: oddHex } }) };
  const oddError = await next();
  check(typeof oddError.pause === 'string' && oddError.pause.includes('provider rate limit') &&
    !oddError.pause.includes(oddHex) && !oddError.pause.includes(expectedKey), 'odd mixed-case hex error protected');
  mode = { body: JSON.stringify(response('exec', oddHex)) };
  check((await next()).pause?.includes('protected'), 'odd mixed-case hex proposal refused');
  const safeHex = JSON.parse(await api.test_poc_protect_output(JSON.stringify({ stdout: oddHex })));
  check(!JSON.stringify(safeHex).includes(oddHex), 'odd mixed-case hex store output protected');
  expectedKey = key;
  await api.poc_configure('https://inference.invalid/v1/chat/completions', 'model-a', new TextEncoder().encode(key));
  const escaped = '\\u' + key.charCodeAt(0).toString(16).padStart(4, '0') + key.slice(1);
  const fragment = 'prefix: {"copy":"' + escaped + '"}';
  mode = { status: 429, body: JSON.stringify({ error: { message: fragment } }) };
  const embeddedError = await next();
  check(typeof embeddedError.pause === 'string' && embeddedError.pause.includes('provider rate limit') &&
    !embeddedError.pause.includes(escaped) && !embeddedError.pause.includes(key), 'embedded JSON error protected');
  mode = { body: JSON.stringify(response('exec', fragment)) };
  check((await next()).pause?.includes('protected'), 'embedded JSON proposal refused');
  mode = undefined;
  await next([['prior', { name: 'done', arguments: { machine: 'machine-a' } }, { stdout: fragment }]]);
  check(!JSON.stringify(requests.at(-1).body).includes(escaped), 'embedded JSON transcript protected');
  let deeplyNested = 0;
  for (let i = 0; i < 20; i++) deeplyNested = [deeplyNested];
  for (const status of [402, 429, 500]) {
    const category = status === 402 ? 'provider limit' : status === 429 ? 'rate limit' : 'request refused';
    mode = { status, body: JSON.stringify({ error: { message: 'provider refused' }, unrelated: deeplyNested }) };
    check((await next()).pause?.includes(category), 'HTTP category survives optional protection bound');
    mode = { status, stalledBody: true };
    accelerate = true;
    check((await next()).pause?.includes(category), 'stalled error body retains HTTP category');
    accelerate = false;
  }
  mode = { body: new Uint8Array([255]) };
  check((await next()).pause?.includes('malformed JSON'), 'non-UTF8 response is malformed');
  for (const status of [402, 429]) {
    mode = { status, body: 'x'.repeat(300000) };
    check((await next()).pause?.includes(status === 402 ? 'provider limit' : 'rate limit'), 'limit status precedes oversized body');
  }
  mode = undefined;
  const first = await next([], 'Inspect ' + key);
  check(first.tool?.name === 'exec' && first.tool.arguments.command === 'printf ok', 'exec normalized');
  mode = { body: JSON.stringify(response('done', '', 'call-b')) };
  const second = await next([[first.id, first.tool, { stdout: JSON.stringify({ nested: key }) }]]);
  check(second.tool?.name === 'done' && second.tool.arguments.machine === 'machine-a', 'done normalized');
  const transcript = requests.at(-1).body.messages;
  check(transcript[2].role === 'assistant' && transcript[2].tool_calls[0].id === first.id &&
    typeof transcript[2].tool_calls[0].function.arguments === 'string' &&
    transcript[3].role === 'tool' && transcript[3].tool_call_id === first.id,
  'completed transcript uses matching call identity');
  for (const command of ['printf ' + key, 'printf ' + btoa(key)]) {
    mode = { body: JSON.stringify(response('exec', command)) };
    const result = await next();
    check(Boolean(result.pause) && !JSON.stringify(result).includes(key), 'credential proposal refused');
  }
  mode = { network: true };
  let count = requests.length;
  check((await next()).pause?.includes('incomplete') && requests.length === count + 1,
    'network failure pauses without retry');

  mode = { pending: true };
  pending = undefined;
  accelerate = true;
  count = requests.length;
  check((await next()).pause?.includes('incomplete') && timerSeen &&
    requests.length === count + 1 && aborted > 0, 'finite timeout aborts without retry');
  accelerate = false;
  mode = { pending: true, ignoreAbort: true };
  pending = undefined;
  const frozen = next();
  await awaitPending();
  const lateFreeze = pending;
  const beforeFreeze = aborted;
  await api.lifecycle_transition('freeze');
  check((await frozen).pause?.includes('incomplete') && aborted > beforeFreeze && api.poc_key_is_set(),
    'freeze aborts and retains key');
  lateFreeze.resolve(good());
  await delay(10);
  check(api.poc_key_is_set(), 'late freeze response preserves custody');
  await api.lifecycle_transition('resume');
  mode = undefined;
  check((await next()).tool?.name === 'exec', 'resume permits fresh request');
  for (const size of [1024, 10240]) {
    for (const output of [('Package abc012345 xyz789 installed successfully.\n').repeat(Math.ceil(size/49)).slice(0,size),
      ('Abc0123456789xyzXYZ').repeat(Math.ceil(size/18)).slice(0,size)]) {
      const value = {stdout:output,stderr:'',record:{stdout:[...new TextEncoder().encode(output)].map(b=>b.toString(16).padStart(2,'0')).join(''),stderr:''}};
      const safe = JSON.parse(await measured('protect_output ' + size, () => api.test_poc_protect_output(JSON.stringify(value))));
      check(safe.stdout === output && safe.record.stdout === value.record.stdout, 'ordinary output and hex evidence remain usable');
      mode = undefined;
      const r = await measured('request ' + size, () => next([['prior',{name:'exec',arguments:{machine:'machine-a',command:'true'}},value]]));
      check(r.tool?.name === 'exec', 'ordinary request ' + size + ' usable: ' + r.pause);
      const excerpt = requests.at(-1).body.messages[3].content;
      check(r.tool?.name === 'exec' && excerpt.includes(output.slice(0,40)), 'ordinary transcript reaches model with useful excerpt');
    }
  }
  let lifecycleAck;
  globalThis.onmessage = async ({data}) => {
    if (data.fixtureLifecycle !== 'freeze') return;
    await api.lifecycle_transition('freeze');
    postMessage({lifecycleAck:data.id});
    lifecycleAck();
  };
  const withFreeze = async (label, action) => {
    const acknowledged = new Promise(resolve => { lifecycleAck = resolve; });
    const result = await measured(label, action, 'freeze');
    await acknowledged;
    check(api.poc_key_is_set(), 'queued freeze retains key');
    await api.lifecycle_transition('resume');
    return result;
  };
  for (const [size, fixtureKey] of [[65536,key],[262144,key],[393216,'']]) {
    const output = 'Package abc012345 xyz789 installed successfully.\n'.repeat(Math.ceil(size/47)).slice(0,size);
    const result = JSON.parse(await measured('durable job settlement ' + size + (fixtureKey ? ' keyed' : ' no-key'),
      () => api.test_poc_job_evidence(output, '', fixtureKey, '')));
    check(result.report?.state === 'finished' && result.report.exit_status === 7 &&
      result.report.stdout === output && result.admitted && result.replayed &&
      result.collectable === 0 && !result.journal_contains_key, 'ordinary durable job is collected/replayed with full safe output: ' + size + ' ' + result.withheld);
  }
  const packageOutput = size => 'Package abc012345 xyz789 installed successfully.\n'.repeat(Math.ceil(size/47)).slice(0,size);
  const toHex = text => [...new TextEncoder().encode(text)].map(b=>b.toString(16).padStart(2,'0')).join('');
  const previousKey = 'previous-normal-key-482700';
  const normalKey = 'normal-synthetic-key-482700';
  const finished = (result, output, stderr) => result.report?.state === 'finished' &&
    result.report.exit_status === 7 && result.report.stdout === output && result.report.stderr === stderr &&
    result.report.record.stdout === toHex(output) && result.report.record.stderr === toHex(stderr) &&
    result.served?.outcome?.stdout === output && result.served?.outcome?.stderr === stderr &&
    result.served?.outcome?.job_record?.record?.stdout === toHex(output) &&
    result.collected?.outcome?.collected?.[0]?.stdout === output &&
    result.held_dispatch?.outcome?.calls?.[0]?.dispatch_result?.stdout === output && result.canonical_replayed &&
    result.admitted && result.replayed && result.collectable === 0 && result.terminals === 1 &&
    result.launches === 1 && result.duplicate_refused && !result.journal_contains_key;
  for (const [label, output, stderr, fixtureKey, previous] of [
    ['two-stream',packageOutput(262144),packageOutput(16384),normalKey,''],
    ['rotated-margin',packageOutput(327680),packageOutput(24576),normalKey,previousKey],
    ['textual-hex',toHex(packageOutput(131072)),'',normalKey,''],
    ['accepted-boundary-key',packageOutput(262144),packageOutput(16384),boundaryKey,''],
  ]) {
    check(!JSON.parse(await configure(fixtureKey)).error, label + ' configuration accepted');
    const result = JSON.parse(await measured('poc exact ' + label,
      () => api.test_poc_job_evidence(output,stderr,fixtureKey,previous)));
    check(finished(result,output,stderr), label + ' settles/releases/replays without another launch: ' + result.withheld);
  }
  for (const [label, releaseOutput, stderr, previous, command, sudo] of [
    ['181890',toHex(packageOutput(181890)),'','',undefined,false],
    ['183300',toHex(packageOutput(183300)),'','',undefined,false],
    ['185344',toHex(packageOutput(185344)),'','',undefined,false],
    ['long-command',packageOutput(327680),packageOutput(24576),previousKey,'#'.repeat(8192),false],
    ['long-command-sudo',packageOutput(327680),packageOutput(24576),previousKey,'#'.repeat(8192),true],
  ]) {
    await configure(normalKey);
    const releaseBound = JSON.parse(await measured('poc served release-bound ' + label,
      () => api.test_poc_job_evidence(releaseOutput,stderr,normalKey,previous,command,sudo)));
    const refusedBeforeAppend = releaseBound.phase === 'settlement' && releaseBound.withheld?.includes('bound') &&
      releaseBound.terminals === 0 && releaseBound.collectable === 1 && !releaseBound.admitted &&
      releaseBound.unchanged && releaseBound.replayed && releaseBound.launches === 1;
    check(finished(releaseBound,releaseOutput,stderr) || refusedBeforeAppend,
      'poc served release-bound never commits then withholds ' + label + ': ' + JSON.stringify(releaseBound));
    postMessage({diagnostic:{label:'served release-bound '+label,phase:releaseBound.phase,
      terminals:releaseBound.terminals,collectable:releaseBound.collectable,withheld:releaseBound.withheld}});
  }
  const collisionConfig = JSON.parse(await configure('true'));
  check(collisionConfig.error?.includes('at least 16 bytes'), 'short collision key refused by configuration');
  // Direct fixture registration preserves the late-credential collision independently of admission.
  const evidenceCollision = JSON.parse(await measured('poc comparison-collision',
    () => api.test_poc_job_evidence('ordinary package output','','true','')));
  check(evidenceCollision.replayed && evidenceCollision.report?.agreement === 'finding' &&
    evidenceCollision.report.journal === toHex('<redacted>') && evidenceCollision.report.record.command === toHex('<redacted>') &&
    evidenceCollision.report.stdout === 'ordinary package output' && evidenceCollision.report.stderr === '' &&
    evidenceCollision.admitted && evidenceCollision.collectable === 0 && evidenceCollision.terminals === 1 &&
    evidenceCollision.launches === 1 && evidenceCollision.duplicate_refused,
    'poc comparison-collision preserves replayed comparison and original single call');
  expectedKey = key;
  await configure(key);
  for (const [label, output, stderr, previous] of [
    ['two-stream rotated margin',packageOutput(327680),packageOutput(24576),previousKey],
    ['textual-hex',toHex(packageOutput(131072)),'',''],
  ]) {
    const result = JSON.parse(await withFreeze('durable job ' + label,
      () => api.test_poc_job_evidence(output, stderr, key, previous)));
    check(result.report?.state === 'finished' && result.report.exit_status === 7 &&
      result.report.stdout === output && result.report.stderr === stderr &&
      result.report.record.stdout === toHex(output) && result.report.record.stderr === toHex(stderr) &&
      result.admitted && result.replayed && result.collectable === 0 && !result.journal_contains_key,
      'ordinary durable ' + label + ' releases useful output and clears hold: ' + result.withheld);
  }
  for (const size of [2097152,3145728]) {
    const output = packageOutput(size);
    const result = JSON.parse(await measured('larger no-key diagnostic ' + size,
      () => api.test_poc_job_evidence(output, '', '', '')));
    const finished = result.report?.state === 'finished' && result.report.exit_status === 7 &&
      result.report.stdout === output && result.report.stderr === '' &&
      result.report.record.stdout === toHex(output) && result.report.record.stderr === '' &&
      result.admitted && result.replayed && result.collectable === 0;
    check(finished || result.withheld?.includes('bound'), 'larger output finishes or honestly withholds');
    postMessage({diagnostic:{label:'larger no-key ' + size,finished,withheld:result.withheld}});
  }
  for (const encoded of [key,btoa(key),btoa(JSON.stringify({nested:btoa(key)}))]) {
    const output = 'Package abc012345 xyz789 installed successfully.\n'.repeat(1500) + encoded;
    const result = JSON.parse(await measured('durable encoded echo ' + (encoded === key ? 'raw' : 'encoded'),
      () => api.test_poc_job_evidence(output,'',key,'')));
    check(result.report?.state === 'finished' && result.report.exit_status === 7 && result.admitted &&
      result.replayed && result.collectable === 0 && !result.journal_contains_key &&
      result.report.stdout.includes('<redacted>') && !JSON.stringify(result).includes(key) &&
      !result.report.stdout.includes(encoded), 'large durable echo protected before journal/release');
  }
  const digits = ['1','2','3','4'].map(d => d.repeat(4096)).join(' ');
  mode = undefined;
  const bounded = await measured('four block repeated digit goal', () => next([],digits));
  check(bounded.tool?.name === 'exec' || bounded.pause?.includes('bound'), 'adversarial goal completes with tool or bounded refusal');
  // The main page queues freeze while this protection call is outstanding. Its watchdog
  // runs independently of the blocked worker; synchronous Rust may complete before the ack.
  const malicious = Array(1200000).fill('neutral abc012 xyz789');
  const withheld = JSON.parse(await withFreeze('aggregate node exhaustion', () => api.test_poc_protect_output(JSON.stringify(malicious))));
  check(withheld.withheld?.includes('bound'), 'aggregate complexity withholds safely');
  globalThis.onmessage = null;
  check(api.poc_key_is_set(), 'bounded scanning leaves lifecycle handling usable');
  await api.lifecycle_transition('resume');
  check((await next()).tool?.name === 'exec', 'worker remains usable after budget refusal');

  // The dedicated served exports use the ordinary approval journal and real harness
  // admission paths. WebSocket is a throwing contact spy; no host is reached.
  check(!JSON.parse(await enroll(target)).error, 'safe existing-machine enrollment passes');
  const bound = JSON.parse(await api.poc_bind('machine-a'));
  const session = bound.sessions.find(s => s.bound_set.includes('machine-a')).identity;
  const proposed = {kind:'declaration',machine:'machine-a',declaration:bound.poc_declaration_candidate};
  check(Boolean(JSON.parse(await api.poc_propose_requirements(JSON.stringify({session,proposal:proposed}))).error), 'declaration refuses without goal and acting authority');
  await api.goal_request(JSON.stringify({session,text:'Install a small service',document_source:null}));
  check(!JSON.parse(await api.poc_accept(JSON.stringify({session}))).error, 'explicit PoC acting acceptance');
  const offered = JSON.parse(await api.poc_propose_requirements(JSON.stringify({session,proposal:proposed})));
  const candidate = offered.sessions.find(s=>s.identity===session).pending_requirements.candidate;
  let contacts = [];
  const originalSocket = globalThis.WebSocket;
  globalThis.WebSocket = function(url) { contacts.push(url); throw Error('fixture relay contact refused'); };
  try {
    const pre = JSON.parse(await api.test_poc_transport('machine-a',false,''));
    check(JSON.stringify(pre).includes('declaration missing') && contacts.length===0, 'command refuses before declaration approval');
    const approved = JSON.parse(await api.requirements_answer(JSON.stringify({session,machine:'machine-a',candidate,decision:'approve'})));
    check(!approved.error, 'explicit declaration approval journaled via served export');
    for (const collect of [false,true]) {
      for (const bad of [{...target,profile:'v2'}, {...target,relay:'ws://relay.invalid/'}, {...target,pin:''}]) {
        const result = JSON.parse(await api.test_poc_transport('machine-a',collect,JSON.stringify(bad)));
        check(Boolean(result.refused) && contacts.length===0, 'command/collect invalid target refuses before contact');
      }
      const unknown = JSON.parse(await api.test_poc_transport('unknown',collect,''));
      check(Boolean(unknown.refused) && contacts.length===0, 'unknown stored command/collect refuses before contact');
    }
    await api.test_poc_transport('machine-a',false,'');
    check(contacts.length===1 && contacts[0]==='wss://relay.invalid/base/v1/tcp/192.0.2.1/22', 'approved stored command reaches exact v1 contact seam');
  } finally { globalThis.WebSocket = originalSocket; }
  expectedKey = 'L'.repeat(4096);
  await api.poc_configure('https://inference.invalid/v1/chat/completions', 'model-a', new TextEncoder().encode(expectedKey));
  mode = { body: JSON.stringify({ ...response(), extra: 'x'.repeat(200000) }) };
  const started = performance.now();
  const longKeyResult = await next();
  check(longKeyResult.tool?.name === 'exec' && performance.now() - started < 10000, 'maximum key and bounded response finish promptly: ' + longKeyResult.pause);
  expectedKey = key;
  await api.poc_configure('https://inference.invalid/v1/chat/completions', 'model-a', new TextEncoder().encode(key));
  const markerKey = '<redacted>';
  const markerConfiguration = JSON.parse(await configure(markerKey));
  check(markerConfiguration.error?.includes('at least 16 bytes') && api.poc_key_is_set(),
    'short marker configuration refuses without replacing the current key');
  // Register the earlier marker directly in the isolated fixture despite admission refusal.
  const collision = JSON.parse(await api.test_poc_job_evidence(key, '', key, markerKey));
  check(Boolean(collision.withheld) && !JSON.stringify(collision).includes(markerKey) &&
    collision.phase === 'settlement' && collision.terminals === 0 && collision.collectable === 1 &&
    collision.unchanged && collision.replayed && !collision.admitted,
    'rotation cannot reintroduce older credential through marker');
  mode = { pending: true, ignoreAbort: true };
  pending = undefined;
  const ended = next();
  await awaitPending();
  const lateEnd = pending;
  const beforeEnd = aborted;
  await api.end_sessions();
  check((await ended).pause?.includes('incomplete') && aborted > beforeEnd && !api.poc_key_is_set(),
    'session end aborts and clears key');
  lateEnd.resolve(good());
  await delay(10);
  check(!api.poc_key_is_set(), 'late response cannot restore key');
  const afterEnd = JSON.parse(await api.test_poc_protect_output(JSON.stringify({ stdout: key, encoded: 'echo: ' + embedded })));
  check(!JSON.stringify(afterEnd).includes(key) && !JSON.stringify(afterEnd).includes(embedded), 'ended worker retains only output protection');
  check(requests.every(request => request.transport && request.bodySafe), 'transport options and body boundary');
  return checks;
}

// Drive the actual packaged page/worker, including its publication and lifecycle path.
async function pageCases() {
  const checks = [];
  const $ = id => document.getElementById('tau-' + id);
  const until = async (predicate, label) => {
    const start = performance.now();
    while (!predicate()) {
      if (performance.now() - start > 15000) throw Error('page watchdog: ' + label + '; store error: ' + window.__pocReports.at(-1)?.store_error + '; page: ' + $('store-state').textContent);
      await new Promise(resolve => setTimeout(resolve,20));
    }
    checks.push(label);
  };
  await until(() => $('store')?.dataset.state === 'locked', 'fresh page opens replayed locked store');
  $('passphrase').value = 'fixture passphrase for browser checks'; $('unlock').click();
  await until(() => $('store').dataset.state === 'unlocked', 'operator unlock');
  await until(() => $('poc-key-status').textContent === 'Key unset.', 'worker loss clears custody');
  $('poc-endpoint').value = 'https://inference.invalid/v1/chat/completions';
  $('poc-model').value = 'model-a'; $('poc-key').value = 'fixture-page-custody-key-4827';
  $('poc-inference-form').requestSubmit();
  await until(() => $('poc-key-status').textContent === 'Key set.', 'configured key reported by real page publication');
  if ($('poc-key').value !== '') throw Error('page key input was retained');
  // Exercise the dedicated declaration controls, without entering the old goal loop.
  [...$('poc-targets').querySelectorAll('button')].find(b=>b.textContent==='Bind machine-a').click();
  await until(() => document.querySelector('[data-goal-text]'), 'bound session exposes goal form');
  document.querySelector('[data-goal-text]').value = 'Inspect a small service';
  document.querySelector('[data-goal-enter]').click();
  await until(() => document.querySelector('[data-poc-accept]'), 'PoC acceptance control visible');
  document.querySelector('[data-poc-accept]').click();
  await until(() => document.querySelector('[data-poc-declaration]'), 'visible editable declaration candidate');
  const initial = document.querySelector('[data-poc-declaration]').value;
  const custom = JSON.parse(initial);
  custom.services = [{name:'draft-check',scope:{kind:'system'},lifecycle:'running-at-delivery'}];
  const draft = JSON.stringify(custom,null,2);
  const setDraft = text => { const field=document.querySelector('[data-poc-declaration]');field.value=text;field.dispatchEvent(new Event('input',{bubbles:true})); };
  const assertDraft = text => { if(document.querySelector('[data-poc-declaration]')?.value !== text)throw Error('declaration draft lost'); };
  setDraft(draft);
  const reports = window.__pocReports.length;
  [...$('poc-targets').querySelectorAll('button')].find(b=>b.textContent==='Show public keys machine-a').click();
  await until(() => window.__pocReports.length > reports, 'unrelated real report delivered');
  assertDraft(draft);
  for (const visibility of ['hidden','visible']) {
    const count = window.__pocLifecycle.length;
    Object.defineProperty(document,'visibilityState',{value:visibility,configurable:true});
    document.dispatchEvent(new Event('visibilitychange'));
    await until(() => window.__pocLifecycle.length > count && window.__pocLifecycle.at(-1) === visibility,
      'real worker received ' + visibility + ' lifecycle');
    assertDraft(draft);
    if ($('poc-key-status').textContent !== 'Key set.') throw Error('visibility cycle lost key custody');
  }
  delete document.visibilityState;
  checks.push('ordinary hide/visible preserves exact custom draft and key custody');
  document.dispatchEvent(new Event('freeze'));
  await until(() => ['suspended','reconciling'].includes($('store-state').dataset.lifecycle), 'freeze report reaches page');
  if ($('poc-key-status').textContent !== 'Key set.') throw Error('freeze falsely reported key unset');
  if ([...$('poc').querySelectorAll('input,select,button')].some(control=>!control.disabled)) throw Error('suspended controls enabled');
  checks.push('freeze reports retained custody with disabled controls');
  document.dispatchEvent(new Event('resume'));
  await until(() => !$('poc-endpoint').disabled, 'resume restores authority without key re-entry');
  if ($('poc-key-status').textContent !== 'Key set.') throw Error('resume lost key custody');
  assertDraft(draft);
  // Valid custom candidate survives a real refused proposal report, then the next click
  // submits that exact same candidate. The deliberately unknown session must refuse.
  const beforeRefusal = window.__pocReports.length;
  window.__pocWorkers.at(-1).postMessage({poc_propose_requirements:{session:'unknown-session',proposal:{kind:'declaration',machine:'machine-a',declaration:custom}}});
  await until(() => window.__pocReports.length > beforeRefusal && Boolean(window.__pocReports.at(-1).store_error), 'proposal concretely refused');
  assertDraft(draft);
  const invalid = JSON.stringify({...custom,version:1},null,2);
  setDraft(invalid);
  const beforeInvalid = window.__pocReports.length;
  document.querySelector('[data-poc-propose]').click();
  await until(() => window.__pocReports.length > beforeInvalid && Boolean(window.__pocReports.at(-1).store_error), 'editable invalid proposal refused in same session');
  assertDraft(invalid);
  setDraft(draft);
  document.querySelector('[data-poc-propose]').click();
  await until(() => document.querySelector('[data-requirements-decision="approve"]'), 'custom proposal displayed for explicit approval');
  const sent = window.__pocMessages.filter(m=>m.poc_propose_requirements).at(-1).poc_propose_requirements;
  if (JSON.stringify(sent.proposal.declaration)!==JSON.stringify(custom))throw Error('next proposal discarded custom draft');
  if (!document.querySelector('[data-requirements-card]').textContent.includes('draft-check'))throw Error('approval card lost submitted candidate');
  document.querySelector('[data-requirements-decision="approve"]').click();
  await until(() => !document.querySelector('[data-requirements-decision="approve"]'), 'explicit operator approves exact custom requirements');
  assertDraft(draft);
  $('lock').click();
  await until(() => $('store').dataset.state === 'locked' && $('poc-key-status').textContent === 'Key unset.', 'Lock ends custody on real page');
  $('passphrase').value = 'fixture passphrase for browser checks'; $('unlock').click();
  await until(() => $('store').dataset.state === 'unlocked', 'unlock after Lock');
  [...$('poc-targets').querySelectorAll('button')].find(b=>b.textContent==='Bind machine-a').click();
  await until(() => document.querySelector('[data-goal-text]'), 'new session after Lock');
  document.querySelector('[data-goal-text]').value='Inspect the new session';document.querySelector('[data-goal-enter]').click();
  await until(() => document.querySelector('[data-poc-accept]'), 'new session goal entered');
  document.querySelector('[data-poc-accept]').click();
  await until(() => document.querySelector('[data-poc-declaration]'), 'new session declaration candidate');
  if(document.querySelector('[data-poc-declaration]').value !== initial)throw Error('Lock reused prior session draft');
  setDraft(draft);
  checks.push('Lock/new session clears old declaration draft');
  $('poc-endpoint').value = 'https://inference.invalid/v1/chat/completions';
  $('poc-model').value = 'model-a'; $('poc-key').value = 'fixture-worker-loss-key-9751';
  $('poc-inference-form').requestSubmit();
  await until(() => $('poc-key-status').textContent === 'Key set.', 'key held before forced worker loss');
  return checks;
}

const workerSource = `import init, * as api from '/pkg/tau_web.js';
(${cases.toString()})(api, init).then(checks => postMessage({checks}), error => postMessage({error:error.stack}));`;
const pageSource = `window.result = new Promise((resolve, reject) => {
  const worker = new Worker('/worker.js', {type:'module'});
  const pending = new Map(), timings = [];
  const stop = error => { worker.terminate(); for (const timer of pending.values()) clearTimeout(timer?.timer ?? timer); reject(error); };
  worker.onmessage = event => {
    if (event.data.diagnostic) { timings.push(event.data.diagnostic); return; }
    if (event.data.start) {
      const {id,label} = event.data.start;
      pending.set(id,setTimeout(()=>stop(Error('main-page watchdog: '+label+' exceeded 15 seconds')),15000));
      if (event.data.start.lifecycle) {
        const start = performance.now();
        pending.set('lifecycle-'+id,{start,sentAt:performance.timeOrigin+start,timer:setTimeout(()=>stop(Error('lifecycle acknowledgment exceeded 15 seconds')),15000)});
        worker.postMessage({fixtureLifecycle:event.data.start.lifecycle,id});
      }
      return;
    }
    if (event.data.lifecycleAck) {
      const id = 'lifecycle-'+event.data.lifecycleAck, entry = pending.get(id);
      clearTimeout(entry.timer); pending.delete(id);
      timings.push({label:'main-page queued freeze acknowledgment',ms:performance.now()-entry.start}); return;
    }
    if (event.data.timing) {
      const {id,label,ms,completedAt} = event.data.timing;
      const queued = pending.get('lifecycle-'+id);
      if (queued && queued.sentAt >= completedAt) { stop(Error('lifecycle request was not posted while protection was outstanding')); return; }
      clearTimeout(pending.get(id)); pending.delete(id);
      timings.push({label,ms}); return;
    }
    worker.terminate(); for (const timer of pending.values()) clearTimeout(timer?.timer ?? timer);
    event.data.error ? reject(Error(event.data.error + JSON.stringify(timings.slice(-8)))) : resolve({checks:event.data.checks,timings});
  };
  worker.onerror = () => stop(Error('worker initialization failed'));
});`;

const server = createServer(async (request, response) => {
  try {
    const path = new URL(request.url, 'http://localhost').pathname;
    if (path === '/release-case') {
      response.setHeader('Content-Type','text/html');
      response.end('<!doctype html>');
    } else if (path === '/release-worker.js') {
      const name = new URL(request.url, 'http://localhost').searchParams.get('case');
      response.setHeader('Content-Type','text/javascript');
      response.end(`import init, * as api from '${name.startsWith('b1') ? '/served-pkg/' : '/pkg/'}tau_web.js';
        (${releaseCases.toString()})(api,init,${JSON.stringify(name)}).then(result=>postMessage(result),error=>postMessage({error:error.stack}));`);
    } else if (/^\/served-pkg\/[a-zA-Z0-9_.-]+$/.test(path)) {
      response.setHeader('Content-Type',path.endsWith('.wasm')?'application/wasm':'text/javascript');
      response.end(await readFile(new URL('../dist/served/pkg/' + path.split('/').at(-1), import.meta.url)));
    } else if (path === '/') {
      response.setHeader('Content-Type', 'text/html');
      response.end('<!doctype html><script type="module" src="/page.js"></script>');
    } else if (path === '/page.js' || path === '/worker.js') {
      response.setHeader('Content-Type', 'text/javascript');
      response.end(path === '/page.js' ? pageSource : workerSource);
    } else if (path === '/app/' || /^\/app\/(boot|worker)\.js$/.test(path)) {
      const name = path === '/app/' ? 'index.html' : path.split('/').at(-1);
      let text = await readFile(new URL('../www/' + name, import.meta.url),'utf8');
      // This fixture server is HTTP loopback. Remove only its response's CSP meta so
      // wasm can load over HTTP; the shipped HTTPS CSP is checked independently.
      if (name === 'index.html') text = text.replace(/<meta http-equiv="Content-Security-Policy"[^>]*>\n/, '');
      if (name === 'worker.js') text = text.replace(
        'await reportStore(await lifecycle_transition(data.lifecycle));',
        'await reportStore(await lifecycle_transition(data.lifecycle)); postMessage({fixture_lifecycle_received:data.lifecycle});');
      response.setHeader('Content-Type',name === 'index.html' ? 'text/html' : 'text/javascript');
      response.end(text);
    } else if (/^\/app\/pkg\/[a-zA-Z0-9_.-]+$/.test(path)) {
      response.setHeader('Content-Type',path.endsWith('.wasm')?'application/wasm':'text/javascript');
      response.end(await readFile(new URL('../dist/tracer' + path.slice(4),import.meta.url)));
    } else if (/^\/pkg\/[a-zA-Z0-9_.-]+$/.test(path)) {
      response.setHeader('Content-Type', path.endsWith('.wasm') ? 'application/wasm' : 'text/javascript');
      response.end(await readFile(new URL('../dist/tracer' + path, import.meta.url)));
    } else { response.writeHead(404).end(); }
  } catch { response.writeHead(500).end(); }
});

let child, socket, profile;
const timeout = setTimeout(() => {
  console.error('browser check exceeded its time bound');
  child?.kill('SIGKILL');
}, 180000);
try {
  if (!process.env.CHROME || !process.env.TMPDIR) throw Error('CHROME and TMPDIR are required');
  profile = await mkdtemp(join(process.env.TMPDIR, 'poc-browser-'));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  child = spawn(process.env.CHROME, ['--headless', '--no-sandbox', '--disable-gpu',
    '--disable-background-networking', '--disable-component-update', '--disable-sync',
    '--disable-default-apps', '--no-default-browser-check', '--no-first-run',
    '--remote-debugging-port=0', '--user-data-dir=' + profile, 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
  const exited = new Promise(resolve => {
    child.once('exit', resolve);
    child.once('error', resolve);
  });
  const endpoint = await new Promise((resolve, reject) => {
    let text = '';
    child.stderr.on('data', chunk => {
      text = (text + chunk).slice(-8192);
      const match = text.match(/DevTools listening on (ws:\/\/[^\s]+)/);
      if (match) resolve(match[1]);
    });
    child.once('error', reject);
    child.once('exit', () => reject(Error('browser exited before ready')));
  });
  socket = new WebSocket(endpoint);
  await once(socket, 'open');
  let sequence = 0;
  const pending = new Map();
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    const callback = pending.get(message.id);
    if (callback) { pending.delete(message.id); callback(message); }
  });
  const call = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const id = ++sequence;
    pending.set(id, message => message.error ? reject(Error(method + ' failed')) : resolve(message.result));
    socket.send(JSON.stringify({ id, method, params, ...(sessionId ? {sessionId} : {}) }));
  });
  socket.addEventListener('close', () => {
    for (const callback of pending.values()) callback({error: true});
    pending.clear();
  });
  const regressionNames = process.env.TAU_POC_CASE ? [process.env.TAU_POC_CASE] :
    ['b1','b1-encoded','b2-first-command','b2-rotation-command','b2-first-collection','b2-rotation-collection','b2-first-held','b2-rotation-held','b2-echo-command','b2-first-freeze','b2-rotation-freeze','b2-first-end','b2-rotation-end','b2-first-append-error','b2-rotation-append-error'];
  for (const name of regressionNames) {
    const {browserContextId} = await call('Target.createBrowserContext');
    try {
      const {targetId} = await call('Target.createTarget',{url:`http://127.0.0.1:${server.address().port}/release-case`,browserContextId});
      const {sessionId} = await call('Target.attachToTarget',{targetId,flatten:true});
      const start = Date.now();
      const result = await call('Runtime.evaluate',{expression:`new Promise((resolve,reject)=>{
        const worker = new Worker('/release-worker.js?case=' + ${JSON.stringify(name)}, {type:'module'});
        const timer = setTimeout(()=>{worker.terminate();reject(Error('release case watchdog'));},15000);
        worker.onmessage = ({data}) => {clearTimeout(timer);worker.terminate();data.error?reject(Error(data.error)):resolve(data);};
        worker.onerror=()=>{clearTimeout(timer);worker.terminate();reject(Error('release worker failed'));};
      })`,awaitPromise:true,returnByValue:true},sessionId);
      console.log(JSON.stringify({regression:name,ms:Date.now()-start,...result}));
      if (result.exceptionDetails || !result.result?.value?.checks) throw Error('regression failed: ' + name);
    } finally { await call('Target.disposeBrowserContext',{browserContextId}); }
  }
  if (!process.env.TAU_POC_CASE) {
  const { targetId } = await call('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await call('Target.attachToTarget', { targetId, flatten: true });
  await call('Page.enable', {}, sessionId);
  const loaded = new Promise(resolve => {
    const listener = event => {
      const message = JSON.parse(event.data);
      if (message.sessionId === sessionId && message.method === 'Page.loadEventFired') {
        socket.removeEventListener('message', listener);
        resolve();
      }
    };
    socket.addEventListener('message', listener);
  });
  await call('Page.navigate', { url: `http://127.0.0.1:${server.address().port}/` }, sessionId);
  await loaded;
  const { result, exceptionDetails } = await call('Runtime.evaluate', {
    expression: 'new Promise((resolve,reject)=>{const poll=()=>window.result?window.result.then(resolve,reject):setTimeout(poll,10);poll()})',
    awaitPromise: true, returnByValue: true,
  }, sessionId);
  if (exceptionDetails || !Array.isArray(result.value?.checks)) throw Error('browser case failed: ' + (exceptionDetails?.exception?.description ?? result.description ?? 'no result'));
  console.log(`PoC browser checks passed: ${result.value.checks.length}`);
  console.log(JSON.stringify({timings:result.value.timings}));
  await call('Page.addScriptToEvaluateOnNewDocument',{source:`
    window.__pocWorkers=[];window.__pocMessages=[];window.__pocLifecycle=[];window.__pocReports=[];
    const RealWorker=window.Worker;
    window.Worker=class extends RealWorker {
      constructor(...args){super(...args);window.__pocWorkers.push(this);
        this.addEventListener('message',event=>{
          if(event.data.fixture_lifecycle_received){window.__pocLifecycle.push(event.data.fixture_lifecycle_received);event.stopImmediatePropagation();}
          if(event.data.store)window.__pocReports.push(event.data.store);
        });
      }
      postMessage(data,...args){
        if(data.lifecycle || data.poc_propose_requirements)window.__pocMessages.push(structuredClone(data));
        return super.postMessage(data,...args);
      }
    };`},sessionId);
  await call('Page.navigate', {url:`http://127.0.0.1:${server.address().port}/app/`},sessionId);
  const pageResult = await call('Runtime.evaluate',{expression:'(' + pageCases.toString() + ')()',awaitPromise:true,returnByValue:true},sessionId);
  if (pageResult.exceptionDetails || !Array.isArray(pageResult.result?.value)) throw Error('actual page check failed: ' + (pageResult.exceptionDetails?.exception?.description ?? 'no page result'));
  console.log(JSON.stringify({pageChecks:pageResult.result.value}));
  await call('Runtime.evaluate',{expression:'window.__pocWorkers.at(-1).terminate()'},sessionId);
  await call('Page.reload',{},sessionId);
  const loss = await call('Runtime.evaluate',{expression:`new Promise((resolve,reject)=>{const start=performance.now();const poll=()=>{if(document.querySelector('#tau-store')?.dataset.state==='locked' && document.querySelector('#tau-poc-key-status')?.textContent==='Key unset.' && !document.querySelector('[data-poc-declaration]')) return resolve(true);if(performance.now()-start>15000)return reject(Error('worker-loss page watchdog'));setTimeout(poll,20);};poll();})`,awaitPromise:true,returnByValue:true},sessionId);
  if (loss.exceptionDetails || loss.result?.value !== true) throw Error('worker loss did not clear published custody');
  console.log('Real page worker-loss custody/draft clearing check passed');
  }
  await call('Browser.close').catch(() => {});
  await exited;
} finally {
  clearTimeout(timeout);
  socket?.close();
  if (child?.pid && child.exitCode === null && child.signalCode === null) {
    const exited = once(child, 'exit');
    child.kill('SIGKILL');
    await exited;
  }
  await new Promise(resolve => server.close(resolve));
  if (profile) await rm(profile, { recursive: true, maxRetries: 10, retryDelay: 50 });
}
