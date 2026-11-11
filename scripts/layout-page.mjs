import assert from 'node:assert/strict';
import {readFile, writeFile, mkdir} from 'node:fs/promises';
import {join} from 'node:path';

export const layoutCases = ['layout-steps', 'layout-phone', 'layout-fixture', 'layout-keys'];
export const lifecycleText = "Switching apps or locking the device screen may leave data-key, seed, account and machine authority unlocked in memory indefinitely. Permitted work, including already approved destructive actions such as a disk wipe, may run unseen. End is the kill switch; Lock pauses, and dormant sessions retain their machines. An already approved destructive action may run after reload or worker loss without a new tap. Already accepted remote work may continue after End. The phone may freeze or discard this page without a final callback.";
const visibleSource = `node => !!node && node.getClientRects().length > 0 && getComputedStyle(node).visibility === 'visible' && !node.closest('[hidden]') && [...function*(){for(let p=node.parentElement;p;p=p.parentElement)yield p;}()].every(p=>p.tagName!=='DETAILS'||p.open||p.querySelector('summary')?.contains(node))`;

async function ordinaryReports(c) {
 for (const lifecycle of ['hidden', 'visible']) {
  const count = await c.evaluate('(window.fixtureReports ?? window.reports).length');
  await c.message({lifecycle});
  await c.wait(`(window.fixtureReports ?? window.reports).length > ${count}`);
 }
}

async function observeSends(c) {
 await c.evaluate(`(() => {
  const worker=(window.fixtureWorkers ?? window.workers).at(-1), original=worker.sendAt;
  if(typeof original!=='function')throw Error('missing captured-handler boundary');
  window.layoutFoldMessages=0;
  worker.sendAt=function(...args){window.layoutFoldMessages++;return original.apply(this,args);};
  window.layoutRestoreMessages=()=>{worker.sendAt=original;delete window.layoutRestoreMessages;};
 })()`);
}

async function toggleWithoutAction(c, selector, opening) {
 await observeSends(c);
 try {
  await c.evaluate(`(() => {
   for(const n of document.querySelectorAll(${JSON.stringify(selector)}))if(n.open!==${opening})n.querySelector('summary').click();
  })()`);
  await c.evaluate('new Promise(resolve=>setTimeout(resolve,100))');
  assert.equal(await c.evaluate('layoutFoldMessages'),0,'fold toggles send no action through captured handlers');
 } finally { await c.evaluate('layoutRestoreMessages()'); }
}

async function interruptionDetails(c, selector) {
 const read=()=>c.evaluate(`Array.from(document.querySelectorAll(${JSON.stringify(selector)}),n=>({key:n.dataset.foldKey,open:n.open}))`);
 for(const opening of [true,false]) {
  await toggleWithoutAction(c,selector,opening);
  const before=await read();
  assert.ok(before.length,'actual task Details before freeze');
  await c.message({lifecycle:'freeze'});
  await c.wait("fixtureReports.at(-1)?.lifecycle_state==='reconciling'");
  assert.equal((await read()).length,0,'reconciling projection withholds task Details');
  await c.message({lifecycle:'resume'});
  await c.wait("fixtureReports.at(-1)?.lifecycle_state==='running'");
  assert.deepEqual(await read(),before,'same task fold keys and operator choices survive processed freeze/resume');
  await phonePair(c,opening?'details-resumed-open':'details-resumed-closed');
 }
}

async function retainDetails(c, selector) {
 const read = () => c.evaluate(`Array.from(document.querySelectorAll(${JSON.stringify(selector)}), n=>({content:n.querySelector('[data-raw-json]').textContent,open:n.open}))`);
 const initial = await read();
 assert.ok(initial.length, `actual Details offered: ${selector}`);
 await toggleWithoutAction(c,selector,true);
 await ordinaryReports(c);
 assert.deepEqual(await read(), initial.map(n=>({...n,open:true})), `same records keep opened Details: ${selector}`);
 await observeSends(c);
 try {
  await c.evaluate(`document.querySelector(${JSON.stringify(selector)}).querySelector('summary').click()`);
  await c.evaluate('new Promise(resolve=>setTimeout(resolve,100))');
  assert.equal(await c.evaluate('layoutFoldMessages'),0,'closing Details sends no action through captured handlers');
 } finally { await c.evaluate('layoutRestoreMessages()'); }
 await ordinaryReports(c);
 assert.deepEqual(await read(), initial.map((n,i)=>({...n,open:i!==0})), `same records keep closed and opened Details: ${selector}`);
 c.check(true, `Details choices and record content survive ordinary reports: ${selector}`);
}

async function phonePair(c, state) {
 await phoneSnapshot(c,state);
 await c.call('Emulation.setDeviceMetricsOverride',{width:360,height:844,deviceScaleFactor:1,mobile:true},c.sessionId);
 await phoneSnapshot(c,state+'-360');
 await c.call('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true},c.sessionId);
}

async function controlAudit(c) {
 const baseline=JSON.parse(await readFile(new URL('./layout-controls.json',import.meta.url)));
 const actual=await c.evaluate(`(() => ({
  controls:Object.fromEntries([...document.querySelectorAll('[id]')].map(n=>[n.id,{tag:n.tagName.toLowerCase(),form:n.form?.id??null}])),
  dynamic:${JSON.stringify(baseline.dynamicControls)}.map(row=>({...row,nodes:[...document.querySelectorAll(row.selector)].map(n=>({tag:n.tagName.toLowerCase(),type:n.type,form:n.form?.id??null}))}))
 }))()`);
 for(const [id,tag] of Object.entries(baseline.controls))assert.equal(actual.controls[id]?.tag,tag,`baseline control ${id}`);
 for(const [id,form] of Object.entries(baseline.formOwners))assert.equal(actual.controls[id]?.form,form,`form owner ${id}`);
 for(const row of actual.dynamic)for(const node of row.nodes){
  assert.equal(node.tag,row.tag,`dynamic control ${row.selector}`);
  if(row.type)assert.equal(node.type,row.type,`dynamic type ${row.selector}`);
  assert.equal(node.form,null,`dynamic form owner ${row.selector}`);
 }
 console.log(JSON.stringify({controls:actual.dynamic.filter(row=>row.nodes.length).map(row=>[row.selector,row.nodes.length])}));
}

export async function presentationCheck({evaluate, check}) {
 const result = await evaluate(`(() => {
  const visible = node => !!node && node.getClientRects().length > 0 && getComputedStyle(node).visibility === 'visible' && !node.closest('[hidden]') && [...function*(){for(let p=node.parentElement;p;p=p.parentElement)yield p;}()].every(p=>p.tagName!=='DETAILS'||p.open||p.querySelector('summary')?.contains(node));
  const ids = [...document.querySelectorAll('[id]')].map(n=>n.id);
  const dumps = [...document.body.querySelectorAll('*')].filter(n=>{
   if(n.closest('textarea, input, [data-command-output]'))return false;
   const text=[...n.childNodes].filter(n=>n.nodeType===Node.TEXT_NODE).map(n=>n.textContent).join('').trim();
   if(!text)return false;
   for(let i=0;i<text.length;i++) {
    if(!'[{'.includes(text[i]))continue;
    let candidate=text.slice(i).trim();
    if('.;'.includes(candidate.at(-1)))candidate=candidate.slice(0,-1).trim();
    try {const value=JSON.parse(candidate);if(value!==null&&typeof value==='object')return true;}catch{}
   }
   return false;
  });
  return {
   languageClear:(()=>{const body=document.body.cloneNode(true);body.querySelector('#tau-seed-backup-words')?.remove();return !/verified|no anomalies found|proven|formally verified|machine-checked/i.test(body.textContent);})(),
   headings:[...document.querySelectorAll('[data-step] > h2')].map(n=>n.textContent),
   statuses:[...document.querySelectorAll('[data-step] > .step-status')].map(n=>n.textContent),
   statusCounts:[...document.querySelectorAll('[data-step]')].map(n=>n.querySelectorAll(':scope > .step-status').length),
   statusesVisible:[...document.querySelectorAll('[data-step] > .step-status')].every(visible),
   creditStatusRole:document.querySelector('#tau-credit-status')?.getAttribute('role'),
   duplicateIds:ids.filter((id,i)=>ids.indexOf(id)!==i),
   rawOutside:dumps.filter(n=>!n.closest('details')||n.closest('details').querySelector('summary')?.textContent!=='Details').map(n=>n.textContent.slice(0,100)),
   lifecycle:document.querySelector('#tau-lifecycle-disclosure')?.textContent,
   lifecycleVisible:visible(document.querySelector('#tau-lifecycle-disclosure')),
   lifecycleBesideLock:document.querySelector('#tau-lock').hidden || document.querySelector('#tau-lifecycle-disclosure').previousElementSibling?.id==='tau-lifecycle-line',
   lockVisible:document.querySelector('#tau-lock').hidden||visible(document.querySelector('#tau-lock')),
   ends:[...document.querySelectorAll('[data-end-session]')].every(visible),
   disclosureBeforeStart:[...document.querySelectorAll('button')].filter(n=>n.textContent.startsWith('Start session ')).every(n=>{let p=n.previousElementSibling;return p?.hasAttribute('data-start-disclosure')&&visible(p)===visible(n)&&p.textContent===${JSON.stringify(lifecycleText)};}),
   pageWidth:document.documentElement.scrollWidth, viewport:document.documentElement.clientWidth,
   visibleErrors:[...document.querySelectorAll('.step-error')].filter(n=>n.textContent).every(visible),
   mainOffered:[...document.querySelectorAll('[data-step]')].map(n=>[...n.querySelectorAll('button')].some(n=>!n.closest('[hidden]'))),
   mainCounts:[...document.querySelectorAll('[data-step]')].map(n=>n.querySelectorAll('button.main-action').length),
  };
 })()`);
 check(result.languageClear,'page text contains no reserved claims');
 assert.deepEqual(result.headings, ['1 Local store', '2 Inference credit', '3 Machine', '4 Task']);
 check(result.statuses.every(Boolean), 'each step has a status');
 assert.deepEqual(result.statusCounts,[1,1,1,1],'each step has exactly one status line');
 assert.equal(result.creditStatusRole,'status','original credit status role stays intact');
 check(result.statusesVisible,'step status lines stay visible outside folds');
 assert.deepEqual(result.duplicateIds, [], 'no duplicate ids');
 assert.deepEqual(result.rawOutside, [], 'raw JSON stays inside Details');
 assert.equal(result.lifecycle, lifecycleText, 'standing lifecycle wording');
 check(result.lifecycleVisible && result.lifecycleBesideLock && result.lockVisible && result.ends, 'lifecycle disclosure, Lock and End stay outside closed folds');
 check(result.disclosureBeforeStart, 'exact lifecycle disclosure before each Start session');
 check(result.pageWidth <= result.viewport, `phone has no horizontal document scroll (${result.pageWidth}/${result.viewport} CSS px)`);
 assert.deepEqual(result.mainCounts,result.mainOffered.map(Boolean).map(n=>n?1:0),'one emphasized existing action in each step with an offered action');
 check(result.visibleErrors,'step errors stay visible outside closed folds');
 await controlAudit({evaluate});
}

export async function phoneSnapshot(c, state) {
 await presentationCheck(c);
 const directory = process.env.TAU_LAYOUT_SCREENSHOTS;
 if (!directory) return;
 await mkdir(directory, {recursive:true});
 const metrics=await c.call('Page.getLayoutMetrics',{},c.sessionId);
 const {data} = await c.call('Page.captureScreenshot', {format:'png',captureBeyondViewport:true,clip:{x:0,y:0,width:await c.evaluate('innerWidth'),height:metrics.cssContentSize.height,scale:1}}, c.sessionId);
 const path = join(directory, `${c.name}-${state}.png`);
 await writeFile(path, Buffer.from(data, 'base64'));
 console.log(JSON.stringify({screenshot:path,state,viewport:await c.evaluate('({width:innerWidth,height:innerHeight})')}));
}

export async function layoutObserver(c, state) {
 if(state==='delivery') await deliveryLayout(c);
 if (state==='none') {
  const baseline=JSON.parse(await readFile(new URL('./layout-controls.json',import.meta.url)));
  const actual=await c.evaluate("Object.fromEntries([...document.querySelectorAll('[id]')].map(n=>[n.id,n.tagName.toLowerCase()]))");
  for(const [id,role] of Object.entries(baseline.controls)) assert.equal(actual[id],role,`baseline control ${id}`);
  assert.deepEqual(await c.evaluate("[...document.querySelectorAll('[data-step] > details[id^=\"tau-step-\"]')].map(n=>n.open)"),[true,false,false,false]);
  const source=await readFile(new URL('../www/index.html',import.meta.url),'utf8');
  assert.equal(source.match(/<meta http-equiv="Content-Security-Policy"[^>]*>/)[0],baseline.csp,'CSP unchanged');
  assert.equal(source.match(/<p>Use a dedicated, already[^<]+<\/p>/)[0],baseline.providerParagraph,'provider paragraph changes only one word');
  assert.equal((source.match(/<style>/g)||[]).length,1,'one inline style');
  assert.ok(source.indexOf('</style>')<source.indexOf('</head>'),'style stays in head');
 }
 if(state==='unlocked') {
  const later = await c.evaluate(`(() => {
   const visible=${visibleSource}, fold=document.querySelector('#tau-step-machine-fold');
   const prose=[...document.querySelectorAll('[data-step="machine"] p')].filter(n=>n.textContent.startsWith('Use a dedicated, already')||n.textContent.startsWith('The published pin comes')||n.textContent.startsWith('App Lock, reload and worker loss'));
   const action=document.querySelector('#tau-provider-key-form');
   return {creditCurrent:document.querySelector('[data-step="credit"]').dataset.current,open:fold.open,
    ordinary:prose.map(n=>({inFold:fold.contains(n),visible:visible(n)})),
    actionVisible:visible(action)&&visible(action.querySelector('button')),actionOutside:!fold.contains(action)};
  })()`);
  assert.equal(later.creditCurrent,'true','credit is current before inference configuration');
  assert.equal(later.open,false,'Machine starts folded while credit is current');
  assert.deepEqual(later.ordinary,Array(3).fill({inFold:true,visible:false}),'ordinary Machine prose actually folds');
  c.check(later.actionVisible&&later.actionOutside,'later Machine main action remains visible outside its ordinary fold');
  await phonePair(c,'later-machine-folded');
  const routes=await c.workerEvaluate(`(async()=>{
   const m=await import(new URL('./pkg/tau_web.js',location.href));const result=[];
   for(const step of ['store','credit','machine','task','invalid']){
    const report=JSON.parse(await m.open());report.error='Display fixture failure.';report.page_error_step=step;
    const value=JSON.parse(await m.protect_publication(m.publication_generation(),'',JSON.stringify(report)));
    result.push(value.page_error_step);
   }
   return result;
  })()`);
  assert.deepEqual(routes,['store','credit','machine','task','store'],'publication carries only fixed presentation routes');
  const before=await c.evaluate('fixtureReports.length');
  await c.click('#tau-step-machine-fold > summary');
  c.check(await c.evaluate(`(() => {const visible=${visibleSource};return [...document.querySelectorAll('#tau-step-machine-fold p')].filter(n=>n.textContent.startsWith('Use a dedicated, already')||n.textContent.startsWith('The published pin comes')||n.textContent.startsWith('App Lock, reload and worker loss')).every(visible);})()`),'opening Machine reveals its ordinary body');
  await c.invoke(()=>{document.querySelector('#tau-provider-machine').value='draft machine';document.querySelector('#tau-poc-endpoint').value='https://example.invalid/completions';});
  await c.message({lifecycle:'hidden'});await c.message({lifecycle:'visible'});
  await c.wait(`fixtureReports.length>${before}`);
  c.check(await c.evaluate("document.querySelector('#tau-step-machine-fold').open && document.querySelector('#tau-provider-machine').value==='draft machine' && document.querySelector('#tau-poc-endpoint').value==='https://example.invalid/completions'"),'manual fold and form drafts survive lifecycle reports');
  await phonePair(c,'later-machine-open');
  const beforeToggle=await c.evaluate('fixtureReports.length');
  await c.click('#tau-step-machine-fold > summary');
  await c.evaluate('new Promise(resolve=>setTimeout(resolve,100))');
  assert.equal(await c.evaluate('fixtureReports.length'),beforeToggle,'folding sends no action');
  await c.message({poc_public_keys:{machine:'missing'}});
  const refusal=await c.wait('fixtureReports.at(-1)?.poc_keys?.refused');
  c.check(await c.invoke(refusal=>document.querySelector('#tau-step-task-error').innerText.includes(refusal)&&!document.querySelector('#tau-step-task-error').closest('details:not([open])'),refusal),'public-key refusal stays outside the closed Task fold');
  // A real rejected configuration reports through the production handler.
  await c.invoke(()=>{document.querySelector('#tau-poc-endpoint').value='http://invalid.example/';document.querySelector('#tau-poc-key').value='synthetic-entry';document.querySelector('#tau-poc-inference-form').requestSubmit();});
  await c.wait('fixtureReports.at(-1)?.store_error');
  c.check(await c.evaluate("document.querySelector('#tau-step-credit-error').textContent===fixtureReports.at(-1).store_error && !document.querySelector('#tau-store-state').textContent.includes(fixtureReports.at(-1).store_error)"),'configuration failure appears at Inference credit');
 }
 if(state==='before-start') {
  assert.equal(await c.evaluate("document.querySelector('#tau-step-task-fold').open"),true,'new current step opens');
 }
 if(state==='session') {
  await c.invoke(()=>{document.querySelector('[data-goal-text]').value='Draft goal';document.querySelector('[data-document-source]').value='https://example.invalid/goal';});
  const n=await c.evaluate('fixtureReports.length');await c.message({lifecycle:'hidden'});await c.message({lifecycle:'visible'});await c.wait(`fixtureReports.length>${n}`);
  c.check(await c.evaluate("document.querySelector('[data-goal-text]').value==='Draft goal' && document.querySelector('[data-document-source]').value==='https://example.invalid/goal'"),'goal and document drafts survive ordinary reports');
  c.check(await c.evaluate("document.querySelector('[data-goal-enter]')?.tagName==='BUTTON' && document.querySelector('[data-goal-text]')?.tagName==='TEXTAREA' && document.querySelector('[data-document-source]')?.tagName==='INPUT'"),'goal controls retain their roles');
  c.check(await c.evaluate("document.querySelector('[data-goal-enter]').classList.contains('main-action')"),'Set goal is emphasized before End');
 }
 if(state==='requirements') {
  const draft=await c.evaluate("document.querySelector('[data-poc-declaration]').value+'  '");
  await c.invoke(draft=>{const input=document.querySelector('[data-poc-declaration]');input.value=draft;input.dispatchEvent(new Event('input',{bubbles:true}));},draft);
  const n=await c.evaluate('fixtureReports.length');await c.message({lifecycle:'hidden'});await c.message({lifecycle:'visible'});await c.wait(`fixtureReports.length>${n}`);
  assert.equal(await c.evaluate("document.querySelector('[data-poc-declaration]').value"),draft,'declaration draft survives ordinary reports');
  c.check(await c.evaluate("['approve','reject'].every(value=>document.querySelector('[data-requirements-decision='+value+']')?.tagName==='BUTTON') && document.querySelector('[data-poc-propose]')?.tagName==='BUTTON' && document.querySelector('[data-poc-declaration]')?.tagName==='TEXTAREA'"),'requirements and declaration controls retain their roles');
  c.check(await c.evaluate("document.querySelector('[data-requirements-decision=approve]').classList.contains('main-action')"),'requirements approval is emphasized before Resume and End');
 }
 if(state==='running') {
  await retainDetails(c,'[data-task] details');
  await toggleWithoutAction(c,'[data-step] > details[id^="tau-step-"]',true);
  await toggleWithoutAction(c,'[data-step] > details[id^="tau-step-"]',false);
  c.check(await c.evaluate("[...document.querySelectorAll('[data-end-session]')].length>0"),'running session offers End outside all closed folds');
  c.check(await c.evaluate("[...document.querySelectorAll('[data-task] button')].some(n=>n.textContent==='Resume'&&n.classList.contains('main-action'))"),'Resume is emphasized before End');
  c.check(await c.evaluate("document.querySelector('[aria-label=\"Task request limit\"]')?.max==='1000' && document.querySelector('[aria-label=\"Task step limit\"]')?.max==='2000' && [...document.querySelectorAll('[data-task] button')].some(n=>n.textContent==='Raise limits')"),'task budget controls retain their roles and bounds');
  const limits=await c.evaluate('JSON.stringify(fixtureReports.at(-1).tasks[0].limits)');
  const drafts=await c.invoke(()=>['Task request limit','Task step limit'].map(label=>{const input=document.querySelector(`[aria-label="${label}"]`);input.value=String(Number(input.min)+1);return input.value;}));
  const n=await c.evaluate('fixtureReports.length');await c.message({lifecycle:'hidden'});await c.message({lifecycle:'visible'});await c.wait(`fixtureReports.length>${n}`);
  assert.deepEqual(await c.evaluate("['Task request limit','Task step limit'].map(label=>document.querySelector('[aria-label=\"'+label+'\"]').value)"),drafts,'budget drafts survive ordinary reports');
  assert.equal(await c.evaluate('JSON.stringify(fixtureReports.at(-1).tasks[0].limits)'),limits,'draft edits do not raise task budgets');
 }
 await phoneSnapshot(c,state);
 await c.call('Emulation.setDeviceMetricsOverride',{width:360,height:844,deviceScaleFactor:1,mobile:true},c.sessionId);
 await phoneSnapshot(c,state+'-360');
 await c.call('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true},c.sessionId);
}

export async function purchaseSnapshot(c, report, state) {
 if(report.procurement?.selection) {
  const selectionText=await c.evaluate("document.querySelector('#tau-provider-selection-view [data-raw-json]').textContent");
  const previous=await c.evaluate('window.layoutPreviousSelection ?? null');
  if(previous!==null&&previous!==selectionText)assert.equal(await c.evaluate("document.querySelector('#tau-provider-selection-view details').open"),false,'changed purchase review does not inherit another snapshot’s open choice');
  await retainDetails(c,'#tau-provider-selection-view details');
  // Leave this review open so a later, different review must start closed.
  await c.evaluate(`window.layoutPreviousSelection=${JSON.stringify(selectionText)};document.querySelector('#tau-provider-selection-view details > summary').click()`);
  const baseline=JSON.parse(await readFile(new URL('./layout-controls.json',import.meta.url)));
  for(const [id,text] of Object.entries(baseline.checkboxTerms).filter(([id])=>id.startsWith('tau-provider-'))){
   assert.equal(await c.evaluate(`document.getElementById(${JSON.stringify(id)}).closest('label').innerText.trim()`),text,'exact visible approval checkbox terms');
  }
  const question='Will this machine serve people you have never met? If unsure, choose Not sure.';
  c.check(await c.evaluate(`document.querySelector('#tau-provider-approval-form').innerText.includes(${JSON.stringify(question)})`),'class question stays visible at approval');
  assert.deepEqual(await c.evaluate("[...document.querySelector('#tau-provider-class').options].map(n=>[n.value,n.textContent])"),[['','Choose an answer'],['yes','Yes'],['no','No, only me and people I know'],['not_sure','Not sure']],'all class answers remain available');
  if(!report.procurement.phase)assert.equal(await c.evaluate("document.querySelector('#tau-provider-class').value"),'','nothing preselected at first approval');
  if(report.procurement.relay && await c.evaluate("!document.querySelector('#tau-provider-approval-form button').disabled || document.querySelector('#tau-provider-relay').value!==''"))assert.equal(await c.evaluate("document.querySelector('#tau-provider-relay').value"),report.procurement.relay,'recorded relay stays at approval');
  const review = await c.evaluate(`(() => {
   const root=document.querySelector('#tau-provider-selection-view');
   const flatten=(list,path=[])=>[...list.children].flatMap((node,i,all)=>{
    if(node.tagName!=='DT')return [];
    const key=[...path,node.textContent],value=all[i+1];
    return value.firstElementChild?.tagName==='DL'?flatten(value.firstElementChild,key):[[key.join('.'),value.textContent]];
   });
   const outside=root.closest('details:not([open])')===null;
   return {facts:root.querySelector('dl')?flatten(root.querySelector('dl')):[],outside,raw:JSON.parse(root.querySelector('[data-raw-json]').textContent)};
  })()`);
  const flatten=(object,path=[])=>Object.entries(object).flatMap(([key,value])=>{
   const p=[...path,key.replaceAll('_',' ')];
   return value!==null&&typeof value==='object'&&Object.keys(value).length?flatten(value,p):[[p.join('.'),value===null?'None':typeof value==='object'?(Array.isArray(value)?'Empty list':key==='limits'?'No caps (empty limits)':'Empty set'):String(value)]];
  });
  assert.deepEqual(review.facts,flatten(report.procurement.selection),'readable purchase facts exactly match the recorded snapshot');
  assert.deepEqual(review.raw,report.procurement.selection,'Details retains that same snapshot');
  c.check(review.outside,'purchase facts stay visible outside closed folds');
  c.check(await c.evaluate("!document.querySelector('#tau-provider-approval-form').closest('details:not([open])')"),'approval terms stay beside the visible snapshot');
 }
 if(report.procurement?.billing){
  const b=report.procurement.billing,q=b.terms;
  const quote=`Initial Lightning quote for VM ${b.vm_id}: amount ${q.amount}, tax ${q.tax}, processing fee ${q.processing_fee} (${q.currency==='BTC'?'millisats':q.currency+' cents'}); ${q.time} seconds for one approved billing period. Review these exact terms before issuing. Refresh may update this quote before issuance.`;
  c.check(await c.evaluate(`document.querySelector('#tau-provider-progress').innerText.includes(${JSON.stringify(quote)})`),'exact invoice approval quote remains visible');
 }
 if(report.procurement?.payment){
  c.check(await c.evaluate("document.querySelector('#tau-provider-progress a[href^=\"lightning:\"]')?.textContent==='Open in wallet' && [...document.querySelectorAll('#tau-provider-progress button')].some(n=>n.textContent==='Copy') && document.querySelector('#tau-provider-progress [data-invoice-expires]')"),'invoice wallet, copy and time controls remain present');
 }
 await phoneSnapshot(c,state);
 await c.call('Emulation.setDeviceMetricsOverride',{width:360,height:844,deviceScaleFactor:1,mobile:true},c.sessionId);
 await phoneSnapshot(c,state+'-360');
 await c.call('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true},c.sessionId);
}

export async function fixtureLayout(c) {
 await c.call('Page.navigate',{url:c.pageOrigin+'/'},c.sessionId);
 await c.wait("document.querySelector('#tau-store')?.dataset.state==='none'");
 await c.invoke(()=>{document.querySelector('#tau-passphrase').value=document.querySelector('#tau-confirm').value='durable fixture passphrase';document.querySelector('#tau-create').click();});
 await c.wait("!document.querySelector('#tau-seed-backup-answer').disabled");
 await c.click('#tau-seed-backup-answer');await c.wait("!document.querySelector('#tau-seed-backup-skip').disabled");await c.click('#tau-seed-backup-skip');
 await c.wait("document.querySelector('#tau-setup-approve')");
 c.check(await c.evaluate("document.querySelector('#tau-setup-approve').tagName==='BUTTON'"),'fixture approval retains its id and button role');
 const approval=await c.evaluate(`(() => {
  const visible=${visibleSource}, root=document.querySelector('#tau-setup'), facts=document.querySelector('#tau-setup-facts'), button=document.querySelector('#tau-setup-approve');
  return {visible:visible(button)&&[...facts.querySelectorAll('p')].every(visible),paired:root.contains(facts)&&root.contains(button)&&!!(facts.compareDocumentPosition(button)&Node.DOCUMENT_POSITION_FOLLOWING),machine:root.closest('[data-step]').dataset.step,creditCurrent:document.querySelector('[data-step="credit"]').dataset.current,foldOpen:document.querySelector('#tau-step-machine-fold').open};
 })()`);
 assert.deepEqual(approval,{visible:true,paired:true,machine:'machine',creditCurrent:'true',foldOpen:false},'fixture price review and approval are visible together before approval');
 await phonePair(c,'fixture-pre-approval');
 await c.click('#tau-setup-approve');await c.wait("document.querySelectorAll('[data-class-answers]').length===2");
 c.check(await c.evaluate("[...document.querySelectorAll('[data-class-answers]')].every(group=>group.querySelectorAll('button[data-answer]').length===3)"),'all class answers stay available');
 const classes=await c.evaluate(`(() => {
  const visible=${visibleSource};return [...document.querySelectorAll('[data-class-answers]')].map(group=>{
   const card=group.closest('[data-machine]');return {question:[...card.querySelectorAll('p')].filter(n=>n.textContent.startsWith('Machine class for ')||n.textContent.startsWith('Will this machine serve')||n.textContent.startsWith('If you are not sure')).map(n=>({text:n.textContent,visible:visible(n)})),answers:[...group.querySelectorAll('button')].map(n=>({value:n.dataset.answer,text:n.textContent,visible:visible(n),disabled:n.disabled,selected:n.hasAttribute('aria-pressed')||n.hasAttribute('checked')}))};
  });
 })()`);
 for(const [index,card] of classes.entries()) {
  assert.deepEqual(card.question,[`Machine class for ${index===0?'fixture':'fixture-other'}.`,"Will this machine serve people you have never met, for example by renting out space on it or hosting other people's accounts?","If you are not sure, the machine is treated as serving people you have never met: it never holds spendable keys and is always bound alone."].map(text=>({text,visible:true})),'unanswered class question and help are rendered outside closed folds');
  assert.deepEqual(card.answers,[['yes','Yes'],['no','No, only me and people I know'],['not_sure','Not sure']].map(([value,text])=>({value,text,visible:true,disabled:false,selected:false})),'all exact class answers are visible with nothing preselected');
 }
 await phonePair(c,'fixture-unanswered-class');
 const deliveryNames=await c.evaluate(`(() => {
  const visible=${visibleSource};return [...document.querySelectorAll('[data-delivery-card]')].map(card=>({machine:card.dataset.deliveryCard,heading:card.querySelector('h3')?.textContent,visible:visible(card.querySelector('h3'))}));
 })()`);
 assert.deepEqual(deliveryNames,['fixture','fixture-other'].map(machine=>({machine,heading:'Delivery for '+machine,visible:true})),'each delivery card visibly names its machine');
 for(const machine of ['fixture','fixture-other']) {
  await c.click(`[data-machine="${machine}"] [data-answer="no"]`);
  await c.wait(`fixtureReports.at(-1)?.setup?.find(m=>m.entry.machine===${JSON.stringify(machine)})?.class`);
 }
 await c.wait("document.querySelector('[data-bind=fixture]')");
 await phoneSnapshot(c,'fixture-before-start');
 await c.click('[data-bind=fixture]');await c.wait('fixtureReports.at(-1)?.sessions?.length===1');
 const session=await c.evaluate('fixtureReports.at(-1).sessions[0].identity');
 assert.equal(await c.workerEvaluate(`(async()=>{const m=await import(new URL('./pkg/tau_web.js',location.href));return m.test_inference_account(new TextEncoder().encode('synthetic-limit-entry'));})()`),true,'existing local limit fixture initialized');
 await c.message({lifecycle:'hidden'});await c.wait('fixtureReports.at(-1)?.sessions?.[0]?.inference_limits');
 const limits=await c.evaluate('fixtureReports.at(-1).sessions[0].inference_limits');
 const cap=BigInt(limits.confirmed.cap_hundredths);
 const lines=[`Confirmed limit: ${cap/100n}.${String(cap%100n).padStart(2,'0')} ${limits.confirmed.unit}; lifetime ${limits.confirmed.lifetime_seconds/60} minutes. No renewal; observed spend ${limits.observed_spend}. Unaccounted spend is not zero or refunded.`,limits.original_expiry?`Original requested expiry: ${new Date(limits.original_expiry*1000).toISOString()} (UTC). All delays and hidden or frozen time consume this lifetime.`:'Lifetime has not started.'];
 for(const text of lines)c.check(await c.invoke(text=>[...document.querySelectorAll('#tau-task-setup p')].some(n=>n.textContent===text&&n.getClientRects().length>0&&!n.closest('details:not([open])')),text),'exact noncredit limit qualification stays visible');
 await phoneSnapshot(c,'fixture-session');
 await c.workerEvaluate(`(async()=>{const m=await import(new URL('./pkg/tau_web.js',location.href));await m.test_session_transition(${JSON.stringify(session)},'uncertain');return true;})()`);
 await c.message({lifecycle:'hidden'});await c.wait("fixtureReports.at(-1)?.sessions?.[0]?.inference_limits?.state==='clock-withheld'");
 c.check(await c.evaluate("document.querySelector('#tau-task-setup').innerText.includes('Clock validity unknown; verification required. The original expiry has not changed.') && document.querySelector('[data-verify-clock]')?.tagName==='BUTTON'"),'clock warning and verification control stay visible');
 await phoneSnapshot(c,'fixture-clock');
 await c.message({lifecycle:'freeze'});await c.wait("fixtureReports.at(-1)?.lifecycle_state==='reconciling'");
 await phoneSnapshot(c,'fixture-reconciling');
 await c.message({lifecycle:'resume'});await c.wait("fixtureReports.at(-1)?.lifecycle_state==='running'");
 await c.click('[data-end-session]');await c.wait("fixtureReports.at(-1)?.sessions?.[0]?.session_state==='ended'");
 await phoneSnapshot(c,'fixture-ended');
}

export async function publicKeysLayout(c) {
 await c.call('Page.navigate',{url:c.pageOrigin+'/'},c.sessionId);
 await c.wait("document.querySelector('#tau-store')?.dataset.state==='none'");
 await c.invoke(()=>{document.querySelector('#tau-passphrase').value=document.querySelector('#tau-confirm').value='durable fixture passphrase';document.querySelector('#tau-create').click();});
 await c.wait("!document.querySelector('#tau-seed-backup-answer').disabled");
 await c.click('#tau-seed-backup-answer');await c.wait("!document.querySelector('#tau-seed-backup-skip').disabled");await c.click('#tau-seed-backup-skip');
 await c.wait("!document.querySelector('#tau-poc-target-form button').disabled");
 await c.invoke(info=>{
  for(const [id,value]of Object.entries({machine:'machine-a',relay:info.relay,profile:'v1',host:'127.0.0.1',port:info.port,user:'tracer',elevation:'none',pin:info.pin,class:'no'}))document.querySelector('#tau-poc-'+id).value=value;
  document.querySelector('#tau-poc-approve-existing').checked=document.querySelector('#tau-poc-approve-access').checked=true;
  document.querySelector('#tau-poc-target-form').requestSubmit();
 },c.info);
 await c.wait('fixtureReports.at(-1)?.poc_targets?.length===1');
 await observeSends(c);
 try {
  await c.invoke(()=>[...document.querySelectorAll('#tau-poc-targets button')].find(n=>n.textContent==='Show public keys machine-a').click());
  await c.wait("fixtureReports.at(-1)?.poc_keys?.machine==='machine-a'");
  assert.equal(await c.evaluate('layoutFoldMessages'),1,'positive control detects actual captured-handler public-key request');
 } finally { await c.evaluate('layoutRestoreMessages()'); }
 const result=await c.evaluate(`(() => {
  const visible=${visibleSource},slot=document.querySelector('#tau-poc-public-keys');
  return {creditCurrent:document.querySelector('[data-step="credit"]').dataset.current,taskOpen:document.querySelector('#tau-step-task-fold').open,nodes:[...slot.children].map(n=>({tag:n.tagName,visible:visible(n)})),text:slot.innerText};
 })()`);
 assert.equal(result.creditCurrent,'true');assert.equal(result.taskOpen,false,'successful result preserves closed Task choice');
 assert.deepEqual(result.nodes,['P','P','P','PRE','BUTTON','P','PRE','BUTTON'].map(tag=>({tag,visible:true})),'all eight public-key result nodes are visible beside the action');
 assert.ok(result.text.includes('Registering the machine SSH public key with the provider does not enroll the relay. Copy the separate relay public key and ask your relay operator to enroll it before configuration.'));
 await toggleWithoutAction(c,'#tau-step-task-fold',true);
 await toggleWithoutAction(c,'#tau-step-task-fold',false);
 await phonePair(c,'keys-credit-current-task-closed');
}

export async function deliveryLayout(c) {
 await retainDetails(c,'[data-task] details');
 await interruptionDetails(c,'[data-task] details');
 const session=await c.evaluate('fixtureReports.at(-1).sessions.find(s=>s.session_state!=="ended").identity');
 const machine='machine-a';
 const measured=value=>({read:'value',value});
 const clean={inbound:measured([{proto:'tcp',port:22,from:'any'}]),outbound:measured([]),services:measured([]),spendable:measured(false),permitted:measured([]),required:measured([]),credentials:measured([]),fixed_default_credentials:measured(true),sshd_posture:measured(true),placing_session:false};
 const act=async request=>{const n=await c.evaluate('fixtureReports.length');await c.message({delivery:{session,machine,...request}});await c.wait(`fixtureReports.length>${n}`);assert.ok(!await c.evaluate('fixtureReports.at(-1).store_error'),'delivery fixture action accepted');};
 const inject=async value=>c.workerEvaluate(`(async()=>{const m=await import('./pkg/tau_web.js');await m.test_delivery_fixture(${JSON.stringify(session)},${JSON.stringify(machine)},${JSON.stringify(JSON.stringify(value))});return true;})()`);
 await inject(clean);await act({action:'check'});
 await act({action:'application',name:'Example application'});
 const baseline=JSON.parse(await readFile(new URL('./layout-controls.json',import.meta.url)));
 const exact=[baseline.fixtureLimit,"Delivered covers the declared machine state and the fixed lockdown checks.","Example application is an AI that acts on this server by itself. tau-web's promises cover what tau-web's AI does, not what Example application does.","It does not mean Example application works","Checks the AI wrote — not part of Delivered"];
 const visibleText=()=>c.evaluate("document.querySelector('[data-delivery-card=\"machine-a\"]').innerText");
 c.check(await c.evaluate("document.querySelectorAll('[data-delivery-card=\"machine-a\"] details > pre[data-raw-json]').length>0"),'recorded reports remain present inside Details');
 let text=await visibleText();for(const sentence of exact)assert.ok(text.includes(sentence),`delivery qualification: ${sentence}`);
 await retainDetails(c,'[data-delivery-card="machine-a"] details');
 await phoneSnapshot(c,'delivery');
 // Opening raw reports changes presentation only, and long command history remains contained.
 await c.invoke(()=>{for(const n of document.querySelectorAll('[data-raw-json]'))n.closest('details').open=true;});
 await c.call('Emulation.setDeviceMetricsOverride',{width:360,height:844,deviceScaleFactor:1,mobile:true},c.sessionId);
 await phoneSnapshot(c,'delivery-details-360');
 await inject({...clean,sshd_posture:{read:'missing'}});await act({action:'check'});
 await retainDetails(c,'[data-delivery-measurements="machine-a"]');
 text=await visibleText();assert.ok(text.includes('Latest attempt incomplete; no final demonstration recorded.')&&text.includes('The last completed result is historical; a final demonstration is still needed.'),'incomplete and historical qualifications');
 await phoneSnapshot(c,'delivery-incomplete');
 let service={name:'sample',scope:{kind:'system'},lifecycle:'enabled-survives-reboot'};
 const declaration={version:2,listeners:{inbound:[{proto:'tcp',port:22,from:'any'}],outbound:[]},services:[service],key_material:{spendable:false,permitted:[]},drift_checks:[],required:[],default_credentials:'none'};
 const propose=async d=>{
  await c.invoke(d=>{const input=document.querySelector('[data-poc-declaration]');input.value=JSON.stringify(d);input.dispatchEvent(new Event('input',{bubbles:true}));document.querySelector('[data-poc-propose]').click();},d);
  await c.wait("document.querySelector('[data-requirements-decision=approve]')");
  await c.click('[data-requirements-decision=approve]');await c.wait("!document.querySelector('[data-requirements-decision=approve]')");
 };
 await propose(declaration);
 assert.ok((await visibleText()).includes('The current declaration needs a re-check; the completed check used earlier values.'),'outdated declaration qualification');
 for(const [state,note,lifecycle] of [['enabled_restart_not_demonstrated','enabled, restart not demonstrated','enabled-survives-reboot'],['stopped_since_restart','stopped since a restart, as approved','running-at-delivery']]) {
  if(service.lifecycle!==lifecycle){service={...service,lifecycle};declaration.services=[service];await propose(declaration);}
  await inject({...clean,services:measured([{service,state,running_after_last_placement:false}])});await act({action:'check'});
  assert.ok((await visibleText()).includes(note),'lifecycle evidence label '+note);
  await phoneSnapshot(c,'delivery-'+state);
 }
 await inject({...clean,sshd_posture:measured(false),services:measured([{service,state:'running',running_after_last_placement:true}])});await act({action:'check'});
 assert.ok((await visibleText()).includes('handed over with findings'),'findings never receive a successful delivery label');
 c.check(await c.evaluate("[...document.querySelectorAll('[data-delivery-card] [data-raw-json]')].every(n=>!n.closest('.success,.passed,[data-success]'))"),'reports receive no success treatment');
 await phoneSnapshot(c,'delivery-findings');
 await c.call('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true},c.sessionId);
}
