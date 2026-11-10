import assert from 'node:assert/strict';
export const creditCases = ['credit-funding','credit-expiry','credit-failures','credit-key','credit-lock','credit-reload','credit-loss','credit-defaults','credit-defaults-invalid','credit-defaults-missing','credit-control-account','credit-control-key','credit-control-name','credit-lifecycle','credit-refusals','credit-account-write','credit-double-press','credit-late-lock','credit-late-end','credit-poll-bounds','credit-defaults-directory','credit-defaults-late','credit-mint-pause','credit-existing-balance','credit-defaults-urls','credit-new-balance-failure','credit-resolved-history','credit-goal-drafts','credit-refresh-contention','credit-ensure-contention','credit-balance-loss-refresh','credit-balance-loss-mint',...['collection','verification'].flatMap(phase=>['refused','lost','wrong-cap'].map(mode=>`credit-mint-${phase}-${mode}`))];
export const creditId = 'synthetic-credit-identity-482700';
export const defaultKey = 'synthetic-default-credential-482700';
export function fixtureCredit() {
 const state={balance:0,accountCalls:0,invoiceCalls:0,statusCalls:0,mintCalls:0,listCalls:0,deletes:[],requests:[],invoices:[],keys:[],status:'New',amountPaid:0,mode:'normal',mintMode:'normal',delay:0,onMint:null,orderingFailures:[],defaultsPaths:[],releaseDefaults:null};
 const handler=async(req,res,path)=>{
  if(!path.startsWith('/credit/'))return false;
  const chunks=[];for await(const chunk of req)chunks.push(chunk);
  const raw=Buffer.concat(chunks).toString(),body=raw?JSON.parse(raw):null;
  const route=path.slice('/credit'.length),method=req.method;
  const evidence=req.headers['x-fixture-credit-evidence']?JSON.parse(req.headers['x-fixture-credit-evidence']):null;
  state.requests.push({route,method,evidence,at:Date.now()});
  res.setHeader('Content-Type','application/json');
  const answer=(code,value)=>res.writeHead(code).end(JSON.stringify(value));
  if(route==='/accounts/create'){
   assert.equal(method,'POST');assert.equal(raw,'');assert.equal(req.headers.authorization,undefined);state.accountCalls++;
   if(state.mode==='account-fail'){answer(503,{error:'private-prefix'});return true;}
   if(state.mode==='account-lost'){res.destroy();return true;}
   if(state.delay)await new Promise(resolve=>setTimeout(resolve,state.delay));
   answer(201,{success:true,credit_id:creditId,api_key:defaultKey,balance:0});return true;
  }
  if(route==='/credits/balance'){
   assert.equal(method,'POST');assert.deepEqual(body,{credit_id:creditId});
   if(state.onBalance)await state.onBalance();
   if(state.mode==='balance-lost'){res.destroy();return true;}
   if(state.mode==='balance-badbody'){res.writeHead(200).end('{');return true;}
   if(state.mode==='balance-fail')answer(503,{error:'private-prefix'});else answer(200,{balance:state.balance});return true;
  }
  if(route.startsWith('/topup/'))assert.equal(req.headers.authorization,'Bearer '+defaultKey);
  else assert.equal(req.headers['x-credit-id'],creditId);
  if(route==='/topup/create/btc-lightning'){
   assert.equal(method,'POST');state.invoiceCalls++;assert.equal(body.currency,'SATS');
   assert.equal(evidence?.account_records,1,'account record committed before invoice dispatch');
   assert.equal(evidence?.account_contains,true,'account pair is already readable before invoice dispatch');
   if(state.mode==='invoice-lost'){res.destroy();return true;}
   if(state.mode==='invoice-fail'){answer(503,{error:'private-prefix'});return true;}
   const invoice={invoice_id:'invoice-'+state.invoiceCalls,amount:body.amount,currency:'SATS',created_at:Math.floor(Date.now()/1000),expires_at:Math.floor(Date.now()/1000)+(state.mode==='past-expiry'?-1:120),lightning_invoice:'lnbc1000synthetic'+state.invoiceCalls,checkout_url:'https://checkout.example/unused'};
   if(state.mode==='invoice-invalid')invoice.lightning_invoice='LNBC1000invalid';
   state.invoices.push(invoice);answer(201,invoice);return true;
  }
  if(route.startsWith('/topup/status/')){
   assert.equal(method,'GET');state.statusCalls++;
   if(state.mode==='status-fail'){answer(503,{error:'private-prefix'});return true;}
   const invoice=state.invoices.find(i=>route.endsWith('/'+i.invoice_id));assert.ok(invoice);
   const value={...invoice,status:state.status,amount_paid:state.amountPaid,amount_due:0.00001,payment_method:'btc-lightning'};
   if(state.mode==='mismatch')value.invoice_id='unrelated-invoice';
   if(state.mode==='missing-paid')delete value.amount_paid;
   if(state.mode==='malformed-paid')value.amount_paid='0';
   answer(200,value);return true;
  }
  if(route==='/keys?include_disabled=true'){
   assert.equal(method,'GET');state.listCalls++;answer(200,{status:'success',data:state.keys.map(({api_key,...publicFields})=>publicFields)});return true;
  }
  if(route.startsWith('/keys/')){
   assert.equal(method,'DELETE');state.deletes.push(route.slice(6));
   const key=state.keys.find(k=>k._id===route.slice(6));if(key)key.deleted_at='2026-11-10T00:00:00Z';
   answer(state.mintMode==='revoke-fail'?503:200,{status:'success',message:'Key deleted'});return true;
  }
  if(route==='/keys'){
   assert.equal(method,'POST');state.mintCalls++;
   if(!evidence?.mint_names?.includes(body.name))state.orderingFailures.push('mint name was not committed before request');
   assert.equal(body.usage_limit_usd,0.25);assert.equal(body.name.length,25);
   assert.ok(Math.abs(Date.parse(body.expire_at)-Date.now()-86400000)<5000);
   if(state.mintMode==='refused'){answer(403,{error:'private-prefix'});return true;}
   const key={_id:'key-'+state.mintCalls,name:body.name,api_key:'synthetic-session-credential-'+state.mintCalls+'-482700',created_at:new Date().toISOString(),usage_limit_usd:0.25,reset_period:null,expire_at:body.expire_at,deleted_at:null};
   state.keys.push(key);
   if(state.onMint)await state.onMint(key);
   if(state.mintMode==='lost'){res.writeHead(201);res.write('{"status":');await new Promise(r=>setTimeout(r,25));res.destroy();return true;}
   if(state.mintMode==='wrong-cap')key.usage_limit_usd=0.5;
   if(state.mintMode==='wrong-expiry')key.expire_at=new Date(Date.parse(key.expire_at)+61000).toISOString();
   if(state.mintMode==='reset')key.reset_period='daily';
   if(state.mintMode==='missing-cap')delete key.usage_limit_usd;
   if(state.delay)await new Promise(resolve=>setTimeout(resolve,state.delay));
   answer(201,{status:'success',data:key});return true;
  }
  throw Error('unexpected credit fixture request '+method+' '+route);
 };
 return {state,handler};
}

export async function creditProof(c) {
 const {name,info,call,sessionId,evaluate,workerEvaluate,invoke,wait,click,message,hold,point,release,check,control,pageOrigin,credit,inferenceEndpoint}=c;
 const state=credit.state;
 const report=()=>evaluate('fixtureReports.at(-1)');
 const request=async(action)=>{
  const count=await evaluate('fixtureEvents.filter(e=>e.fixture_credit_complete).length');await message({credit_request:action});
  await wait(`fixtureEvents.filter(e=>e.fixture_credit_complete).length>${count}`);return report();
 };
 const workerCall=async(method,value)=>workerEvaluate(`(async()=>{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);return JSON.parse(await m[${JSON.stringify(method)}](${JSON.stringify(value)}));})()`);
 const journal=needle=>workerCall('test_poc_journal',needle);
 const checked=async()=>{
  const before=state.statusCalls;await request({action:'check'});
 assert.ok(state.statusCalls>before || state.mode==='status-fail');return report();
 };
 await call('Page.navigate',{url:pageOrigin+(name==='credit-defaults-directory'?'/nested/index.html':'/')},sessionId);
 await wait("document.querySelector('#tau-store')?.dataset.state==='none'");
 if(name==='credit-defaults-late'){
  for(let n=0;n<100&&!state.releaseDefaults;n++)await new Promise(r=>setTimeout(r,5));assert.equal(typeof state.releaseDefaults,'function');
  await invoke(()=>{for(const [id,value]of [['provider-origin','https://edited.example'],['poc-model','edited-model'],['credit-amount','1400']]){const input=document.querySelector('#tau-'+id);input.value=value;input.dispatchEvent(new Event('input',{bubbles:true}));}});
  state.releaseDefaults();await wait("document.querySelector('#tau-defaults-status').textContent.includes('loaded')");
  assert.deepEqual(await evaluate("['provider-origin','poc-model','credit-amount'].map(k=>document.querySelector('#tau-'+k).value)"),['https://edited.example','edited-model','1400']);
  assert.equal(await evaluate("document.querySelector('#tau-poc-endpoint').value"),'https://credit.example/v1/chat/completions');
  check(true,'late defaults preserve edited fields while filling untouched public configuration');return;
 }
 if(name==='credit-defaults-urls'){
  const fields=['provider-origin','provider-relay','poc-relay','poc-endpoint','poc-model','credit-amount','poc-class','provider-class'];
  const read=()=>evaluate(`Object.fromEntries(${JSON.stringify(fields)}.map(k=>[k,document.querySelector('#tau-'+k).value]))`);
  const base={provider_origin:'https://provider.example',relay_url:'wss://relay.example/',chat_endpoint:'https://credit.example/v1/chat/completions',model:'example-model',topup_sat:1200};
  const fallback={'provider-origin':'https://api.lnvps.net','provider-relay':'','poc-relay':'','poc-endpoint':'','poc-model':'','credit-amount':'1000','poc-class':'','provider-class':''};
  const invalid={
   provider_origin:['https:provider.example','https:/provider.example','https:///provider.example','https:////provider.example','https://provider.example/extra/..','https://provider.example//','https://provider.example:','https://provider.example:65536','https://-provider.example','https://provider..example','https://127.1','https://provider.example/path'],
   relay_url:['wss:relay.example/','wss:/relay.example/','wss:///relay.example/','wss://relay.example/../','wss://relay.example/a/./','wss://relay.example','wss://relay.example:0/','wss://relay.example:65536/','wss://relay.example:/','wss://relay..example/','wss://relay.example/a!b/'],
   chat_endpoint:['https:credit.example/v1/chat/completions','https:/credit.example/v1/chat/completions','https:///credit.example/v1/chat/completions','https://credit.example:0/v1','https://credit.example:/v1','https://credit.example:65536/v1','https://credit..example/v1','https://xn--name.example/v1','https://127.1/v1','https://credit.example/a[b]']
  };
  const reload=async override=>{
   state.defaultsOverride=override;await call('Page.reload',{},sessionId);
   await wait("document.querySelector('#tau-defaults-status') && !document.querySelector('#tau-defaults-status').textContent.includes('Reading')");
  };
  for(const [field,values]of Object.entries(invalid))for(const value of values){
   await reload({[field]:value});assert.deepEqual(await read(),fallback,field+': '+value);
   assert.match(await evaluate("document.querySelector('#tau-defaults-status').textContent"),/missing or invalid/);
  }
  for(const override of [{},{provider_origin:'https://provider.example:8443/',relay_url:'wss://relay.example:8443/route_v1/sub-path/',chat_endpoint:"https://credit.example:8443/v1/chat_completions~!$&'()*+,;=:"},{provider_origin:'https://[::1]:8443/',relay_url:'wss://127.0.0.1/v1/',chat_endpoint:'https://127.0.0.1:8443/v1/chat/completions'}]){
   await reload(override);const expected={...base,...override};
   assert.deepEqual(await read(),{'provider-origin':expected.provider_origin,'provider-relay':expected.relay_url,'poc-relay':expected.relay_url,'poc-endpoint':expected.chat_endpoint,'poc-model':expected.model,'credit-amount':String(expected.topup_sat),'poc-class':'','provider-class':''});
   assert.match(await evaluate("document.querySelector('#tau-defaults-status').textContent"),/loaded/);
  }
  check(true,'the actual defaults loader refuses repaired URL spellings atomically and accepts supported paths');return;
 }
 if(name.startsWith('credit-defaults')){
  await wait("!document.querySelector('#tau-defaults-status').textContent.includes('Reading')");
  if(name==='credit-defaults-directory')assert.deepEqual(state.defaultsPaths,['/nested/poc-defaults.json']);
  const values=await evaluate("Object.fromEntries(['provider-origin','provider-relay','poc-relay','poc-endpoint','poc-model','credit-amount','poc-class','provider-class'].map(k=>[k,document.querySelector('#tau-'+k).value]))");
  if(name==='credit-defaults'||name==='credit-defaults-directory'){
   assert.equal(values['provider-origin'],'https://provider.example');assert.equal(values['provider-relay'],'wss://relay.example/');assert.equal(values['poc-endpoint'],'https://credit.example/v1/chat/completions');assert.equal(values['poc-model'],'example-model');assert.equal(values['credit-amount'],'1200');
  }else{assert.equal(values['provider-origin'],'https://api.lnvps.net');assert.equal(values['provider-relay'],'');assert.equal(values['poc-endpoint'],'');assert.equal(values['poc-model'],'');assert.equal(values['credit-amount'],'1000');}
  assert.equal(values['poc-class'],'');assert.equal(values['provider-class'],'');
  check(await evaluate("document.querySelector('#tau-defaults-status').textContent.includes('"+(['credit-defaults','credit-defaults-directory'].includes(name)?'loaded':'missing or invalid')+"')"),'defaults are one same-directory object with unchanged fallback and unanswered classes');
  return;
 }
 await invoke(()=>{document.querySelector('#tau-passphrase').value=document.querySelector('#tau-confirm').value='durable fixture passphrase';document.querySelector('#tau-create').click();});
 await wait("!document.querySelector('#tau-seed-backup-answer').disabled");await click('#tau-seed-backup-answer');await wait("!document.querySelector('#tau-seed-backup-skip').disabled");await click('#tau-seed-backup-skip');
 await wait("!document.querySelector('#tau-credit-invoice').disabled");
 check(await evaluate("document.querySelector('#tau-credit-status').textContent==='No inference credit yet.' && document.querySelector('#tau-credit').textContent.includes(\"If the store is lost, the credit is lost.\")"),'initial credit notice and range precede funding');
 if(name==='credit-account-write'){
  await workerEvaluate(`(async()=>{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);await m.test_seed_backup_fail_append();})()`);
  const r=await request({action:'invoice',amount:1000});assert.match(r.credit_error,/store write failed/);assert.equal(state.invoiceCalls,0);
  const accounts=state.accountCalls;await request({action:'invoice',amount:1000});assert.equal(state.accountCalls,accounts,'write hold prevents a second account dispatch');
  assert.equal(state.invoiceCalls,0);check(true,'failed account append withholds invoices and retains the write hold');return;
 }
 if(name==='credit-balance-loss-refresh'){
  state.mode='invoice-fail';await request({action:'invoice',amount:1000});
  assert.equal((await report()).credit.account,true);assert.equal((await report()).credit.invoices.length,0);
  for(const mode of ['balance-lost','balance-badbody']){
   state.mode='normal';state.balance=0.789;await request({action:'check'});
   assert.equal((await report()).credit.can_start,true);
   state.mode=mode;const failed=await request({action:'refresh'});
   assert.equal(failed.credit_error,"Couldn't read inference credit balance.");
   assert.equal(failed.credit.balance,null);assert.equal(failed.credit.can_start,false);
   assert.equal(failed.credit.invoices.length,0);assert.equal(state.accountCalls,1);assert.equal(state.invoiceCalls,1);
  }
  state.mode='normal';await request({action:'check'});assert.equal((await report()).credit.can_start,true);
  check(true,'lost or undecodable current balance reads clear cached credit on the same account without issuing an invoice');return;
 }
 if(name==='credit-double-press'){
  state.delay=250;
  await message({credit_request:{action:'invoice',amount:1000}});await message({credit_request:{action:'invoice',amount:1000}});
  await wait('fixtureReports.some(r=>r.credit_error?.includes("still in progress"))');
  await wait('fixtureReports.at(-1)?.credit?.invoices?.length===1');
  assert.equal(state.accountCalls,1);assert.equal(state.invoiceCalls,1);check(true,'duplicate funding presses share one serialized mutation');return;
 }
 if(name==='credit-failures'){
  for(const mode of ['account-fail','account-lost']){
   state.mode=mode;const r=await request({action:'invoice',amount:1000});assert.match(r.credit_error,/Couldn't create the credit account/);assert.equal(state.invoiceCalls,0);assert.equal((await journal(creditId)).account_records,0);
  }
  state.mode='balance-fail';await request({action:'invoice',amount:1000});assert.equal(state.invoiceCalls,0);assert.equal((await journal(creditId)).account_records,1);
  const accounts=state.accountCalls;
  for(const mode of ['invoice-fail','invoice-lost','invoice-invalid']){
   state.mode=mode;const r=await request({action:'invoice',amount:1000});assert.ok(r.credit_error);assert.equal(state.accountCalls,accounts);assert.equal(r.credit.invoices.length,0);assert.equal(await evaluate("document.querySelectorAll('#tau-credit-invoices a').length"),0);
  }
 }
 state.mode=name==='credit-expiry'?'past-expiry':'normal';
 await request({action:'invoice',amount:1000});
 await wait('fixtureReports.at(-1)?.credit?.invoices?.length===1');
 const idScan=await journal(creditId),keyScan=await journal(defaultKey);
 assert.equal(idScan.account_records,1);assert.equal(idScan.account_contains,true);assert.equal(idScan.contains,false);assert.equal(keyScan.account_contains,true);assert.equal(keyScan.contains,false);
 check(await evaluate("document.querySelector('#tau-credit-invoices a').getAttribute('href').startsWith('lightning:lnbc') && document.querySelector('#tau-credit-invoices').textContent.includes('1000 sat') && document.querySelector('#tau-credit-invoices [data-invoice-expires]').textContent.includes('minutes left')"),'saved invoice has amount, wallet link, Copy and countdown');
 if(name==='credit-new-balance-failure'){
  state.mode='balance-fail';await checked();
  assert.equal((await report()).credit.invoices[0].outcome,'unknown');
  assert.match(await evaluate("document.querySelector('#tau-credit-invoices').textContent"),/Payment status unknown\./);
  assert.equal(await evaluate("document.querySelector('#tau-credit-invoice').disabled"),true);
  assert.equal(await evaluate("document.querySelector('#tau-credit-check').disabled"),false);
  await request({action:'invoice',amount:1000});assert.equal(state.invoiceCalls,1);
  state.mode='normal';await checked();assert.equal((await report()).credit.invoices[0].outcome,'pending');
  assert.equal(state.invoiceCalls,1);check(true,'New requires a fresh balance read, retains manual checking and recovers without another invoice');return;
 }
 if(name==='credit-resolved-history'){
  for(const [status,amountPaid,balance,outcome] of [['Settled',0.00001,0.78,'paid'],['Expired',0.00001,0.9,'paid'],['Expired',0,0,'expired_unpaid']]){
   Object.assign(state,{status,amountPaid,balance,mode:'normal'});await checked();
   const index=(await report()).credit.invoices.length-1;
   assert.equal((await report()).credit.invoices[index].outcome,outcome);
   const historical=(await report()).credit.invoices[index];
   for(const [mode,balance]of [['status-fail',0.5],['balance-fail',0.5],['normal',0]]){
    Object.assign(state,{mode,balance,status:'Expired',amountPaid:0.00001});await checked();
    assert.deepEqual((await report()).credit.invoices[index],historical);
    assert.equal((await report()).credit.balance,mode==='balance-fail'?null:balance);
    assert.equal(await evaluate("document.querySelector('#tau-credit-invoice').disabled"),false);
    await message({lifecycle:'hidden'});const before=state.statusCalls;const completed=await evaluate('fixtureEvents.filter(e=>e.fixture_lifecycle_complete==="visible").length');await message({lifecycle:'visible'});
    await wait(`fixtureEvents.filter(e=>e.fixture_lifecycle_complete==='visible').length>${completed}`);
    for(let n=0;n<100&&state.statusCalls===before;n++)await new Promise(r=>setTimeout(r,10));assert.ok(state.statusCalls>before);
    assert.deepEqual((await workerCall('open','')).credit.invoices[index],historical);
    await call('Page.reload',{},sessionId);await wait("document.querySelector('#tau-store')?.dataset.state==='locked'");
    await invoke(()=>{document.querySelector('#tau-passphrase').value='durable fixture passphrase';document.querySelector('#tau-unlock').click();});
    await wait('fixtureEvents.some(e=>e.fixture_unlock_complete)');
    assert.deepEqual((await report()).credit.invoices[index],historical);
    assert.equal((await report()).credit.balance,mode==='balance-fail'?null:balance);
   }
   state.mode='normal';state.balance=0;state.status='New';await request({action:'invoice',amount:1000});
   assert.equal((await report()).credit.invoices.length,index+2);
  }
  state.mode='status-fail';await checked();assert.equal((await report()).credit.invoices.at(-1).outcome,'unknown');
  const count=state.invoiceCalls;await request({action:'invoice',amount:1000});assert.equal(state.invoiceCalls,count);
  check(true,'established paid and expired-unpaid histories survive manual, return and unlock refresh while unresolved invoices still block');return;
 }
 if(name==='credit-control-account'){
  const r=await request({action:'configure',endpoint:inferenceEndpoint,model:'example-model'});assert.ok(r.credit_error);
  const protectedValue=await workerCall('test_poc_protect_output',JSON.stringify({account:creditId,key:defaultKey}));
  assert.ok(!JSON.stringify(protectedValue).includes(creditId)&&!JSON.stringify(protectedValue).includes(defaultKey),'account credential refused by filter');
  const before=(await journal(creditId)).records;
  const probe=await workerCall('test_credit_append_probe',creditId);assert.equal(probe.refused,true,'account credential refused at commit');assert.equal((await journal(creditId)).records,before);
  check(true,'account credential filter refuses ordinary records');return;
 }
 if(name==='credit-expiry'){
  const count=state.invoiceCalls;
  for(const [status,paid,mode,balance] of [['New',0,'normal',0],['Invalid',0,'normal',0],['Unknown',0,'normal',0],['Expired',1,'normal',0],['Expired',0,'missing-paid',0],['Expired',0,'malformed-paid',0],['Expired',0,'balance-fail',0],['Expired',0,'mismatch',0],['Expired',0,'status-fail',0]]){
   Object.assign(state,{status,amountPaid:paid,mode,balance});await checked();
   assert.equal(await evaluate("document.querySelector('#tau-credit-invoice').disabled"),true,'unknown outcome never enables another invoice');await request({action:'invoice',amount:1000});assert.equal(state.invoiceCalls,count);
  }
  Object.assign(state,{status:'Expired',amountPaid:0,mode:'normal',balance:0});await checked();
  assert.equal(await evaluate("document.querySelector('#tau-credit-invoice').disabled"),false);assert.equal(await evaluate("document.querySelector('#tau-credit-invoice').textContent"),'New invoice');
  await request({action:'invoice',amount:1200});assert.equal((await report()).credit.invoices.length,2);
  Object.assign(state,{status:'Expired',amountPaid:0,balance:0.78});await checked();assert.equal((await report()).credit.invoices.at(-1).outcome,'paid');
  check(true,'all three unpaid conditions and identity are necessary; positive continuations retain history');return;
 }
 if(name==='credit-funding'){
  await invoke(()=>Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async value=>{globalThis.fixtureCopied=value;}}}));
  await invoke(()=>[...document.querySelectorAll('#tau-credit-invoices button')].find(b=>b.textContent==='Copy').click());
  await wait('globalThis.fixtureCopied');assert.equal(await evaluate('fixtureCopied'),state.invoices[0].lightning_invoice);
  await invoke(()=>{globalThis.fixtureDateNow=Date.now;Date.now=()=>fixtureDateNow()+61000;});
  await wait(`document.querySelector('#tau-credit-invoices [data-invoice-expires]').textContent==='1 minutes left'`);
  await invoke(()=>{Date.now=fixtureDateNow;});
  const before=state.statusCalls;await new Promise(resolve=>setTimeout(resolve,5200));assert.ok(state.statusCalls>before,'visible automatic status poll');
  const times=state.requests.filter(r=>r.route.startsWith('/topup/status')).map(r=>r.at);assert.ok(times.every((t,i)=>i===0||t-times[i-1]>=4900));
 }
 if(name==='credit-poll-bounds'){
  await message({lifecycle:'hidden'});const before=state.statusCalls;
  await new Promise(r=>setTimeout(r,5200));assert.equal(state.statusCalls,before,'hidden page does not poll');
  await message({lifecycle:'visible'});await wait(`fixtureReports.at(-1)?.store_state==='unlocked'`);
  for(let n=0;n<100&&state.statusCalls===before;n++)await new Promise(r=>setTimeout(r,25));assert.ok(state.statusCalls>before,'visibility return reads saved invoice');
  const expiry=state.invoices[0].expires_at;
  await workerEvaluate(`globalThis.fixtureCreditDateNow=Date.now;Date.now=()=>${(expiry+61)*1000}`);
  const stopped=state.statusCalls;await new Promise(r=>setTimeout(r,5200));assert.equal(state.statusCalls,stopped,'automatic reads stop at expiry plus sixty');
  await checked();assert.ok(state.statusCalls>stopped,'manual Check now remains available');assert.equal(state.invoiceCalls,1);
  await workerEvaluate('Date.now=fixtureCreditDateNow');check(true,'credit polling obeys visibility and expiry bounds without minting');return;
 }
 Object.assign(state,{status:'Settled',mode:'balance-fail',balance:0.789});await checked();
 assert.equal((await report()).credit.invoices.at(-1).outcome,'seen');assert.equal((await report()).credit.can_start,false);
 Object.assign(state,{status:'Settled',mode:'normal',balance:0.789});await checked();
 assert.equal((await report()).credit.balance_text,'Inference credit: 0.78 USD, as reported by the credit service');
 if(name==='credit-existing-balance'){
  Object.assign(state,{status:'Settled',mode:'normal',balance:0.789});await checked();
  assert.equal((await report()).credit.invoices.at(-1).outcome,'paid');
  state.status='New';await request({action:'invoice',amount:1000});await checked();
  assert.equal((await report()).credit.invoices.at(-1).outcome,'pending');
  assert.equal((await report()).credit.can_start,true,'pending invoice retains freshly reported existing credit');
  assert.equal(await evaluate("document.querySelector('#tau-credit-invoice').disabled"),true,'existing balance does not permit replacement');
  await call('Page.reload',{},sessionId);await wait("document.querySelector('#tau-store')?.dataset.state==='locked'");
  await invoke(()=>{document.querySelector('#tau-passphrase').value='durable fixture passphrase';document.querySelector('#tau-unlock').click();});
  await wait('fixtureReports.at(-1)?.credit?.can_start===true && fixtureReports.at(-1)?.credit?.invoices?.length===2');
  assert.equal((await report()).credit.invoices.at(-1).outcome,'pending');
  const blocked=await request({action:'invoice',amount:1000});assert.match(blocked.credit_error,/unresolved/);
  assert.equal(state.accountCalls,1);assert.equal(state.invoiceCalls,2);assert.equal(state.mintCalls,0);
  check(true,'pending top-up preserves existing credit across unlock while withholding another invoice');return;
 }
 if(name==='credit-funding'||name==='credit-failures'){check(true,'settlement reads balance and keeps account values out of page messages');return;}
 await invoke(info=>{for(const [id,value] of Object.entries({machine:'machine-a',relay:info.relay,profile:'v1',host:'127.0.0.1',port:info.port,user:'tracer',elevation:'none',pin:info.pin,class:'no'}))document.querySelector('#tau-poc-'+id).value=value;document.querySelector('#tau-poc-approve-existing').checked=document.querySelector('#tau-poc-approve-access').checked=true;document.querySelector('#tau-poc-target-form').requestSubmit();},info);
 await wait('fixtureReports.at(-1)?.poc_targets?.length===1');
 await invoke(endpoint=>{document.querySelector('#tau-poc-endpoint').value=endpoint;document.querySelector('#tau-poc-model').value='example-model';const goal=document.querySelector('[data-credit-goal]');goal.value='Install and check a small service';goal.dispatchEvent(new Event('input',{bubbles:true}));},inferenceEndpoint);
 if(name==='credit-goal-drafts'){
  await request({action:'check'});
  assert.equal(await evaluate("document.querySelector('[data-credit-goal]').value"),'Install and check a small service');
 }
 if(name==='credit-lifecycle')state.delay=1200;
 if(name==='credit-late-lock'||name==='credit-late-end')await hold('credit_mint_return');
 if(name==='credit-late-lock')await workerEvaluate(`globalThis.fixtureOriginalSend=self.postMessage.bind(self);self.postMessage=(value,...transfer)=>{if(value?.runtime_retired===true)globalThis.fixtureRetirementAck=value;else fixtureOriginalSend(value,...transfer);};`);
 await invoke(()=>[...document.querySelectorAll('#tau-poc-targets button')].find(b=>b.textContent==='Start session machine-a').click());
 if(name==='credit-late-lock'||name==='credit-late-end'){
  await point('credit_mint_return');
  const session=(await workerCall('open','')).sessions[0].identity;
  if(name==='credit-late-lock'){
   await click('#tau-lock');await wait("document.querySelector('#tau-store')?.dataset.state==='locking'");
   await workerEvaluate('fixtureCreditRelease("credit_mint_return")');
  }else{
   await message({task:{action:'end-session',session}});await wait("fixtureReports.at(-1)?.sessions?.[0]?.session_state==='ended'");
  }
  if(name!=='credit-late-lock')await release('credit_mint_return');
  for(let n=0;n<200&&!state.deletes.includes('key-1');n++)await new Promise(r=>setTimeout(r,25));
  assert.ok(state.deletes.includes('key-1'),'late returned key revoked best effort');
  assert.equal(await workerEvaluate(`(async()=>{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);return m.poc_key_is_set();})()`),false);
  if(name==='credit-late-end')assert.equal((await journal('')).mint_names.length,1);
  else {await workerEvaluate('fixtureOriginalSend(fixtureRetirementAck)');await wait("document.querySelector('#tau-store')?.dataset.state==='locked'");}
  check(true,'retirement rejects the late key and still attempts narrow cleanup');return;
 }
 if(name==='credit-lifecycle'){
  for(let n=0;n<100&&!state.mintCalls;n++)await new Promise(r=>setTimeout(r,25));
  await click('#tau-lock');await wait("document.querySelector('#tau-store')?.dataset.state==='locked'");
  await new Promise(r=>setTimeout(r,1500));
  assert.equal(await evaluate("document.querySelector('#tau-poc-key').value"),'');check(true,'Lock retires a pending mint without actionable handback');return;
 }
 await wait('fixtureReports.at(-1)?.sessions?.[0]?.credit_backed && fixtureReports.at(-1)?.poc_configuration?.key_set');
 const session=(await report()).sessions[0].identity;
 assert.equal(state.mintCalls,1);assert.equal((await journal(state.keys[0].api_key)).contains,false);
 assert.ok((await journal('')).mint_names.includes(state.keys[0].name));
 if(name==='credit-control-name'||name==='credit-control-key'){assert.deepEqual(state.orderingFailures,[],'mint name committed before actual request');check(true,name==='credit-control-name'?'mint name committed before actual request':'session key absent from every decrypted record');return;}
 if(name==='credit-goal-drafts'){
  await wait("fixtureEvents.some(e=>e.fixture_credit_complete==='start')");
  assert.equal(await evaluate("document.querySelector('[data-credit-goal]').value"),'','successful Start consumes its draft');
  assert.equal((await report()).sessions[0].goal.text,'Install and check a small service');
  await invoke(()=>{const goal=document.querySelector('[data-credit-goal]');goal.value='Unsubmitted next goal';goal.dispatchEvent(new Event('input',{bubbles:true}));});
  await request({action:'check'});assert.equal(await evaluate("document.querySelector('[data-credit-goal]').value"),'Unsubmitted next goal');
  await click('#tau-lock');await wait("document.querySelector('#tau-store')?.dataset.state==='locked'");
  await invoke(()=>{document.querySelector('#tau-passphrase').value='durable fixture passphrase';document.querySelector('#tau-unlock').click();});
  await wait('fixtureReports.at(-1)?.credit?.can_start');
  assert.equal(await evaluate("document.querySelector('[data-credit-goal]').value"),'','Lock clears an unsubmitted draft');
  await click('[data-end-session]');await wait("fixtureReports.at(-1)?.sessions?.[0]?.session_state==='ended'");
  assert.equal(await evaluate("document.querySelector('[data-credit-goal]').value"),'','fresh session entry stays empty');
  assert.equal((await report()).sessions[0].goal.text,'Install and check a small service');
  check(true,'goal drafts survive ordinary renders, are consumed on Start and cleared by Lock while original history remains');return;
 }
 if(name==='credit-refresh-contention'){
  state.status='New';await request({action:'invoice',amount:1000});
  const expiry=state.invoices.at(-1).expires_at;
  let entered;const held=new Promise(resolve=>entered=resolve);
  state.onMint=()=>new Promise(resolve=>{state.releaseMint=resolve;entered();});
  await message({credit_request:{action:'new_key',session}});await held;
  await workerEvaluate(`Date.now=()=>${(expiry+61)*1000}`);
  const statusBefore=state.statusCalls,mints=state.mintCalls,invoices=state.invoiceCalls;
  await message({credit_request:{action:'new_key',session}});
  await wait('fixtureReports.at(-1)?.credit_error?.includes("still in progress")');
  await message({lifecycle:'hidden'});await message({lifecycle:'visible'});
  assert.equal(state.statusCalls,statusBefore,'return refresh waits behind held mint');
  state.onMint=null;state.releaseMint();
  await wait('fixtureReports.at(-1)?.credit?.invoices?.at(-1)?.outcome==="unknown"');
  assert.equal(state.statusCalls,statusBefore+1,'required refresh happens once outside automatic window');
  assert.equal(state.mintCalls,mints);assert.equal(state.invoiceCalls,invoices);
  assert.equal((await report()).sessions[0].identity,session);
  check(true,'a return refresh waits behind mint outside the polling window and duplicate New key never mints twice');return;
 }
 const minted=state.mintCalls;
 await message({lifecycle:'hidden'});await message({lifecycle:'visible'});await new Promise(r=>setTimeout(r,250));assert.equal(state.mintCalls,minted);
 if(name==='credit-mint-pause'||name==='credit-ensure-contention'||name==='credit-balance-loss-mint'){
  await hold('poc_inference_writer');
  await invoke(()=>{document.querySelector('[aria-label="Verification commands, one per line"]').value='true';document.querySelector('[data-goal-accept]').click();});
  await wait('fixtureReports.at(-1)?.tasks?.[0]?.pause_reason');
  await click('[data-poc-propose]');await wait("document.querySelector('[data-requirements-decision=approve]')");await click('[data-requirements-decision=approve]');await wait("!document.querySelector('[data-requirements-decision=approve]')");
  await invoke(()=>[...document.querySelectorAll('[data-task] button')].find(b=>b.textContent==='Resume').click());await point('poc_inference_writer');
  const original=(await workerCall('open','')).tasks[0];assert.equal(original.requests,1);
  state.mintMode=name==='credit-mint-pause'?'refused':'normal';await call('Page.reload',{},sessionId);await wait("document.querySelector('#tau-store')?.dataset.state==='locked'");
  await workerEvaluate(`globalThis.fixtureCreditRefusal={status:503,error:'private-prefix'}`);
  if(name==='credit-balance-loss-mint')state.mode='balance-lost';
  let balanceEntered, balanceHeld;
  if(name==='credit-ensure-contention'){
   await hold('poc_progress_publication');
   balanceHeld=new Promise(resolve=>balanceEntered=resolve);
   state.onBalance=()=>new Promise(resolve=>{state.releaseBalance=resolve;balanceEntered();});
  }
  await invoke(()=>{document.querySelector('#tau-passphrase').value='durable fixture passphrase';document.querySelector('#tau-unlock').click();});
  if(name==='credit-ensure-contention'){
   await point('poc_progress_publication');await balanceHeld;
   await release('poc_progress_publication');
   assert.equal(state.mintCalls,1,'automatic key work waits behind refresh');
   state.onBalance=null;state.releaseBalance();
   await wait(`fixtureReports.at(-1)?.tasks?.[0]?.requests===2 && fixtureReports.at(-1)?.tasks?.[0]?.pause_reason==='inference provider request refused (HTTP 503)'`);
   assert.equal(state.mintCalls,2);assert.equal((await report()).tasks[0].id,original.id);
   assert.equal((await report()).tasks[0].start_session,original.start_session);assert.equal((await report()).tasks[0].pending,null);
   check(true,'eligible keyless work waits behind a held refresh and continues once without a phantom Request');return;
  }
  const failedMessage=name==='credit-balance-loss-mint'?"Couldn't read inference credit balance.":"Couldn't create this session's inference key.";
  const attempts=name==='credit-balance-loss-mint'?1:2;
  await wait(`fixtureReports.at(-1)?.tasks?.[0]?.pause_reason===${JSON.stringify(failedMessage)}`);
  assert.equal(state.mintCalls,attempts);assert.equal((await report()).tasks[0].requests,original.requests);
  if(name==='credit-balance-loss-mint'){assert.equal((await report()).credit.balance,null);assert.equal((await report()).credit.can_start,false);}
  await request({action:'check'});await message({lifecycle:'resume'});await new Promise(r=>setTimeout(r,250));assert.equal(state.mintCalls,attempts,'prerequisite wakeups do not retry a failed mint');
  state.mode='normal';state.mintMode='normal';await invoke(()=>[...document.querySelectorAll('[data-task] button')].find(b=>b.textContent==='Resume').click());
  await wait(`fixtureReports.at(-1)?.tasks?.[0]?.requests===2 && fixtureReports.at(-1)?.tasks?.[0]?.pause_reason==='inference provider request refused (HTTP 503)'`);
  assert.equal(state.mintCalls,attempts+1);assert.equal((await report()).tasks[0].id,original.id);
  check(true,'one failed automatic mint pauses without consuming inference; explicit Resume retries under a new name');return;
 }
 if(name==='credit-refusals'){
  await workerEvaluate(`globalThis.fixtureCreditRefusal={status:401,error:'API key expired'}`);
  await invoke(()=>{document.querySelector('[aria-label="Verification commands, one per line"]').value='true';document.querySelector('[data-goal-accept]').click();});
  await wait('fixtureReports.at(-1)?.tasks?.[0]?.pause_reason');
  await click('[data-poc-propose]');await wait("document.querySelector('[data-requirements-decision=approve]')");await click('[data-requirements-decision=approve]');await wait("!document.querySelector('[data-requirements-decision=approve]')");
  await invoke(()=>[...document.querySelectorAll('[data-task] button')].find(b=>b.textContent==='Resume').click());
  await wait('fixtureReports.at(-1)?.tasks?.[0]?.requests>0 && fixtureReports.at(-1)?.tasks?.[0]?.pause_reason');
  assert.equal((await report()).tasks[0].pause_reason,"This session's inference key expired.");
  for(const [status,error,balance,expected] of [
   [402,`Insufficient credit on credit id ${creditId.slice(0,14)}: this request requires a minimum balance of $0.0002 and your current balance is $0.0000. Please top up.`,0.0001,'Inference credit used up.'],
   [402,'Insufficient credit: minimum $0.0002',0.78,'The credit service refused this request.'],
   [401,'private-prefix',0.78,'The credit service refused this request.'],
   [403,'private-prefix',0.78,'The credit service refused this request.'],
   [429,'private-prefix',0.78,'The credit service refused this request.'],
   [503,'private-prefix',0.78,'inference provider request refused (HTTP 503)']]){
   state.balance=0.78;const minted=await request({action:'new_key',session});assert.ok(!minted.credit_error,minted.credit_error);state.balance=balance;
   await workerEvaluate(`globalThis.fixtureCreditRefusal=${JSON.stringify({status,error})}`);
   const requests=(await report()).tasks[0].requests;
   await invoke(()=>[...document.querySelectorAll('[data-task] button')].find(b=>b.textContent==='Resume').click());
   await wait(`fixtureReports.at(-1)?.tasks?.[0]?.requests>${requests} && fixtureReports.at(-1)?.tasks?.[0]?.pause_reason`);
   assert.equal((await report()).tasks[0].pause_reason,expected);
  }
  const page=await evaluate('document.body.textContent');assert.ok(!page.includes('private-prefix')&&!page.includes(creditId.slice(0,14)));
  check(true,'recorded refusal shapes pause with fixed protected sentences after a fresh balance read');return;
 }
 if(name==='credit-key'){
  for(const mode of ['wrong-cap','wrong-expiry','reset','missing-cap','refused','lost','normal']){
   state.mintMode=mode;const r=await request({action:'new_key',session});
   if(mode!=='normal')assert.equal(r.credit_error,"Couldn't create this session's inference key.");else assert.ok(!r.credit_error);
  }
  assert.ok(state.listCalls>=6);assert.ok(state.deletes.includes('key-1'));assert.ok(state.deletes.includes('key-'+(state.mintCalls-1)),'lost answer located by committed name');
  assert.equal(new Set(state.keys.map(k=>k.name)).size,state.keys.length);
  for(const key of state.keys)assert.equal((await journal(key.api_key)).contains,false);
  await click('[data-end-session]');await wait("fixtureReports.at(-1)?.sessions?.[0]?.session_state==='ended'");
  check(true,'Start, hide, New key limits and prior-name cleanup preserve one session');return;
 }
 // Reuse the real relay and command runner: collection must precede a new mint.
 await invoke(()=>[...document.querySelectorAll('#tau-poc-targets button')].find(b=>b.textContent==='Show public keys machine-a').click());
 const keys=await wait('fixtureReports.at(-1)?.poc_keys');assert.equal((await control({keys})).installed,true);
 const command=`while [ ! -f '${info.directory}/continue' ]; do sleep 0.1; done; printf installed`;
 if(name.startsWith('credit-mint-collection-')||name.startsWith('credit-mint-verification-')){
  const verifying=name.startsWith('credit-mint-verification-');
  const mode=name.slice((verifying?'credit-mint-verification-':'credit-mint-collection-').length);
  await control({inference:{key:state.keys[0].api_key,commands:verifying?[null]:[command,null]}});
  await invoke(checks=>{document.querySelector('[aria-label="Verification commands, one per line"]').value=checks;document.querySelector('[data-goal-accept]').click();},verifying?command:'true');
  await wait('fixtureReports.at(-1)?.tasks?.[0]?.pause_reason');await click('[data-poc-propose]');await wait("document.querySelector('[data-requirements-decision=approve]')");await click('[data-requirements-decision=approve]');await wait("!document.querySelector('[data-requirements-decision=approve]')");
  await hold('credit_mint_writer');
  await message({credit_request:{action:'new_key',session}});await point('credit_mint_writer');
  await invoke(()=>[...document.querySelectorAll('[data-task] button')].find(b=>b.textContent==='Resume').click());
  await wait('fixtureReports.at(-1)?.tasks?.[0]?.pending');
  const original=(await report()).tasks[0];assert.equal(original.verifying,verifying);
  let launched=false;
  for(let n=0;n<100&&!launched;n++){launched=(await control({inspect:true})).launches.some(j=>j.job===original.pending.job);if(!launched)await new Promise(r=>setTimeout(r,25));}
  assert.ok(launched);
  state.mintMode=mode;await release('credit_mint_writer');
  await wait(`fixtureReports.at(-1)?.credit_error===${JSON.stringify("Couldn't create this session's inference key.")}`);
  const after=(await workerCall('open','')).tasks[0];
  assert.equal(after.revision,original.revision,'mint failure does not invalidate the running collector');
  assert.deepEqual(after.pending,original.pending);assert.equal(after.requests,original.requests);
  await control({release:true});
  if(!verifying){
   await wait(`fixtureReports.at(-1)?.tasks?.[0]?.pause_reason===${JSON.stringify("Couldn't create this session's inference key.")} && !fixtureReports.at(-1)?.tasks?.[0]?.pending`);
   const paused=(await report()).tasks[0];assert.equal(paused.requests,original.requests,'failure consumes no inference request');
   assert.equal(state.mintCalls,2,'collection does not retry a failed mint');
   state.mintMode='normal';state.onMint=async key=>{await control({inference:{key:key.api_key,commands:[null]}});};
   await invoke(()=>[...document.querySelectorAll('[data-task] button')].find(b=>b.textContent==='Resume').click());
  }
  await wait("fixtureReports.at(-1)?.tasks?.[0]?.status==='complete'");
  const done=(await report()).tasks[0];assert.equal(done.id,original.id);assert.equal(done.start_session,original.start_session);
  assert.equal(done.requests,original.requests+(verifying?0:1));
  assert.equal(done.verification.length,1);assert.equal(done.verification[0].exit_status,0);
  assert.equal((await control({inspect:true})).launches.filter(j=>j.job===original.pending.job).length,1);
  check(true,'mint failure preserves original collection and independent verification, pausing only a later inference turn');return;
 }
 await control({inference:{key:state.keys.at(-1).api_key,commands:[command,null]}});
 state.onMint=async key=>{await control({inference:{key:key.api_key,commands:[null]}});await new Promise(r=>setTimeout(r,info.relay_spacing_ms+50));};
 await invoke(checks=>{document.querySelector('[aria-label="Verification commands, one per line"]').value=checks;document.querySelector('[data-goal-accept]').click();},`test -f '${info.directory}/verified'`);
 await wait('fixtureReports.at(-1)?.tasks?.[0]?.pause_reason');await click('[data-poc-propose]');await wait("document.querySelector('[data-requirements-decision=\"approve\"]')");await click('[data-requirements-decision="approve"]');await wait("!document.querySelector('[data-requirements-decision=\"approve\"]')");
 await invoke(()=>[...document.querySelectorAll('[data-task] button')].find(b=>b.textContent==='Resume').click());
 await wait('fixtureReports.at(-1)?.tasks?.[0]?.pending');
 const original=(await report()).tasks[0];
 let launched=false;
 for(let n=0;n<100&&!launched;n++){
  launched=(await control({inspect:true})).launches.some(j=>j.job===original.pending.job);
  if(!launched)await new Promise(r=>setTimeout(r,25));
 }
 assert.ok(launched,'interrupt only after the fixture has recorded this command launch');
 if(name==='credit-lock')await click('#tau-lock');else{if(name==='credit-loss')await evaluate('fixtureWorkers.at(-1).terminate()');await call('Page.reload',{},sessionId);}
 await wait("document.querySelector('#tau-store')?.dataset.state==='locked'");
 await new Promise(resolve=>setTimeout(resolve,info.relay_spacing_ms+50));
 await invoke(()=>{document.querySelector('#tau-passphrase').value='durable fixture passphrase';document.querySelector('#tau-unlock').click();});
 await wait('fixtureReports.at(-1)?.tasks?.[0]?.pending');assert.equal(state.mintCalls,1,'pending collection before fresh mint');
 await control({verify:true});await control({release:true});
 await invoke(()=>[...document.querySelectorAll('[data-task] button')].find(b=>b.textContent==='Resume').click());
 await wait("fixtureReports.at(-1)?.tasks?.[0]?.status==='complete'");
 const restored=(await report()).tasks[0];assert.equal(restored.id,original.id);assert.equal(restored.start_session,original.start_session);assert.equal(state.mintCalls,2);
 const seen=await control({inspect:true});assert.equal(seen.launches.filter(j=>j.job===original.pending.job).length,1);
 check(true,'credit unlock restores account, collects the original job first and mints without typing');
}
