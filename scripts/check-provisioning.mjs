import assert from 'node:assert/strict';
import {createServer} from 'node:https';
import {readFile, writeFile, mkdtemp, rm, mkdir} from 'node:fs/promises';
import {spawn, spawnSync} from 'node:child_process';
import {once} from 'node:events';
import {createInterface} from 'node:readline';
import {join, resolve} from 'node:path';
import {digest, publicIdentity, verifyRequest, acceptRequest, IdenticalReplay, fixtureAuthorization, signatureForms} from './provisioning-protocol.mjs';

const scenario=process.argv[2]??'fixed';
if(scenario==='protocol-controls'){
  const key='31'.repeat(32),account=publicIdentity(key),url='https://127.0.0.1:12345/api/v1/vm',body=Buffer.from('{"template_id":1}'),accepted=new Map();
  const header=fixtureAuthorization(key,url,'POST',body);
  const event=verifyRequest(header,url,'POST',body,account,accepted);acceptRequest(accepted,event,header,url,'POST',body);
  assert.throws(()=>verifyRequest(header,url,'POST',body,account,accepted),IdenticalReplay);
  for(const args of [[header,url+'?changed','POST',body],[header,url,'GET',body],[header,url,'POST',Buffer.from('{}')],['Nostr !!!',url,'POST',body]]){
    assert.throws(()=>verifyRequest(...args,account,accepted),error=>!(error instanceof IdenticalReplay));
  }
  const tampered=JSON.parse(Buffer.from(header.slice(6),'base64').toString());tampered.sig='00'.repeat(64);
  assert.throws(()=>verifyRequest('Nostr '+Buffer.from(JSON.stringify(tampered)).toString('base64'),url,'POST',body,account,accepted),error=>!(error instanceof IdenticalReplay));
  const alteredEnvelope=JSON.parse(Buffer.from(header.slice(6),'base64').toString());alteredEnvelope.extra='changed';
  assert.throws(()=>verifyRequest('Nostr '+Buffer.from(JSON.stringify(alteredEnvelope)).toString('base64'),url,'POST',body,account,accepted),error=>!(error instanceof IdenticalReplay));
  const fresh=fixtureAuthorization(key,url,'POST',body,'fresh-counter-control');
  assert.doesNotThrow(()=>verifyRequest(fresh,url,'POST',body,account,accepted));
  for(const offset of [-2,2])assert.doesNotThrow(()=>verifyRequest(header,url,'POST',body,account,new Map(),event.created_at+offset));
  for(const offset of [-61,61])assert.throws(()=>verifyRequest(header,url,'POST',body,account,new Map(),event.created_at+offset),error=>!(error instanceof IdenticalReplay));
  const forms=signatureForms(event.sig);assert.deepEqual(forms.map(value=>value.length),[88,128,128]);
  console.log(JSON.stringify({scenario,identicalReplay:1,nonReplayRefusals:6,freshAccepted:1,clockSkewAccepted:2,clockSkewRefused:2,signatureEncodings:3,checks:'passed'}));process.exit(0);
}
const scenarios=['origin-entry','custom-origin-entry','origin-stale-review','origin-validation','fixed','pending-custody','custom','lost-create','empty-create','incomplete-create','multiple-create','lost-invoice','empty-invoice','expired-invoice','publication','pre-send-reload','associated-reload','registration','failed-write','credentials','transport','refusals','mismatched-host','multiple-invoice','incomplete-invoice','conflicting-invoice','conflicting-create','popularity','popularity-lost','mismatched-image','fixed-terms','fixed-terms-reload','fixed-config','custom-terms','custom-terms-reload','custom-config','counter-identical','counter-fresh','lifecycle','fixed-unavailable','custom-unavailable','later-image','fixed-config-reload','custom-config-reload','custom-resource','fixed-cpu-direct','custom-cpu-direct','fixed-cpu-lost','custom-cpu-lost','fixed-cpu-later','custom-cpu-later','clock-ahead','custom-clock-behind','clock-lost-behind','custom-clock-lost-ahead','clock-old-evidence','custom-clock-future-evidence','fixed-eur','custom-usd','existing-paid','existing-unpaid','unknown-quote','quote-change','quote-unavailable','lost-invoice-quote-reload','signature-encodings','approval-authority','custom-caps-mismatched','custom-caps-missing','custom-caps-lost-mismatched','custom-caps-lost-missing','custom-caps-later','custom-caps-matching','custom-caps-network','custom-caps-uncapped','missing-limits','fixed-caps-mismatched','fixed-caps-missing','custom-deadline-headers','custom-deadline-body','custom-deadline-inside','custom-deadline-clock','fixed-transfer-direct','fixed-transfer-lost','fixed-transfer-later','custom-transfer-direct','custom-transfer-lost','custom-transfer-later'];
if(scenario==='list'){console.log(JSON.stringify(scenarios));process.exit(0);}
if(!scenarios.includes(scenario))throw Error('unknown provisioning case');
const deadlineCase=scenario.startsWith('custom-deadline-');
const deadlineInside=scenario==='custom-deadline-inside';
let responseDelay=0,responseAborts=0,deadlineMeasurement=null;
const transferCase=scenario.match(/^(fixed|custom)-transfer-(direct|lost|later)$/);
const transferPhase=transferCase?.[2];
let transferBad=Boolean(transferCase&&transferPhase!=='later'),transferChecks=0;
const capsCase=scenario.startsWith('custom-caps-')||scenario.startsWith('fixed-caps-');
const capsLater=scenario==='custom-caps-later';
let inheritedCapChecks=0,missingLimitsRefusals=0;
let capsVariant=scenario.endsWith('missing')?'missing':'mismatched',capsBad=capsCase&&!capsLater&&!['custom-caps-matching','custom-caps-network'].includes(scenario);
const originCase=scenario.includes('origin-');
const cpuCase=scenario.match(/^(fixed|custom)-cpu-(direct|lost|later)$/);
const cpuPhase=cpuCase?.[2];
let cpuVariant=scenario==='custom-cpu-direct'?'arch-missing':'arch';
const cpuVariants=['arch','arch-missing','mfg','mfg-missing','features','features-missing'];
const providerOffsetSeconds=scenario.includes('clock')?(scenario.endsWith('ahead')?2:scenario.endsWith('behind')?-2:0):0;
const creationOffsetSeconds=scenario.endsWith('old-evidence')?-90:scenario.endsWith('future-evidence')?180:0;
const providerNow=()=>Date.now()+providerOffsetSeconds*1000;
const planCurrency=scenario.endsWith('-eur')?'EUR':scenario.endsWith('-usd')?'USD':'BTC';
const periodSeconds=scenario==='calendar-period'||planCurrency!=='BTC'?2678400:2592000;
const existingHistory=scenario==='existing-paid'||scenario==='existing-unpaid';
const unknownQuote=scenario==='unknown-quote';

const secret='31'.repeat(32), other='32'.repeat(32), inference='fixture~inference~key~482700';
const account=publicIdentity(secret), used=new Map(), counts={}, replays={}, effects={}, refusals={}, errors=[], authForms=new Set(), dispatches=[];
let browser,socket,provider,alternateProvider,page,fixture,temp;let alternateContacts=0,allowedAlternateContacts=0,originChecks=0;const fixtureTimers=new Set();
await mkdir('target',{recursive:true});
temp=await mkdtemp(resolve('target/provisioning-'));
const check=(condition,label)=>assert.ok(condition,label);
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const image={id:3,distribution:'archlinux',flavour:'base',version:'rolling',release_date:'2026-10-01T00:00:00Z',cpu_arch:'x86_64',default_username:'arch',encrypted:false,popularity:0.1};
const region={id:1,name:'Dublin fixture',country_code:'IE',company_id:1};
const london={id:2,name:'London fixture',country_code:'GB',company_id:1};
const cost={id:1,name:'Monthly',currency:planCurrency,amount:planCurrency==='BTC'?1000000:1200,other_price:[],interval_amount:1,interval_type:'month'};
const fixed={limits:{},id:1,name:'Small fixed fixture',created:'2026-01-01T00:00:00Z',cpu:1,memory:1073741824,disk_size:10737418240,disk_type:'ssd',disk_interface:'scsi',cpu_arch:'x86_64',cpu_mfg:'amd',cpu_features:['AVX2','AES'],cost_plan:cost,region};
const custom={limits:{},id:2,name:'Custom fixture',region:london,cpu_arch:'x86_64',cpu_mfg:'amd',cpu_features:['AVX2','AES'],min_cpu:1,max_cpu:8,min_memory:1073741824,max_memory:8589934592,disks:[{min_disk:10737418240,max_disk:107374182400,disk_type:'ssd',disk_interface:'scsi'}],interval_amount:1,interval_type:'month',transfer:{min:100,max:2000,default:500},network:{min:100,max:1000,default:500}};
if(capsCase)(scenario.startsWith('custom-')?custom:fixed).limits=scenario==='custom-caps-uncapped'?{}:{cpu_limit:0.5,disk_iops_read:5000,disk_iops_write:2500,disk_mbps_read:500,disk_mbps_write:250,network_mbps:1000};
if(scenario==='missing-limits'){delete fixed.limits;delete custom.limits;}
const resources={pricing_id:2,cpu:2,memory:2147483648,disk:21474836480,disk_type:'ssd',disk_interface:'scsi',ip4_count:1,ip6_count:0,transfer_gb:500,network_mbps:500};
if(transferCase&&scenario.startsWith('custom-')){delete custom.transfer;delete resources.transfer_gb;}
let machines=[],payments=[],hostKey,hostPin,fixtureInfo,publication=scenario!=='publication',paid=scenario==='existing-paid',changePrice=false,changeConfig=false,popularityDrift=false,heldProviderResponse=null,failCatalogue=false,raiseMinimum=false,selectedResources=resources,echo=null,echoSignatureMode=null,heldSignatureEcho=null,quoteVersion=0,quoteResponseMode=unknownQuote?'missing':null,unavailableQuote=false,cpuBad=Boolean(cpuCase&&cpuPhase!=='later'),transport=null,modelCalls=0;
const iso=()=>new Date(providerNow()).toISOString();
const count=route=>counts[route]??0;
const effect=route=>effects[route]=(effects[route]??0)+1;
const isCustom=scenario==='custom'||scenario.startsWith('custom-');
const lostCreate=transferPhase==='lost'||scenario.includes('caps-lost-')||cpuPhase==='lost'||scenario.includes('clock-lost')||['lost-create','empty-create','incomplete-create','multiple-create','conflicting-create','popularity-lost','mismatched-image'].includes(scenario);
const lostInvoice=['lost-invoice-quote-reload','lost-invoice','empty-invoice','multiple-invoice','incomplete-invoice','conflicting-invoice'].includes(scenario);
const createRoute='POST /api/v1/vm'+(isCustom?'/custom-template':'');
const invoiceRoute='GET /api/v1/vm/11/renew?method=lightning&intervals=1';
const createRoutes=['POST /api/v1/vm','POST /api/v1/vm/custom-template'];
const mutationRoutes=['POST /api/v1/ssh-key',...createRoutes,invoiceRoute];
const mutationDispatches=()=>Object.fromEntries(mutationRoutes.map(route=>[route,dispatches.filter(d=>d.method+' '+d.path===route).length]));
const enforceCounts=()=>{for(const route of mutationRoutes){check((mutationDispatches()[route]??0)<=1,'at most one application dispatch per durable intent: '+route);check((effects[route]??0)<=1,'at most one accepted mutation per durable intent: '+route);}check(createRoutes.reduce((n,route)=>n+(mutationDispatches()[route]??0),0)<=1,'at most one application dispatch across create routes for the durable create intent');check(createRoutes.reduce((n,route)=>n+(effects[route]??0),0)<=1,'at most one accepted effect across create routes for the durable create intent');};
const requiredCsp=(await readFile('www/index.html','utf8')).match(/<meta http-equiv="Content-Security-Policy"[^>]*>/)[0];
const makeVm=(body,customOrder)=>({id:11,created:new Date(providerNow()+creationOffsetSeconds*1000).toISOString(),mac_address:'02:00:00:00:00:01',image:{...image,popularity:popularityDrift?0.1001:image.popularity},template:customOrder?{...fixed,id:91,cpu:body.cpu,memory:body.memory,disk_size:body.disk,region:london,transfer_gb:body.transfer_gb,limits:{...(custom.limits??{}),network_mbps:body.network_mbps}}:structuredClone(fixed),ssh_key:{id:7,name:'tau-0',created:iso()},ip_assignments:[{id:1,ip:'192.0.2.10/24',gateway:'192.0.2.1'}],status:{timestamp:Math.floor(providerNow()/1000),state:'running',cpu_usage:0,mem_usage:0,uptime:1,net_in:0,net_out:0,disk_write:0,disk_read:0},auto_renewal_enabled:true,max_prepay_days:365,host_ssh_keys:publication?[hostKey]:[]});
const returnedTemplate=template=>{
  const returned={...template,cpu_features:['AES','AVX2','SSE2']};
  if(transferBad)returned.transfer_gb=1;
  if(capsBad){returned.limits=capsVariant==='missing'?{network_mbps:template.limits.network_mbps}:{...template.limits,cpu_limit:0.25,disk_iops_read:2500};}
  if(!cpuBad)return returned;
  const field=cpuVariant.startsWith('arch')?'cpu_arch':cpuVariant.startsWith('mfg')?'cpu_mfg':'cpu_features';
  if(cpuVariant.endsWith('-missing'))delete returned[field];
  else returned[field]=field==='cpu_arch'?'arm64':field==='cpu_mfg'?'intel':['SSE2'];
  return returned;
};
const responseVm=vm=>({...vm,template:returnedTemplate(vm.template),image:{...vm.image,popularity:popularityDrift?0.1001:vm.image.popularity},host_ssh_keys:publication?[hostKey]:[]});
const renewalQuote=()=>({amount:quoteVersion?1000000*(quoteVersion+1):changePrice&&planCurrency==='BTC'?2000000:1000000,tax:230000,processing_fee:10000,currency:'BTC',time:periodSeconds});
const makePayment=()=>({id:'aabb',vm_id:11,created:iso(),expires:new Date(providerNow()+(scenario==='expired-invoice'?1000:86400000)).toISOString(),...renewalQuote(),is_paid:paid,data:{lightning:'lnbc1fixtureinvoice'},is_upgrade:false});
const watchdog=setTimeout(()=>{if(browser?.exitCode===null)browser.kill('SIGKILL');},240000);
try {
  const cert=join(temp,'cert.pem'),key=join(temp,'key.pem');
  check(spawnSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','1','-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1'],{stdio:'ignore'}).status===0,'isolated certificate creation');
  const tls={key:await readFile(key),cert:await readFile(cert)};
  const pem=spawnSync('openssl',['x509','-in',cert,'-pubkey','-noout'],{encoding:'utf8'});check(pem.status===0,'certificate public key');
  const der=spawnSync('openssl',['pkey','-pubin','-outform','DER'],{input:pem.stdout});check(der.status===0,'certificate public encoding');
  const spki=digest(der.stdout).toString('base64');
  fixture=spawn('target/debug/tracer',['poc-fixtures'],{stdio:['pipe','pipe','inherit']});
  const lines=createInterface({input:fixture.stdout}),responses=[],pending=[];
  lines.on('line',line=>{const value=JSON.parse(line),r=pending.shift();r?r(value):responses.push(value);});
  const read=()=>responses.length?Promise.resolve(responses.shift()):new Promise(r=>pending.push(r));
  const control=async value=>{fixture.stdin.write(JSON.stringify(value)+'\n');return read();};
  fixtureInfo=await read();await control({provisioning:true});
  const [algorithm,blob]=fixtureInfo.host_key.split(' ');hostPin=fixtureInfo.pin;hostKey={key_type:algorithm,public_key:blob,fingerprint_sha256:hostPin};
  const providerHandler=async(req,res)=>{
    if(req.socket.localPort!==provider.address().port)alternateContacts++;
    const requestOrigin=`https://127.0.0.1:${req.socket.localPort}`;
    const route=req.method+' '+req.url;counts[route]=count(route)+1;
    try {
      const chunks=[];for await(const chunk of req)chunks.push(chunk);const body=Buffer.concat(chunks);
      check(req.headers.origin===pageOrigin,'actual cross-origin fetch Origin');check(!req.headers.cookie,'provider cookies omitted');
      res.setHeader('Access-Control-Allow-Origin',pageOrigin);res.setHeader('Vary','Origin');
      if(req.method==='OPTIONS'){
        check(req.headers['access-control-request-headers']?.includes('authorization'),'actual authorization preflight');
        res.setHeader('Access-Control-Allow-Methods','GET,POST');res.setHeader('Access-Control-Allow-Headers','authorization,content-type');res.writeHead(204).end();return;
      }
      if(req.url==='/inference') {
        check(req.headers.authorization==='Bearer '+inference,'inference fixture authorization');
        const request=JSON.parse(body);const encoded=JSON.stringify(request);
        for(const value of [secret,other,...authForms])check(!encoded.includes(value),'no provider credential in model context');
        const tool=modelCalls++===0?'exec':'done';
        const argumentsValue=tool==='exec'?{machine:'machine-a',command:'true'}:{machine:'machine-a'};
        res.setHeader('Content-Type','application/json');res.end(JSON.stringify({choices:[{finish_reason:'tool_calls',message:{role:'assistant',content:null,tool_calls:[{id:'call-'+modelCalls,type:'function',function:{name:tool,arguments:JSON.stringify(argumentsValue)}}]}}]}));return;
      }
      const event=verifyRequest(req.headers.authorization,requestOrigin+req.url,req.method,body,account,used,providerNow()/1000);
      const accept=()=>acceptRequest(used,event,req.headers.authorization,requestOrigin+req.url,req.method,body);
      authForms.add(req.headers.authorization);authForms.add(event.sig);authForms.add(JSON.stringify(event));for(const form of signatureForms(event.sig))authForms.add(form);
      if(failCatalogue&&req.url==='/api/v1/vm/templates'){res.writeHead(503).end();return;}
      if(transport==='delayed'&&req.url==='/api/v1/vm/templates'){heldProviderResponse=()=>{res.setHeader('Content-Type','application/json');res.end(JSON.stringify({data:{templates:[fixed],custom_template:[custom]}}));};return;}
      if(transport==='redirect'){res.writeHead(302,{Location:pageOrigin+'/credential-trap'}).end();return;}
      if(transport==='oversized'&&req.url==='/api/v1/vm/templates'){accept();res.end(JSON.stringify({data:{templates:[fixed],custom_template:[custom]},padding:'x'.repeat(262145)}));return;}
      if(transport==='malformed'){res.end('{');return;}
      if(transport==='stall'&&req.url==='/api/v1/vm/templates'){accept();res.writeHead(200,{'Content-Type':'application/json'});const timer=setTimeout(()=>{fixtureTimers.delete(timer);if(!res.destroyed)res.end(JSON.stringify({data:{templates:[fixed],custom_template:[custom]}}));},16000);fixtureTimers.add(timer);return;}
      if(echoSignatureMode!==null&&req.url==='/api/v1/vm/templates'){heldSignatureEcho??=signatureForms(event.sig)[echoSignatureMode];res.setHeader('Content-Type','application/json');res.end(JSON.stringify({data:{templates:[{...fixed,name:heldSignatureEcho}],custom_template:[custom]}}));return;}
      if(echo&&req.url==='/api/v1/vm/templates'){res.setHeader('Content-Type','application/json');res.end(JSON.stringify({data:{templates:[{...fixed,name:echo}],custom_template:[custom]}}));return;}
      let result;
      const value=body.length?JSON.parse(body):null;
      switch(route){
        case 'GET /api/v1/vm/templates': result={templates:[{...fixed,cpu:changeConfig?2:fixed.cpu,cost_plan:{...cost,amount:changePrice?2000000:cost.amount}},{...fixed,id:4,name:'Hourly fixture',cost_plan:{...cost,interval_type:'hour'}}],custom_template:[{...custom,min_cpu:raiseMinimum?3:custom.min_cpu,max_cpu:changeConfig?7:custom.max_cpu}]};break;
        case 'GET /api/v1/image': result=[image,{...image,id:4,encrypted:true}];break;
        case 'POST /api/v1/vm/custom-template/price': assert.deepEqual(value,selectedResources);result={currency:planCurrency,amount:changePrice?2000000:cost.amount,interval_amount:1,interval_type:'month',other_price:[]};break;
        case 'POST /api/v1/ssh-key':check(value.key_data.startsWith('ssh-ed25519 '),'derived SSH public key');check(!value.key_data.includes('PRIVATE'),'no private SSH bytes');result={id:7,name:value.name,created:iso()};accept();effect(route);if(scenario==='registration'){res.destroy();return;}break;
        case 'GET /api/v1/ssh-key':result=[{id:7,name:'tau-0',created:iso()}];break;
        case 'GET /api/v1/vm':
          result=machines.map(responseVm);
          if(['empty-create','pre-send-reload'].includes(scenario))result=[];
          if(scenario==='incomplete-create'&&machines.length)result=[{...responseVm(machines[0]),ssh_key:{id:99,name:'other',created:iso()}}];
          if(scenario==='conflicting-create'&&machines.length)result=[{...responseVm(machines[0]),image:{...image,id:9}}];
          if(scenario==='multiple-create'&&machines.length)result.push({...responseVm(machines[0]),id:12});break;
        case 'POST /api/v1/vm': case 'POST /api/v1/vm/custom-template':
          check(value.image_id===3&&value.ssh_key_id===7,'create exactly approved image and registered SSH key');
          if(req.url.endsWith('custom-template'))assert.deepEqual(value,{...selectedResources,image_id:3,ssh_key_id:7});else assert.deepEqual(value,{template_id:1,image_id:3,ssh_key_id:7});
          check(!machines.length,'one fixture order');if(scenario==='popularity'||scenario==='popularity-lost')popularityDrift=true;machines.push(makeVm(value,isCustom));if(changePrice)machines[0].template.cost_plan={...cost,amount:2000000};if(changeConfig&&!isCustom)machines[0].template.cpu=2;if(scenario==='mismatched-image')machines[0].image={...image,id:9};accept();effect(route);if(existingHistory)payments.push(makePayment());result=responseVm(machines[0]);
          check(!('payment' in result),'create has no invoice');
          if(lostCreate){res.destroy();return;}break;
        case 'GET /api/v1/vm/11':result=responseVm(machines[0]);break;
        case 'GET /api/v1/vm/12':result={...responseVm(machines[0]),id:12};break;
        case 'GET /api/v1/vm/11/payments?limit=100&offset=0':{let history=payments.map(p=>({...p}));if(scenario==='empty-invoice')history=[];if(scenario==='multiple-invoice'&&history.length)history.push({...history[0],id:'aacc'});if(scenario==='incomplete-invoice'&&history.length)history=Array.from({length:100},(_,i)=>({...history[0],id:i.toString(16).padStart(4,'0')}));if(scenario==='conflicting-invoice'&&history.length)history[0].vm_id=12;result=history;break;}
        case 'GET /api/v1/vm/11/renew/quote?method=lightning&intervals=1':if(unavailableQuote){res.writeHead(503).end();return;}result=quoteResponseMode==='missing'?{currency:'BTC'}:quoteResponseMode==='malformed'?{...renewalQuote(),time:'unknown'}:renewalQuote();break;
        case 'GET /api/v1/vm/11/renew?method=lightning&intervals=1':check(!payments.length||scenario==='counter-fresh','one initial invoice');payments.push({...makePayment(),id:payments.length?'aacc':'aabb'});result=payments.at(-1);accept();effect(route);if(lostInvoice){res.destroy();return;}break;
        case 'GET /api/v1/payment/aabb':result={...payments[0],is_paid:paid};break;
        default: throw Error('unapproved provider route');
      }
      accept();res.setHeader('Content-Type','application/json');
      if(responseDelay){
        res.once('close',()=>{if(!res.writableFinished)responseAborts++;});
        // Keep every exchange below its own bound while crossing the action deadline.
        if(scenario==='custom-deadline-body'){res.writeHead(200);res.flushHeaders();}
        const timer=setTimeout(()=>{fixtureTimers.delete(timer);if(!res.destroyed)res.end(JSON.stringify({data:result}));},responseDelay);
        fixtureTimers.add(timer);
      }else res.end(JSON.stringify({data:result}));
    }catch(error){if(error instanceof IdenticalReplay){const route=req.method+' '+req.url;replays[route]=(replays[route]??0)+1;res.writeHead(409).end(JSON.stringify({error:'fixture replay refused'}));return;}refusals[route]=(refusals[route]??0)+1;errors.push('provider authorization or schema failure');res.writeHead(400).end(JSON.stringify({error:'fixture refusal'}));}
  };
  provider=createServer(tls,providerHandler);
  provider.listen(0,'127.0.0.1');await once(provider,'listening');
  const providerOrigin=`https://127.0.0.1:${provider.address().port}`;
  let alternateOrigin=null;
  if(originCase){alternateProvider=createServer(tls,providerHandler);alternateProvider.listen(0,'127.0.0.1');await once(alternateProvider,'listening');alternateOrigin=`https://127.0.0.1:${alternateProvider.address().port}`;}
  const injection=`\nimport * as fixtureApi from './pkg/tau_web.js';\n${originCase?'':`await fixtureApi.test_procurement_origin(${JSON.stringify(providerOrigin)});`}\nconst fixtureSend=self.postMessage.bind(self);self.postMessage=(value,...transfer)=>{if(value?.runtime_retired===true)fixtureSend({fixture_provider_custody:fixtureApi.provider_key_is_set(),fixture_provider_custody_point:'ending_worker'});return fixtureSend(value,...transfer);};const fixtureHolds=new Map();const transportFetch=self.fetch.bind(self);let dispatchControl=null,rollbackClock=false;const fixtureDateNow=Date.now.bind(Date);const observedFetch=(input,init)=>{const request=input instanceof Request?input:new Request(input,init);const url=new URL(request.url);postMessage({fixture_dispatch:{method:request.method,path:url.pathname+url.search,origin:url.origin}});return transportFetch(input,init).then(response=>{if(rollbackClock&&url.pathname==='/api/v1/vm'&&request.method==='GET'){rollbackClock=false;Date.now=()=>fixtureDateNow()-10000;postMessage({fixture_clock_rollback:true});}return response;});};self.fetch=async(input,init)=>{const request=input instanceof Request?input:new Request(input,init);if(dispatchControl&&request.url.includes('/renew?')){const repeat=request.clone(),control=dispatchControl;dispatchControl=null;const response=await observedFetch(input,init);if(control.authorization)repeat.headers.set('Authorization',control.authorization);await observedFetch(repeat);return response;}return observedFetch(input,init);};const original=onmessage;onmessage=async e=>{const f=e.data?.request?.fixture;if(!f){await original(e);if(e.data?.request?.task||e.data?.request?.goal_accept)postMessage({fixture_task_complete:true});if(e.data?.request?.lifecycle)postMessage({fixture_lifecycle:e.data.request.lifecycle});return;}if(f.rollbackClock)rollbackClock=true;if(f.restoreClock)Date.now=fixtureDateNow;if(f.providerCustody)postMessage({fixture_provider_custody:fixtureApi.provider_key_is_set(),fixture_provider_custody_point:f.providerCustody});if(f.dispatchControl)dispatchControl=f.dispatchControl;if(f.hold){let release;const p=new Promise(r=>release=r);fixtureHolds.set(f.hold,release);fixtureApi.test_hold_session_point(f.hold,p,()=>postMessage({fixture_point:f.hold}));}if(f.release)fixtureHolds.get(f.release)?.();if(f.fail)await fixtureApi.test_seed_backup_fail_append();if(f.command)postMessage({fixture_command:JSON.parse(await fixtureApi.run_command(JSON.stringify({machine:'machine-a',command:'true'})))});if(f.scanRestore)postMessage({fixture_scan_restored:await fixtureApi.test_scan_reload(false)});if(f.scanUnavailable){await fixtureApi.test_scan_fixture('approval fixture',new Uint8Array(new TextEncoder().encode('required-secret-1234')));await fixtureApi.test_scan_reload(true);postMessage({fixture_scan_unavailable:true});}if(f.journalNeedles){let contains=false,available=true;for(const needle of f.journalNeedles){const result=JSON.parse(await fixtureApi.test_poc_journal(needle));available &&=typeof result.contains==='boolean'&&Number.isSafeInteger(result.records)&&result.records>0;contains ||=result.contains===true;}postMessage({fixture_journal_batch:{contains,available,checked:f.journalNeedles.length}});}if(f.journal){const result=JSON.parse(await fixtureApi.test_poc_journal(f.journal));postMessage({fixture_journal:result});}if(f.probe)postMessage({fixture_probe:JSON.parse(await fixtureApi.test_poc_protect_output(JSON.stringify(f.probe)))});postMessage({fixture_ack:true});};\n`;
  page=createServer(tls,async(req,res)=>{
    try{
      if(req.url==='/credential-trap'){errors.push('redirect reached credential trap');res.writeHead(400).end();return;}
      const path=new URL(req.url,'https://fixture.invalid').pathname;const file=path==='/'?'index.html':path.slice(1);
      if(!/^(index.html|boot.js|worker.js|pkg\/[a-zA-Z0-9_.-]+)$/.test(file)){res.writeHead(404).end();return;}
      let data=await readFile(join('dist/tracer',file));
      if(file==='index.html')check(data.toString().includes(requiredCsp),'served CSP unchanged');
      if(file==='worker.js'){res.setHeader('Content-Security-Policy',requiredCsp.match(/content="([^"]+)"/)[1]);data=data.toString()+injection;}
      res.setHeader('Set-Cookie','fixture_cookie=must_be_omitted; Secure; SameSite=None');
      res.setHeader('Content-Type',file.endsWith('.wasm')?'application/wasm':file.endsWith('.html')?'text/html':'text/javascript');res.end(data);
    }catch{res.writeHead(500).end('fixture file refused');}
  });
  page.listen(0,'127.0.0.1');await once(page,'listening');
  const pageOrigin=`https://127.0.0.1:${page.address().port}`;
  browser=spawn(process.env.CHROME,['--headless','--no-sandbox','--disable-gpu','--disable-background-networking','--disable-component-update','--disable-sync','--disable-default-apps','--no-first-run','--remote-debugging-port=0','--ignore-certificate-errors-spki-list='+spki+','+fixtureInfo.spki,'--user-data-dir='+join(temp,'profile'),'about:blank'],{stdio:['ignore','ignore','pipe']});
  const endpoint=await new Promise((resolve,reject)=>{let output='';browser.stderr.on('data',chunk=>{output=(output+chunk).slice(-8192);const m=output.match(/DevTools listening on (ws:\/\/\S+)/);if(m)resolve(m[1]);});browser.once('exit',()=>reject(Error('fixture browser exited')));});
  socket=new WebSocket(endpoint);await once(socket,'open');let sequence=0;const calls=new Map();
  socket.addEventListener('message',e=>{const message=JSON.parse(e.data),p=calls.get(message.id);if(p){calls.delete(message.id);message.error?p.reject(Error('browser command failed')):p.resolve(message.result);}});
  socket.addEventListener('close',()=>{for(const pending of calls.values())pending.reject(Error('fixture browser connection closed'));calls.clear();});
  const call=(method,params={},sessionId)=>new Promise((resolve,reject)=>{const id=++sequence;calls.set(id,{resolve,reject});socket.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));});
  const {targetId}=await call('Target.createTarget',{url:'about:blank'}),{sessionId}=await call('Target.attachToTarget',{targetId,flatten:true});
  await call('Page.enable',{},sessionId);
  await call('Page.addScriptToEvaluateOnNewDocument',{source:`window.reports=[];window.events=[];window.workers=[];window.sinkLogs=[];window.addEventListener('error',()=>sinkLogs.push('page error'));const Original=Worker;window.Worker=class extends Original{constructor(...args){super(...args);workers.push(this);this.addEventListener('message',e=>{if(e.data.store)reports.push(e.data.store);else if(Object.keys(e.data).some(k=>k.startsWith('fixture_'))){events.push(e.data);e.stopImmediatePropagation();}});}};`},sessionId);
  const evaluate=async expression=>{
    const r=await call('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true},sessionId);
    if(r.exceptionDetails){
      const details=r.exceptionDetails,exception=details.exception;
      // Only fixed diagnostic text and numeric coordinates may leave the page.
      const classes=['Error','TypeError','ReferenceError','SyntaxError','RangeError','URIError','EvalError','AggregateError','AssertionError'];
      const kind=classes.includes(exception?.className)?exception.className:'[withheld class]';
      const message=kind==='Error'&&exception?.description?.split('\n',1)[0]==='Error: fixture wait'?'fixture wait':'[withheld message]';
      const frame=details.stackTrace?.callFrames?.[0];
      const coordinate=value=>Number.isSafeInteger(value)&&value>=0&&value<10000000;
      // Awaited rejections may carry their location only in the first anonymous stack frame.
      const anonymous=exception?.description?.split('\n')[1]?.match(/^    at (?:[^()\r\n]+ \()?<anonymous>:([1-9][0-9]{0,6}):([1-9][0-9]{0,6})\)?$/);
      const location=coordinate(frame?.lineNumber)&&coordinate(frame?.columnNumber)
        ?[frame.lineNumber+1,frame.columnNumber+1]
        :anonymous?[Number(anonymous[1]),Number(anonymous[2])]:['unknown','unknown'];
      throw Error(`page evaluation failed: ${kind}: ${message}; throw line ${location[0]}, column ${location[1]} (source text withheld)`);
    }
    return r.result.value;
  };
  const invoke=(fn,...args)=>evaluate(`(${fn.toString()})(...${JSON.stringify(args)})`);
  const wait=(expression,limit=45000)=>evaluate(`new Promise((resolve,reject)=>{const started=performance.now();const poll=()=>{const result=(${expression});if(result)return resolve(result);if(performance.now()-started>${limit})return reject(Error('fixture wait'));setTimeout(poll,25);};poll();})`);
  const click=selector=>invoke(s=>document.querySelector(s).click(),selector);
  const message=data=>invoke(d=>workers.at(-1).postMessage(d),data);
  const report=()=>evaluate('reports.at(-1)');
  const action=async value=>{
    const request={...value};
    if(value.action==='approve'&&!Object.hasOwn(value,'selection'))request.selection=structuredClone((await report()).procurement?.selection??null);
    if(value.action==='initial_invoice'&&!Object.hasOwn(value,'billing'))request.billing=structuredClone((await report()).procurement?.billing??null);
    await sleep(1100);const n=await evaluate('reports.length');await message({provider_request:request});await wait(`reports.length>${n}`);const result=await report();if(['origin-entry','custom-origin-entry'].includes(scenario)&&result.procurement?.phase)check(alternateContacts===allowedAlternateContacts,'wrong origin receives no bound-Purchase traffic');return result;
  };
  const clickInitialInvoice=async()=>{await sleep(1100);const n=await evaluate('reports.length');await click('#tau-provider-invoice');await wait(`reports.length>${n}`);return report();};
  const journalMetadata=async()=>{
    await evaluate('events=events.filter(e=>!e.fixture_journal)');
    await message({fixture:{journal:'fixture-journal-inspection-marker'}});
    const result=await wait('events.find(e=>e.fixture_journal)?.fixture_journal');
    check(result.contains===false&&Number.isSafeInteger(result.records)&&result.records>0&&Number.isSafeInteger(result.provider_protection)&&result.provider_protection>=0&&result.provider_protection<result.records&&Number.isSafeInteger(result.machines)&&Number.isSafeInteger(result.passes)&&result.targets===0,'authenticated unselected journal and allocation observed');
    return {records:result.records,providerProtection:result.provider_protection,machines:result.machines,passes:result.passes,targets:result.targets};
  };
  const setOrigin=value=>invoke(value=>{document.querySelector('#tau-provider-origin').value=value;},value);
  const setKey=async keyValue=>{const n=await evaluate('reports.length');await invoke(key=>{document.querySelector('#tau-provider-key').value=key;document.querySelector('#tau-provider-key-form').requestSubmit();},keyValue);await wait(`reports.length>${n}`);check(await evaluate("document.querySelector('#tau-provider-key').value===''") ,'provider password cleared before evidence');return report();};
  const collectDispatches=async()=>{dispatches.push(...await evaluate('events.filter(e=>e.fixture_dispatch).map(e=>e.fixture_dispatch)'));await evaluate('events=events.filter(e=>!e.fixture_dispatch)');};
  const reload=async()=>{await collectDispatches();await evaluate('workers.at(-1).terminate()');await call('Page.reload',{},sessionId);await wait("reports.at(-1)?.store_state==='locked'");await invoke(()=>{document.querySelector('#tau-passphrase').value='provisioning fixture passphrase';document.querySelector('#tau-unlock').click();});await wait("reports.at(-1)?.store_state==='unlocked'");check(!(await report()).provider_configuration.key_set,'reload clears provider custody');const before=Object.values(counts).reduce((a,b)=>a+b,0);const refused=await action({action:'catalogue'});check(refused.store_error?.includes('Re-enter'),'provider reads require fresh key entry after reload');check(Object.values(counts).reduce((a,b)=>a+b,0)===before,'keyless reload sends no provider traffic');};
  await call('Page.navigate',{url:pageOrigin+'/'},sessionId);await wait("reports.at(-1)?.store_state==='none'");
  await invoke(()=>{document.querySelector('#tau-passphrase').value=document.querySelector('#tau-confirm').value='provisioning fixture passphrase';document.querySelector('#tau-create').click();});
  await wait("!document.querySelector('#tau-seed-backup-answer').disabled");await click('#tau-seed-backup-answer');await wait("!document.querySelector('#tau-seed-backup-skip').disabled");await click('#tau-seed-backup-skip');await wait("!document.querySelector('#tau-provider-key-form button').disabled");
  const beforeAccountEntry=await journalMetadata();
  if(originCase)await setOrigin(providerOrigin+'/');
  check(!(await setKey(secret)).store_error,'provider key accepted');
  if(originCase){check((await report()).provider_configuration.origin===providerOrigin,'entered origin normalized by worker');originChecks++;}
  assert.deepEqual(await journalMetadata(),beforeAccountEntry,'account entry keeps private-key scan material out of the journal');
  let current=await action({action:'catalogue'});if(scenario==='missing-limits'){check(current.store_error&&!current.provider_catalogue,'missing limits object refuses catalogue before approval');check(!Object.values(effects).some(Boolean),'missing limits creates no provider effect');missingLimitsRefusals++;fixed.limits={};current=await action({action:'catalogue'});check(current.store_error&&!current.provider_catalogue,'missing custom limits object refuses catalogue before approval');missingLimitsRefusals++;custom.limits={};current=await action({action:'catalogue'});}if(!current.provider_catalogue)throw Error(JSON.stringify({reason:current.store_error,counts,errors}));  check(current.provider_catalogue.offers.templates.length===2,'actual catalogue fetched');
  check(await evaluate("[...document.querySelectorAll('#tau-provider-offer option')].some(o=>o.textContent.includes('London'))"),'London selectable');
  check(await evaluate("[...document.querySelectorAll('#tau-provider-offer option')].find(o=>o.textContent.includes('Hourly')).disabled"),'hourly unsupported before approval');
  check(await evaluate("[...document.querySelectorAll('#tau-provider-image option')].find(o=>o.value==='4').disabled"),'encrypted image unsupported before approval');
  let signatureEncodingChecks=0,signatureReloadChecks=0;
  if(scenario==='signature-encodings'){
    const nonProtectionJournal=({records,providerProtection,...allocation})=>({records:records-providerProtection,...allocation});
    const beforeSignatureProbes=nonProtectionJournal(await journalMetadata());
    const noSelection=value=>!Object.hasOwn(value,'procurement')||(value.procurement?.selection===null&&!value.procurement.phase);
    const ordinaryRefusal=value=>value.store_state==='unlocked'&&value.lifecycle_state!=='reconciling'&&value.lifecycle_state!=='ended'&&value.store_error==='Provider response refused; saved identities remain unchanged.';
    for(const mode of [0,1,2]){
      echoSignatureMode=mode;heldSignatureEcho=null;
      let refused=await action({action:'catalogue'});
      check(ordinaryRefusal(refused)&&!refused.provider_catalogue,'encoded request signature refused before catalogue publication');
      check(heldSignatureEcho?.length===(mode===0?88:128),'actual schema-valid signature representation selected');signatureEncodingChecks++;
      await reload();await setKey(secret);
      refused=await action({action:'catalogue'});
      check(ordinaryRefusal(refused)&&!refused.provider_catalogue,'prior request signature refused after worker reload');signatureReloadChecks++;
      refused=await action({action:'select',choice:{offer_id:1,image_id:3,resources:null}});
      check(ordinaryRefusal(refused)&&noSelection(refused),'encoded request signature refused before selection or approval');
      refused=await action({action:'approve',approval:{origin:(await report()).provider_configuration.origin,machine:'machine-a',relay:fixtureInfo.relay,class_answer:'no',approve_charge:true,approve_maintained_access:true}});
      check(refused.store_state==='unlocked'&&refused.store_error==='Invalid provisioning request.'&&noSelection(refused),'unsafe signature evidence cannot become an approved entry');
      assert.deepEqual(nonProtectionJournal(await journalMetadata()),beforeSignatureProbes,'signature refusals preserve every non-protection journal record and allocation');
    }
    echoSignatureMode=null;heldSignatureEcho=null;
    current=await action({action:'catalogue'});
    check(current.provider_catalogue&&!current.store_error,'fresh unmodified catalogue remains usable after reload signature refusals');
  }
  if(scenario==='lifecycle'){
    transport='delayed';const before=await evaluate('reports.length'),imagesBefore=count('GET /api/v1/image');
    await sleep(1100);await message({provider_request:{action:'catalogue'}});
    for(let attempt=0;!heldProviderResponse&&attempt<200;attempt++)await sleep(25);check(heldProviderResponse,'real provider read is pending');
    const freezing=Date.now();await invoke(()=>document.dispatchEvent(new Event('freeze')));await wait("events.some(e=>e.fixture_lifecycle==='freeze')");check(Date.now()-freezing<2000,'freeze promptly aborts the active provider request');
    heldProviderResponse();heldProviderResponse=null;await sleep(200);
    check(count('GET /api/v1/image')===imagesBefore,'freeze cancels provider continuation before another read');
    check(!await evaluate(`reports.slice(${before}).some(r=>r.provider_catalogue)`),'late provider response cannot publish after freeze');
    transport=null;await invoke(()=>document.dispatchEvent(new Event('resume')));await wait("events.some(e=>e.fixture_lifecycle==='resume')");
    check((await action({action:'catalogue'})).provider_catalogue,'explicit resumed read works after cancellation');
  }else if(scenario==='transport'||scenario==='credentials') {
    const probes=scenario==='transport'?['redirect','oversized','malformed','stall']:[secret,Buffer.from(secret).toString('hex'),Buffer.from(secret).toString('base64'),inference];
    if(scenario==='credentials') {await invoke(url=>{document.querySelector('#tau-poc-endpoint').value=url;document.querySelector('#tau-poc-model').value='fixture-a';document.querySelector('#tau-poc-key').value='fixture~inference~key~482700';document.querySelector('#tau-poc-inference-form').requestSubmit();},providerOrigin+'/inference');await wait('reports.at(-1)?.poc_configuration?.key_set');}
    for(const probe of probes){if(scenario==='transport')transport=probe;else echo=probe;const r=await action({action:'catalogue'});check(r.store_error&&!r.provider_catalogue,'unsafe or bounded response refused');}
    transport=null;echo=null;
  } else {
    const choice={offer_id:isCustom?2:1,image_id:3,resources:isCustom?resources:null};
    await sleep(1100);let submitted=await evaluate('reports.length');
    await invoke((choice,kind)=>{document.querySelector('#tau-provider-offer').value=kind+':'+choice.offer_id;document.querySelector('#tau-provider-image').value=String(choice.image_id);document.querySelector('#tau-provider-resources').value=JSON.stringify(choice.resources??{});document.querySelector('#tau-provider-selection-form').requestSubmit();},choice,isCustom?'custom':'fixed');await wait(`reports.length>${submitted}`);current=await report();check(!current.store_error&&current.procurement.selection,'selected current price');
    const approval={origin:current.procurement.origin,machine:'machine-a',relay:fixtureInfo.relay,class_answer:'no',approve_charge:true,approve_maintained_access:true};
    if(originCase){
      check(await invoke(origin=>document.querySelector('#tau-provider-selection-view').textContent.includes(origin),providerOrigin),'plan review names normalized origin');
      if(scenario==='origin-validation'){
        const before=await journalMetadata(),selection=structuredClone(current.procurement.selection),requests=Object.values(counts).reduce((a,b)=>a+b,0);
        const invalid=['','http://127.0.0.1','https://','https://@127.0.0.1','https://'+secret+'@127.0.0.1',providerOrigin+'?',providerOrigin+'#',providerOrigin+'/..',providerOrigin+'/%2e',providerOrigin+'\\',' '+providerOrigin,providerOrigin+'\t/', 'https://[::1','https://127.0.0.1:65536'];
        for(const value of invalid){
          await setOrigin(value);const refused=await setKey(other);
          check(refused.store_error&&refused.procurement.origin===providerOrigin,'invalid origin preserves configured authority');
          assert.deepEqual(refused.procurement.selection,selection,'invalid configuration preserves reviewed selection');
          assert.deepEqual(await journalMetadata(),before,'invalid origin changes neither journal nor allocation');originChecks++;
        }
        const alias='a'.repeat(42)+'c',candidate=Buffer.from(alias,'base64').toString('hex');
        await setOrigin('https://'+alias.toUpperCase()+'.invalid');const refused=await setKey(candidate);
        check(refused.store_error?.includes('protected or unscannable')&&refused.procurement.origin===providerOrigin,'normalization cannot introduce candidate key material');
        assert.deepEqual(await journalMetadata(),before,'normalized-key refusal preserves journal and allocation');originChecks++;
        check(Object.values(counts).reduce((a,b)=>a+b,0)===requests&&alternateContacts===0,'invalid origins dispatch nothing');
        check(await invoke(()=>document.querySelector('#tau-provider-origin').value===reports.at(-1).procurement.origin),'raw rejected entry cleared');
      }
      if(scenario==='origin-stale-review'){
        const stale=structuredClone(approval),selection=structuredClone(current.procurement.selection);
        await setOrigin(alternateOrigin);check(!(await setKey(secret)).store_error,'second origin configured');
        check(!(await report()).procurement?.selection,'origin change invalidates old review');
        current=await action({action:'select',choice});assert.deepEqual(current.procurement.selection,selection,'both origins offer identical terms');
        const before=await journalMetadata(),requests=Object.values(counts).reduce((a,b)=>a+b,0);
        current=await action({action:'approve',approval:stale,selection});
        check(current.store_error?.includes('origin is stale')&&!current.procurement.phase,'stale origin consent refused at worker boundary');
        check(Object.values(counts).reduce((a,b)=>a+b,0)===requests,'stale consent dispatches nothing');assert.deepEqual(await journalMetadata(),before);
        await setOrigin(providerOrigin);await setKey(secret);current=await action({action:'select',choice});
        allowedAlternateContacts=alternateContacts;check(allowedAlternateContacts>0,'second loopback provider actually observed during review');originChecks++;
      }
    }
    if(scenario==='approval-authority'){
      const setInference=async key=>{const n=await evaluate('reports.length');await invoke((url,key)=>{document.querySelector('#tau-poc-endpoint').value=url;document.querySelector('#tau-poc-model').value='fixture-a';document.querySelector('#tau-poc-key').value=key;document.querySelector('#tau-poc-inference-form').requestSubmit();},providerOrigin+'/inference',key);await wait(`reports.length>${n}&&reports.at(-1)?.poc_configuration?.key_set`);};
      const retained='retained-inference-key-9751';await setInference(retained);await setInference(inference);
      const before=await journalMetadata(),approvedSelection=structuredClone((await report()).procurement.selection);let refusalsChecked=0;
      for(const key of [inference,retained])for(const alias of [Buffer.from(key).toString('hex'),key,Buffer.from(key).toString('hex').toUpperCase(),Buffer.from(key).toString('base64'),Buffer.from(key).toString('base64url'),[...Buffer.from(key)].map(b=>'%'+b.toString(16).padStart(2,'0')).join('')]){
        for(const field of ['machine','relay']){
          const candidate={...approval,[field]:field==='machine'?alias:fixtureInfo.relay+alias+'/'};
          await sleep(1100);const n=await evaluate('reports.length');await invoke(approval=>{document.querySelector('#tau-provider-machine').value=approval.machine;document.querySelector('#tau-provider-relay').value=approval.relay;document.querySelector('#tau-provider-class').value=approval.class_answer;document.querySelector('#tau-provider-approve-charge').checked=document.querySelector('#tau-provider-approve-access').checked=true;document.querySelector('#tau-provider-approval-form').requestSubmit();},candidate);await wait(`reports.length>${n}`).catch(async error=>{console.log(JSON.stringify({approvalDiagnostic:await evaluate("({error:reports.at(-1)?.store_error,phase:reports.at(-1)?.procurement?.phase,disabled:document.querySelector('#tau-provider-approve-charge').disabled,valid:document.querySelector('#tau-provider-approval-form').checkValidity()})"),field,aliasIndex:refusalsChecked}));throw error;});current=await report();
          check(current.store_error?.includes('protected or unscannable')&&!current.procurement.phase,'encoded inference key refused before durable approval');
          assert.deepEqual(await journalMetadata(),before,'credential refusal preserves journal and allocated identities');
          check(!machines.length&&!Object.values(effects).some(Boolean),'refused authority permits no mutation');
          await evaluate('events=events.filter(e=>!e.fixture_journal_batch)');await message({fixture:{journalNeedles:[alias]}});const inspected=await wait('events.find(e=>e.fixture_journal_batch)?.fixture_journal_batch');check(inspected.available&&inspected.checked===1&&!inspected.contains,'encoded inference absent from authenticated durable entries');
          refusalsChecked++;
        }
      }
      await message({fixture:{scanUnavailable:true}});await wait('events.some(e=>e.fixture_scan_unavailable)');
      current=await action({action:'approve',approval,selection:approvedSelection});check(current.store_error&&!current.procurement?.phase,'unscannable authority refused before durable approval');assert.deepEqual(await journalMetadata(),before);
      await message({fixture:{scanRestore:true}});await wait('events.some(e=>e.fixture_scan_restored)');await reload();await setKey(secret);check(!(await report()).procurement?.phase,'refusal remains unapproved after reload');assert.deepEqual(await journalMetadata(),before);
      await setInference(retained);await setInference(inference);current=await action({action:'select',choice});current=await action({action:'approve',approval});check(!current.store_error&&current.procurement.phase==='approved','safe authority remains approvable with both credential generations protected');check(!Object.values(effects).some(Boolean),'approval alone has no provider effect');
      console.log(JSON.stringify({approvalAuthorityRefusals:refusalsChecked,unscannableRefusals:1,journalUnchanged:true,identitiesUnchanged:true}));
    }else if(scenario==='refusals'){
      changePrice=true;check((await action({action:'approve',approval})).store_error,'changed price needs renewed approval');check(!(await report()).procurement.phase,'changed charge not approved');
      check((await action({action:'select',choice:{offer_id:4,image_id:3,resources:null}})).store_error,'worker refuses hourly plan');
      check((await action({action:'select',choice:{offer_id:1,image_id:4,resources:null}})).store_error,'worker refuses encrypted image');
      check((await action({action:'select',choice:{offer_id:2,image_id:3,resources:{...resources,cpu:999}}})).store_error,'worker refuses invalid custom counts');
      check(!machines.length,'refused configuration never orders');
    }else{
      await sleep(1100);submitted=await evaluate('reports.length');await invoke(approval=>{for(const [name,value]of Object.entries({machine:approval.machine,relay:approval.relay,class:approval.class_answer}))document.querySelector('#tau-provider-'+name).value=value;document.querySelector('#tau-provider-approve-charge').checked=document.querySelector('#tau-provider-approve-access').checked=true;document.querySelector('#tau-provider-approval-form').requestSubmit();},approval);await wait(`reports.length>${submitted}`);current=await report();check(!current.store_error&&current.procurement.phase==='approved','exact configuration durably approved');
      check((await control({inspect:true})).contacts===0,'no contact before published pin');
      const identity=current.procurement.identity;
      if(originCase){
        await setOrigin(alternateOrigin);await setKey(secret);
        check((await report()).procurement.origin===providerOrigin,'entry cannot redirect approved Purchase');
        await reload();await setOrigin(alternateOrigin);await setKey(secret);
        current=await report();check(current.procurement.origin===providerOrigin,'reload and different field retain bound origin');
        assert.deepEqual(current.procurement.identity,identity);originChecks++;
      }
      const selectedAtApproval=structuredClone(current.procurement.selection);
      const publicKeys=current.procurement.public_keys;
      if(scenario.includes('-terms')||scenario.includes('-config')){
        changePrice=scenario.includes('-terms');changeConfig=scenario.includes('-config');
        if(scenario.endsWith('-reload')){await reload();await setKey(secret);}
        current=await action({action:'resume'});
        check(current.store_error&&current.procurement.phase==='terms_changed','changed current terms pause before create intent');
        check(!machines.length&&!(effects[createRoute]??0),'changed terms never create');
        assert.deepEqual(current.procurement.identity,identity);assert.deepEqual(current.procurement.public_keys,publicKeys);
        check((effects['POST /api/v1/ssh-key']??0)===1,'registration association retained for review');
        if(scenario==='fixed-terms'||scenario==='custom-terms'){
          current=await action({action:'approve',approval,selection:undefined});
          check(current.store_error&&current.procurement.phase==='terms_changed','missing displayed selection cannot approve changed terms');
        }
        current=await action({action:'approve',approval,selection:selectedAtApproval});
        check(current.store_error&&current.procurement.phase==='terms_changed'&&(effects[createRoute]??0)===0,'stale displayed selection cannot approve changed terms');
        assert.deepEqual(current.procurement.identity,identity);
        await reload();await setKey(secret);current=await report();
        check(current.procurement.phase==='terms_changed','pending terms survive replay without authority');
        check(!await evaluate("document.querySelector('#tau-provider-approve-charge').checked"),'renewed charge approval is explicit after reload');
        check(await evaluate("document.querySelector('#tau-provider-machine').value==='machine-a'&&document.querySelector('#tau-provider-machine').disabled"),'same machine identity displayed and locked');
        current=await action({action:'resume'});check(current.store_error&&current.procurement.phase==='terms_changed','Resume cannot approve changed terms');
        await sleep(1100);const reviewed=await evaluate('reports.length');await invoke(()=>{document.querySelector('#tau-provider-approve-charge').checked=document.querySelector('#tau-provider-approve-access').checked=true;document.querySelector('#tau-provider-approval-form').requestSubmit();});await wait(`reports.length>${reviewed}`);current=await report();check(!current.store_error&&current.procurement.phase==='registered'&&current.procurement.ssh_key_id===7,'renewed explicit page approval retains registered SSH identity');
        assert.deepEqual(current.procurement.identity,identity);assert.deepEqual(current.procurement.public_keys,publicKeys);
        await reload();await setKey(secret);
      }
      if(scenario==='custom-resource'){
        raiseMinimum=true;current=await action({action:'resume'});check(current.store_error&&!machines.length,'invalidated custom resource terms cannot create');
        await reload();await setKey(secret);selectedResources={...resources,cpu:3};
        current=await action({action:'select',choice:{offer_id:2,image_id:3,resources:selectedResources}});check(!current.store_error&&current.procurement.phase==='terms_changed','valid custom resources require renewed approval');
        current=await action({action:'approve',approval});check(!current.store_error&&current.procurement.phase==='registered'&&current.procurement.ssh_key_id===7,'same identity approves changed valid custom resources with retained SSH identity');assert.deepEqual(current.procurement.identity,identity);assert.deepEqual(current.procurement.public_keys,publicKeys);
      }
      if(['fixed-unavailable','custom-unavailable'].includes(scenario)){failCatalogue=true;current=await action({action:'resume'});check(current.store_error&&!machines.length,'unavailable selected terms send no create');assert.deepEqual(current.procurement.identity,identity);failCatalogue=false;await reload();await setKey(secret);}
      if(scenario==='failed-write'){await message({fixture:{fail:true}});await wait('events.some(e=>e.fixture_ack)');}
      if(['pre-send-reload','associated-reload'].includes(scenario)){
        const point=scenario==='pre-send-reload'?'procurement_create_intent':'procurement_associated';await message({fixture:{hold:point}});await sleep(1100);await message({provider_request:{action:'resume'}});await wait(`events.some(e=>e.fixture_point===${JSON.stringify(point)})`);await reload();check((await setKey(other)).store_error,'different account cannot resume');await setKey(secret);
      }
      if(deadlineCase){
        if(scenario==='custom-deadline-clock')await message({fixture:{rollbackClock:true}});
        responseDelay=deadlineInside?5000:11000;
        await sleep(1100);const before=await evaluate('reports.length'),started=Date.now();
        await message({provider_request:{action:'resume'}});
        // This dedicated wait covers the product's 60-second deadline, not the ordinary fixture wait.
        const deadlineReport=await evaluate(`new Promise((resolve,reject)=>{const started=performance.now();const poll=()=>{if(reports.length>${before})return resolve(reports.at(-1));if(performance.now()-started>75000)return reject(Error('deadline action did not return'));setTimeout(poll,25);};poll();})`);
        const elapsed=Date.now()-started;responseDelay=0;
        if(scenario==='custom-deadline-clock'){check(await evaluate('events.some(e=>e.fixture_clock_rollback)'),'worker wall clock rollback actually applied');await message({fixture:{restoreClock:true}});}
        console.log(JSON.stringify({deadlineObservation:{elapsedMilliseconds:elapsed,phase:deadlineReport.procurement?.phase,wallClockRollback:scenario==='custom-deadline-clock'}}));
        if(deadlineInside){
          check(elapsed<60000&&deadlineReport.procurement?.phase==='initial_invoice'&&deadlineReport.procurement?.vm_id===11,'action completes inside its remaining budget');
        }else{
          check(elapsed>=59000&&elapsed<64000,'remaining action deadline promptly cancels the pending exchange');
          for(let attempt=0;responseAborts===0&&attempt<40;attempt++)await sleep(25);
          check(responseAborts===1,'deadline abort cancels the active provider HTTP exchange');
          check(deadlineReport.store_error&&deadlineReport.procurement?.phase==='create_uncertain'&&!deadlineReport.procurement?.vm_id,'timed-out create retains uncertain intent without late success');
          check(machines.length===1&&(effects[createRoute]??0)===1&&!payments.length,'deadline cancellation preserves one possible create and no invoice');
          const savedPurchase=structuredClone(deadlineReport.procurement);
          check(!(await setKey(secret)).store_error,'deadline releases store authority for credential re-entry');
          await sleep(7500);
          assert.deepEqual((await report()).procurement,savedPurchase,'late headers or body cannot revive timed-out authority');
          await reload();await setKey(secret);
          assert.deepEqual((await report()).procurement,savedPurchase,'deadline uncertainty survives reload and same-account re-entry');
        }
        deadlineMeasurement={elapsedMilliseconds:elapsed,responseDelayMilliseconds:deadlineInside?5000:11000,phase:deadlineReport.procurement.phase,pending:scenario.endsWith('body')?'body':'headers',insideBudget:deadlineInside,responseAborts,wallClockRollback:scenario==='custom-deadline-clock'};
        console.log(JSON.stringify({deadlineMeasurement}));
      }
      if(scenario==='fixed'){await sleep(1100);const start=await evaluate('reports.length');await invoke(()=>{workers.at(-1).postMessage({provider_request:{action:'resume'}});workers.at(-1).postMessage({provider_request:{action:'resume'}});});await wait(`reports.slice(${start}).some(r=>r.procurement?.vm_id===11&&r.procurement?.phase==='initial_invoice')`);}
      current=await action({action:'resume'});
      if(lostCreate||scenario==='registration')check(/outcome.*unknown/i.test(current.store_error??''),'lost mutation diagnostic preserves unknown outcome and saved intent');
      if(transferCase&&transferPhase!=='later'){
        check(current.store_error&&current.procurement.phase==='create_uncertain'&&!current.procurement.vm_id,'unmetered offer cannot acquire an unapproved transfer cap');transferChecks++;
        const savedPurchase=structuredClone(current.procurement);
        await reload();await setKey(secret);
        for(let attempt=0;attempt<2;attempt++){
          current=await action({action:'resume'});check(current.store_error&&current.procurement.phase==='create_uncertain'&&!current.procurement.vm_id,'transfer contradiction keeps the uncertain create intent');transferChecks++;
          assert.deepEqual(current.procurement.identity,identity);assert.deepEqual(current.procurement.public_keys,publicKeys);assert.deepEqual(current.procurement.approved_selection,savedPurchase.approved_selection);
          check((effects[createRoute]??0)===1&&!(effects[invoiceRoute]??0)&&!current.poc_targets?.length,'transfer contradiction never reorders, invoices or hands off');
        }
        transferBad=false;current=await action({action:'resume'});check(current.procurement.vm_id===11&&current.procurement.phase==='initial_invoice','matching unmetered evidence recovers only the same created VM');
      }
      if(capsBad){
        check(current.store_error&&current.procurement.phase==='create_uncertain'&&!current.procurement.vm_id,(isCustom?'custom':'fixed')+' inherited caps must match before association');
        inheritedCapChecks++;const uncertain=structuredClone(current.procurement);
        await reload();await setKey(secret);
        for(let attempt=0;attempt<2;attempt++){
          current=await action({action:'resume'});check(current.store_error&&current.procurement.phase==='create_uncertain'&&!current.procurement.vm_id,'custom caps refusal preserves uncertainty on reconciliation');
          inheritedCapChecks++;assert.deepEqual(current.procurement.identity,identity);assert.deepEqual(current.procurement.public_keys,publicKeys);assert.deepEqual(current.procurement.approved_selection,uncertain.approved_selection);
          check((effects[createRoute]??0)===1&&!(effects[invoiceRoute]??0)&&!current.poc_targets?.length,'cap refusal never reorders, invoices or hands off');
        }
        check((await action({action:'approve',approval})).store_error,'cap uncertainty cannot be reset by approval');check((await action({action:'select',choice})).store_error,'cap uncertainty cannot be reset by selection');
        console.log(JSON.stringify({capRefusal:{phase:current.procurement.phase,vmId:current.procurement.vm_id??null,approvedLimits:current.procurement.approved_selection.offer.limits??{},observedLimits:returnedTemplate(machines[0].template).limits,createEffects:effects[createRoute]??0,invoiceEffects:effects[invoiceRoute]??0,checks:inheritedCapChecks}}));
        capsBad=false;current=await action({action:'resume'});check(current.procurement.vm_id===11&&current.procurement.phase==='initial_invoice','matching inherited caps recover only the same created VM');
      }
      if(cpuCase&&cpuPhase!=='later'){
        check(current.store_error&&current.procurement.phase==='create_uncertain'&&!current.procurement.vm_id,'CPU evidence refuses direct or uncertain association');
        await reload();await setKey(secret);
        for(const variant of cpuVariants){
          cpuVariant=variant;current=await action({action:'resume'});
          check(current.store_error&&current.procurement.phase==='create_uncertain'&&!current.procurement.vm_id,'CPU conflicting or missing evidence keeps the create intent');
          assert.deepEqual(current.procurement.identity,identity);
          check((effects[createRoute]??0)===1&&!current.poc_targets?.length,'CPU refusal never creates again or contacts an unpinned target');
        }
        cpuBad=false;current=await action({action:'resume'});
        check(current.procurement.vm_id===11&&current.procurement.phase==='initial_invoice','valid CPU evidence resumes the same created machine');
      }
      if(['empty-create','incomplete-create','multiple-create','conflicting-create','mismatched-image','pre-send-reload','registration','failed-write'].includes(scenario)||creationOffsetSeconds!==0){
        if(scenario!=='failed-write') {await reload();await setKey(secret);await action({action:'resume'});await action({action:'resume'});}
        if((await report()).procurement.phase==='create_uncertain'){const before=(await report()).procurement;check((await action({action:'approve',approval})).store_error,'uncertain create refuses renewed approval');assert.deepEqual((await report()).procurement.identity,before.identity);check((await report()).procurement.phase==='create_uncertain','renewal cannot erase possibly sent create');}
        check((await report()).store_error,'uncertainty paused concretely');
        check((effects[createRoute]??0)===(['pre-send-reload','registration','failed-write'].includes(scenario)?0:1),'uncertainty has no second accepted create');
        check((effects['POST /api/v1/ssh-key']??0)===(scenario==='failed-write'?0:1),'registration accepted at most once');
        check(!(await report()).poc_targets?.length,'no unpinned target');
      }else if(existingHistory){
        check(current.procurement.vm_id===11&&current.procurement.payment?.id==='aabb','complete initial history reuses the existing payment');
        check(current.procurement.billing?.vm_id===11,'existing history has same-VM quote evidence');
        const savedBilling=structuredClone(current.procurement.billing),quoteReads=count('GET /api/v1/vm/11/renew/quote?method=lightning&intervals=1');
        check((effects[invoiceRoute]??0)===0,'existing paid or unpaid history never issues another invoice');
        await reload();await setKey(secret);quoteVersion=1;
        current=await action({action:'initial_invoice'});assert.deepEqual(current.procurement.billing,savedBilling);
        check(count('GET /api/v1/vm/11/renew/quote?method=lightning&intervals=1')===quoteReads,'associated payment retains its original quote through reload');
        paid=true;current=await action({action:'resume'});
        check(current.procurement.phase==='handed_off'&&current.poc_targets[0].pin===hostPin,'existing payment continues into published-pin handoff');
        assert.deepEqual(current.procurement.identity,identity);check((effects[createRoute]??0)===1&&(effects[invoiceRoute]??0)===0,'history reuse preserves one machine and zero invoice effects');
      }else{
        if(lostCreate&&!cpuCase)current=await action({action:'resume'});
        check(current.procurement.vm_id===11&&current.procurement.phase==='initial_invoice','same VM durably associated, no invoice on create');
        if(capsCase){const expectedLimits={...(isCustom?custom:fixed).limits};if(isCustom)expectedLimits.network_mbps=selectedResources.network_mbps;assert.deepEqual(returnedTemplate(machines[0].template).limits,expectedLimits,'matching inherited caps retain only the explicit network override');inheritedCapChecks++;}
        if(unknownQuote){
          for(const mode of ['missing','malformed','unavailable']){
            quoteResponseMode=mode==='unavailable'?null:mode;unavailableQuote=mode==='unavailable';
            current=await action({action:'resume'});
            check(current.store_error&&current.procurement.vm_id===11&&!current.procurement.billing,'unknown initial quote pauses with the same machine');
            current=await action({action:'initial_invoice'});
            check(current.store_error&&!current.procurement.billing,'missing displayed quote cannot authorize issuance');
            check((effects[invoiceRoute]??0)===0,'unknown quote sends no invoice mutation');
          }
          await reload();await setKey(secret);quoteResponseMode=null;unavailableQuote=false;current=await action({action:'resume'});
          check(current.procurement.billing?.vm_id===11,'read-only recovery establishes a displayed initial quote');
        }
        check(current.procurement.billing?.vm_id===11,'initial one-period Lightning quote saved for the associated VM');
        const displayedBilling=structuredClone(current.procurement.billing);
        await reload();check((await setKey(other)).store_error,'account binding after reload');await setKey(secret);
        assert.deepEqual((await report()).procurement.billing,displayedBilling);
        if(scenario==='quote-change'){
          quoteVersion=1;current=await clickInitialInvoice();
          check(current.store_error&&current.procurement.billing?.terms?.amount===2000000&&(effects[invoiceRoute]??0)===0,'changed Lightning quote requires another explicit approval before invoice dispatch');
          const firstChangedBilling=structuredClone(current.procurement.billing);
          for(const missing of [undefined,null]){
            current=await action({action:'initial_invoice',billing:missing});
            check(current.store_error&&(effects[invoiceRoute]??0)===0,'missing displayed billing cannot authorize an invoice');
          }
          current=await action({action:'initial_invoice',billing:displayedBilling});
          check(current.store_error&&(effects[invoiceRoute]??0)===0,'stale displayed billing approval cannot issue an invoice');
          assert.deepEqual(current.procurement.billing,firstChangedBilling);
          await reload();await setKey(secret);quoteVersion=2;current=await clickInitialInvoice();
          check(current.store_error&&current.procurement.billing?.terms?.amount===3000000&&(effects[invoiceRoute]??0)===0,'reloaded quote changes remain read-only until renewed approval');
          current=await action({action:'initial_invoice',billing:firstChangedBilling});
          check(current.store_error&&(effects[invoiceRoute]??0)===0,'reloaded stale displayed billing cannot authorize an invoice');
          unavailableQuote=true;current=await action({action:'initial_invoice'});
          check(current.store_error&&(effects[invoiceRoute]??0)===0,'unavailable current quote cannot use a stale displayed quote');unavailableQuote=false;
        }
        if(scenario==='quote-unavailable'){
          unavailableQuote=true;current=await action({action:'initial_invoice'});
          check(current.store_error&&(effects[invoiceRoute]??0)===0,'unavailable initial quote sends no invoice');
          await reload();await setKey(secret);current=await action({action:'initial_invoice'});
          check(current.store_error&&(effects[invoiceRoute]??0)===0,'quote unavailability persists safely through reload');unavailableQuote=false;
        }
        if(scenario.startsWith('counter-')){await message({fixture:{dispatchControl:scenario==='counter-identical'?{}:{authorization:fixtureAuthorization(secret,providerOrigin+'/api/v1/vm/11/renew?method=lightning&intervals=1','GET',Buffer.alloc(0),'fresh-invoice-counter')}}});await wait('events.some(e=>e.fixture_ack)');}
        current=scenario==='quote-change'?await clickInitialInvoice():await action({action:'initial_invoice'});
        if(lostInvoice){check(/outcome.*unknown/i.test(current.store_error??''),'lost invoice diagnostic preserves unknown outcome');}
        if(lostInvoice){
          const savedBilling=structuredClone(current.procurement.billing),quoteReads=count('GET /api/v1/vm/11/renew/quote?method=lightning&intervals=1');
          if(scenario==='lost-invoice-quote-reload'){quoteVersion=1;await reload();await setKey(secret);}
          current=await action({action:'initial_invoice'});
          assert.deepEqual(current.procurement.billing,savedBilling);
          check(count('GET /api/v1/vm/11/renew/quote?method=lightning&intervals=1')===quoteReads,'possibly issued invoice reconciles with frozen quote without requoting');
        }
        if(['empty-invoice','multiple-invoice','incomplete-invoice','conflicting-invoice'].includes(scenario)){
          await reload();await setKey(secret);await action({action:'initial_invoice'});await action({action:'resume'});check((await report()).procurement.phase==='invoice_uncertain','ambiguous invoice evidence stays uncertain');check(!(await report()).procurement.payment,'no ambiguous payment identity associated');
        }else{
          check(current.procurement.payment?.id==='aabb','initial payment linked durably');
          check(current.procurement.payment.currency==='BTC'&&current.procurement.payment.time===periodSeconds,'initial payment matches the provider Lightning quote currency and duration');
          if(planCurrency!=='BTC')check(current.procurement.selection.charge.currency===planCurrency&&current.procurement.billing.terms.currency==='BTC','fiat selected plan uses separately quoted Lightning billing terms');
          check(await evaluate("document.body.textContent.includes('tax 230000')&&document.body.textContent.includes('processing fee 10000')&&document.body.textContent.includes('policy: enabled')"),'invoice tax fee and actual auto-renewal display');
          if(scenario==='expired-invoice') {await sleep(1100);current=await action({action:'resume'});check(current.store_error.includes('expired'),'expired invoice pauses without reissue');}
          else{
            paid=true;if(scenario==='later-image')machines[0].image={...image,id:9};if(capsLater)capsBad=true;if(transferPhase==='later')transferBad=true;if(cpuCase&&cpuPhase==='later')cpuBad=true;current=await action({action:'resume'});
            if(transferPhase==='later'){
              check(current.store_error&&current.procurement.vm_id===11&&!current.poc_targets?.length,'later transfer cap refuses published-pin readiness');transferChecks++;
              await reload();await setKey(secret);current=await action({action:'resume'});
              check(current.store_error&&current.procurement.vm_id===11&&!current.poc_targets?.length,'later transfer contradiction survives reload');transferChecks++;
              assert.deepEqual(current.procurement.identity,identity);check((effects[createRoute]??0)===1&&(effects[invoiceRoute]??0)===1,'later transfer contradiction cannot reorder or reissue');
              transferBad=false;current=await action({action:'resume'});
            }
            if(capsLater){
              for(const variant of ['mismatched','missing']){
                capsBad=true;capsVariant=variant;current=await action({action:'resume'});check(current.store_error&&current.procurement.vm_id===11&&!current.poc_targets?.length,'later inherited cap contradiction refuses published-pin readiness');inheritedCapChecks++;assert.deepEqual(current.procurement.identity,identity);check((effects[createRoute]??0)===1&&(effects[invoiceRoute]??0)===1,'later cap contradiction cannot reorder or reissue');await reload();await setKey(secret);
              }
              capsBad=false;current=await action({action:'resume'});
            }
            if(cpuCase&&cpuPhase==='later'){
              check(current.store_error&&current.procurement.vm_id===11&&!current.poc_targets?.length,'later CPU contradiction refuses published-pin readiness');
              await reload();await setKey(secret);
              for(const variant of cpuVariants){
                cpuVariant=variant;current=await action({action:'resume'});
                check(current.store_error&&current.procurement.vm_id===11&&!current.poc_targets?.length,'later missing or conflicting CPU evidence preserves associated identity');
                assert.deepEqual(current.procurement.identity,identity);
              }
              cpuBad=false;current=await action({action:'resume'});
            }
            if(scenario==='later-image'){check(current.store_error&&!current.poc_targets?.length,'later mismatched image refuses readiness');await reload();await setKey(secret);current=await action({action:'resume'});check(current.store_error&&current.procurement.vm_id===11&&!current.poc_targets?.length,'later mismatch preserves associated identity across replay');}else{
            if(scenario==='publication'){check(current.store_error.includes('published host key'),'empty publication truthfully waits');check(!current.poc_targets?.length,'empty publication cannot contact');publication=true;current=await action({action:'resume'});}
            check(current.procurement.phase==='handed_off','published pin handoff');check(current.poc_targets[0].pin===hostPin&&current.poc_targets[0].host==='192.0.2.10'&&current.poc_targets[0].user==='arch'&&current.poc_targets[0].elevation==='sudo -n','actual pinned immutable target');assert.deepEqual(current.procurement.identity,identity);
            check((await control({inspect:true})).contacts===0,'no contact before ordinary relay and runner approvals');
            const savedTarget=structuredClone(current.procurement.target);
            if(originCase)check(current.procurement.publication.origin===providerOrigin,'Handoff provenance uses bound origin');
            await reload();if(originCase)await setOrigin(alternateOrigin);await setKey(secret);current=await action({action:'resume'});check(current.procurement.phase==='handed_off','handoff reload replays same target');
            if(originCase){assert.deepEqual(current.procurement.target,savedTarget);assert.deepEqual(current.procurement.identity,identity);check(current.procurement.origin===providerOrigin&&current.procurement.publication.origin===providerOrigin,'replayed Handoff retains authority');originChecks++;}
            await control({keys:current.procurement.public_keys});
            await invoke(url=>{document.querySelector('#tau-poc-endpoint').value=url;document.querySelector('#tau-poc-model').value='fixture-a';document.querySelector('#tau-poc-key').value='fixture~inference~key~482700';document.querySelector('#tau-poc-inference-form').requestSubmit();},providerOrigin+'/inference');await wait('reports.at(-1)?.poc_configuration?.key_set');
            await invoke(()=>[...document.querySelectorAll('#tau-poc-targets button')].find(b=>b.textContent==='Start session machine-a').click());await wait("document.querySelector('[data-goal-enter]')");
            await invoke(()=>{document.querySelector('[data-goal-text]').value='Check a small service';document.querySelector('[data-goal-enter]').click();});await wait("document.querySelector('[data-goal-accept]')");
            await invoke(()=>{document.querySelector('[aria-label="Verification commands, one per line"]').value='true';document.querySelector('[data-goal-accept]').click();});await wait('reports.at(-1)?.tasks?.length===1');await wait("document.querySelector('[data-poc-propose]')");await click('[data-poc-propose]');await wait("document.querySelector('[data-requirements-decision=approve]')");await click('[data-requirements-decision=approve]');await wait("!document.querySelector('[data-requirements-decision=approve]')");
            if(scenario==='mismatched-host')await control({wrong_host_key:true});
            const resumeTask=async()=>{const count=await evaluate('events.filter(e=>e.fixture_task_complete).length');await invoke(()=>[...document.querySelectorAll('[data-task] button')].find(b=>b.textContent==='Resume').click());await wait(`events.filter(e=>e.fixture_task_complete).length>${count}`);};
            if(scenario==='pending-custody'){
              const responseRun=await evaluate('events.filter(e=>e.fixture_task_complete).length');await message({fixture:{hold:'poc_model_return'}});await invoke(()=>[...document.querySelectorAll('[data-task] button')].find(b=>b.textContent==='Resume').click());await wait("events.some(e=>e.fixture_point==='poc_model_return')");
              check((await setKey(secret)).store_error?.includes('command response pending'),'provider credential entry respects pending command response');
              const before=count('GET /api/v1/vm/templates');check((await action({action:'catalogue'})).store_error?.includes('command response pending'),'provider reads respect pending command response');check(count('GET /api/v1/vm/templates')===before,'no auth-filter inventory change while response pending');
              await message({fixture:{release:'poc_model_return'}});
              await wait(`events.filter(e=>e.fixture_task_complete).length>${responseRun}`);
            }
            if(scenario!=='pending-custody'||(await report()).tasks[0].status!=='complete')await resumeTask();
            if(scenario==='mismatched-host'){
              await wait("reports.at(-1)?.tasks?.[0]?.pause_reason?.includes('host-key')");check((await control({inspect:true})).launches.length===0,'mismatched first host key refuses execution');
            }else{
              for(let step=0;step<4&&(await report()).tasks[0].status!=='complete';step++)await resumeTask();
              const status=await report();check(status.tasks[0].status==='complete',JSON.stringify({reason:status.store_error,pause:status.tasks[0].pause_reason,status:status.tasks[0].status,modelCalls,errors}));const observed=await control({inspect:true});check(observed.launches.length>=2,'existing runner executes and verifies through real local SSH');check(observed.execs.every(e=>e.startsWith('sudo -n sh -c')),'existing whole-script elevation preserved');
              if(scenario==='fixed'){await control({wrong_host_key:true});await message({fixture:{command:true}});const refusal=await wait('events.find(e=>e.fixture_command)?.fixture_command');check(JSON.stringify(refusal).toLowerCase().includes('host'),'later mismatching host key refuses');const later=await control({inspect:true});check(later.launches.length===observed.launches.length&&later.authentication.length===observed.authentication.length,'later mismatch never authenticates or launches');}
            }
            }
          }
        }
        check((effects[createRoute]??0)===1,'exactly one accepted create');check((effects[invoiceRoute]??0)===(scenario==='counter-fresh'?2:1),'initial invoice accepted effects');
      }
    }
  }
  // Input fields are empty before every DOM/durable evidence scan.
  check(await evaluate("document.querySelector('#tau-provider-key').value===''&&document.querySelector('#tau-poc-key').value===''") ,'both credential inputs empty');
  const sinks=await evaluate('JSON.stringify({dom:document.documentElement.outerHTML,reports,sinkLogs})');
  for(const value of [secret,other,inference,Buffer.from(secret).toString('hex'),Buffer.from(secret).toString('base64'),...authForms])check(!sinks.includes(value),'credential absent from DOM reports and errors');
  const journalNeedles=[secret,other,inference,Buffer.from(secret).toString('hex'),Buffer.from(secret).toString('base64'),...authForms];
  await evaluate('events=events.filter(e=>!e.fixture_journal_batch)');await message({fixture:{journalNeedles}});
  const journalResult=await wait('events.find(e=>e.fixture_journal_batch)?.fixture_journal_batch',90000);
  check(journalResult.available===true&&journalResult.checked===journalNeedles.length&&journalResult.contains===false,'authenticated durable entries contain no credentials or encoded request material');
  await collectDispatches();if(originCase){check(alternateContacts===allowedAlternateContacts,'wrong origin receives no bound-Purchase traffic');check(dispatches.filter(d=>mutationRoutes.includes(d.method+' '+d.path)).every(d=>d.origin===providerOrigin),'all mutations dispatched to bound origin');originChecks++;}check(!errors.length,'all provider transport and schema checks passed');for(const route of mutationRoutes)check(count(route)===(effects[route]??0)+(replays[route]??0)+(refusals[route]??0),'every raw mutation has one disposition: '+route);
  if(scenario.startsWith('counter-')){check(mutationDispatches()[invoiceRoute]===2,'second application invocation observed, including identical bytes');assert.throws(enforceCounts,/at most one application dispatch/);if(scenario==='counter-identical')check(replays[invoiceRoute]===1&&effects[invoiceRoute]===1,'identical second application invocation rejected before second effect');else check(!replays[invoiceRoute]&&effects[invoiceRoute]===2,'fresh second invocation is an independent accepted effect, never a replay');}else enforceCounts();
  const beforeLock=await report();
  await evaluate('events=events.filter(e=>!Object.hasOwn(e,"fixture_provider_custody"))');
  await message({fixture:{providerCustody:'before_lock'}});
  const beforeCustody=await wait("events.find(e=>e.fixture_provider_custody_point==='before_lock')");
  check(typeof beforeCustody.fixture_provider_custody==='boolean','actual pre-Lock holder custody observed');
  if(scenario==='fixed')assert.equal(beforeCustody.fixture_provider_custody,true,'provider key present in the actual holder before Lock');
  await click('#tau-lock');await wait("document.querySelector('#tau-store')?.dataset.state==='locked'");
  check(await evaluate("document.querySelector('#tau-provider-key').value===''") ,'Lock clears entry');
  const endingCustody=await wait("events.find(e=>e.fixture_provider_custody_point==='ending_worker')");
  assert.equal(endingCustody.fixture_provider_custody,false,'ending worker clears actual provider custody before termination');
  await message({fixture:{providerCustody:'locked_worker'}});
  const lockedCustody=await wait("events.find(e=>e.fixture_provider_custody_point==='locked_worker')");
  assert.equal(lockedCustody.fixture_provider_custody,false,'new locked worker has no provider custody');
  console.log(JSON.stringify({scenario,rawHttp:counts,applicationDispatches:mutationDispatches(),replayRejections:replays,nonReplayRefusals:refusals,acceptedEffects:effects,distinctAcceptedAuthorizations:used.size,mutationIntents:mutationRoutes.map(route=>({operation:route.includes('/ssh-key')?'registration':route.includes('/renew?')?'initial_invoice':'create',identity:beforeLock.procurement?.identity??null,route,dispatches:mutationDispatches()[route],rawTransmissions:count(route),replayRejections:replays[route]??0,acceptedEffects:effects[route]??0})),traffic:{preflight:Object.entries(counts).filter(([route])=>route.startsWith('OPTIONS ')).reduce((n,[,count])=>n+count,0),reads:Object.entries(counts).filter(([route])=>!route.startsWith('OPTIONS ')&&!mutationRoutes.includes(route)).reduce((n,[,count])=>n+count,0),mutations:mutationRoutes.reduce((n,route)=>n+count(route),0),total:Object.values(counts).reduce((n,count)=>n+count,0)},vm:beforeLock.procurement?.vm_id??null,payment:beforeLock.procurement?.payment?.id??null,phase:beforeLock.procurement?.phase??null,clockEvidence:{providerOffsetSeconds,creationOffsetSeconds},billing:beforeLock.procurement?.billing??null,originEvidence:{fieldPath:originCase,legacyOverride:!originCase,checks:originChecks,bound:beforeLock.procurement?.origin,alternateContacts,allowedAlternateContacts},deadlineMeasurement,transferChecks,missingLimitsRefusals,inheritedCapChecks,signatureEncodingChecks,signatureReloadChecks,cpuAttributeChecks:cpuCase?cpuVariants.length:0,providerCustody:{beforeLock:beforeCustody.fixture_provider_custody,endingWorker:endingCustody.fixture_provider_custody,lockedWorker:lockedCustody.fixture_provider_custody},cspPreserved:true,checks:scenario.startsWith('counter-')?'counter detected the deliberate violation':'passed'}));
  await call('Browser.close');await once(browser,'exit');socket.close();
  fixture.stdin.write('{"stop":true}\n');await once(fixture,'exit');
} finally {
  clearTimeout(watchdog);for(const timer of fixtureTimers)clearTimeout(timer);
  if(browser?.exitCode===null){browser.kill('SIGTERM');await once(browser,'exit');}
  if(fixture?.exitCode===null){fixture.stdin.write('{"stop":true}\n');await once(fixture,'exit');}
  socket?.close();
  for(const server of [provider,alternateProvider,page])if(server){server.closeAllConnections();await new Promise(r=>server.close(r));}
  await rm(temp,{recursive:true,force:true,maxRetries:5,retryDelay:100});
}
