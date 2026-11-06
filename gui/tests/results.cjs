const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const api = require('../ui/results.js');
const deferred = () => { let resolve, reject; const promise = new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject}; };
test('Results serializes repeated clicks, exports only loaded tokens, and issues zero execution calls', async () => {
  const calls=[], updates=[], load=deferred(), save=deferred();
  const ctl=api.controller((name,args)=>{calls.push({name,args});return name==='open_results'?load.promise:save.promise;},state=>updates.push(state));
  const first=ctl.open(); await ctl.open(); await ctl.export('json'); assert.equal(calls.length,1);
  load.resolve({token:'loaded',summary:{rows:[]}});await first;
  const exported=ctl.export('json'); await ctl.export('markdown'); await ctl.open(); assert.equal(calls.length,2);
  assert.deepEqual(calls[1],{name:'export_results',args:{token:'loaded',format:'json'}});
  save.reject(new Error('destination exists'));await exported; assert.match(updates.find(s=>s.message?.startsWith('Export failed')).message,/destination exists/);
  assert.equal(updates.at(-1).busy,false);assert.ok(calls.every(c=>['open_results','export_results'].includes(c.name)));
});
test('Out-of-order completions cannot replace newer selection or clear busy state',async()=>{
  const a=deferred(),b=deferred(),updates=[];let count=0;
  const ctl=api.controller(()=> (++count===1?a:b).promise,s=>updates.push(s));
  const old=ctl.open();ctl.invalidate();const current=ctl.open();
  b.resolve({token:'new',summary:{rows:[]}});await current;
  a.resolve({token:'old',summary:{rows:[]}});await old;
  assert.equal(updates.at(-1).loaded.token,'new');assert.equal(updates.at(-1).busy,false);
});
test('Cancellation and unavailable load keep previous verified view and surface safe error',async()=>{
  let answer={token:'one',summary:{rows:[]}},calls=0;const updates=[];
  const ctl=api.controller(async()=>{calls++;if(calls===3)throw new Error('Selection manifest exceeds 1 MiB');return answer;},s=>updates.push(s));
  await ctl.open();answer=null;await ctl.open();assert.equal(updates.at(-1).loaded.token,'one');
  await ctl.open();assert.equal(updates.at(-1).loaded.token,'one');assert.ok(updates.some(s=>s.message?.includes('exceeds 1 MiB')));
});
test('Filters distinguish mixed applications, functions and outcomes without inferring results',()=>{
  const rows=[{application:'Notepad++',outcome:'failed',functions:{install:'unmeasured',launch:'unmeasured'}},{application:'Bambu Studio',outcome:'insufficientEvidence',functions:{install:'passed',stlTo3mfExport:'passed'}}];
  assert.deepEqual(api.filterRows(rows,{application:'Bambu Studio'}),[rows[1]]);
  assert.equal(api.filterRows(rows,{function:'launch',status:'failed'}).length,0);
  assert.deepEqual(api.filterRows(rows,{function:'launch',status:'unmeasured'}),[rows[0]]);
  assert.equal(api.filterRows(rows,{outcome:'unavailable'}).length,0);
});
function dom() {
  const elements=new Map();let focused=null;
  const make=tag=>({tag,children:[],handlers:{},attributes:{},value:'',classList:{toggle(){}},append(...nodes){this.children.push(...nodes);},replaceChildren(...nodes){this.children=nodes;},setAttribute(k,v){this.attributes[k]=v;},addEventListener(k,v){this.handlers[k]=v;},focus(){focused=this;},set innerHTML(_){throw new Error('HTML injection');}});
  const get=id=>{if(!elements.has(id))elements.set(id,make(id));return elements.get(id);};
  return {document:{getElementById:get,createElement:make},get,focused:()=>focused};
}
test('DOM renders hostile strings inertly, navigates focus, filters, and restores dialog focus',async()=>{
  const d=dom(),calls=[];
  const row={selection:1,application:'<img src=x onerror=alert(1)>',workflow:'synthetic example',outcome:'failed',functions:{install:'unmeasured'},stages:[{stage:'launch',status:'failed'},{stage:'close',status:'notReached'}],failureEvidence:'rejected',evidenceReferences:[],evidenceGaps:['<script>hostile</script>'],historicalCleanupVerified:true};
  const window={document:d.document,__TAURI__:{core:{invoke:async(name)=>{calls.push(name);return {token:'synthetic',selectionLabels:['<script>label</script>'],summary:{rows:[row]}};}}}};
  vm.runInNewContext(fs.readFileSync(require.resolve('../ui/results.js'),'utf8'),{window});
  d.get('resultsView').handlers.click();assert.equal(d.focused(),d.get('resultsHeading'));
  await d.get('openResults').handlers.click();assert.equal(d.focused(),d.get('openResults'));assert.equal(d.get('resultsRows').children.length,1);
  const tr=d.get('resultsRows').children[0];assert.equal(tr.children[1].textContent,'<img src=x onerror=alert(1)> / synthetic example');
  const detail=tr.children[0].children[0];assert.equal(detail.tag,'details');assert.match(detail.children[0].textContent,/<script>label/);
  d.get('resultsApplication').value='Bambu Studio';d.get('resultsApplication').handlers.change();assert.match(d.get('resultsCount').textContent,/0 of 1/);
  d.get('workflowView').handlers.click();assert.equal(d.focused(),d.get('workflowView'));
  assert.deepEqual(calls,['open_results']);
});
test('Results IPC commands are declared and allowed; no execution routes or HTML sinks',()=>{
  const source=fs.readFileSync(require.resolve('../ui/results.js'),'utf8'), build=fs.readFileSync(require.resolve('../build.rs'),'utf8'),cap=JSON.parse(fs.readFileSync(require.resolve('../capabilities/administrator.json'),'utf8'));
  for(const cmd of ['open_results','export_results']) {assert.ok(build.includes('"'+cmd+'"'));assert.ok(cap.permissions.includes('allow-'+cmd.replaceAll('_','-')));}
  assert.doesNotMatch(source,/innerHTML|start_approved|prepare_workflow|recover_msix|cancel_pending/);
  const html=fs.readFileSync(require.resolve('../ui/index.html'),'utf8');
  assert.match(html,/<summary>|resultsTable/);assert.match(html,/resultsHeading" tabindex="-1"/);assert.match(html,/scope="col"/);
});
test('Results assets are valid UTF-8 and hostile control text stays inert',()=>{
  const decoder=new TextDecoder('utf-8',{fatal:true});
  for(const name of ['../ui/index.html','../ui/results.js'])decoder.decode(fs.readFileSync(require.resolve(name)));
  assert.equal(api.clean('safe\u202e\u0000text'),'safe  text');
});

test('Paired filters preserve denied, missing, timeout and unknown cleanup distinctions',()=>{
  const app={application:'Notepad++',outcome:'failed',functions:{install:'unmeasured'}};
  const fixed={application:'Fixed AIW controls',outcome:'insufficientEvidence',functions:{install:'unmeasured'},paired:{eligible:false,origin:'syntheticRehearsal',cases:[{case:'file',variant:'candidate',outcome:'accessDenied'},{case:'registry',variant:'baseline',outcome:'notFound'},{case:'child',variant:'candidate',outcome:'timeout'}]},historicalCleanupVerified:null};
  assert.deepEqual(api.filterRows([app,fixed],{comparison:'inconclusive'}),[fixed]);
  assert.equal(api.filterRows([app,fixed],{comparison:'eligible'}).length,0);
  assert.deepEqual(api.filterRows([app,fixed],{control:'registry',controlOutcome:'notFound'}),[fixed]);
  assert.equal(api.filterRows([app,fixed],{control:'registry',controlOutcome:'accessDenied'}).length,0);
  assert.equal(api.filterRows([fixed],{function:'install',status:'passed'}).length,0);
  assert.equal(fixed.historicalCleanupVerified,null);
});

test('Paired drill-down remains inert and exposes token facts without executing a run',async()=>{
  const d=dom(),calls=[];
  const row={selection:1,application:'Fixed AIW controls',workflow:'Ordinary user / classic AppContainer',outcome:'failed',functions:{install:'unmeasured'},stages:[],failureEvidence:'driverIncomplete',evidenceReferences:[],evidenceGaps:[],historicalCleanupVerified:null,paired:{origin:'syntheticRehearsal',eligible:false,reason:'baselineFailed',cases:[{variant:'baseline',case:'file',outcome:'notFound',nativeCode:2,process:{heldTokenObserved:true,selfTokenObserved:false,integrity:'medium',appContainer:false,noCapabilities:true,jobEmpty:null}},{variant:'candidate',case:'child',outcome:'timeout',process:{timedOut:true},descendantTokenObserved:false}]}};
  const window={document:d.document,__TAURI__:{core:{invoke:async(name)=>{calls.push(name);return {token:'paired-synthetic',summary:{rows:[row]}};}}}};
  vm.runInNewContext(fs.readFileSync(require.resolve('../ui/results.js'),'utf8'),{window});
  await d.get('openResults').handlers.click();assert.equal(d.focused(),d.get('openResults'));
  const walk=n=>[n.textContent||'',...n.children.flatMap(walk)].join(' ');
  const text=walk(d.get('resultsRows'));assert.match(text,/SYNTHETIC offline example/);assert.match(text,/Resource missing.*native error 2/);assert.match(text,/Timed out/);assert.match(text,/Held token observed: yes/);assert.match(text,/Outer worker cleanup is listed separately/);
  d.get('resultsControlOutcome').value='accessDenied';d.get('resultsControlOutcome').handlers.change();assert.match(d.get('resultsCount').textContent,/0 of 1/);
  assert.deepEqual(calls,['open_results']);
});

test('An unstarted native-worker profile is never labeled as native observations',async()=>{
  const d=dom();const row={selection:1,application:'Fixed AIW controls',workflow:'profile only',outcome:'partial',functions:{},stages:[],failureEvidence:'absent',evidenceReferences:[],evidenceGaps:[],historicalCleanupVerified:null,paired:{origin:'nativeWorker',evidenceStatus:'absent',observationsVerified:false,eligible:false,reason:'unmeasured',cases:[]}};
  const window={document:d.document,__TAURI__:{core:{invoke:async()=>({token:'unstarted',summary:{rows:[row]}})}}};
  vm.runInNewContext(fs.readFileSync(require.resolve('../ui/results.js'),'utf8'),{window});await d.get('openResults').handlers.click();
  const walk=n=>[n.textContent||'',...n.children.flatMap(walk)].join(' ');const text=walk(d.get('resultsRows'));
  assert.match(text,/Native-worker profile; no verified fixed-control observations/);assert.doesNotMatch(text,/Verified native fixed-control observations/);
});


test('Archive filters exclude unrelated profiles and expose the 7-Zip application',()=>{
  const rows=[{application:'Notepad++',functions:{install:'passed'}},{application:'Bambu Studio',functions:{stlTo3mfExport:'passed'}},{application:'Fixed AIW controls',functions:{}},{application:'7-Zip 26.05',functions:{createArchive:'passed',testArchive:'unmeasured'}}];
  assert.deepEqual(api.filterRows(rows,{function:'createArchive'}),[rows[3]]);
  assert.deepEqual(api.filterRows(rows,{function:'testArchive'}),[]);
  assert.deepEqual(api.filterRows(rows,{function:'testArchive',status:'unmeasured'}),[rows[3]]);
  assert.deepEqual(api.filterRows(rows,{application:'7-Zip 26.05'}),[rows[3]]);
  assert.match(fs.readFileSync(require.resolve('../ui/index.html'),'utf8'),/<option>7-Zip 26.05<\/option>/);
});
