const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const { clean } = require("../ui/display.js");
const display = require("../ui/display.js");

test("every desktop UI command is declared and allowed for the main window", () => {
  const source = fs.readFileSync(require.resolve("../ui/app.js"), "utf8");
  const manifest = fs.readFileSync(require.resolve("../build.rs"), "utf8");
  const capability = JSON.parse(fs.readFileSync(require.resolve("../capabilities/administrator.json"), "utf8"));
  assert.deepEqual(capability.windows, ["main"]);
  const commands = [...source.matchAll(/(?:call|action)\("([a-z_]+)"/g)].map(match => match[1]);
  assert.ok(commands.includes("recover_msix_worker"));
  for (const command of new Set(commands)) {
    assert.ok(manifest.includes(`"${command}"`), `missing command declaration: ${command}`);
    assert.ok(capability.permissions.includes(`allow-${command.replaceAll("_", "-")}`), `missing command permission: ${command}`);
  }
});

test("MSIX selects its own file path and keeps editing and recovery under backend control", async () => {
  const elements=new Map();
  const element=id=>{if(!elements.has(id))elements.set(id,{value:"",textContent:"",disabled:false,handlers:{},classList:{toggle(){}},scrollIntoView(){},addEventListener(event,handler){this.handlers[event]=handler;}});return elements.get(id);};
  const radios=[{value:"msix",handlers:{},addEventListener(event,handler){this.handlers[event]=handler;}}];
  const calls=[],intervals=[];let snapshot={phase:"idle",workflowId:null};
  const context={document:{getElementById:element,querySelector:()=>({value:"msix"}),querySelectorAll:()=>radios},window:{AiwDisplay:display,__TAURI__:{core:{invoke:async(name,args)=>{calls.push({name,args});if(name==="choose_input")return "C:\\input\\application.msix";return snapshot;}}}},setInterval:callback=>intervals.push(callback)};
  vm.runInNewContext(fs.readFileSync(require.resolve("../ui/app.js"),"utf8"),context);
  await new Promise(setImmediate);radios[0].handlers.change();
  await element("chooseInstaller").handlers.click();assert.equal(calls.at(-1).args.kind,"msix");
  element("evidence").value="C:\\evidence";element("operatorIdentity").value="operator";
  await element("prepare").handlers.click();assert.equal(calls.find(c=>c.name==="prepare_workflow").args.kind,"msix");
  assert.equal(calls.some(c=>c.name==="start_approved_workflow"),false);
  snapshot={phase:"running",workflowId:"msix-run",progress:"Open VM107 document; save and close"};
  await intervals.find(callback=>callback.name==="poll")();
  assert.equal(element("progressSummary").textContent,snapshot.progress);
  assert.equal(element("prepare").disabled,true);assert.equal(element("recoverMsix").disabled,true);
  assert.equal(element("export").disabled,true);
});

test("verified transfer restores destination selection after a busy action", async () => {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, {
      value: "", disabled: false, handlers: {},
      classList: { toggle() {} }, scrollIntoView() {},
      addEventListener(event, handler) { this.handlers[event] = handler; },
    });
    return elements.get(id);
  };
  const intervals = [];
  let snapshot = { phase: "idle", workflowId: null };
  const context = {
    document: {
      getElementById: element,
      querySelector: () => ({ value: "interactive" }),
      querySelectorAll: () => [],
    },
    window: { AiwDisplay: { clean }, __TAURI__: { core: { invoke: async (name) => {
      if (name === "prepare_workflow") snapshot = { phase: "preparing", workflowId: "first" };
      return snapshot;
    } } } },
    setInterval: (callback) => intervals.push(callback),
  };
  vm.runInNewContext(fs.readFileSync(require.resolve("../ui/app.js"), "utf8"), context);
  await new Promise(setImmediate);
  await element("prepare").handlers.click();
  assert.equal(element("chooseDestination").disabled, true);
  snapshot = { phase: "completed", workflowId: "first", result: { outcome: "verified", canExportDocument: true } };
  await intervals.find((callback) => callback.name === "poll")();
  assert.equal(element("chooseDestination").disabled, false);
  assert.equal(element("export").disabled, false);
  snapshot.result.canExportDocument = false;
  await intervals.find((callback) => callback.name === "poll")();
  assert.equal(element("chooseDestination").disabled, true);
  assert.equal(element("export").disabled, true);
});

test("review overview stays inert, preserves expanded details, and resets on a new challenge", async () => {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, {
      value: "", textContent: "", innerHTML: "untouched", open: false, disabled: false, hidden: false, handlers: {},
      classList: { toggle(name, on) { if (name === "hidden") element(id).hidden = on; } },
      scrollIntoView() {}, addEventListener(event, handler) { this.handlers[event] = handler; },
    });
    return elements.get(id);
  };
  const recipe = { schemaVersion: "aiw.dev/admin-bambu-recipe/v0alpha1", executionIdentity: "<img src=x>\u202eexecution", dataLifetime: "Export is explicit", limits: "No printing", runPlan: { trustDeltas: ["Tools read-only; output untrusted"] } };
  let snapshot = { phase: "review", workflowId: "fixed", review: { challengeId: "one", recipeJson: JSON.stringify(recipe), planJson: '{"fixed":true}', approvalJson: "{}", exactConfirmation: "approve exact-hash", planHash: "exact-hash" } };
  const intervals = [], calls = [];
  const context = {
    document: { getElementById: element, querySelector: () => ({ value: "bambu" }), querySelectorAll: () => [] },
    window: { AiwDisplay: display, __TAURI__: { core: { invoke: async (name, args) => { calls.push({ name, args }); return snapshot; } } } },
    setInterval: (callback) => intervals.push(callback),
  };
  vm.runInNewContext(fs.readFileSync(require.resolve("../ui/app.js"), "utf8"), context);
  await new Promise(setImmediate);
  const poll = intervals.find((callback) => callback.name === "poll");
  assert.equal(element("reviewDetails").open, false);
  assert.equal(element("reviewExecution").textContent, "<img src=x>\\u202eexecution");
  assert.equal(element("reviewExecution").innerHTML, "untouched");
  assert.equal(element("exactConfirmation").textContent, "approve exact-hash");
  element("reviewDetails").open = true;
  element("confirmation").value = "approve exact-hash";
  await poll();
  assert.equal(element("reviewDetails").open, true);
  assert.equal(element("confirmation").value, "approve exact-hash");
  await element("approve").handlers.click();
  const approval = calls.find((call) => call.name === "submit_approval");
  assert.equal(approval.args.confirmation, "approve exact-hash");
  assert.equal(approval.args.challengeId, "one");
  assert.equal(calls.some((call) => call.name === "start_approved_workflow"), false);
  snapshot.review = { ...snapshot.review, challengeId: "two", recipeJson: "{}" };
  await poll();
  assert.equal(element("reviewDetails").open, true);
  assert.equal(element("reviewSummary").hidden, true);
  assert.equal(element("reviewSummaryUnavailable").hidden, false);
  assert.equal(element("reviewExecution").textContent, "");
  assert.equal(element("confirmation").value, "");
  assert.match(element("planJson").textContent, /"fixed": true/);
});

test("Bambu mode selects the EXE path and dispatches the fixed workflow without export", async () => {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, {
      value: "", textContent: "", placeholder: "", disabled: false, handlers: {},
      classList: { toggle() {} }, scrollIntoView() {},
      addEventListener(event, handler) { this.handlers[event] = handler; },
    });
    return elements.get(id);
  };
  let selectedKind = "assessment";
  const radios = ["assessment", "interactive", "bambu"].map((value) => ({ value, disabled: false, handlers: {}, addEventListener(event, handler) { this.handlers[event] = handler; } }));
  const calls = [];
  const intervals = [];
  let snapshot = { phase: "idle", workflowId: null };
  const context = {
    document: {
      getElementById: element,
      querySelector: () => ({ value: selectedKind }),
      querySelectorAll: () => radios,
    },
    window: { AiwDisplay: { clean }, __TAURI__: { core: { invoke: async (name, args) => {
      calls.push({ name, args });
      if (name === "choose_input") return "C:\\input\\BambuStudio.exe";
      if (name === "prepare_workflow") snapshot = { phase: "preparing", workflowId: "bambu-run" };
      return snapshot;
    } } } },
    setInterval: (callback) => intervals.push(callback),
  };
  vm.runInNewContext(fs.readFileSync(require.resolve("../ui/app.js"), "utf8"), context);
  await new Promise(setImmediate);
  selectedKind = "bambu";
  radios[2].handlers.change();
  assert.equal(element("chooseInstaller").textContent, "Choose EXE");
  assert.match(element("setupHint").textContent, /fixed STL input is package supplied/);
  await element("chooseInstaller").handlers.click();
  assert.equal(calls.at(-1).args.kind, "bambu-installer");
  element("evidence").value = "C:\\evidence";
  element("operatorIdentity").value = "operator";
  await element("prepare").handlers.click();
  const dispatch = calls.find((call) => call.name === "prepare_workflow");
  assert.equal(dispatch.args.kind, "bambu");
  assert.equal(dispatch.args.documentInput, null);
  snapshot = { phase: "completed", workflowId: "bambu-run", result: { outcome: "verified", canExportDocument: false } };
  await intervals.find((callback) => callback.name === "poll")();
  assert.equal(element("chooseDestination").disabled, true);
  assert.equal(element("export").disabled, true);
});


test("paired workflow drops installer inputs, fences stale polling and serializes explicit cancellation/recovery", async () => {
  const elements = new Map(), calls = [], intervals = [];
  const element = id => {
    if (!elements.has(id)) elements.set(id, { value:"", textContent:"", disabled:false, hidden:false, handlers:{},
      classList:{toggle(name,on){if(name==="hidden") element(id).hidden=on;}}, scrollIntoView(){}, focus(){},
      addEventListener(event,handler){this.handlers[event]=handler;} });
    return elements.get(id);
  };
  let snapshot={phase:"idle",workflowId:null}, heldPoll=null, releaseAction=null;
  const context={document:{getElementById:element,querySelector:()=>({value:"paired"}),querySelectorAll:()=>[]},
    window:{AiwDisplay:display,__TAURI__:{core:{invoke:async(name,args)=>{
      calls.push({name,args});
      if(name==="get_state") { if(heldPoll) { const held=heldPoll; heldPoll=null; return held.promise; } return snapshot; }
      if(name==="prepare_workflow") { await new Promise(resolve=>releaseAction=resolve); snapshot={phase:"preparing",workflowId:"owned-pair"}; }
      if(name==="cancel_paired_workflow") snapshot={phase:"running",workflowId:"owned-pair",pairedCancelRequested:true};
      if(name==="recover_paired_workflow") snapshot={phase:"running",workflowId:"owned-pair",pairedRecoveryRequired:true};
    }}}},setInterval:callback=>intervals.push(callback)};
  vm.runInNewContext(fs.readFileSync(require.resolve("../ui/app.js"),"utf8"),context);
  await new Promise(setImmediate);
  assert.equal(element("installerField").hidden,true);
  element("installer").value="must not enter paired request";
  element("documentInput").value="must not enter paired request";
  let releasePoll;
  heldPoll={promise:new Promise(resolve=>releasePoll=resolve)};
  const poll=intervals.find(callback=>callback.name==="poll");
  const oldPoll=poll();
  const preparing=element("prepare").handlers.click();
  await element("prepare").handlers.click();
  assert.equal(calls.filter(c=>c.name==="prepare_workflow").length,1);
  const request=calls.find(c=>c.name==="prepare_workflow").args;
  assert.equal(request.installer,""); assert.equal(request.documentInput,null);
  releasePoll({phase:"completed",workflowId:"stale",result:{outcome:"verified",canExportDocument:true}});
  await oldPoll;
  assert.equal(element("export").disabled,true);
  releaseAction(); await preparing;
  assert.equal(calls.some(c=>c.name==="start_approved_workflow"),false);
  snapshot={phase:"running",workflowId:"owned-pair",pairedCancelAvailable:true}; await poll();
  element("cancel").handlers.click(); element("cancel").handlers.click(); await new Promise(setImmediate);
  assert.equal(calls.filter(c=>c.name==="cancel_paired_workflow").length,1);
  assert.deepEqual(JSON.parse(JSON.stringify(calls.find(c=>c.name==="cancel_paired_workflow").args)),{workflowId:"owned-pair"});
  assert.match(element("cancel").textContent,/waiting for cleanup/);
  snapshot={phase:"failed",workflowId:"owned-pair",pairedRecoveryRequired:true}; await poll();
  assert.equal(element("prepare").disabled,true);
  assert.equal(element("recoverPaired").disabled,false);
  assert.equal(calls.some(c=>c.name==="recover_paired_workflow"),false);
  element("recoverPaired").handlers.click(); element("recoverPaired").handlers.click(); await new Promise(setImmediate);
  assert.equal(calls.filter(c=>c.name==="recover_paired_workflow").length,1);
  assert.deepEqual(JSON.parse(JSON.stringify(calls.find(c=>c.name==="recover_paired_workflow").args)),{workflowId:"owned-pair"});
  snapshot={phase:"completed",workflowId:"owned-pair",pairedCancelRequested:false,pairedRecoveryRequired:false}; await poll();
  assert.equal(element("cancel").hidden,true); assert.equal(element("recoverPaired").hidden,true);
});


test("phase transitions focus their destination without stealing focus on repeated polls", async () => {
  const elements=new Map(),intervals=[];let focused=null,snapshot={phase:"idle",workflowId:null},fail=false;
  const element=id=>{if(!elements.has(id))elements.set(id,{value:"",textContent:"",disabled:false,handlers:{},classList:{toggle(){}},scrollIntoView(){},focus(){focused=id;},addEventListener(event,handler){this.handlers[event]=handler;}});return elements.get(id);};
  const context={document:{getElementById:element,querySelector:()=>({value:"paired"}),querySelectorAll:()=>[]},window:{AiwDisplay:display,__TAURI__:{core:{invoke:async()=>{if(fail)throw new Error("synthetic failure");return snapshot;}}}},setInterval:callback=>intervals.push(callback)};
  vm.runInNewContext(fs.readFileSync(require.resolve("../ui/app.js"),"utf8"),context);await new Promise(setImmediate);
  const poll=intervals.find(callback=>callback.name==="poll");
  snapshot={phase:"review",workflowId:"owned",review:{challengeId:"exact",recipeJson:"{}",planJson:"{}",approvalJson:"{}",exactConfirmation:"approve exact"}};
  await poll();assert.equal(focused,"reviewCard");focused="confirmation";await poll();assert.equal(focused,"confirmation");
  snapshot={...snapshot,phase:"approved",startChallengeId:"start"};await poll();assert.equal(focused,"startBox");
  snapshot={...snapshot,phase:"running"};await poll();assert.equal(focused,"progressCard");
  snapshot={phase:"completed",workflowId:"owned",result:{outcome:"incomplete",canExportDocument:false}};await poll();assert.equal(focused,"resultCard");
  fail=true;await poll();assert.equal(focused,"errorCard");
});
