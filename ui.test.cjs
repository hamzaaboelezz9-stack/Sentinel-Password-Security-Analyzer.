/* Headless DOM integration, not a visual browser audit. No real credentials. */
'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const {parseHTML} = require('linkedom');
const core = require('../dist/analysis-core.js');
const zxcvbn = require('zxcvbn');
const root = path.join(__dirname,'../dist');
function createApp() {
  const {document,window} = parseHTML(fs.readFileSync(path.join(root,'index.html'),'utf8'));
  const tools = new Map(), workers = [];
  const $ = id => document.getElementById(id);
  document.modelContext = {registerTool:tool => tools.set(tool.name,tool)};
  $('password').value = ''; $('breach-toggle').checked = false;
  // linkedom's select.value is getter-only; emulate the standard browser API.
  Object.defineProperty($('gpu-rate'),'value',{value:'10000000000',writable:true,configurable:true});
  class FakeWorker {
    constructor(){this.terminated=false;workers.push(this);}
    postMessage(value,transfer) { this.input = structuredClone(value,{transfer}); }
    terminate(){this.terminated=true;}
    emit(value){this.onmessage({data:value});}
  }
  const context=vm.createContext({document,window,Worker:FakeWorker,SentinelCore:core,TextEncoder,AbortController,setTimeout,clearTimeout,Date});
  vm.runInContext(fs.readFileSync(path.join(root,'app.js'),'utf8'),context);
  const submit=()=>$('analyzer-form').dispatchEvent(new window.Event('submit',{cancelable:true}));
  const click=id=>$(id).dispatchEvent(new window.Event('click'));
  function complete(worker) {
    const secret=new TextDecoder().decode(worker.input.bytes);
    worker.emit({type:'local',report:core.analyze(secret,zxcvbn)});
    worker.emit({type:'done'});
  }
  return {$,document,window,workers,tools,submit,click,complete};
}
test('Submit clears input and visibility immediately; result and Clear update the same UI',()=>{
  const app=createApp();
  app.$('password').value='PUBLIC-Example-284!';
  app.click('visibility'); assert.equal(app.$('password').type,'text');
  app.submit();
  assert.equal(app.$('password').value,''); assert.equal(app.$('password').type,'password');
  assert.equal(app.$('password').disabled,true);
  assert.equal(app.workers[0].input.breach,false);
  app.complete(app.workers[0]);
  assert.equal(app.$('password').disabled,false);
  assert.notEqual(app.$('score-number').textContent,'—');
  assert.equal(app.$('breach-status').textContent,'Not requested');
  assert.equal(app.workers[0].terminated,true);
  assert.ok(!app.document.body.textContent.includes('PUBLIC-Example-284!'));
  app.click('clear-button');
  assert.equal(app.$('score-number').textContent,'—');
  assert.equal(app.$('password').value,'');
});
test('Validation fails safely and clears unsupported input',()=>{
  const app=createApp();
  app.$('password').value='a'.repeat(129); app.submit();
  assert.equal(app.workers.length,0);
  assert.equal(app.$('password').value,'');
  assert.equal(app.$('input-error').hidden,false);
  assert.match(app.$('input-error').textContent,/128/);
});
test('Compromised match overrides score and dictionary time; stale canceled messages are ignored',()=>{
  const app=createApp();
  app.$('password').value='vG7!cQ2#zM9@bL4$kT8%';
  app.$('breach-toggle').checked=true; app.submit();
  const worker=app.workers[0];
  worker.emit({type:'local',report:core.analyze('vG7!cQ2#zM9@bL4$kT8%',zxcvbn)});
  assert.equal(app.$('score-number').textContent,'100');
  worker.emit({type:'breach-loading'});
  worker.emit({type:'breach',count:1});
  assert.equal(app.$('score-number').textContent,'0');
  assert.equal(app.$('strength-label').textContent,'Compromised');
  assert.equal(app.$('time-dictionary').textContent,'Known · try immediately');
  app.click('clear-button');
  worker.emit({type:'breach',count:100});
  assert.equal(app.$('breach-status').textContent,'Not checked');
});
test('Public examples never enable network, and optional WebMCP accepts no secrets',async()=>{
  const app=createApp();
  assert.equal(app.tools.size,2);
  app.$('breach-toggle').checked=true;
  const tool=app.tools.get('analyze_public_password_example');
  const pending=tool.execute({example:'strong'});
  assert.equal(app.workers[0].input.breach,false);
  app.complete(app.workers[0]);
  const result=await pending;
  assert.equal(result.score,100); assert.equal(result.breachRequested,false);
  await assert.rejects(()=>tool.execute({example:'strong',password:'never accepted'}));
  const clear=app.tools.get('clear_password_analysis');
  assert.throws(()=>clear.execute({password:'never accepted'}));
  assert.equal(clear.execute({}).cleared,true);
  assert.equal(app.$('score-number').textContent,'—');
});
test('Leaving page visibility clears input, aggregate report, and active worker',()=>{
  const app=createApp();
  app.$('password').value='PUBLIC-example'; app.submit();
  Object.defineProperty(app.document,'hidden',{value:true});
  app.document.dispatchEvent(new app.window.Event('visibilitychange'));
  assert.equal(app.workers[0].terminated,true);
  assert.equal(app.$('password').value,'');
  assert.equal(app.$('score-number').textContent,'—');
});
test('DOM IDs are unique and all locally referenced assets exist',()=>{
  const html=fs.readFileSync(path.join(root,'index.html'),'utf8');
  const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(m=>m[1]);
  assert.equal(new Set(ids).size,ids.length);
  for(const match of html.matchAll(/(?:href|src)="\.\/([^"#]+)"/g)) {
    if(match[1]==='source.zip') continue; // generated after validation
    assert.equal(fs.existsSync(path.join(root,match[1])),true,match[1]);
  }
  assert.ok(!/localStorage|sessionStorage|indexedDB|console\./.test(fs.readFileSync(path.join(root,'app.js'),'utf8')));
});
