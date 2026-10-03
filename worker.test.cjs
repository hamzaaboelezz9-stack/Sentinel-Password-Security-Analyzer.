// Integration tests use PUBLIC synthetic samples and mock HIBP, never real credentials.
'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const {webcrypto,createHash} = require('node:crypto');
const root = path.join(__dirname,'../dist');
async function evaluate(secret, breach, responder) {
  const messages = [], requests = [];
  let finish;
  const done = new Promise(resolve => { finish = resolve; });
  const context = vm.createContext({TextDecoder,TextEncoder,Uint8Array,ArrayBuffer,setTimeout,clearTimeout,AbortController,Number,crypto:webcrypto});
  context.self = context;
  context.postMessage = value => messages.push(value);
  context.close = () => finish();
  context.fetch = async (url, options) => {
    requests.push({url,options});
    assert.equal(bytes.every(byte => byte === 0),true,'input bytes erased before network');
    return responder(url,options);
  };
  context.importScripts = (...files) => files.forEach(file => vm.runInContext(fs.readFileSync(path.join(root,file),'utf8'),context));
  vm.runInContext(fs.readFileSync(path.join(root,'analyzer.worker.js'),'utf8'),context);
  const bytes = new TextEncoder().encode(secret);
  await context.onmessage({data:{bytes:bytes.buffer,breach}});
  await done;
  return {messages,requests,bytes};
}
function response(body,ok=true) { return {ok,headers:new Headers(),body:new Response(body).body}; }
test('Default local analysis makes no network request, clears bytes, and emits no secret', async () => {
  const secret = 'P@ssw0rd123!';
  const out = await evaluate(secret,false,() => { throw new Error('Unexpected network'); });
  assert.equal(out.requests.length,0);
  assert.equal(out.bytes.every(b=>b===0),true);
  assert.deepEqual(out.messages.map(m=>m.type),['local','done']);
  assert.ok(!JSON.stringify(out.messages).includes(secret));
});
test('Opt-in sends ONLY SHA-1 prefix with padded private HTTPS range request', async () => {
  const secret='PUBLIC-integration-test-123!';
  const hash=createHash('sha1').update(secret,'utf8').digest('hex').toUpperCase();
  const out=await evaluate(secret,true,()=>response(hash.slice(5)+':42\r\n'+'A'.repeat(35)+':0\r\n'));
  assert.equal(out.requests.length,1);
  assert.equal(out.requests[0].url,'https://api.pwnedpasswords.com/range/'+hash.slice(0,5));
  const options=out.requests[0].options;
  assert.equal(options.headers['Add-Padding'],'true');
  assert.equal(options.cache,'no-store'); assert.equal(options.credentials,'omit'); assert.equal(options.referrerPolicy,'no-referrer');
  assert.equal(options.redirect,'error');
  assert.equal(out.messages.find(m=>m.type==='breach').count,42);
  assert.ok(!JSON.stringify(out.messages).includes(hash));
  assert.ok(!JSON.stringify(out.requests).includes(hash.slice(5)));
});
test('A successful miss is distinct from network, HTTP, and malformed-response errors', async () => {
  const miss=await evaluate('public-example',true,()=>response('A'.repeat(35)+':0\n'));
  assert.equal(miss.messages.find(m=>m.type==='breach').count,0);
  for(const responder of [()=>{throw new Error('Unavailable')},()=>response('unavailable',false),()=>response('not a range')]) {
    const out=await evaluate('public-example',true,responder);
    assert.ok(out.messages.some(m=>m.type==='local'));
    assert.ok(out.messages.some(m=>m.type==='breach-error'));
    assert.ok(!out.messages.some(m=>m.type==='breach'));
    assert.equal(out.bytes.every(b=>b===0),true);
  }
});
