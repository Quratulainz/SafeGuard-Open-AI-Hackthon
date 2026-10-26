// Offline extension contract checks. No live HTTP, browser, or model calls.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {fixture,extension}=require('./extension_fixture');

test('fixed public identity matches the backend extension identity',()=>{
 const manifest=JSON.parse(fs.readFileSync(path.join(extension,'manifest.json')));
 const identity=JSON.parse(fs.readFileSync(path.join(extension,'..','server','extension_identity.json')));
 const digest=crypto.createHash('sha256').update(Buffer.from(manifest.key,'base64')).digest('hex').slice(0,32);
 const id=[...digest].map(x=>String.fromCharCode(97+parseInt(x,16))).join('');
 assert.equal(id,identity.extension_id);
});
test('worker automatically connects and scans with the opaque token without manual input',async()=>{
 const f=fixture();await f.ready;
 assert.equal(f.requests[0].url,'http://127.0.0.1:8765/api/local/connect');
 assert.equal(f.requests[0].options.method,'POST');assert.equal(f.requests[0].options.body,'{}');
 const result=await f.dispatch({type:'inspect',kind:'message',value:'Fixture text.'});
 assert.equal(result.ok,true);assert.equal(f.requests.at(-1).options.headers['X-SafeGuard-Token'],'fixture-token-only');
 assert.equal(result.token,undefined);assert.equal(f.store.local_token,undefined);
 for(const file of ['popup.html','options.html'])assert.doesNotMatch(fs.readFileSync(path.join(extension,file),'utf8'),/type="password"|Save connection|pairing-key/);
});

test('visible context is bounded and relayed only from the selected popup tab',async()=>{
 const f=fixture({tabs:[{id:7,url:'https://example.com/page#current'}]});await f.ready;
 const result=await f.dispatch({type:'inspect',kind:'url',value:'https://example.com/page#scan',page_tab_id:7,
  page_context:{url:'https://example.com/page',title:'T'.repeat(301),text:'A'.repeat(16001),truncated:false,source:'browser_visible_page',extra:'discard'}});
 assert.equal(result.ok,true);
 const body=JSON.parse(f.requests.at(-1).options.body);
 assert.equal(body.page_context.text.length,16000);assert.equal(body.page_context.title.length,300);
 assert.equal(body.page_context.truncated,true);assert.equal(body.page_context.extra,undefined);assert.equal(body.page_tab_id,undefined);
});

test('mismatched, switched-tab, subframe and non-URL context is rejected before inspect HTTP',async()=>{
 const f=fixture({tabs:[{id:7,url:'https://example.com/'}]});await f.ready;
 const context={url:'https://example.com/',title:'Fixture',text:'Public text.',truncated:false,source:'browser_visible_page'};
 const base={type:'inspect',kind:'url',value:context.url,page_tab_id:7,page_context:context};
 const sender={id:f.chrome.runtime.id,url:context.url,tab:{id:7,url:context.url},frameId:0};
 for(const [msg,from] of [
  [{...base,page_tab_id:8},undefined],
  [{...base,page_context:{...context,url:'https://different.example/'}},undefined],
  [{...base,kind:'message'},undefined],
  [base,{...sender,frameId:1}],
  [base,{...sender,url:'https://different.example/'}],
  [base,{...sender,tab:{id:7,url:'https://different.example/'}}],
  [base,{...sender,id:'other-extension'}],
 ])assert.equal((await f.dispatch(msg,from)).ok,false);
 assert.equal(f.requests.filter(request=>request.url.endsWith('/inspect')).length,0);
});

test('current top-frame assistant context is accepted but a pasted URL has no implicit context',async()=>{
 const f=fixture();await f.ready;
 const page_context={url:'https://example.com/',title:'Fixture',text:'Visible text.',truncated:false,source:'browser_visible_page'};
 const sender={id:f.chrome.runtime.id,url:page_context.url,tab:{id:7,url:page_context.url},frameId:0};
 assert.equal((await f.dispatch({type:'inspect',kind:'url',value:page_context.url,page_context},sender)).ok,true);
 assert.equal(JSON.parse(f.requests.at(-1).options.body).page_context.text,'Visible text.');
 assert.equal((await f.dispatch({type:'inspect',kind:'url',value:'https://pasted.example/'},sender)).ok,true);
 assert.equal(JSON.parse(f.requests.at(-1).options.body).page_context,undefined);
});
test('form context is revalidated and stripped of values and URL tokens before HTTP',async()=>{
 const f=fixture();await f.ready;
 const form={action:'https://example.com/login?token=secret#private',method:'post',has_password:true,has_otp:false,
  invalid_action:false,has_embedded_credentials:false,value:'DO NOT SEND'};
 const page_context={url:'https://example.com/',title:'Fixture',text:'Visible text.',truncated:false,
  source:'browser_visible_page',forms:[form],forms_truncated:false};
 const sender={id:f.chrome.runtime.id,url:page_context.url,tab:{id:7,url:page_context.url},frameId:0};
 const msg={type:'inspect',kind:'url',value:page_context.url,page_context};
 assert.equal((await f.dispatch(msg,sender)).ok,true);
 const body=JSON.parse(f.requests.at(-1).options.body);
 assert.equal(body.page_context.forms[0].action,'https://example.com/login');
 assert.doesNotMatch(JSON.stringify(body),/secret|private|DO NOT SEND/);
 for(const change of [{forms:Array(21).fill(form)},{forms_truncated:'false'},{forms:[{...form,has_password:'false'}]}]){
  assert.equal((await f.dispatch({...msg,page_context:{...page_context,...change}},sender)).ok,false);
 }
 assert.equal(f.requests.filter(request=>request.url.endsWith('/inspect')).length,1);
});
test('401 refreshes the local token once and does not loop on persistent rejection',async()=>{
 let connects=0,inspects=0;
 const f=fixture({fetchImpl:async(url,options,res)=>{
  if(url.endsWith('/local/connect'))return res({connected:true,token:'fixture-token-'+(++connects)});
  if(url.endsWith('/inspect')){inspects++;return res({error:'Rejected fixture'},401)}
  return res([]);
 }});await f.ready;
 const result=await f.dispatch({type:'inspect',kind:'message',value:'Fixture'});
 assert.equal(result.ok,false);assert.equal(inspects,2);assert.equal(connects,2);
 assert.equal(f.requests.at(-1).options.headers['X-SafeGuard-Token'],'fixture-token-2');
});
test('startup reconnect failure stays explicit and does not claim a successful local connection',async()=>{
 const f=fixture({fetchImpl:async()=>{throw Error('Offline fixture')}});await f.ready;
 const result=await f.dispatch({type:'connection-status'});
 assert.equal(result.ok,false);assert.match(result.error,/Start the SafeGuard local app/);
});
test('automatic assistant defaults off and never requests website permission in the background',async()=>{
 const f=fixture({granted:['https://*/*'],tabs:[{id:1,url:'https://example.com/'}]});await f.ready;
 assert.equal(f.store.assistant_enabled,false);assert.equal(f.injected.length,0);
 assert.equal(f.registrations.length,0);assert.equal(f.chrome.permissions.request,undefined);
});
test('enable injects existing approved tabs and later updated/activated tabs only',async()=>{
 const tabs=[{id:1,url:'https://example.com/'},{id:2,url:'https://unapproved.test/'},{id:3,url:'edge://settings'}];
 const f=fixture({granted:['https://example.com/*'],tabs});await f.ready;
 const enabled=await f.dispatch({type:'assistant-set',enabled:true,origins:['https://example.com/*']});
 assert.equal(enabled.ok,true);assert.equal(f.registrations.length,1);
 assert.deepEqual(Array.from(f.registrations[0].js),['report.js','page-context.js','assistant.js']);
 assert.deepEqual(f.injected.map(x=>x.target.tabId),[1]);
 await f.chrome.tabs.onUpdated.emit(1,{status:'complete'},tabs[0]);
 await f.chrome.tabs.onActivated.emit({tabId:1});
 assert.equal(f.injected.length,3);
 assert.equal(f.requests.filter(x=>x.url.endsWith('/inspect')).length,0,'Display must never automatically scan.');
});
test('permission denial and content-script preference writes cannot expand automatic display',async()=>{
 const f=fixture();await f.ready;
 const denied=await f.dispatch({type:'assistant-set',enabled:true,origins:['https://*/*']});
 assert.equal(denied.ok,false);assert.equal(f.store.assistant_enabled,false);
 const forged=await f.dispatch({type:'assistant-set',enabled:true,origins:['https://*/*']},
  {id:f.chrome.runtime.id,url:'https://example.com/'});
 assert.equal(forged.ok,false);assert.equal(f.registrations.length,0);
});
test('turning off unregisters automatic scripts and removes an already displayed assistant',async()=>{
 const f=fixture({initial:{assistant_enabled:true,assistant_origins:['https://example.com/*']},
  granted:['https://example.com/*'],tabs:[{id:1,url:'https://example.com/'}]});await f.ready;
 f.hidden.length=0;
 const result=await f.dispatch({type:'assistant-set',enabled:false});
 assert.equal(result.ok,true);assert.equal(f.registrations.length,0);
 assert.equal(f.hidden[0].message.type,'assistant-hide');assert.equal(f.store.assistant_enabled,false);
});
test('previous explicit per-site permission is migrated without broadening its scope',async()=>{
 const f=fixture({granted:['https://example.com/*'],registered:[{id:'safeguard-site-example-com',matches:['https://example.com/*']}]});await f.ready;
 assert.equal(f.store.assistant_enabled,true);
 assert.deepEqual(Array.from(f.store.assistant_origins),['https://example.com/*']);
 assert.equal(f.registrations[0].id,'safeguard-auto-assistant');
});
test('browser startup checks seven-day reminders and same-day restart does not repeat them',async()=>{
 const subscriptions=[{id:1,name:'Fixture renewal',renewal:'2026-11-01',long_term:true},
  {id:2,name:'Fixture later',renewal:'2026-11-02'}];
 const first=fixture({subscriptions});await first.ready;
 assert.equal(first.notifications.length,1);assert.match(first.notifications[0].options.message,/7 day/);
 await first.chrome.runtime.onStartup.emit();assert.equal(first.notifications.length,1);
 const restarted=fixture({initial:first.store,subscriptions});await restarted.ready;
 assert.equal(restarted.notifications.length,0);
 assert.equal(restarted.alarms[0].options.periodInMinutes,60);
});
test('missed dates are caught up and explicit cancel_on is honored even for long-term subscriptions',async()=>{
 const f=fixture({subscriptions:[{id:1,name:'Fixture long term',renewal:'2026-10-24',cancel_on:'2026-10-25',long_term:true}]});await f.ready;
 assert.equal(f.notifications.length,2);assert.match(f.notifications[0].options.title,/cancellation review/);
 assert.match(f.notifications[0].options.message,/nothing has been cancelled/);
 assert.match(f.notifications[1].options.message,/was 1 day/);
 assert.doesNotMatch(f.notifications[1].options.message,/cancel/i);
});
test('each target can notify again next day and renewal date changes are tracked separately',async()=>{
 const original=[{id:1,name:'Fixture',renewal:'2026-10-26'}];
 const first=fixture({subscriptions:original});await first.ready;
 const next=fixture({initial:first.store,subscriptions:original,now:'2026-10-26T12:00:00'});await next.ready;
 assert.equal(next.notifications.length,1);
 const updated=fixture({initial:next.store,subscriptions:[{...original[0],renewal:'2026-11-02'}],now:'2026-10-26T12:00:00'});await updated.ready;
 assert.equal(updated.notifications.length,1);
});
test('civil-day planning handles month changes, DST dates, leap days and invalid dates',async()=>{
 const f=fixture();await f.ready;const plan=f.context.SafeGuardReminders.plan;
 assert.equal(plan([{id:1,renewal:'2026-03-09'}],{},'2026-03-02')[0].message.includes('7 day'),true);
 assert.equal(plan([{id:1,renewal:'2026-11-02'}],{},'2026-10-26')[0].message.includes('7 day'),true);
 assert.equal(plan([{id:1,renewal:'2028-03-01'}],{},'2028-02-29')[0].message.includes('1 day'),true);
 assert.equal(plan([{id:1,renewal:'2026-02-29'}],{},'2026-02-28').length,0);
});
