const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {extension}=require('./extension_fixture');
const flush=()=>new Promise(resolve=>setImmediate(resolve));
function controls({enabled=false,origins=[],grant=true}={}){
 const elements={},messages=[],permissionRequests=[];
 const element=id=>elements[id]||(elements[id]={textContent:'',checked:false,disabled:false,open:false});
 let current={enabled,origins};
 const chrome={runtime:{lastError:null,sendMessage(message,callback){
  messages.push(message);
  if(message.type==='assistant-state')callback({ok:true,...current});
  else if(message.type==='assistant-set'){current={enabled:message.enabled,origins:message.origins||current.origins};callback({ok:true,...current})}
  else callback({ok:true,connected:true});
 }},permissions:{async request(request){permissionRequests.push(request);return grant}},
 tabs:{async query(){return [{id:1,url:'https://example.com/page'}]}}};
 const context=vm.createContext({chrome,document:{getElementById:element},URL});
 vm.runInContext(fs.readFileSync(path.join(extension,'controls.js'),'utf8'),context);
 context.SafeGuardUI.bindControls();
 return {elements,element,messages,permissionRequests};
}
test('first activation explicitly requests website scopes and permission refusal leaves it off',async()=>{
 const ui=controls({grant:false});await flush();
 ui.element('assistant-enabled').checked=true;await ui.element('assistant-enabled').onchange();
 assert.deepEqual(Array.from(ui.permissionRequests[0].origins),['http://*/*','https://*/*']);
 assert.equal(ui.messages.filter(x=>x.type==='assistant-set').length,0);
 assert.equal(ui.element('assistant-enabled').checked,false);
 assert.match(ui.element('assistant-status').textContent,/not granted/);
});
test('reenabling existing scopes reuses them instead of expanding to all websites',async()=>{
 const ui=controls({origins:['https://example.com/*']});await flush();
 ui.element('assistant-enabled').checked=true;await ui.element('assistant-enabled').onchange();
 assert.deepEqual(Array.from(ui.permissionRequests[0].origins),['https://example.com/*']);
 assert.equal(ui.messages.at(-1).enabled,true);
});
test('only this site replaces a previous broad automatic display scope',async()=>{
 const ui=controls({enabled:true,origins:['https://*/*','http://*/*']});await flush();
 ui.element('allow-site').onclick();await flush();
 assert.deepEqual(Array.from(ui.permissionRequests[0].origins),['https://example.com/*']);
 assert.deepEqual(Array.from(ui.messages.at(-1).origins),['https://example.com/*']);
});
test('switching off does not request permissions or reconnect manually',async()=>{
 const ui=controls({enabled:true,origins:['https://example.com/*']});await flush();
 ui.element('assistant-enabled').checked=false;await ui.element('assistant-enabled').onchange();
 assert.equal(ui.permissionRequests.length,0);assert.equal(ui.messages.at(-1).enabled,false);
 assert.match(ui.element('connection-status').textContent,/Connected automatically/);
});
