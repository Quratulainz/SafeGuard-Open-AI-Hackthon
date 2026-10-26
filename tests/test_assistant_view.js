// Exercise actual content-script handlers with a small DOM fixture; no browser or network.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {event,extension}=require('./extension_fixture');
const flush=()=>new Promise(resolve=>setImmediate(resolve));
function view(){
 const roots=[],sent=[],saved={assistant_enabled:true};let shadow,captureReads=0;
 function node(tag){
  const listeners={},classes=new Set();
  return {tag,style:{},dataset:{},children:[],isConnected:false,value:'',textContent:'',ownerDocument:document,
   classList:{add:x=>classes.add(x),remove:x=>classes.delete(x),toggle(x){if(classes.has(x)){classes.delete(x);return false}classes.add(x);return true}},
   addEventListener(name,fn){listeners[name]=fn},async fire(name){return listeners[name]?.()},
   append(...children){this.children.push(...children)},replaceChildren(...children){this.children=children},
   remove(){this.isConnected=false},attachShadow(){
    const ids={};shadow={getElementById:id=>ids[id],querySelectorAll:()=>[],
     set innerHTML(html){for(const match of html.matchAll(/id="([^"]+)"/g))ids[match[1]]=node('fixture')},
    };return shadow;
   }};
 }
 const document={createElement:node,getElementById:id=>roots.find(root=>root.isConnected&&root.id===id),
  documentElement:{appendChild(root){root.isConnected=true;roots.push(root)}},title:'Visible fixture',
  body:{nodeType:1,tagName:'BODY',hasAttribute:()=>false,getAttribute:()=>null,getClientRects:()=>[{}],
   childNodes:[{nodeType:3,get nodeValue(){captureReads++;return 'Visible public fixture text.'}}]}};
 const chrome={runtime:{id:'fixture-extension',lastError:null,onMessage:event(),sendMessage(message,reply){
  sent.push(message);reply({ok:true,data:{risk_level:'low',decision:{verdict:'safe',reasons:[{text:'Protective reminder.'}],next_steps:['Keep the code private.']}}});
 }},storage:{local:{async get(){return saved}},onChanged:event()}};
 const context=vm.createContext({document,chrome,location:{href:'https://example.com/'},URL,window:{open(){}},confirm:()=>false,
  getComputedStyle:()=>({display:'block',visibility:'visible',opacity:'1'})});
 const load=()=>{for(const file of ['report.js','page-context.js','assistant.js'])vm.runInContext(fs.readFileSync(path.join(extension,file),'utf8'),context)};
 load();return {roots,sent,saved,chrome,context,load,get shadow(){return shadow},get captureReads(){return captureReads}};
}
test('assistant injects once, never auto-scans, and can be removed and re-enabled',async()=>{
 const f=view();await flush();
 assert.equal(f.roots.filter(x=>x.isConnected).length,1);assert.equal(f.sent.length,0);
 assert.equal(f.captureReads,0);
 f.load();await flush();assert.equal(f.roots.filter(x=>x.isConnected).length,1);
 assert.equal(f.chrome.runtime.onMessage.listeners.length,1);
 f.saved.assistant_enabled=false;
 await f.chrome.storage.onChanged.emit({assistant_enabled:{newValue:false}},'local');
 assert.equal(f.roots.filter(x=>x.isConnected).length,0);assert.equal(f.chrome.runtime.onMessage.listeners.length,0);
 f.saved.assistant_enabled=true;f.load();await flush();assert.equal(f.roots.filter(x=>x.isConnected).length,1);
 assert.equal(f.captureReads,0);
});
test('a chosen assistant scan sends only its supplied value and renders collapsed details',async()=>{
 const f=view();await flush();
 f.shadow.getElementById('type').value='message';
 f.shadow.getElementById('value').value='Never share your OTP.';
 await f.shadow.getElementById('scan').fire('click');await flush();
 assert.equal(f.sent.length,1);assert.equal(f.sent[0].value,'Never share your OTP.');
 assert.equal(f.sent[0].page_context,undefined);assert.equal(f.captureReads,0);
 const result=f.shadow.getElementById('result');
 assert.equal(result.children[0].className,'brief-answer verdict-safe');
 assert.match(result.children[0].textContent,/✓ Safe/);
 assert.equal(result.children[1].tag,'details');assert.notEqual(result.children[1].open,true);
 assert.equal(f.shadow.getElementById('scan').disabled,false);
});

test('assistant reads visible page text only when its current-website button is chosen',async()=>{
 const f=view();await flush();assert.equal(f.captureReads,0);
 await f.shadow.getElementById('bot').fire('click');assert.equal(f.captureReads,0);
 await f.shadow.getElementById('current').fire('click');await flush();
 assert.equal(f.captureReads,1);assert.equal(f.sent.length,1);
 assert.equal(f.sent[0].kind,'url');assert.equal(f.sent[0].value,'https://example.com/');
 assert.equal(f.sent[0].page_context.text,'Visible public fixture text.');
 assert.equal(f.sent[0].page_context.source,'browser_visible_page');
});
