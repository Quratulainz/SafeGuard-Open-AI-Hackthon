// Explicit current-page capture only. Synthetic DOM; no browser or network.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {extension}=require('./extension_fixture');
const source=fs.readFileSync(path.join(extension,'page-context.js'),'utf8');
function text(value,onRead=()=>{}){return {nodeType:3,get nodeValue(){onRead();return value}}}
function element(tag,children=[],attributes={},style={}){
 return {nodeType:1,tagName:tag,childNodes:children,hidden:false,isContentEditable:false,
  hasAttribute:name=>Object.hasOwn(attributes,name),getAttribute:name=>attributes[name]??null,
  getClientRects:()=>style.noRect?[]:[{}],_style:{display:'block',visibility:'visible',opacity:'1',...style}};
}
function context(body,extra={}){
 const world=vm.createContext({URL,location:{href:'https://example.com/path#section'},
  document:{body,title:'Public page'},getComputedStyle:node=>node._style,...extra});
 vm.runInContext(source,world);return world;
}
test('loading the helper does not inspect the page; explicit capture excludes private controls and hidden content',()=>{
 let visibleReads=0,privateReads=0;
 const secret=()=>text('DO NOT CAPTURE',()=>privateReads++);
 const children=[element('H1',[text('Public heading',()=>visibleReads++)]),element('P',[text('Visible description.')])];
 for(const tag of ['INPUT','TEXTAREA','SELECT','OPTION','SCRIPT','STYLE','NOSCRIPT','TEMPLATE','IFRAME','OBJECT','EMBED']){
  const node=element(tag,[secret()]);Object.defineProperty(node,'value',{get(){throw Error('Form values must never be read.')}});children.push(node);
 }
 children.push(element('DIV',[element('P',[secret()])],{contenteditable:'true'}),
  element('DIV',[secret()],{'aria-hidden':'true'}),element('DIV',[secret()],{inert:''}),
  element('DIV',[secret()],{'data-safeguard-owner':'fixture'}),element('DIV',[secret()],{}, {display:'none'}),
  element('DIV',[secret()],{}, {visibility:'hidden'}),element('DIV',[secret()],{}, {opacity:'0'}),
  element('DIV',[secret()],{}, {noRect:true}));
 const world=context(element('BODY',children));assert.equal(visibleReads,0);assert.equal(privateReads,0);
 const result=world.SafeGuardPageContext.collect();
 assert.equal(result.text,'Public heading\nVisible description.');assert.equal(result.truncated,false);
 assert.equal(result.url,'https://example.com/path');assert.equal(result.source,'browser_visible_page');
 assert.equal(visibleReads,1);assert.equal(privateReads,0);
});
test('serialized collection function is independent of popup closures and bounds text, title and traversal',()=>{
 const original=context(element('BODY',[]));
 const detached=context(element('BODY',[text('A'.repeat(17000))]),{document:{body:element('BODY',[text('A'.repeat(17000))]),title:'T'.repeat(400)}});
 const result=vm.runInContext('('+original.SafeGuardPageContext.collect.toString()+')()',detached);
 assert.equal(result.text.length,16000);assert.equal(result.title.length,300);assert.equal(result.truncated,true);
 const many=context(element('BODY',Array.from({length:13000},()=>element('SPAN',[]))));
 assert.equal(many.SafeGuardPageContext.collect().truncated,true);
});
test('empty pages stay empty and non-web locations are rejected',()=>{
 assert.equal(context(null).SafeGuardPageContext.collect().text,'');
 assert.throws(()=>context(null,{location:{href:'edge://settings/'}}).SafeGuardPageContext.collect(),/regular public website/);
});
test('form metadata follows base URLs and submit overrides without reading values or leaking query strings',()=>{
 const password=element('INPUT',[],{type:'password',name:'password'});
 const otp=element('INPUT',[],{autocomplete:'one-time-code'});
 const submit=element('BUTTON',[],{formaction:'https://other.example/collect?token=secret#fragment',formmethod:'POST'});
 const form=element('FORM',[],{action:'login?csrf=private',method:'POST'});form.elements=[password,otp,submit];
 for(const node of [password,otp,submit])Object.defineProperty(node,'value',{get(){throw Error('Never read a form value')}});
 const doc={body:element('BODY',[text('Public text.')]),title:'Form page',baseURI:'https://login.example/account/',forms:[form]};
 const result=context(doc.body,{document:doc}).SafeGuardPageContext.collect();
 assert.equal(result.forms.length,2);assert.equal(result.forms[0].action,'https://login.example/account/login');
 assert.equal(result.forms[0].has_password,true);assert.equal(result.forms[0].has_otp,true);
 assert.equal(result.forms[1].action,'https://other.example/collect');assert.equal(result.forms[1].method,'post');
 assert.equal(result.forms_truncated,false);assert.doesNotMatch(JSON.stringify(result),/secret|csrf|private|fragment/);
});
test('empty form actions use the document, unsafe addresses are flagged, and form/control caps stay explicit',()=>{
 const form=action=>Object.assign(element('FORM',[],{action}),{elements:[]});
 const doc={body:null,title:'Form page',baseURI:'https://base.example/',forms:[form(''),form('https://user:secret@other.example/'),form('javascript:submit()')]};
 let result=context(null,{document:doc}).SafeGuardPageContext.collect();
 assert.equal(result.forms[0].action,'https://example.com/path');
 assert.equal(result.forms[1].has_embedded_credentials,true);assert.equal(result.forms[1].invalid_action,true);
 assert.equal(result.forms[1].action,'');assert.equal(result.forms[2].invalid_action,true);
 doc.forms=Array.from({length:21},()=>form('/login'));result=context(null,{document:doc}).SafeGuardPageContext.collect();
 assert.equal(result.forms.length,20);assert.equal(result.forms_truncated,true);
 doc.forms=[form('/')];doc.forms[0].elements=Array.from({length:501},()=>element('INPUT',[],{}));
 assert.equal(context(null,{document:doc}).SafeGuardPageContext.collect().forms_truncated,true);
});
test('popup captures the selected tab only on Scan this page; pasted URLs and messages carry no context',async()=>{
 const nodes={},sent=[],captures=[];
 const get=id=>nodes[id]??=( {value:'',textContent:'',style:{},disabled:false} );
 const page={url:'https://example.com/',title:'Example',text:'Public fixture text.',truncated:false,source:'browser_visible_page'};
 const world=vm.createContext({document:{getElementById:get},URL,
  SafeGuardPageContext:{collect:function collect(){}},SafeGuardReport:{render(){}},
  SafeGuardUI:{bindControls(){},async send(msg){sent.push(msg);return {ok:true,data:{}}}},
  chrome:{tabs:{async query(){return [{id:7,url:page.url}]}},scripting:{async executeScript(opts){captures.push(opts);return [{frameId:0,result:page}]}},runtime:{}}});
 vm.runInContext(fs.readFileSync(path.join(extension,'popup.js'),'utf8'),world);
 assert.equal(captures.length,0);assert.equal(sent.length,0);
 get('kind').value='url';get('input').value='https://pasted.example/';await get('scan').onclick();
 assert.equal(sent[0].page_context,undefined);assert.equal(captures.length,0);
 await get('scan-current').onclick();
 assert.equal(captures.length,1);assert.equal(captures[0].target.tabId,7);assert.equal(captures[0].target.allFrames,undefined);
 assert.equal(sent[1].page_context,page);assert.equal(sent[1].page_tab_id,7);
 get('kind').value='message';get('input').value='Example message';await get('scan').onclick();
 assert.equal(sent[2].page_context,undefined);assert.equal(captures.length,1);
});
