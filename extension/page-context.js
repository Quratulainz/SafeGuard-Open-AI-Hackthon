// Collection is invoked only by an explicit current-page scan. This function
// is self-contained so Chrome can serialize it into the selected tab.
(()=>{
 function collect(){
  const page=new URL(location.href);
  if(!['http:','https:'].includes(page.protocol)||page.username||page.password)throw Error('Open a regular public website first.');
  page.hash='';
  const limit=16000,parts=[];let length=0,visited=0,truncated=false;
  const excluded=new Set(['INPUT','TEXTAREA','SELECT','OPTION','SCRIPT','STYLE','NOSCRIPT','TEMPLATE','IFRAME','OBJECT','EMBED']);
  function walk(node){
   if(++visited>12000){truncated=true;return false}
   if(node.nodeType===1){
    if(excluded.has(node.tagName)||node.isContentEditable||node.hasAttribute('contenteditable')||node.hidden||node.hasAttribute('inert')||
       node.getAttribute('aria-hidden')==='true'||node.hasAttribute('data-safeguard-owner'))return true;
    const style=getComputedStyle(node);
    if(style.display==='none'||style.visibility==='hidden'||style.visibility==='collapse'||style.opacity==='0')return true;
    if(style.display!=='contents'&&!node.getClientRects().length)return true;
    for(const child of node.childNodes)if(!walk(child))return false;
   }else if(node.nodeType===3){
    const text=(node.nodeValue||'').replace(/\s+/g,' ').trim();
    if(!text)return true;
    const separator=parts.length?'\n':'';
    const available=limit-length;
    const fragment=separator+text;
    parts.push(fragment.slice(0,available));length+=Math.min(fragment.length,available);
    if(fragment.length>available){truncated=true;return false}
   }
   return true;
  }
  const body=document.body;
  if(body)walk(body);
  const forms=[];let forms_truncated=false;
  function destination(raw){
   try{
    const url=new URL(raw||page.href,raw?document.baseURI||page.href:page.href);
    const credentials=Boolean(url.username||url.password);
    if(credentials||!['http:','https:'].includes(url.protocol))return {action:'',invalid_action:true,has_embedded_credentials:credentials};
    url.search='';url.hash='';
    if(url.href.length>4096)return {action:'',invalid_action:true,has_embedded_credentials:false};
    return {action:url.href,invalid_action:false,has_embedded_credentials:false};
   }catch{return {action:'',invalid_action:true,has_embedded_credentials:false}}
  }
  const method=value=>['get','post','dialog'].includes(String(value||'').toLowerCase())?String(value).toLowerCase():'get';
  function add(form){if(forms.length<20)forms.push(form);else forms_truncated=true}
  const pageForms=document.forms||[];
  for(let i=0;i<Math.min(pageForms.length,21);i++){
   if(i===20){forms_truncated=true;break}
   const form=pageForms[i],controls=form.elements||[],overrides=[];
   let has_password=false,has_otp=false;
   if(controls.length>500)forms_truncated=true;
   for(let j=0;j<Math.min(controls.length,500);j++){
    const control=controls[j],type=String(control.getAttribute('type')||'').toLowerCase();
    has_password||=type==='password';
    has_otp||=/(?:one-time-code|(?:^|[\s_-])otp(?:$|[\s_-])|verification[\s_-]*code)/i.test(
     [control.getAttribute('autocomplete'),control.getAttribute('name'),control.getAttribute('id')].filter(Boolean).join(' '));
    const submit=control.tagName==='BUTTON'?(!type||type==='submit'):control.tagName==='INPUT'&&['submit','image'].includes(type);
    if(submit&&control.hasAttribute('formaction'))overrides.push({raw:control.getAttribute('formaction'),method:method(control.getAttribute('formmethod')||form.getAttribute('method'))});
   }
   add({...destination(form.getAttribute('action')),method:method(form.getAttribute('method')),has_password,has_otp});
   for(const override of overrides)add({...destination(override.raw),method:override.method,has_password,has_otp});
  }
  return {url:page.href,title:String(document.title||'').slice(0,300),text:parts.join(''),truncated,source:'browser_visible_page',forms,forms_truncated};
 }
 globalThis.SafeGuardPageContext={collect};
})();
