// Automatic display only on websites explicitly granted by the user.
(()=>{
 const SCRIPT_ID='safeguard-auto-assistant';
 const pending=new Map();let syncJob=Promise.resolve();
 const validPattern=value=>typeof value==='string'&&/^https?:\/\/(?:\*|[a-z0-9.-]+)(?::\d+)?\/\*$/i.test(value);
 async function state(){
  const saved=await chrome.storage.local.get(['assistant_enabled','assistant_origins']);
  return {enabled:saved.assistant_enabled===true,origins:[...new Set((Array.isArray(saved.assistant_origins)?saved.assistant_origins:[]).filter(validPattern))]};
 }
 function matches(url,patterns){
  let page;try{page=new URL(url)}catch{return false}
  if(!['http:','https:'].includes(page.protocol)||page.origin==='http://127.0.0.1:8765')return false;
  return patterns.some(pattern=>{
   const [scheme,host]=pattern.slice(0,-2).split('://');
   return page.protocol===scheme+':'&&(host==='*'||page.host===host||page.hostname===host);
  });
 }
 async function allowedOrigins(origins){
  const allowed=[];
  for(const origin of origins)if(await chrome.permissions.contains({origins:[origin]}))allowed.push(origin);
  return allowed;
 }
 async function inject(tab){
  if(!tab?.id||!tab.url)return false;
  if(pending.has(tab.id))return pending.get(tab.id);
  const job=(async()=>{
   const current=await state();if(!current.enabled||!matches(tab.url,current.origins))return false;
   const origins=await allowedOrigins(current.origins);if(!matches(tab.url,origins))return false;
   await chrome.scripting.executeScript({target:{tabId:tab.id},files:['report.js','page-context.js','assistant.js']});
   return true;
  })().catch(()=>false).finally(()=>pending.delete(tab.id));
  pending.set(tab.id,job);return job;
 }
 async function hide(tab){
  if(!tab?.id||!/^https?:/.test(tab.url||''))return;
  try{const reply=await chrome.tabs.sendMessage(tab.id,{type:'assistant-hide'});if(reply?.ok)return}catch{}
  try{await chrome.scripting.executeScript({target:{tabId:tab.id},func:()=>{
   if(globalThis.__safeguardAssistant){globalThis.__safeguardAssistant.remove();return}
   const old=document.getElementById('sga-root');
   if(old?.style.position==='fixed'&&old.style.zIndex==='2147483647')old.remove();
  }})}catch{/* A restricted tab or revoked permission cannot be injected. */}
 }
 async function syncNow(){
  const current=await state(),origins=current.enabled?await allowedOrigins(current.origins):[];
  const registrations=await chrome.scripting.getRegisteredContentScripts();
  const ids=registrations.filter(item=>item.id===SCRIPT_ID||item.id.startsWith('safeguard-site-')).map(item=>item.id);
  if(ids.length)await chrome.scripting.unregisterContentScripts({ids});
  if(origins.length)await chrome.scripting.registerContentScripts([{id:SCRIPT_ID,matches:origins,
   js:['report.js','page-context.js','assistant.js'],runAt:'document_idle',persistAcrossSessions:true}]);
  const tabs=await chrome.tabs.query({});
  await Promise.allSettled(tabs.map(tab=>current.enabled&&matches(tab.url,origins)?inject(tab):hide(tab)));
  return {...current,authorized_origins:origins};
 }
 function sync(){syncJob=syncJob.catch(()=>{}).then(syncNow);return syncJob}
 async function setEnabled(enabled,origins){
  if(typeof enabled!=='boolean')throw Error('Choose whether the automatic assistant is enabled.');
  const current=await state();
  const selected=origins===undefined?current.origins:[...new Set((Array.isArray(origins)?origins:[]).filter(validPattern))];
  if(enabled&&(!selected.length||(await allowedOrigins(selected)).length!==selected.length))
   throw Error('Approve the selected website access before enabling the assistant.');
  await chrome.storage.local.set({assistant_enabled:enabled,assistant_origins:selected});
  return sync();
 }
 async function initialize(){
  const saved=await chrome.storage.local.get('assistant_enabled');
  if(saved.assistant_enabled===undefined){
   const old=await chrome.scripting.getRegisteredContentScripts();
   const origins=[...new Set(old.filter(item=>item.id.startsWith('safeguard-site-')).flatMap(item=>item.matches||[]).filter(validPattern))];
   const granted=await allowedOrigins(origins);
   await chrome.storage.local.set({assistant_enabled:granted.length>0,assistant_origins:granted});
  }
  return sync();
 }
 globalThis.SafeGuardAssistant={state,matches,inject,sync,setEnabled,initialize};
})();
