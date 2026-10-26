(()=>{
 function communicationError(message){
  const detail=String(message||'No extension response.').slice(0,240);
  if(/context invalidated/i.test(detail))return 'Open this extension popup again to use the updated version.';
  if(/receiving end does not exist|could not establish connection/i.test(detail))return 'The extension background is unavailable. '+detail;
  return 'Extension communication failed. '+detail;
 }
 function send(message){return new Promise(resolve=>{
  try{chrome.runtime.sendMessage(message,response=>{
   if(chrome.runtime.lastError)return resolve({ok:false,error:communicationError(chrome.runtime.lastError.message)});
   resolve(response||{ok:false,error:communicationError()});
  })}catch(error){resolve({ok:false,error:communicationError(error.message)})}
 })}
 function bindControls(){
  const el=id=>document.getElementById(id),toggle=el('assistant-enabled'),status=el('assistant-status');
  let current={enabled:false,origins:[]},tab=null;
  function show(result){
   if(!result.ok){status.textContent=result.error;toggle.checked=current.enabled;return}
   current=result;toggle.checked=current.enabled;
   status.textContent=current.enabled?'Automatic display is on for: '+current.origins.join(', '):'Automatic display is off.';
  }
  async function connect(){
   el('connection-status').textContent='Connecting to the local app…';
   const result=await send({type:'connection-status'});
   el('connection-status').textContent=result.ok?'Connected automatically to the local app.':result.error;
  }
  toggle.disabled=true;
  send({type:'assistant-state'}).then(result=>{
   show(result);toggle.disabled=false;
   if(el('assistant-controls'))el('assistant-controls').open=!result.ok||!result.enabled;
  });
  async function enable(origins){
   toggle.disabled=true;status.textContent='Waiting for website access…';
   try{
    const granted=await chrome.permissions.request({origins});
    if(!granted){status.textContent='Website access was not granted. Your previous setting is unchanged.';toggle.checked=current.enabled;return}
    show(await send({type:'assistant-set',enabled:true,origins}));
   }catch(error){status.textContent=error.message;toggle.checked=current.enabled}
   finally{toggle.disabled=false}
  }
  toggle.onchange=async()=>{
   if(toggle.checked)return enable(current.origins.length?current.origins:['http://*/*','https://*/*']);
   toggle.disabled=true;try{show(await send({type:'assistant-set',enabled:false}))}finally{toggle.disabled=false}
  };
  el('allow-all').onclick=()=>enable(['http://*/*','https://*/*']);
  if(el('allow-site')){
   el('allow-site').disabled=true;
   chrome.tabs.query({active:true,currentWindow:true}).then(tabs=>{tab=tabs[0];el('allow-site').disabled=!/^https?:/.test(tab?.url||'')});
   el('allow-site').onclick=()=>{
    if(!/^https?:/.test(tab?.url||'')){status.textContent='Open a regular website to allow just that site.';return}
    const origin=new URL(tab.url).origin+'/*';enable([origin]);
   };
  }
  el('reconnect').onclick=connect;connect();
  if(el('check-reminders'))el('check-reminders').onclick=async()=>{
   const result=await send({type:'check-reminders'});
   el('reminder-status').textContent=result.ok?'Reminders checked. '+result.notifications+' new notification(s).':result.error;
  };
 }
 globalThis.SafeGuardUI={send,bindControls};
})();
