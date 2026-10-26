importScripts('reminders.js','assistant-lifecycle.js');
const HOST='http://127.0.0.1:8765';
let localToken=null,connecting=null,reminderJob=null,initializing=null;
async function request(path,{method='GET',body,token,timeoutMs=15000}={}){
 const controller=timeoutMs?new AbortController():null;
 const timer=controller?setTimeout(()=>controller.abort(),timeoutMs):null;
 try{
  let response;
  try{response=await fetch(HOST+'/api/'+path,{method,mode:'cors',credentials:'omit',redirect:'error',
   headers:{'Content-Type':'application/json',...(token?{'X-SafeGuard-Token':token}:{})},
   body:body===undefined?undefined:JSON.stringify(body),...(controller?{signal:controller.signal}:{})})}
  catch{throw Error(controller?.signal.aborted?'The local app did not respond in time. Try again.':'Start the SafeGuard local app to connect automatically.')}
  let data;try{data=await response.json()}catch{throw Error('The local app returned an unreadable response.')}
  if(!response.ok){const error=Error(response.status===401?'The local connection was rejected.':data?.error||'The local request failed.');error.status=response.status;throw error}
  return data;
 }finally{if(timer!==null)clearTimeout(timer)}
}
async function connect(force=false){
 if(connecting)return connecting;
 if(localToken&&!force)return {connected:true};
 connecting=(async()=>{
  const result=await request('local/connect',{method:'POST',body:{}});
  if(result.connected!==true||typeof result.token!=='string'||!result.token||result.token.length>4096)
   throw Error('The local app did not confirm this extension connection.');
  localToken=result.token;
  return {connected:true};
 })().finally(()=>{connecting=null});
 return connecting;
}
async function api(path,method='GET',body){
 await connect();
 const options={method,body,token:localToken,timeoutMs:path==='inspect'?0:15000};
 try{return await request(path,options)}catch(error){
  if(error.status!==401)throw error;
  localToken=null;await connect(true);
  return request(path,{...options,token:localToken});
 }
}
function checkReminders(){
 if(reminderJob)return reminderJob;
 reminderJob=(async()=>{
  const subscriptions=await api('subscriptions');
  if(!Array.isArray(subscriptions))throw Error('Subscription records were not returned.');
  const saved=await chrome.storage.local.get('reminder_notifications');
  const ledger=saved.reminder_notifications&&typeof saved.reminder_notifications==='object'?saved.reminder_notifications:{};
  const plan=SafeGuardReminders.plan(subscriptions,ledger);
  for(const reminder of plan){
   await chrome.notifications.create('safeguard-'+reminder.key,{type:'basic',iconUrl:'icon.png',title:reminder.title,message:reminder.message});
   ledger[reminder.key]=reminder.day;
   await chrome.storage.local.set({reminder_notifications:ledger});
  }
  return {checked:true,notifications:plan.length};
 })().finally(()=>{reminderJob=null});
 return reminderJob;
}
function initialize(){
 if(initializing)return initializing;
 initializing=(async()=>{
  await chrome.alarms.create('renewal-check',{periodInMinutes:60});
  await Promise.allSettled([SafeGuardAssistant.initialize(),checkReminders()]);
 })().finally(()=>{initializing=null});
 return initializing;
}
chrome.runtime.onInstalled.addListener(()=>initialize());
chrome.runtime.onStartup.addListener(()=>initialize());
chrome.alarms.onAlarm.addListener(alarm=>{if(alarm.name==='renewal-check')checkReminders().catch(()=>{})});
chrome.tabs.onUpdated.addListener((_id,change,tab)=>change.status==='complete'?SafeGuardAssistant.inject(tab):undefined);
chrome.tabs.onActivated.addListener(info=>chrome.tabs.get(info.tabId).then(tab=>SafeGuardAssistant.inject(tab)).catch(()=>{}));
chrome.permissions.onRemoved.addListener(()=>{SafeGuardAssistant.sync().catch(()=>{})});
chrome.notifications.onClicked.addListener(id=>{if(id.startsWith('safeguard-'))chrome.tabs.create({url:HOST+'/#subscriptions'})});
function ownUI(sender){return sender.id===chrome.runtime.id&&['popup.html','options.html'].some(p=>sender.url===chrome.runtime.getURL(p))}
function pageURL(value){
 const url=new URL(value);
 if(!['http:','https:'].includes(url.protocol)||url.username||url.password)throw Error('A regular website URL is required.');
 url.hash='';return url.href;
}
async function inspectionPayload(msg,sender){
 if(sender.id!==chrome.runtime.id)throw Error('Use this extension to start a check.');
 const body={kind:msg.kind,value:msg.value};
 if(msg.page_context===undefined)return body;
 const context=msg.page_context;
 if(msg.kind!=='url'||!context||context.source!=='browser_visible_page'||typeof context.text!=='string'||
    typeof context.title!=='string'||typeof context.truncated!=='boolean'||typeof context.url!=='string')
  throw Error('The visible-page evidence is invalid. Scan the current page again.');
 const target=pageURL(msg.value);
 if(pageURL(context.url)!==target)throw Error('The page changed. Scan the current page again.');
 if(sender.url===chrome.runtime.getURL('popup.html')){
  const tabs=await chrome.tabs.query({active:true,currentWindow:true});
  if(!Number.isInteger(msg.page_tab_id)||!tabs.some(tab=>tab.id===msg.page_tab_id&&pageURL(tab.url)===target))
   throw Error('The active page changed. Scan the current page again.');
 }else if(sender.frameId!==0||!sender.tab||pageURL(sender.url)!==target||pageURL(sender.tab.url)!==target){
  throw Error('Visible-page evidence must come from this page’s main frame.');
 }
 body.page_context={url:target,title:context.title.slice(0,300),text:context.text.slice(0,16000),
  truncated:context.truncated||context.text.length>16000,source:'browser_visible_page'};
 if(context.forms!==undefined){
  if(!Array.isArray(context.forms)||context.forms.length>20||typeof context.forms_truncated!=='boolean')
   throw Error('The form inspection is invalid. Scan the current page again.');
  body.page_context.forms=context.forms.map(form=>{
   const flags=['has_password','has_otp','invalid_action','has_embedded_credentials'];
   if(!form||flags.some(key=>typeof form[key]!=='boolean')||!['get','post','dialog'].includes(form.method)||typeof form.action!=='string'||form.action.length>4096)
    throw Error('The form inspection is invalid. Scan the current page again.');
   const clean={method:form.method,action:''};for(const key of flags)clean[key]=form[key];
   if(form.action){
    try{
     const url=new URL(form.action);
     clean.has_embedded_credentials||=Boolean(url.username||url.password);
     if(clean.has_embedded_credentials||!['http:','https:'].includes(url.protocol))throw Error('Invalid destination');
     url.search='';url.hash='';clean.action=url.href;
    }catch{clean.invalid_action=true}
   }else if(!clean.invalid_action)throw Error('The form destination is missing. Scan the current page again.');
   return clean;
  });
  body.page_context.forms_truncated=context.forms_truncated;
 }
 return body;
}
chrome.runtime.onMessage.addListener((msg,sender,respond)=>{
 let operation;
 if(msg.type==='inspect')operation=inspectionPayload(msg,sender).then(body=>api('inspect','POST',body)).then(data=>({data}));
 else if(msg.type==='subscriptions')operation=api('subscriptions').then(data=>({data}));
 else if(msg.type==='connection-status')operation=connect(true);
 else if(msg.type==='assistant-state')operation=SafeGuardAssistant.state();
 else if(msg.type==='assistant-set'){
  if(!ownUI(sender)){respond({ok:false,error:'Use the extension controls to change automatic display.'});return}
  operation=SafeGuardAssistant.setEnabled(msg.enabled,msg.origins);
 }else if(msg.type==='check-reminders'){
  if(!ownUI(sender)){respond({ok:false,error:'Use the extension controls to check reminders.'});return}
  operation=checkReminders();
 }else if(msg.type==='open-dashboard'){chrome.tabs.create({url:HOST+'/'});respond({ok:true});return}
 else return;
 operation.then(result=>respond({ok:true,...result})).catch(error=>respond({ok:false,error:error.message}));
 return true;
});
// Re-establish local auth and alarms when the service worker starts; no cloud call.
initialize();
