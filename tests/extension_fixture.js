const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const extension=path.join(__dirname,'..','extension');
const event=()=>({listeners:[],addListener(fn){this.listeners.push(fn)},removeListener(fn){this.listeners=this.listeners.filter(x=>x!==fn)},
 async emit(...args){return Promise.all(this.listeners.map(fn=>fn(...args)))}});
function fixture({initial={},granted=[],tabs=[],subscriptions=[],fetchImpl,now='2026-10-25T12:00:00',registered=[]}={}){
 const store={...initial},requests=[],injected=[],hidden=[],notifications=[],registrations=[...registered],alarms=[];
 const covers=(wanted)=>granted.some(pattern=>pattern===wanted||pattern===wanted.split('://')[0]+'://*/*');
 const chrome={runtime:{id:'ledfddgnhebbghhcifdaoomeipamodol',getURL:p=>'chrome-extension://ledfddgnhebbghhcifdaoomeipamodol/'+p,
  onInstalled:event(),onStartup:event(),onMessage:event(),lastError:null},
  storage:{local:{async get(){return {...store}},async set(values){Object.assign(store,values)}},onChanged:event()},
  alarms:{async create(name,options){alarms.push({name,options})},onAlarm:event()},
  permissions:{async contains({origins}){return origins.every(covers)},onRemoved:event()},
  notifications:{async create(id,options){notifications.push({id,options});return id},onClicked:event()},
  tabs:{async query(){return tabs},async get(id){return tabs.find(tab=>tab.id===id)},
   async sendMessage(id,message){hidden.push({id,message});return {ok:true}},create(){},onUpdated:event(),onActivated:event()},
  scripting:{async getRegisteredContentScripts(){return [...registrations]},
   async unregisterContentScripts({ids}){for(let i=registrations.length-1;i>=0;i--)if(ids.includes(registrations[i].id))registrations.splice(i,1)},
   async registerContentScripts(items){registrations.push(...items)},
   async executeScript(options){injected.push(options);return [{frameId:0,result:true}]}}};
 class Clock extends Date{constructor(...args){super(...(args.length?args:[now]))}static now(){return new Date(now).getTime()}}
 const response=(data,status=200)=>({ok:status>=200&&status<300,status,json:async()=>data});
 const fetch=async(url,options)=>{
  requests.push({url,options});if(fetchImpl)return fetchImpl(url,options,response);
  if(url.endsWith('/local/connect'))return response({connected:true,token:'fixture-token-only'});
  if(url.endsWith('/subscriptions'))return response(subscriptions);
  return response({risk_level:'unknown',summary:'Fixture only.'});
 };
 const context=vm.createContext({chrome,fetch,console,AbortController,setTimeout,clearTimeout,URL,Date:Clock});
 context.importScripts=(...files)=>files.forEach(file=>vm.runInContext(fs.readFileSync(path.join(extension,file),'utf8'),context,{filename:file}));
 context.importScripts('background.js');
 const sender={id:chrome.runtime.id,url:chrome.runtime.getURL('popup.html')};
 const dispatch=(message,from=sender)=>new Promise(resolve=>chrome.runtime.onMessage.listeners[0](message,from,resolve));
 return {chrome,store,requests,injected,hidden,notifications,registrations,alarms,context,dispatch,
  ready:vm.runInContext('initialize()',context),response};
}
module.exports={fixture,event,extension};
