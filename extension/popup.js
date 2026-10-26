const el=id=>document.getElementById(id),output=el('output'),send=SafeGuardUI.send;
SafeGuardUI.bindControls();
function report(d){SafeGuardReport.render(output,d)}
async function scan(kind,value,page_context,page_tab_id){
 if(!value.trim()){output.textContent='Enter a website or message first.';return}
 el('scan').disabled=true;el('scan-current').disabled=true;output.textContent='Reviewing available evidence…';
 try{const result=await send({type:'inspect',kind,value,...(page_context?{page_context,page_tab_id}:{})});if(result.ok)report(result.data);else output.textContent=result.error}
 finally{el('scan').disabled=false;el('scan-current').disabled=false}
}
el('scan').onclick=()=>scan(el('kind').value,el('input').value.trim());
el('scan-current').onclick=async()=>{
 try{
  const [tab]=await chrome.tabs.query({active:true,currentWindow:true});
  if(!/^https?:/.test(tab?.url||'')){output.textContent='Open a regular public website first.';return}
  const results=await chrome.scripting.executeScript({target:{tabId:tab.id},func:SafeGuardPageContext.collect});
  const context=results.find(result=>result.frameId===0)?.result;
  if(!context)throw Error('The visible page could not be read. Paste its URL to run a public-page check instead.');
  el('kind').value='url';el('input').value=context.url;await scan('url',context.url,context,tab.id);
 }catch{output.textContent='The visible page could not be read. Paste its URL to run a public-page check instead.'}
};
el('dashboard').onclick=()=>send({type:'open-dashboard'});
el('settings').onclick=()=>chrome.runtime.openOptionsPage();
el('show-subs').onclick=async()=>{
 const result=await send({type:'subscriptions'});
 if(!result.ok){output.textContent=result.error;return}
 output.textContent=result.data.length?result.data.map(s=>s.name+' — renews '+s.renewal+
  (s.cancel_on?' — cancellation review '+s.cancel_on:'')+(s.long_term?' — long term':'')+' — '+s.currency+' '+s.amount+' (user confirmed)').join('\n'):'No subscriptions saved. Add one in the dashboard.';
 el('count').textContent=result.data.length+' of 5 subscriptions tracked. Reminder window: 7 days.';
};
el('visit').onclick=()=>{try{const url=new URL(el('input').value.trim());if(['http:','https:'].includes(url.protocol))chrome.tabs.create({url:url.href})}catch{output.textContent='Enter a valid URL first.'}};
el('kind').onchange=()=>{el('visit').style.display=el('kind').value==='url'?'inline-block':'none'};
