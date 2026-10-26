// Pure calendar-day reminder planning; no automatic subscription actions.
(()=>{
 const DAY=86400000;
 function dayNumber(value){
  if(typeof value!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(value))return null;
  const [y,m,d]=value.split('-').map(Number),date=new Date(Date.UTC(y,m-1,d));
  return date.getUTCFullYear()===y&&date.getUTCMonth()===m-1&&date.getUTCDate()===d?date.getTime()/DAY:null;
 }
 function localToday(now=new Date()){
  return now.getFullYear()+'-'+String(now.getMonth()+1).padStart(2,'0')+'-'+String(now.getDate()).padStart(2,'0');
 }
 function plan(subscriptions,ledger={},today=localToday()){
  const current=dayNumber(today);if(current===null)throw Error('Invalid local calendar date.');
  const reminders=[];
  for(const s of Array.isArray(subscriptions)?subscriptions:[]){
   const targets=[];
   if(s.cancel_on)targets.push(['cancel',s.cancel_on]);
   targets.push(['renewal',s.renewal]);
   for(const [kind,date] of targets){
    const target=dayNumber(date);if(target===null||s.id==null)continue;
    const days=target-current,key=String(s.id)+':'+kind+':'+date;
    if(days>7||ledger[key]===today)continue;
    const name=String(s.name||'Saved subscription').slice(0,100);
    const timing=days<0?'was '+Math.abs(days)+' day(s) ago':days===0?'is today':'is in '+days+' day(s)';
    const message=kind==='cancel'
     ?name+': your chosen cancellation review date '+timing+'. Check the provider and take any action yourself; nothing has been cancelled.'
     :name+': the saved renewal date '+timing+'. Confirm the amount and renewal status with the provider, then update your saved date if needed.';
    reminders.push({key,day:today,title:kind==='cancel'?'SafeGuard: cancellation review':'SafeGuard: renewal reminder',message});
   }
  }
  return reminders;
 }
 globalThis.SafeGuardReminders={plan,localToday,dayNumber};
})();
