// Shared plain-text presentation. Source text is never inserted as HTML.
(()=>{
const list=value=>Array.isArray(value)?value:[];
const text=value=>typeof value==='string'?value:value==null?'':JSON.stringify(value);
function clip(value,limit){const valueText=text(value).replace(/\s+/g,' ').trim();return valueText.length>limit?valueText.slice(0,limit-1)+'…':valueText}
function sourceURL(record){
 const observation=record.observation&&typeof record.observation==='object'?record.observation:{};
 for(const value of [record.source_url,record.url,observation.source_url,observation.url,record.source]){
  try{const url=new URL(value);if(['http:','https:'].includes(url.protocol)&&!url.username&&!url.password)return url.href}catch{}
 }
 return '';
}
function historical(record){return record.historical_only||record.evidence_type==='historical_memory'||record.usable_as_current_evidence===false||['expired','superseded'].includes(record.freshness)}
function inactiveNotice(value,d){
 const line=text(value);
 if(/unconfigured|not configured|not enabled|disabled|\u672a\u542f\u7528|\u672a\u914d\u7f6e/i.test(line))return true;
 const inactive=status=>!status||['unconfigured','disabled','not_applicable'].includes(status);
 if(/Zetaris/i.test(line)&&inactive(d.zetaris?.status))return true;
 if(/Nightshift|AI analysis|AI review/i.test(line)&&inactive(d.ai_analysis?.status))return true;
 return /H-MEM|memory recall|memory save|memory write/i.test(line);
}
function formatInvestigation(d){
 const all=list(d.evidence),records=all.filter(record=>!historical(record)&&record.evidence_type!=='tool_status'&&
  !['disabled','unconfigured','not_applicable'].includes(record.observation?.status));
 const lines=[brief(d)];
 const page=d.website_check;
 if(page){
  const status={checked:'Checked',incomplete:'Incomplete',concern:'Concern'}[page.status]||'Not available';
  const source={public_html:'Public HTML',browser_visible_page:'Visible page text from your chosen scan',none:'No page content'}[page.source]||'Not available';
  lines.push('','Page check: '+status,'Page source: '+source);
  const destination=sourceURL({source_url:page.final_url});
  if(destination)lines.push('Checked destination: '+clip(destination,300));
 }
 lines.push('','Current evidence');
 if(!records.length)lines.push('No current source records are available to display.');
 for(const record of records.slice(0,12)){
  const observation=record.observation;
  const detail=typeof observation==='object'&&observation!==null
   ?observation.text||observation.excerpt||observation.observation||observation.description||observation:observation;
  const date=record.checked_at||record.retrieved_at||observation?.checked_at||observation?.retrieved_at;
  lines.push('['+clip(record.id||'No ID',40)+'] '+clip(record.source||record.evidence_type||'Source not provided',100));
  if(date)lines.push('Time: '+clip(date,40));
  if(record.evidence_type==='keyword_signal')lines.push('Phrase match only; read it in the context of the full message.');
  if(record.evidence_type==='ip_reputation'&&observation?.status==='not_listed')lines.push('The IP was not listed by this source; that does not establish website safety.');
  lines.push('Content: '+clip(detail||'No observation was provided.',300));
  const url=sourceURL(record);if(url)lines.push('Source URL: '+clip(url,300));
 }
 if(records.length>12)lines.push((records.length-12)+' additional source records are available in the complete investigation.');
 if(all.some(historical)||list(d.memory_recall?.matches).length)lines.push('','Historical records are context only, not new evidence for this check. Recheck them before use.');
 const limits=[...new Set([...(page&&page.identity_verified!==true?["The website's identity was not verified by this page check."]:[]),
  ...list(d.decision?.limitations),...list(d.limitations)]
  .filter(item=>!inactiveNotice(item,d)).map(item=>clip(item,180)).filter(Boolean))].slice(0,3);
 if(limits.length)lines.push('','Limitations',...limits.map(item=>'• '+item));
 if(d.risk_basis?.listing_floor_applied)lines.push('','Review note: a current blocklist match keeps the overall assessment cautious; a match alone does not prove fraud.');
 const review=d.ai_analysis?.semantic_validation;
 if(review?.status==='abstained'){
  const labels={elevated:'elevated',caution:'caution',unknown:'unknown',low:'low'};
  lines.push('','Review note: the initial model rating "'+(labels[review.model_risk_level]||'higher risk')+'" was withdrawn for lack of current supporting evidence. The reviewed result applies.');
 }else if(review?.status==='limited')lines.push('','Review note: the model conclusion was limited to what the available evidence supports.');
 if(d.decision?.mode==='model'){
  const ai=d.ai_analysis||{};
  if(ai.model_identity_reported===true&&ai.model)lines.push('','Model: '+clip(ai.model,100));
  if(ai.requested_model)lines.push('Model route: '+clip(ai.requested_model,100));
 }
 return lines.join('\n');
}

function verdict(d){
 const value=d.decision?.verdict;
 const risk=d.risk_level||d.ai_analysis?.analysis?.risk_level||'unknown';
 if(value==='danger'||risk==='elevated')return 'danger';
 return value==='safe'&&d.risk_level==='low'?'safe':'uncertain';
}
function brief(d){
 const arr=x=>Array.isArray(x)?x:[];
 const short=(x,n=180)=>String(x??'').replace(/\s+/g,' ').slice(0,n);
 const ai=d.ai_analysis||{},analysis=ai.status==='online'?ai.analysis:null;
 const decision=d.decision,basis=d.risk_basis,review=ai.semantic_validation,result=verdict(d);
 const heading={safe:'✓ Safe',uncertain:'? Uncertain',danger:'! Danger'}[result];
 const message=result==='safe'&&d.website_check
  ?'No obvious warning signs were found in the checked page.'
  :result==='uncertain'&&d.website_check?.status==='incomplete'
   ?'Page check incomplete. This is not evidence that the website is suspicious.'
   :{safe:'No obvious risk was found in this check. Applies only to the submitted content.',uncertain:'Evidence is incomplete or concerns remain. Verify before acting.',danger:'Significant risk signals were found. Pause before taking the requested action.'}[result];
 const reasons=arr(decision?.reasons).map(reason=>short(typeof reason==='string'?reason:reason.text)).filter(Boolean);
 if(!reasons.length){
  if(basis?.listing_floor_applied)reasons.push('A current source reports a blocklist match. This warrants caution, not a finding of fraud.');
  if(review?.status==='abstained')reasons.push('The initial model rating lacked current supporting evidence.');
  if(review?.status==='limited')reasons.push('A source listing warrants caution but does not establish fraud.');
  arr(analysis?.claims).slice(0,2).forEach(claim=>reasons.push(short(claim.text)));
  if(!analysis)reasons.push('Only the collected local observations are available; not every risk can be assessed.');
  if(!reasons.length)reasons.push(short(decision?.summary||d.summary||'There is not enough evidence for a firm conclusion.'));
 }
 if(reasons.length<2)reasons.push(result==='safe'?'This does not verify the sender’s identity or the website’s overall safety.':'Confirm important details through independently obtained official channels.');
 const selected=[...new Set(reasons)].slice(0,3);
 const next=short(arr(decision?.next_steps||analysis?.next_steps||d.next_steps)[0]||'Verify the source using independently obtained official contact details.');
 return heading+'\n'+message+'\n\n'+selected.map(x=>'• '+x).join('\n')+'\n\nNext step: '+next;
}
function render(container,d){
 const document=container.ownerDocument;
 const answer=document.createElement('div');answer.className='brief-answer verdict-'+verdict(d);answer.textContent=brief(d);
 const details=document.createElement('details');details.className='investigation-details';
 const title=document.createElement('summary');title.textContent='View evidence and details';
 const body=document.createElement('pre');body.textContent=formatInvestigation(d);
 details.append(title,body);container.replaceChildren(answer,details);
}
globalThis.SafeGuardReport={full:formatInvestigation,brief,verdict,render,sourceURL};
})();
