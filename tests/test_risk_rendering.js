// Offline presentation regressions. No browser, network, or model calls.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const project=path.join(__dirname,'..');
const read=p=>fs.readFileSync(path.join(project,p),'utf8');
const dashboardScript=read('server/dashboard.html').match(/<script>([\s\S]*?)<\/script>/)[1];
const dashboardContext=vm.createContext({URL});
vm.runInContext(dashboardScript.slice(0,dashboardScript.indexOf("document.querySelectorAll('[data-tab]')"))+
 '\nglobalThis.helpers={renderResult,verdictInfo,conciseReasons,evidenceText,safeUrl,esc};',dashboardContext);
const dashboard=dashboardContext.helpers;
const reportContext=vm.createContext({URL});vm.runInContext(read('extension/report.js'),reportContext);
const report=reportContext.SafeGuardReport;
const base=(verdict='uncertain',risk='unknown')=>({risk_level:risk,decision:{mode:'rules',verdict,
 summary:'Current evidence has a limited scope.',reasons:[{text:'A current observation.'},{text:'Identity is not verified.'}],
 next_steps:['Check the source.'],limitations:[]},evidence:[]});

for(const [verdict,risk,label,icon] of [['safe','low','Safe','✓'],['uncertain','unknown','Uncertain','?'],['danger','elevated','Danger','!']]){
 test('dashboard and extension use '+verdict+' color with a readable label and symbol',()=>{
  const data=base(verdict,risk),info=dashboard.verdictInfo(data);
  assert.equal(info.key,verdict);assert.equal(info.label,label);assert.equal(info.icon,icon);
  assert.equal(report.verdict(data),verdict);assert.ok(report.brief(data).startsWith(icon+' '+label));
  assert.ok(dashboard.renderResult(data).includes('class="verdict '+verdict+'"'));
  if(verdict==='safe'){assert.match(report.brief(data),/No obvious risk was found in this check/);assert.match(dashboard.renderResult(data),/Applies only to this submission/)}
 });
}
test('contradictory safety data is downgraded and explicit danger has priority',()=>{
 for(const [data,expected] of [[base('safe','unknown'),'uncertain'],[base('safe','caution'),'uncertain'],
  [base('safe','elevated'),'danger'],[base('danger','low'),'danger']]){
  assert.equal(report.verdict(data),expected);assert.equal(dashboard.verdictInfo(data).key,expected);
 }
});
test('no blacklist hit, low alone and missing data never imply green',()=>{
 for(const data of [{risk_level:'unknown',ip_reputation:[{listed:false,status:'not_listed'}]},
  {risk_level:'low'},{}]){
  assert.equal(report.verdict(data),'uncertain');assert.equal(dashboard.verdictInfo(data).key,'uncertain');
 }
});

test('an incomplete page check does not imply the website is suspicious',()=>{
 const data=base();data.website_check={status:'incomplete',source:'none',identity_verified:false,final_url:'https://example.com/'};
 const answer=report.brief(data);
 assert.equal(report.verdict(data),'uncertain');
 assert.match(answer,/Page check incomplete\. This is not evidence that the website is suspicious\./);
 assert.doesNotMatch(answer,/Significant risk signals|concerns remain/);
});

test('a website pass has page-scoped wording and records the actual final destination',()=>{
 const data=base('safe','low');data.source='https://entry.example/';
 data.website_check={status:'checked',source:'public_html',identity_verified:false,final_url:'https://destination.example/home'};
 const answer=report.brief(data),full=report.full(data);
 assert.match(answer,/No obvious warning signs were found in the checked page\./);
 assert.doesNotMatch(answer,/Applies only to the submitted content/);
 assert.match(full,/Page check: Checked/);assert.match(full,/Page source: Public HTML/);
 assert.match(full,/Checked destination: https:\/\/destination\.example\/home/);
 assert.doesNotMatch(full,/Checked destination: https:\/\/entry\.example/);
 assert.match(full,/The website's identity was not verified by this page check\./);
});

test('visible-page source is clear and unsafe destination values are not displayed',()=>{
 for(const final_url of ['javascript:alert(1)','https://user:secret@example.com/','data:text/html,fixture']){
  const data=base();data.website_check={status:'incomplete',source:'browser_visible_page',identity_verified:false,final_url};
  const full=report.full(data);
  assert.match(full,/Page source: Visible page text from your chosen scan/);
  assert.doesNotMatch(full,/Checked destination:|user:secret|javascript:|data:text/);
 }
});

test('supported danger retains its strong warning even when page coverage is incomplete',()=>{
 const data=base('danger','elevated');data.website_check={status:'incomplete',source:'none'};
 assert.match(report.brief(data),/Significant risk signals were found\. Pause before taking the requested action\./);
 assert.doesNotMatch(report.brief(data),/This is not evidence that the website is suspicious/);
});
test('main answer is bounded to three short reasons and one next step',()=>{
 const data=base();data.decision.reasons=Array.from({length:5},(_,i)=>({text:'Reason '+i+' '+ 'x'.repeat(1000)}));
 data.decision.next_steps=['FIRST_STEP '+ 'y'.repeat(1000),'SECOND_STEP'];
 const answer=report.brief(data),reasons=dashboard.conciseReasons(data);
 assert.equal((answer.match(/^• /gm)||[]).length,3);assert.ok(answer.length<1000);
 assert.doesNotMatch(answer,/Reason 3|SECOND_STEP/);assert.equal(reasons.length,3);
 assert.ok(reasons.every(reason=>reason.length<=141));
 assert.doesNotMatch(dashboard.renderResult(data),/Reason 3|SECOND_STEP/);
});
test('extension details contain at most twelve bounded current evidence items with provenance',()=>{
 const data=base();data.evidence=Array.from({length:14},(_,i)=>({id:'E'+(i+1),source:'Fixture feed',
  source_url:'https://evidence.example/item/'+i,checked_at:'2026-10-25T10:00:00Z',
  evidence_type:'text_observation',observation:{text:'ENTRY_'+i+' '+ 'x'.repeat(1000)}}));
 data.decision.limitations=Array.from({length:5},(_,i)=>'LIMIT_'+i+' '+ 'y'.repeat(500));
 const full=report.full(data),contentLines=full.split('\n').filter(line=>line.startsWith('Content: '));
 assert.equal(contentLines.length,12);assert.ok(contentLines.every(line=>line.slice(9).length<=300));
 assert.match(full,/\[E1\] Fixture feed/);assert.match(full,/Time: 2026-10-25T10:00:00Z/);
 assert.match(full,/Source URL: https:\/\/evidence.example\/item\/0/);
 assert.doesNotMatch(full,/\[E13\]|ENTRY_12|LIMIT_3/);assert.match(full,/2 additional source records/);
 assert.ok(full.length<9000);
 const html=dashboard.renderResult(data);assert.doesNotMatch(html,/ENTRY_12|LIMIT_3/);
});
test('source references allow only HTTP(S) without embedded credentials',()=>{
 for(const url of ['javascript:alert(1)','data:text/html,x','https://user:password@example.com/','not-a-url']){
  assert.equal(report.sourceURL({source_url:url}), '');assert.equal(dashboard.safeUrl(url),'');
 }
 assert.equal(report.sourceURL({observation:{source_url:'https://example.com/source'}}),'https://example.com/source');
 assert.equal(report.sourceURL({source:'http://example.com/'}),'http://example.com/');
});
test('inactive services and memory machinery are omitted from compact details',()=>{
 const data=base();Object.assign(data,{zetaris:{status:'unconfigured'},ai_analysis:{status:'disabled',requested_model:'NO_MODEL_ROUTE'},
  memory_recall:{status:'unavailable'},memory_write:{status:'unavailable'},
  limitations:['Zetaris is not configured.','H-MEM recall unavailable.','RELEVANT_LIMIT'],
  validation:{gaps:['Nightshift disabled','H-MEM unavailable']},
  evidence:[{id:'TOOL_STATUS_ONLY',evidence_type:'tool_status',source:'Zetaris',observation:{status:'unconfigured'}}]});
 const full=report.full(data);
 assert.doesNotMatch(full,/Zetaris|Nightshift|H-MEM|NO_MODEL_ROUTE|TOOL_STATUS_ONLY|memory recall|Memory save/);
 assert.match(full,/RELEVANT_LIMIT/);
});
test('model identity and route appear only in an actual model-mode result',()=>{
 const data=base();data.ai_analysis={status:'online',model_identity_reported:true,model:'ACTUAL_MODEL',requested_model:'REQUESTED_ROUTE'};
 assert.doesNotMatch(report.full(data),/ACTUAL_MODEL|REQUESTED_ROUTE/);
 data.decision.mode='model';assert.match(report.full(data),/Model: ACTUAL_MODEL/);assert.match(report.full(data),/Model route: REQUESTED_ROUTE/);
});
test('historical observations are excluded from current evidence and never called fresh',()=>{
 const data=base();data.evidence=[{id:'E1',source:'current source',observation:'CURRENT_OBSERVATION'},
  {id:'OLD',historical_only:true,evidence_type:'historical_memory',source:'old',observation:'PAST_SECRET_REQUEST'}];
 const full=report.full(data),html=dashboard.renderResult(data);
 assert.match(full,/CURRENT_OBSERVATION/);assert.match(html,/CURRENT_OBSERVATION/);
 assert.doesNotMatch(full,/PAST_SECRET_REQUEST/);assert.doesNotMatch(html,/PAST_SECRET_REQUEST/);
 assert.match(full,/Historical records are context only, not new evidence/);
 assert.match(read('server/dashboard.html'),/Previous results are not evidence for a new check/);
});
test('independent listing and model abstention retain a brief visible explanation',()=>{
 const data=base('uncertain','caution');data.risk_basis={listing_floor_applied:true};
 data.ai_analysis={semantic_validation:{status:'abstained',model_risk_level:'elevated'}};
 const full=report.full(data),html=dashboard.renderResult(data);
 assert.match(full,/blocklist match keeps the overall assessment cautious/);assert.match(full,/initial model rating "elevated" was withdrawn for lack of current supporting evidence/);
 assert.match(html,/A blocklist match records a source observation/);assert.match(html,/The initial model assessment was withdrawn because current evidence did not support it/);
 assert.equal(report.verdict(data),'uncertain');
});
test('details are initially collapsed and untrusted source text is inserted only as text',()=>{
 const createElement=tag=>({tag,children:[],open:false,append(...children){this.children.push(...children)},
  set innerHTML(_value){throw Error('Untrusted HTML insertion is forbidden')}});
 const ownerDocument={createElement},container={ownerDocument,replaceChildren(...children){this.children=children}};
 const data=base(),payload='<img src=x onerror=alert(1)>';
 data.decision.reasons=[{text:payload}];data.evidence=[{id:'E1',source:'submitted',observation:payload}];
 report.render(container,data);
 assert.equal(container.children[0].className,'brief-answer verdict-uncertain');assert.match(container.children[0].textContent,/<img/);
 const details=container.children[1];assert.equal(details.tag,'details');assert.equal(details.open,false);
 assert.equal(details.children[0].tag,'summary');assert.equal(details.children[1].tag,'pre');assert.match(details.children[1].textContent,/<img/);
 const html=dashboard.renderResult(data);assert.doesNotMatch(html,/<details[^>]*\bopen\b/);
});
test('dashboard escapes all submitted HTML and refuses unsafe clickable source URLs',()=>{
 const data=base(),payload='<svg onload=alert(1)>';
 data.decision.summary=payload;data.decision.reasons=[{text:payload}];
 data.evidence=[{id:payload,source:payload,observation:payload,source_url:'javascript:alert(1)'}];
 const html=dashboard.renderResult(data);assert.doesNotMatch(html,/<svg|href="javascript:/);
 assert.match(html,/&lt;svg/);assert.equal(dashboard.esc('<>&"'), '&lt;&gt;&amp;&quot;');
});

test('English presentation preserves original multilingual source quotations',()=>{
 const source='\u4e0d\u8981\u5206\u4eab\u9a8c\u8bc1\u7801\u3002';
 const data=base('safe','low');data.evidence=[{id:'E1',source:'Submitted message',observation:{text:source}}];
 const full=report.full(data);
 assert.match(full,/^✓ Safe/);assert.match(full,/Next step: /);assert.match(full,/Current evidence/);
 assert.ok(full.includes('Content: '+source));assert.ok(dashboard.renderResult(data).includes(source));
 const createElement=tag=>({tag,children:[],append(...children){this.children.push(...children)}});
 const container={ownerDocument:{createElement},replaceChildren(...children){this.children=children}};
 report.render(container,data);
 assert.equal(container.children[1].children[0].textContent,'View evidence and details');
});

test('extension-generated defaults and fallbacks are English',()=>{
 for(const data of [base('safe','low'),base('uncertain','unknown'),base('danger','elevated'),{},
  {risk_level:'caution',risk_basis:{listing_floor_applied:true},
   ai_analysis:{semantic_validation:{status:'abstained',model_risk_level:'elevated'}}}])
  assert.doesNotMatch(report.full(data),/[\p{Script=Han}]/u);
 const manifest=JSON.parse(read('extension/manifest.json'));assert.equal(manifest.version,'0.3.2');
});
