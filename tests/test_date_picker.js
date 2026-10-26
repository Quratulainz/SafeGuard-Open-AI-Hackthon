// English calendar and validation regressions; no libraries, browser, or network.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const html=fs.readFileSync(path.join(__dirname,'../server/dashboard.html'),'utf8');
const script=html.match(/<script>([\s\S]*?)<\/script>/)[1];
function harness(){
 const elements=new Map(),events=[];let focused='';
 const element=id=>{if(!elements.has(id))elements.set(id,{id,value:'',type:'text',required:false,validity:{},attrs:{},innerHTML:'',textContent:'',open:false,
  setAttribute(k,v){this.attrs[k]=v},setCustomValidity(value){this.validationMessage=value},
  dispatchEvent(event){events.push(event.type)},focus(){focused=this.id},
  showModal(){this.open=true},close(){this.open=false},
  querySelector(selector){const date=selector.match(/data-calendar-date="([^"]+)"/)?.[1];return {focus(){focused=date}}}});return elements.get(id)};
 const context=vm.createContext({URL,document:{getElementById:element},Event:class{constructor(type){this.type=type}}});
 vm.runInContext(script.slice(0,script.indexOf("document.querySelectorAll('[data-tab]')"))+
  '\nglobalThis.picker={parseCalendarDate,formatCalendarDate,calendarDateLabel,calendarDaysInMonth,moveCalendarMonth,moveCalendarDay,calendarMonthMarkup,englishValidationMessage,validateEnglishField,openCalendar,selectCalendarDate,navigateCalendar,calendarKeyboard};',context);
 return {picker:context.picker,element,events,focused:()=>focused};
}
test('ISO typing rejects impossible dates and handles Gregorian leap-century rules',()=>{
 const {picker:p}=harness();
 for(const date of ['2026-02-29','1900-02-29','2026-04-31','0000-01-01','2026-13-01','2026-00-10','2026-01-00','2026-2-01','01/02/2026'])assert.equal(p.parseCalendarDate(date),null,date);
 for(const date of ['2028-02-29','2000-02-29','0001-01-01','9999-12-31'])assert.equal(p.formatCalendarDate(p.parseCalendarDate(date)),date);
});
test('month navigation crosses years and clamps leap-month day without leaving supported years',()=>{
 const {picker:p}=harness(),move=(date,offset)=>p.formatCalendarDate(p.moveCalendarMonth(p.parseCalendarDate(date),offset));
 assert.equal(move('2028-01-31',1),'2028-02-29');assert.equal(move('2026-03-31',-1),'2026-02-28');
 assert.equal(move('2026-12-15',1),'2027-01-15');assert.equal(move('2026-01-15',-1),'2025-12-15');
 assert.equal(p.moveCalendarMonth(p.parseCalendarDate('0001-01-01'),-1),null);
 assert.equal(p.moveCalendarMonth(p.parseCalendarDate('9999-12-31'),1),null);
 assert.equal(p.formatCalendarDate(p.moveCalendarDay(p.parseCalendarDate('2028-02-28'),1)),'2028-02-29');
 assert.equal(p.formatCalendarDate(p.moveCalendarDay(p.parseCalendarDate('2028-02-29'),1)),'2028-03-01');
});
test('calendar grid shows English labels, valid leap days, selected state and one keyboard tab stop',()=>{
 const {picker:p}=harness(),view=p.parseCalendarDate('2028-02-29');
 const markup=p.calendarMonthMarkup(view,'2028-02-29','2028-02-29','2028-02-28');
 assert.equal((markup.match(/data-calendar-date=/g)||[]).length,29);
 assert.equal((markup.match(/tabindex="0"/g)||[]).length,1);
 assert.match(markup,/aria-label="February 29, 2028" aria-pressed="true"/);
 assert.match(markup,/aria-current="date"/);assert.doesNotMatch(markup,/2028-02-30|\p{Script=Han}/u);
});
test('opening and selecting updates the existing input value and emits input/change events',()=>{
 const h=harness(),input=h.element('sub-renewal'),trigger=h.element('toggle');input.required=true;input.value='2028-02-29';
 h.picker.openCalendar(input,trigger);assert.equal(h.element('date-calendar').open,true);
 assert.equal(h.element('calendar-month').textContent,'February 2028');
 assert.equal(h.element('calendar-selected').textContent,'Selected: February 29, 2028');
 assert.equal(trigger.attrs['aria-expanded'],'true');assert.equal(h.focused(),'2028-02-29');
 h.picker.selectCalendarDate('2028-03-01');assert.equal(input.value,'2028-03-01');
 assert.equal(input.validationMessage,'');assert.deepEqual(h.events,['input','change']);assert.equal(h.element('date-calendar').open,false);
});
test('arrow and page keys cross month boundaries with focus on the resulting day',()=>{
 const h=harness(),input=h.element('sub-cancel');input.value='2028-02-29';h.picker.openCalendar(input,h.element('toggle'));
 let prevented=false;const button={dataset:{calendarDate:'2028-02-29'},closest(){return this}};
 h.picker.calendarKeyboard({target:button,key:'ArrowRight',preventDefault(){prevented=true}});
 assert.ok(prevented);assert.equal(h.element('calendar-month').textContent,'March 2028');assert.equal(h.focused(),'2028-03-01');
 h.picker.calendarKeyboard({target:button,key:'PageDown',preventDefault(){}});assert.equal(h.focused(),'2028-03-29');
});
test('required renewal and optional cancellation remain distinct on clear and typed invalid dates',()=>{
 const h=harness(),renewal=h.element('sub-renewal'),cancel=h.element('sub-cancel');renewal.required=true;
 assert.equal(h.picker.validateEnglishField(renewal),false);assert.match(renewal.validationMessage,/Enter a renewal date/);
 assert.equal(h.picker.validateEnglishField(cancel),true);
 renewal.value='2026-02-30';assert.equal(h.picker.validateEnglishField(renewal),false);assert.match(renewal.validationMessage,/valid date in YYYY-MM-DD/);
 renewal.value='2026-02-28';h.picker.openCalendar(renewal,h.element('toggle'));h.picker.selectCalendarDate('');
 assert.equal(renewal.value,'');assert.match(renewal.validationMessage,/Enter a renewal date/);
 cancel.value='2026-02-28';h.picker.openCalendar(cancel,h.element('toggle'));h.picker.selectCalendarDate('');assert.equal(cancel.validationMessage,'');
});
test('required URL and number errors use explicit English messages',()=>{
 const {picker:p}=harness();
 assert.equal(p.englishValidationMessage({id:'sub-name',validity:{valueMissing:true}}),'Enter a service name.');
 assert.match(p.englishValidationMessage({type:'url',value:'ftp://example.com',validity:{}}),/valid URL starting with http/);
 assert.match(p.englishValidationMessage({type:'url',value:'https://user:secret@example.com',validity:{}}),/without embedded credentials/);
 assert.equal(p.englishValidationMessage({type:'url',value:'https://example.com',validity:{}}),'');
 assert.equal(p.englishValidationMessage({id:'sub-amount',validity:{stepMismatch:true}}),'Use up to two decimal places.');
 assert.match(p.englishValidationMessage({min:'0',validity:{rangeUnderflow:true}}),/0 or greater/);
 assert.equal(p.englishValidationMessage({validity:{badInput:true}}),'Enter a valid number.');
});
test('native date pickers are absent and English dialog controls and validation hooks exist',()=>{
 assert.doesNotMatch(html,/type=["']date["']/i);assert.doesNotMatch(html,/\p{Script=Han}/u);
 for(const label of ['Prev','Next','Today','Clear','Close','Sun','Mon','Tue','Wed','Thu','Fri','Sat'])assert.ok(html.includes('>'+label+'<'),label);
 assert.match(html,/id="sub-renewal" type="text" required/);assert.match(html,/id="sub-cancel" type="text"/);
 assert.match(script,/addEventListener\('invalid'/);assert.match(script,/stopImmediatePropagation\(\);form.reportValidity\(\)/);
 assert.match(script,/refreshFormValidation\(\$\('subscription-form'\)\);closeCalendar\(\)/);
 new Function(script);
});
