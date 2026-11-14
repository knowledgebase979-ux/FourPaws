import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {FileStore,startServer} from '../server.mjs';
import {safeAPI,D1Store,blankState,validateState,runAssistant,parseGeminiResponse,geminiThinkingLevel,scoreComparison,assetResponse,secureResponse,searchNearby,normalizePlaces} from '../worker/index.js';
class SqliteD1 {
 constructor(){this.db=new DatabaseSync(':memory:');}
 prepare(sql){const statement=this.db.prepare(sql);let args=[];return {bind(...values){args=values;return this;},async first(){return statement.get(...args)||null;},async run(){const r=statement.run(...args);return {meta:{changes:Number(r.changes)}};}};}
 async batch(statements){this.db.exec('BEGIN');try{const result=[];for(const s of statements)result.push(await s.run());this.db.exec('COMMIT');return result;}catch(e){this.db.exec('ROLLBACK');throw e;}}
}
const origin='https://pawpath.test';
function caller(store,env={}){let cookie='';return {get cookie(){return cookie;},async request(path,body,method=body?'POST':'GET',extra={}){const headers={'Origin':origin,...(body!==undefined?{'Content-Type':'application/json'}:{}),...(cookie?{'Cookie':cookie}:{}),...extra};const r=await safeAPI(new Request(origin+'/api/'+path,{method,headers,...(body!==undefined?{body:JSON.stringify(path==='register'?{...body,dog:body.dog||{...dog}}:body)}:{})}),store,env);if(r.headers.get('set-cookie'))cookie=r.headers.get('set-cookie').split(';')[0];return {response:r,status:r.status,body:await r.json()};}};}
const dog={id:'dog-a',name:'לוקה',breed:'מעורב',size:'medium',weight:16,birthday:'2023-01-01',notes:'רגישות ידועה',vet:'מרפאה',phone:'',chip:''};
const task={id:'task-a',dogId:dog.id,title:'שקילה',type:'weight',due:new Date().toISOString(),repeatDays:7,done:false,notes:'',completedAt:''};
for(const backend of ['files','d1']){
 test(backend+': auth, isolation, persistence, version conflicts, safety checks',async()=>{
  let store,temp,db;if(backend==='files'){temp=await mkdtemp(join(tmpdir(),'pawpath-test-'));store=new FileStore(temp);}else{db=new SqliteD1();db.db.exec(await readFile(new URL('../drizzle/0000_pawpath.sql',import.meta.url),'utf8'));store=new D1Store(db);}
  try{
   const anon=caller(store),alice=caller(store),bob=caller(store);
   assert.equal((await anon.request('state')).status,401);
   assert.equal((await anon.request('entry')).body.adminExists,false);
   assert.equal((await alice.request('register',{username:'alice',password:'Test1234'},'POST',{'Origin':'https://other.test'})).status,403);
   const register=await alice.request('register',{username:'Alice',password:'Test1234'});assert.equal(register.status,200);assert.equal(register.body.user.username,'alice');assert.match(register.response.headers.get('set-cookie'),/HttpOnly/);assert.match(register.response.headers.get('set-cookie'),/Secure/);
   const duplicate=await anon.request('register',{username:'ALICE',password:'Test1234'});assert.equal(duplicate.status,409);
   assert.equal((await anon.request('login',{username:'alice',password:'bad-password-123'})).status,401);
   assert.equal((await bob.request('register',{username:'bob',password:'Other123'})).status,200);
   const initial=await alice.request('state');assert.equal(initial.body.state.dogs.length,1);assert.equal(initial.body.state.dogs[0].name,dog.name);assert.equal(initial.body.version,0);
   const state={dogs:[dog],tasks:[task],logs:[]};
   assert.equal((await alice.request('state',{state,version:0},'PUT')).status,200);
   assert.equal((await alice.request('state',{state,version:0},'PUT')).status,409);
   assert.equal((await bob.request('state')).body.version,0);
   const bad=structuredClone(state);bad.tasks[0].dogId='other-account-dog';assert.equal((await alice.request('state',{state:bad,version:1},'PUT')).status,400);
   bad.tasks[0].dogId=dog.id;bad.dogs[0].weight=-5;assert.equal((await alice.request('state',{state:bad,version:1},'PUT')).status,400);
   assert.equal((await alice.request('config')).body.aiEnabled,false);
   const configured=await safeAPI(new Request(origin+'/api/config',{headers:{Cookie:alice.cookie}}),store,{GEMINI_API_KEY:'unit-test-secret-placeholder'});const configBody=await configured.json();assert.equal(configBody.aiEnabled,true);assert.equal(configBody.provider,'Gemini');assert.equal(configBody.searchEnabled,false);assert.equal(configBody.searchProvider,'Exa');assert.ok(!JSON.stringify(configBody).includes('unit-test-secret-placeholder'));
   const consult={mode:'consult',question:'יש לכלב סימן ברגל',flags:[],city:'',sort:'relevance',consent:true};
   assert.equal((await alice.request('assistant',consult)).status,503);
   const emergency=await alice.request('assistant',{...consult,flags:['bleeding']});assert.equal(emergency.status,200);assert.equal(emergency.body.kind,'emergency');assert.equal(emergency.body.generated,false);
   assert.equal((await alice.request('assistant',{...consult,image:'https://internal.test/photo'})).status,400);
   if(backend==='files'){const users=JSON.parse(await readFile(join(temp,'users.json'),'utf8'));assert.equal(users.length,2);assert.ok(users[0].password_hash);assert.ok(!JSON.stringify(users).includes('Test1234'));assert.equal((await stat(join(temp,'users.json'))).mode&0o777,0o600);const reopened=new FileStore(temp);assert.equal((await reopened.getState(register.body.user.id)).state.dogs[0].name,'לוקה');}
   const savedCookie=alice.cookie;assert.equal((await alice.request('logout',{})).status,200);const revoked=await safeAPI(new Request(origin+'/api/state',{headers:{Cookie:savedCookie}}),store);assert.equal(revoked.status,401);
   assert.equal((await alice.request('login',{username:'alice',password:'Test1234'})).status,200);
   assert.equal((await alice.request('state')).body.state.dogs[0].name,'לוקה');
   assert.equal((await anon.request('register',{username:'admin',password:'Admin123'})).status,200);
   assert.equal((await bob.request('entry')).body.adminExists,true);
   assert.equal((await bob.request('register',{username:'admin',password:'Other123'})).status,409);
  }finally{if(temp)await rm(temp,{recursive:true,force:true});if(db)db.db.close();}
 });
}
test('HTTP server: real registration, restricted file access and request limit',async()=>{const temp=await mkdtemp(join(tmpdir(),'pawpath-http-'));const server=startServer({port:0,dataDir:temp});await new Promise(r=>server.listening?r():server.once('listening',r));const base='http://127.0.0.1:'+server.address().port;try{assert.equal((await fetch(base+'/')).status,200);assert.equal((await fetch(base+'/admin')).status,200);assert.equal((await fetch(base+'/login')).status,200);assert.equal((await fetch(base+'/data/users.json')).status,404);const r=await fetch(base+'/api/register',{method:'POST',headers:{Origin:base,'Content-Type':'application/json'},body:JSON.stringify({username:'local-test',password:'Test1234',dog})});assert.equal(r.status,200);const cookie=r.headers.get('set-cookie').split(';')[0];const state=await fetch(base+'/api/state',{headers:{Cookie:cookie}});assert.equal(state.status,200);const large=await fetch(base+'/api/state',{method:'PUT',headers:{Cookie:cookie,Origin:base,'Content-Type':'application/json'},body:JSON.stringify({huge:'x'.repeat(520000)})});assert.equal(large.status,413);}finally{server.closeAllConnections();await new Promise(r=>server.close(r));await rm(temp,{recursive:true,force:true});}});
test('rate limiter bounds attempts',async()=>{const dir=await mkdtemp(join(tmpdir(),'pawpath-rate-'));try{const store=new FileStore(dir);for(let i=0;i<15;i++)assert.equal(await store.allow('one-ip'),true);assert.equal(await store.allow('one-ip'),false);}finally{await rm(dir,{recursive:true,force:true});}});

const searchText='מידע לכלב 🐕 ממקור מאומת';
const searchFixture=()=>({candidates:[{finishReason:'STOP',content:{parts:[{thought:true,text:'hidden reasoning'},{text:searchText}]},groundingMetadata:{webSearchQueries:['dog care'],searchEntryPoint:{renderedContent:'<style>.chip{color:#333}</style><a class="chip" href="https://www.google.com/search?q=dog+care">dog care</a>'},groundingChunks:[{web:{uri:'https://source.test/dogs',title:'Source A'}},{web:{uri:'https://second.test/dogs',title:'Source B'}}],groundingSupports:[{segment:{startIndex:0,endIndex:new TextEncoder().encode(searchText).length,text:searchText},groundingChunkIndices:[0,1]}]}}]});
const exaFixture=()=>({results:[{url:'https://source.test/dogs',title:'Source A',text:'מידע לכלב'},{url:'https://second.test/dogs',title:'Source B',text:'מידע נוסף'}]});
const summaryFixture=(sourceIds=[1,2])=>({candidates:[{finishReason:'STOP',content:{parts:[{text:JSON.stringify({blocks:[{text:searchText,sourceIds}]})}]}}]});
const searchEnv={GEMINI_API_KEY:'unit-test-placeholder',EXA_API_KEY:'search-test-placeholder'};
test('Exa Lite search uses one bounded request and Gemini cites only returned sources without Google tools',async()=>{const original=globalThis.fetch;try{
 const calls=[];globalThis.fetch=async(url,opts)=>{const body=JSON.parse(opts.body);calls.push({url,body,headers:opts.headers});return Response.json(url==='https://api.exa.ai/search'?exaFixture():summaryFixture());};
 const result=await runAssistant({mode:'find',question:'חפש מוצר לכלב',city:'חיפה',sort:'price'},{notes:'private clinical note'},searchEnv);
 assert.equal(calls.length,2);assert.equal(calls[0].url,'https://api.exa.ai/search');assert.equal(calls[0].headers['x-api-key'],'search-test-placeholder');assert.equal(calls[0].body.type,'lite');assert.equal(calls[0].body.numResults,6);assert.equal(calls[0].body.contents.text.maxCharacters,6000);assert.match(calls[0].body.query,/חיפה/);
 assert.ok(!calls[1].body.tools);assert.ok(!JSON.stringify(calls).includes('private clinical note'));assert.equal(calls[1].body.generationConfig.responseMimeType,'application/json');
 assert.equal(result.kind,'search');assert.equal(result.provider,'Gemini + Exa');assert.equal(result.blocks[0].annotations.length,2);assert.equal(result.blocks[0].annotations[0].end_index,Array.from(searchText).length);assert.equal(result.searchSuggestions,'');assert.equal(result.sources[0].url,'https://source.test/dogs');
 for(const refs of [[99],[],[1,99]]){globalThis.fetch=async url=>Response.json(url==='https://api.exa.ai/search'?exaFixture():summaryFixture(refs));await assert.rejects(runAssistant({mode:'find',question:'חיפוש'},null,searchEnv),e=>e.status===502);}
}finally{globalThis.fetch=original;}});
test('search profile stays out of Exa, and reaches Gemini only with explicit consent',async()=>{const original=globalThis.fetch;try{
 for(const consent of [false,true]){const calls=[];globalThis.fetch=async(url,opts)=>{calls.push({url,body:JSON.parse(opts.body)});return Response.json(url==='https://api.exa.ai/search'?exaFixture():summaryFixture());};await runAssistant({mode:'find',question:'מזון לכלב',includeDog:true,consent},{notes:'private clinical note',breed:'מעורב'},searchEnv);assert.ok(!JSON.stringify(calls[0]).includes('private clinical note'));assert.equal(JSON.stringify(calls[1]).includes('private clinical note'),consent);}
}finally{globalThis.fetch=original;}});
test('missing Exa key, exhausted credits and invalid search results never fall back or call Gemini',async()=>{const original=globalThis.fetch;try{
 let calls=0;globalThis.fetch=async()=>{calls++;throw Error('should not call');};await assert.rejects(runAssistant({mode:'find',question:'חיפוש'},null,{GEMINI_API_KEY:'test'}),e=>e.status===503);assert.equal(calls,0);
 for(const [status,expected] of [[401,503],[403,503],[402,429],[429,429],[503,502]]){calls=0;globalThis.fetch=async(url)=>{calls++;assert.equal(url,'https://api.exa.ai/search');return Response.json({error:'sensitive provider content'},{status});};await assert.rejects(runAssistant({mode:'find',question:'חיפוש'},null,searchEnv),e=>e.status===expected&&!e.message.includes('sensitive'));assert.equal(calls,1);}
 for(const data of [{results:[]},{},{results:[{url:'javascript:alert(1)',text:'bad'},{url:'https://empty.test',text:''}]}]){calls=0;globalThis.fetch=async()=>{calls++;return Response.json(data);};await assert.rejects(runAssistant({mode:'find',question:'חיפוש'},null,searchEnv),e=>e.status===502);assert.equal(calls,1);}
}finally{globalThis.fetch=original;}});
test('API config separates search readiness and keeps both provider secrets private',async()=>{const temp=await mkdtemp(join(tmpdir(),'fourpaws-config-'));try{const store=new FileStore(temp),client=caller(store,searchEnv);await client.request('register',{username:'config-test',password:'Test1234'});const {body}=await client.request('config');assert.equal(body.aiEnabled,true);assert.equal(body.searchEnabled,true);assert.equal(body.searchProvider,'Exa');assert.ok(!JSON.stringify(body).includes('test-placeholder'));}finally{await rm(temp,{recursive:true,force:true});}});
test('Gemini image consultation uses inlineData, explicit JSON schema and validates required guidance fields',async()=>{const original=globalThis.fetch;try{const guidance={observations:'אין די מידע',possibilities:'לא ניתן לקבוע',urgency:'unclear',nextSteps:['פנייה לווטרינר'],avoid:['אין לתת תרופות'],vetSigns:['כאב או החמרה'],questions:['מתי הופיע?'],limitations:'אינו אבחון'};let sent;globalThis.fetch=async(url,opts)=>{sent=JSON.parse(opts.body);return Response.json({candidates:[{finishReason:'STOP',content:{parts:[{text:JSON.stringify(guidance)}]}}]});};const result=await runAssistant({mode:'consult',question:'תיאור סימן',image:'data:image/png;base64,aW1hZ2U='},{breed:'מעורב'},{GEMINI_API_KEY:'unit-test-placeholder'});assert.equal(result.guidance.urgency,'unclear');assert.equal(sent.contents[0].parts[1].inlineData.mimeType,'image/png');assert.equal(sent.generationConfig.responseMimeType,'application/json');assert.ok(sent.generationConfig.responseJsonSchema.required.includes('limitations'));assert.ok(!sent.tools);assert.throws(()=>parseGeminiResponse({candidates:[{finishReason:'STOP',content:{parts:[{text:'{"urgency":"unclear"}'}]}}]},false),/חלקי ההכוונה/);}finally{globalThis.fetch=original;}});
test('Gemini rejection and quota errors are actionable and do not include provider secrets',async()=>{const original=globalThis.fetch;try{for(const status of [403,429,503]){globalThis.fetch=async()=>Response.json({error:{message:'sensitive provider content'}},{status});await assert.rejects(runAssistant({mode:'consult',question:'test'},null,{GEMINI_API_KEY:'unit-test-placeholder',GEMINI_RETRY_DELAY_MS:0}),e=>{assert.ok(!e.message.includes('sensitive'));return e.status===(status===403?503:status===429?429:502);});}}finally{globalThis.fetch=original;}});
test('HTML gets a fresh CSS nonce and secure wrapping preserves it',async()=>{const first=assetResponse({method:'GET'},'<meta name="style-nonce" content="__STYLE_NONCE__">','text/html');const header=first.headers.get('Content-Security-Policy');const text=await first.text();assert.ok(!text.includes('__STYLE_NONCE__'));const nonce=header.match(/nonce-([^']+)/)[1];assert.ok(text.includes(nonce));assert.equal(secureResponse(first).headers.get('Content-Security-Policy'),header);const next=assetResponse({method:'GET'},'__STYLE_NONCE__','text/html');assert.notEqual(next.headers.get('Content-Security-Policy'),header);});

test('state validation rejects injected IDs, null records, impossible birthdays and future logs',()=>{
 const state={dogs:[dog],tasks:[task],logs:[]};
 for(const mutate of [s=>{s.dogs[0].id='x" onclick="bad';},s=>{s.dogs[0]=null;},s=>{s.dogs[0].birthday='2023-02-31';},s=>{s.tasks[0].due=1234;},s=>{s.logs=[{id:'future',dogId:dog.id,type:'note',date:new Date(Date.now()+86400000).toISOString(),text:'note',value:0}];}]){
 const bad=structuredClone(state);mutate(bad);assert.throws(()=>validateState(bad),e=>e.status===400);
 }
 assert.deepEqual(validateState(state),state);
});
test('non-object JSON payloads receive 400 rather than an internal error',async()=>{
 const temp=await mkdtemp(join(tmpdir(),'fourpaws-json-'));try{const store=new FileStore(temp);for(const value of ['null','[]','42']){
 const response=await safeAPI(new Request(origin+'/api/register',{method:'POST',headers:{Origin:origin,'Content-Type':'application/json'},body:value}),store);assert.equal(response.status,400);
 }}finally{await rm(temp,{recursive:true,force:true});}
});

 test('new account collections preserve data and reject foreign dog references and active photo content',()=>{
 const input={dogs:[dog],tasks:[],logs:[],extras:{challenges:[{dogId:dog.id,challengeId:'room-treasure',week:'2026-11-02',date:new Date().toISOString()}],quiz:[{questionId:'tail',correct:true,date:new Date().toISOString()}],album:[],family:[{id:'f1',dogId:dog.id,title:'מים טריים',assignee:'המשפחה',due:new Date().toISOString(),done:false}],passports:[{dogId:dog.id,nickname:'לוקי',personality:'סקרן',favorites:'משחקי הרחה'}]}};
 const saved=validateState(input);assert.equal(saved.extras.challenges.length,1);assert.equal(saved.extras.passports[0].nickname,'לוקי');const wrong=structuredClone(input);wrong.extras.family[0].dogId='foreign';assert.throws(()=>validateState(wrong));const active=structuredClone(input);active.extras.album.push({id:'photo1',dogId:dog.id,date:new Date().toISOString(),caption:'תמונה',image:'data:image/svg+xml,<svg onload="alert(1)"/>'});assert.throws(()=>validateState(active));
 });

test('nearby provider geocodes the requested place and strictly filters the selected type and radius',async()=>{
 const real=globalThis.fetch,calls=[];globalThis.fetch=async(url)=>{url=new URL(url);calls.push(url);if(url.pathname==='/api/')return Response.json({features:[{properties:{name:'עיר הבדיקה'},geometry:{coordinates:[34.88,32.09]}}]});return Response.json({features:[{properties:{name:'מרפאה',osm_type:'N',osm_id:99,osm_key:'amenity',osm_value:'veterinary',street:'הרצל',housenumber:'10',city:'עיר הבדיקה'},geometry:{coordinates:[34.881,32.091]}},{properties:{name:'חנות',osm_type:'N',osm_id:100,osm_key:'shop',osm_value:'pet'},geometry:{coordinates:[34.881,32.091]}},{properties:{name:'מרפאה רחוקה',osm_type:'N',osm_id:101,osm_key:'amenity',osm_value:'veterinary'},geometry:{coordinates:[36,33]}}]});};
 try{const r=await searchNearby({category:'vet',place:'עיר בדיקה ייחודית',radius:15});assert.equal(calls[0].searchParams.get('q'),'עיר בדיקה ייחודית');assert.equal(calls[1].searchParams.get('osm_tag'),'amenity:veterinary');assert.equal(r.places.length,1);assert.equal(r.places[0].name,'מרפאה');assert.equal(r.places[0].address,'הרצל, 10, עיר הבדיקה');await assert.rejects(searchNearby({category:'unknown',place:'בדיקה'}));}finally{globalThis.fetch=real;}
});
test('Gemini agents set a thinking level for Gemini 3+, fall back on 400, retry one transient 503 and report truncation',async()=>{const original=globalThis.fetch;const env={GEMINI_API_KEY:'unit-test-placeholder',GEMINI_RETRY_DELAY_MS:0};const guidance={observations:'א',possibilities:'ב',urgency:'unclear',nextSteps:['ג'],avoid:['ד'],vetSigns:['ה'],questions:['ו'],limitations:'ז'};const ok=()=>Response.json({candidates:[{finishReason:'STOP',content:{parts:[{text:JSON.stringify(guidance)}]}}]});try{
 assert.equal(geminiThinkingLevel('gemini-3.8-flash',true),'low');assert.equal(geminiThinkingLevel('gemini-3.8-flash',false),'medium');assert.equal(geminiThinkingLevel('gemini-2.5-flash',false),null);assert.equal(geminiThinkingLevel('gemini-3.8-flash',false,{GEMINI_THINKING_LEVEL:'off'}),null);assert.equal(geminiThinkingLevel('gemini-3.8-flash',false,{GEMINI_THINKING_LEVEL:'HIGH'}),'high');
 const sent=[];globalThis.fetch=async(url,opts)=>{sent.push(JSON.parse(opts.body));return sent.length===1?Response.json({error:{message:'bad level'}},{status:400}):ok();};
 const result=await runAssistant({mode:'consult',question:'תיאור סימן'},null,env);assert.equal(result.kind,'consult');assert.equal(sent.length,2);assert.equal(sent[0].generationConfig.thinkingConfig.thinkingLevel,'medium');assert.ok(!sent[1].generationConfig.thinkingConfig);assert.ok(sent[0].generationConfig.responseJsonSchema.properties.urgency.description);
 let calls=0;globalThis.fetch=async()=>{calls++;return calls===1?Response.json({},{status:503}):ok();};assert.equal((await runAssistant({mode:'consult',question:'תיאור סימן'},null,env)).kind,'consult');assert.equal(calls,2);
 calls=0;globalThis.fetch=async()=>{calls++;return Response.json({},{status:503});};await assert.rejects(runAssistant({mode:'consult',question:'תיאור סימן'},null,env),e=>e.status===502);assert.equal(calls,2);
 assert.throws(()=>parseGeminiResponse({candidates:[{finishReason:'MAX_TOKENS',content:{parts:[{text:'{'}]}}]},false),/נקטעה/);
 assert.throws(()=>parseGeminiResponse({candidates:[{finishReason:'PROHIBITED_CONTENT'}]},false),e=>e.status===422);
}finally{globalThis.fetch=original;}});
test('comparison agent searches with Exa first, extracts without tools, scores on the server and recommends only verified stores',async()=>{const original=globalThis.fetch;try{
 const fixture={results:[{url:'https://petstore.co.il/p',title:'חנות',text:'מזון'}, {url:'https://zap.co.il/p',title:'השוואה',text:'מזון'}]};
 const c=(product,sourceDomain,scores,availability='in_stock')=>({product,store:'חנות',sourceDomain,price:'199 ₪',availability,scores,why:'נימוק',caveats:''});
 const extracted={candidates:[c('מזון א 12 ק״ג','www.petstore.co.il',{quality:5,reviews:4,value:3,availability:5}),c('מזון ב','zap.co.il',{quality:3,reviews:3,value:5,availability:4}),c('מזון מומצא','invented.example',{quality:5,reviews:5,value:5,availability:5}),c('מזון ג','petstore.co.il',{quality:4,reviews:4,value:4,availability:4},'out_of_stock'),c('מזון ד','petstore.co.il',{quality:2,reviews:2,value:2,availability:2}),c('מזון ה','zap.co.il',{quality:1,reviews:1,value:1,availability:1})],notes:'הערה'};
 const sent=[];globalThis.fetch=async(url,opts)=>{sent.push(JSON.parse(opts.body));return sent.length===1?Response.json(fixture):sent.length===2?Response.json(summaryFixture()):Response.json({candidates:[{finishReason:'STOP',content:{parts:[{text:JSON.stringify(extracted)}]}}]});};
 const r=await runAssistant({mode:'find',compare:true,question:'מזון לגולדן',city:'',sort:'relevance'},null,searchEnv);
 assert.equal(sent.length,3);assert.equal(sent[0].type,'lite');assert.ok(!sent[1].tools);assert.ok(!sent[2].tools);assert.equal(sent[2].generationConfig.responseMimeType,'application/json');assert.match(JSON.parse(sent[1].contents[0].parts[0].text).today,/^\d{4}-\d{2}-\d{2}$/);
 assert.equal(r.kind,'search');assert.equal(r.searchSuggestions,'');
 const rec=r.comparison.recommendations;assert.equal(rec.length,4);assert.deepEqual(rec.map(x=>x.product),['מזון א 12 ק״ג','מזון ב','מזון ד','מזון ה']);assert.equal(rec[0].total,85);assert.ok(rec.every(x=>x.verified));
 assert.ok(r.comparison.excluded.some(x=>x.product==='מזון מומצא'&&/לא אומת/.test(x.reason)));assert.ok(r.comparison.excluded.some(x=>x.product==='מזון ג'&&/מלאי/.test(x.reason)));
 globalThis.fetch=async(url,opts)=>url==='https://api.exa.ai/search'?Response.json(fixture):JSON.parse(opts.body).generationConfig.responseJsonSchema===undefined?Response.json(summaryFixture()):JSON.parse(opts.body).generationConfig.responseJsonSchema.properties.blocks?Response.json(summaryFixture()):Response.json({candidates:[{finishReason:'STOP',content:{parts:[{text:'not json'}]}}]});
 const fallback=await runAssistant({mode:'find',compare:true,question:'מזון לגולדן'},null,searchEnv);assert.ok(fallback.comparison.error);assert.equal(fallback.blocks[0].text,searchText);
 assert.equal(scoreComparison({candidates:[c('x','a.co.il',{quality:9,reviews:0,value:'5',availability:5})]},[{url:'https://a.co.il/p',title:'a.co.il'}]).recommendations[0].total,Math.round((0.35+0.25+0.25+0.75)/5*100));
}finally{globalThis.fetch=original;}});
test('personal identifiers are blocked before reaching the AI provider',async()=>{const {containsPersonalId}=await import('../worker/index.js');for(const t of ['ת.ז 123456789','הטלפון שלי 054-1234567','כרטיס 4580 1234 5678 9012'])assert.ok(containsPersonalId(t),t);for(const t of ['מזון 12 ק״ג ב־199 ₪','גולדן בן 8','שק 15kg'])assert.ok(!containsPersonalId(t),t);});

test('search query includes every shopping filter and sort, with optional region; dog research has a separate query',async()=>{
 const {buildSearchQuery,validateSearchFilters,parseILSPrice}=await import('../worker/index.js');
 const b={mode:'find',question:'מזון יבש לכלב',sort:'price',city:'השרון',filters:{category:'food',brand:'Acme',minPrice:100,maxPrice:240,packageKg:12,inStockOnly:true}};
 const q=buildSearchQuery(b);for(const part of ['מזון','Acme','100','240','12','במלאי','השרון','מהזול ליקר'])assert.ok(q.includes(part),part);
 assert.notEqual(q,buildSearchQuery({...b,sort:'unitPrice'}));assert.notEqual(q,buildSearchQuery({...b,filters:{...b.filters,category:'accessories',maxPrice:180}}));assert.match(buildSearchQuery({...b,city:''}),/כל הארץ/);
 const context={breed:'גולדן רטריבר',birthday:'2020-01-01',notes:'private clinical note',weight:31};const iq=buildSearchQuery({mode:'info',question:'אילוף חיובי',topic:'training'},context);assert.match(iq,/גולדן רטריבר/);assert.match(iq,/בוגר/);assert.ok(!iq.includes(context.notes));assert.ok(!iq.includes(context.birthday));
 for(const f of [{category:'bad'},{minPrice:200,maxPrice:100},{maxPrice:-1},{minPrice:'100'},{packageKg:0},{inStockOnly:'yes'}])assert.throws(()=>validateSearchFilters(f),e=>e.status===400);
 for(const [text,amount]of [['199 ₪',199],['₪1,299.90',1299.9],['199 ש״ח',199],['אין מחיר',null],['$199',null],['199–299 ₪',null],['החל מ־199 ₪',null],['199 ₪, בעבר 299 ₪',null]])assert.equal(parseILSPrice(text),amount,text);
});
test('server sorts numeric price and unit price independently of quality; unknown prices stay last',()=>{
 const c=(product,price,quality,packageKg)=>({product,price,packageKg,sourceDomain:'pet.test',availability:'in_stock',scores:{quality,reviews:quality,value:quality,availability:quality},category:'food',brand:'Acme'});
 const data={candidates:[c('יקר ואיכותי','300 ₪',5,15),c('זול','100 ₪',2,2),c('בינוני','200 ₪',3,20),c('לא ידוע','לא ידוע',5,12)]},sources=[{url:'https://pet.test/products',title:'pet'}];
 const names=sort=>scoreComparison(data,sources,{sort}).recommendations.map(x=>x.product);
 assert.deepEqual(names('price'),['זול','בינוני','יקר ואיכותי','לא ידוע']);assert.deepEqual(names('priceDesc'),['יקר ואיכותי','בינוני','זול','לא ידוע']);assert.deepEqual(names('unitPrice'),['בינוני','יקר ואיכותי','זול','לא ידוע']);assert.equal(names('relevance')[0],'יקר ואיכותי');
 const r=scoreComparison(data,sources,{sort:'price',filters:{category:'food',brand:'Acme',minPrice:150,maxPrice:250}});assert.deepEqual(r.recommendations.map(x=>x.product),['בינוני']);assert.ok(r.excluded.some(x=>/תקציב/.test(x.reason)));assert.ok(r.excluded.some(x=>/מחיר לא ידוע/.test(x.reason)));
 const unknown=structuredClone(data);unknown.candidates[1].availability='unknown';assert.ok(!scoreComparison(unknown,sources,{filters:{inStockOnly:true}}).recommendations.some(x=>x.product==='זול'));
 assert.equal(scoreComparison(data,sources,{filters:{packageKg:20}}).recommendations.length,1);assert.equal(scoreComparison(data,sources,{filters:{category:'accessories'}}).recommendations.length,0);
});
test('passport information API enforces owner and consent, passes photo to Gemini only, and never runs product comparison',async()=>{
 const original=globalThis.fetch,temp=await mkdtemp(join(tmpdir(),'fourpaws-info-'));try{
 const store=new FileStore(temp),alice=caller(store,searchEnv);await alice.request('register',{username:'info-test',password:'Test1234'});await alice.request('state',{state:{dogs:[dog],tasks:[],logs:[]},version:0},'PUT');
 const request={mode:'info',question:'אילו פעילויות מתאימות לכלב שלי?',topic:'care',dogId:dog.id,includeDog:true,consent:true,flags:[],image:'data:image/png;base64,aW1hZ2U='};
 let calls=[];globalThis.fetch=async(url,opts)=>{const body=JSON.parse(opts.body);calls.push({url,body});if(url==='https://api.exa.ai/search')return Response.json(exaFixture());return Response.json({candidates:[{finishReason:'STOP',content:{parts:[{text:JSON.stringify({blocks:[{text:'פעילות לפי המקורות',evidence:'web',sourceIds:[1]},{text:'תיאור חזותי מסויג',evidence:'photo',sourceIds:[]},{text:'פרטי הדרכון',evidence:'profile',sourceIds:[]}]})}]}}]});};
 const r=await alice.request('assistant',request);assert.equal(r.status,200);assert.equal(r.body.kind,'info');assert.ok(!r.body.comparison);assert.equal(calls.length,2);assert.equal(calls[1].body.contents[0].parts[1].inlineData.mimeType,'image/png');assert.ok(!JSON.stringify(calls[0]).includes(dog.notes));assert.ok(JSON.stringify(calls[1]).includes(dog.notes));assert.match(calls[1].body.systemInstruction.parts[0].text,/NOT a shopping assistant/);assert.equal(r.body.blocks[1].evidence,'photo');
 for(const b of [{...request,consent:false},{...request,dogId:'foreign'},{...request,mode:'find',compare:true}]){calls=[];assert.equal((await alice.request('assistant',b)).status,400);assert.equal(calls.length,0);}
 calls=[];const urgent=await alice.request('assistant',{...request,flags:['breathing']});assert.equal(urgent.body.kind,'emergency');assert.equal(calls.length,0);
 }finally{globalThis.fetch=original;await rm(temp,{recursive:true,force:true});}
});
test('shopping API sends category, budget, brand and sort through search and synthesis and applies them to candidates',async()=>{
 const original=globalThis.fetch,temp=await mkdtemp(join(tmpdir(),'fourpaws-shop-'));try{
 const client=caller(new FileStore(temp),searchEnv);await client.request('register',{username:'shopping-test',password:'Test1234'});let calls=[];
 globalThis.fetch=async(url,opts)=>{const body=JSON.parse(opts.body);calls.push({url,body});if(url==='https://api.exa.ai/search')return Response.json(exaFixture());if(body.generationConfig.responseJsonSchema.properties.blocks)return Response.json(summaryFixture());return Response.json({candidates:[{finishReason:'STOP',content:{parts:[{text:JSON.stringify({candidates:[{product:'רתמה Acme',category:'accessories',brand:'Acme',sourceDomain:'source.test',price:'149 ₪',availability:'in_stock',scores:{quality:3,reviews:3,value:3,availability:3}},{product:'רתמה יקרה',category:'accessories',sourceDomain:'source.test',price:'399 ₪',availability:'in_stock',scores:{quality:5,reviews:5,value:5,availability:5}}],notes:''})}]}}]});};
 const request={mode:'find',question:'רתמה לכלב בינוני',compare:true,city:'',sort:'price',flags:[],filters:{category:'accessories',maxPrice:200,brand:'Acme',inStockOnly:true}};
 const r=await client.request('assistant',request);assert.equal(r.status,200);assert.match(calls[0].body.query,/Acme/);assert.match(calls[0].body.query,/200/);assert.match(calls[0].body.query,/כל הארץ/);assert.match(calls[0].body.query,/מהזול ליקר/);assert.equal(JSON.parse(calls[1].body.contents[0].parts[0].text).filters.maxPrice,200);assert.equal(JSON.parse(calls[2].body.contents[0].parts[0].text).sort,'price');assert.equal(r.body.comparison.recommendations.length,1);assert.equal(r.body.comparison.recommendations[0].priceAmount,149);assert.equal(r.body.applied.filters.category,'accessories');
 }finally{globalThis.fetch=original;await rm(temp,{recursive:true,force:true});}
});

test('pet registration saves a minimal passport, optional email and photo atomically; validates new passwords',async()=>{
 const temp=await mkdtemp(join(tmpdir(),'fourpaws-pet-signup-'));try{
 const store=new FileStore(temp);const request=async b=>{const r=await safeAPI(new Request(origin+'/api/register',{method:'POST',headers:{Origin:origin,'Content-Type':'application/json'},body:JSON.stringify(b)}),store);return {r,body:await r.json()};};
 for(const body of [{username:'no-pet',password:'Test1234'},{username:'no-age',password:'Test1234',dog:{name:'לוקה',breed:'מעורב'}},{username:'long-pass',password:'too-long-pass-123',dog:{name:'לוקה',breed:'מעורב',ageMonths:24}},{username:'no-numbers',password:'abcdefgh',dog:{name:'לוקה',breed:'מעורב',ageMonths:24}}]){assert.equal((await request(body)).r.status,400);assert.equal(await store.userByName(body.username),undefined);}
 const {r,body}=await request({username:'luka-home',password:'Luka2026',dog:{name:'לוקה',breed:'מעורב',ageMonths:18},email:'optional@example.com',photo:'data:image/jpeg;base64,aW1hZ2U='});assert.equal(r.status,200);const saved=await store.getState(body.user.id);assert.equal(saved.state.dogs[0].ageMonths,18);assert.equal(saved.state.dogs[0].birthday,'');assert.equal(saved.state.dogs[0].weight,0);assert.equal(saved.state.extras.contactEmail,'optional@example.com');assert.equal(saved.state.extras.album[0].dogId,saved.state.dogs[0].id);assert.ok(!JSON.stringify(saved).includes('Luka2026'));const user=await store.userByName('luka-home');assert.ok(user.password_hash);
 const login=caller(store);assert.equal((await login.request('login',{username:'luka-home',password:'Luka2026'})).status,200);
 const {passwordHash}=await import('../worker/index.js');const long='a-long-existing-password';await store.createUser({id:'legacy-user',username:'legacy',salt:'legacy-salt',password_hash:await passwordHash(long,'legacy-salt'),created_at:Date.now()});assert.equal((await caller(store).request('login',{username:'legacy',password:long})).status,200);
 }finally{await rm(temp,{recursive:true,force:true});}
});
test('shopping personalization includes active pet traits but excludes private notes, date of birth and contact fields',async()=>{
 const {publicPetContext,buildSearchQuery}=await import('../worker/index.js');const ctx={breed:'פומרניאן',size:'small',ageMonths:9,ageRecordedAt:new Date().toISOString(),weight:0,notes:'private sensitive note',phone:'private-phone',email:'private@example.com'};const pub=publicPetContext(ctx);assert.equal(pub.ageMonths,9);assert.equal(pub.weight,null);for(const key of ['notes','phone','email','birthday'])assert.ok(!Object.hasOwn(pub,key));const q=buildSearchQuery({mode:'find',question:'מזון יבש לכלב',filters:{category:'food'}},ctx);assert.match(q,/פומרניאן/);assert.match(q,/9 חודשים/);assert.ok(!q.includes('private'));
});

test('breed photo search validates input, restricts image origins and retains source credits',async()=>{
 const {searchBreedPhotos}=await import('../worker/index.js');const original=globalThis.fetch;let calls=0;
 try{globalThis.fetch=async(url)=>{calls++;assert.equal(new URL(url).hostname,'commons.wikimedia.org');return Response.json({query:{pages:{one:{pageid:123,title:'File:Golden retriever.jpg',imageinfo:[{url:'https://upload.wikimedia.org/dog.jpg',thumburl:'https://thumb.wikimedia.org/dog.jpg',extmetadata:{Artist:{value:'<b>Photographer</b>'},LicenseShortName:{value:'CC BY-SA 4.0'}}}]},bad:{pageid:124,imageinfo:[{url:'https://evil.test/dog.jpg'}]}}}});};
 await assert.rejects(()=>searchBreedPhotos(''),/הזינו גזע/);assert.equal(calls,0);
 const r=await searchBreedPhotos('Golden retriever');assert.equal(r.photos.length,1);assert.equal(r.photos[0].author,'Photographer');assert.equal(r.photos[0].thumbnail,'https://upload.wikimedia.org/dog.jpg');assert.equal(r.photos[0].source,'https://commons.wikimedia.org/?curid=123');
 globalThis.fetch=async()=>Response.json({error:{code:'failed'}});await assert.rejects(()=>searchBreedPhotos('Golden retriever'),/נכשל/);
 globalThis.fetch=async()=>Response.json({});assert.deepEqual(await searchBreedPhotos('Unknown breed'),{photos:[]});
 }finally{globalThis.fetch=original;}
});
