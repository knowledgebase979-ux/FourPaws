import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {FileStore,startServer} from '../server.mjs';
import {safeAPI,D1Store,blankState,validateState,runAssistant,parseGeminiResponse,assetResponse,secureResponse} from '../worker/index.js';
class SqliteD1 {
 constructor(){this.db=new DatabaseSync(':memory:');}
 prepare(sql){const statement=this.db.prepare(sql);let args=[];return {bind(...values){args=values;return this;},async first(){return statement.get(...args)||null;},async run(){const r=statement.run(...args);return {meta:{changes:Number(r.changes)}};}};}
 async batch(statements){this.db.exec('BEGIN');try{const result=[];for(const s of statements)result.push(await s.run());this.db.exec('COMMIT');return result;}catch(e){this.db.exec('ROLLBACK');throw e;}}
}
const origin='https://pawpath.test';
function caller(store,env={}){let cookie='';return {get cookie(){return cookie;},async request(path,body,method=body?'POST':'GET',extra={}){const headers={'Origin':origin,...(body!==undefined?{'Content-Type':'application/json'}:{}),...(cookie?{'Cookie':cookie}:{}),...extra};const r=await safeAPI(new Request(origin+'/api/'+path,{method,headers,...(body!==undefined?{body:JSON.stringify(body)}:{})}),store,env);if(r.headers.get('set-cookie'))cookie=r.headers.get('set-cookie').split(';')[0];return {response:r,status:r.status,body:await r.json()};}};}
const dog={id:'dog-a',name:'לוקה',breed:'מעורב',size:'medium',weight:16,birthday:'2023-01-01',notes:'רגישות ידועה',vet:'מרפאה',phone:'',chip:''};
const task={id:'task-a',dogId:dog.id,title:'שקילה',type:'weight',due:new Date().toISOString(),repeatDays:7,done:false,notes:'',completedAt:''};
for(const backend of ['files','d1']){
 test(backend+': auth, isolation, persistence, version conflicts, safety checks',async()=>{
  let store,temp,db;if(backend==='files'){temp=await mkdtemp(join(tmpdir(),'pawpath-test-'));store=new FileStore(temp);}else{db=new SqliteD1();db.db.exec(await readFile(new URL('../drizzle/0000_pawpath.sql',import.meta.url),'utf8'));store=new D1Store(db);}
  try{
   const anon=caller(store),alice=caller(store),bob=caller(store);
   assert.equal((await anon.request('state')).status,401);
   assert.equal((await anon.request('entry')).body.adminExists,false);
   assert.equal((await alice.request('register',{username:'alice',password:'test-password-123'},'POST',{'Origin':'https://other.test'})).status,403);
   const register=await alice.request('register',{username:'Alice',password:'test-password-123'});assert.equal(register.status,200);assert.equal(register.body.user.username,'alice');assert.match(register.response.headers.get('set-cookie'),/HttpOnly/);assert.match(register.response.headers.get('set-cookie'),/Secure/);
   const duplicate=await anon.request('register',{username:'ALICE',password:'test-password-123'});assert.equal(duplicate.status,409);
   assert.equal((await anon.request('login',{username:'alice',password:'bad-password-123'})).status,401);
   assert.equal((await bob.request('register',{username:'bob',password:'another-password-123'})).status,200);
   const initial=await alice.request('state');assert.deepEqual(initial.body,{state:blankState(),version:0});
   const state={dogs:[dog],tasks:[task],logs:[]};
   assert.equal((await alice.request('state',{state,version:0},'PUT')).status,200);
   assert.equal((await alice.request('state',{state,version:0},'PUT')).status,409);
   assert.deepEqual((await bob.request('state')).body.state.dogs,[]);
   const bad=structuredClone(state);bad.tasks[0].dogId='other-account-dog';assert.equal((await alice.request('state',{state:bad,version:1},'PUT')).status,400);
   bad.tasks[0].dogId=dog.id;bad.dogs[0].weight=-5;assert.equal((await alice.request('state',{state:bad,version:1},'PUT')).status,400);
   assert.equal((await alice.request('config')).body.aiEnabled,false);
   const configured=await safeAPI(new Request(origin+'/api/config',{headers:{Cookie:alice.cookie}}),store,{GEMINI_API_KEY:'unit-test-secret-placeholder'});const configBody=await configured.json();assert.equal(configBody.aiEnabled,true);assert.equal(configBody.provider,'Gemini');assert.ok(!JSON.stringify(configBody).includes('unit-test-secret-placeholder'));
   const consult={mode:'consult',question:'יש לכלב סימן ברגל',flags:[],city:'',sort:'relevance',consent:true};
   assert.equal((await alice.request('assistant',consult)).status,503);
   const emergency=await alice.request('assistant',{...consult,flags:['bleeding']});assert.equal(emergency.status,200);assert.equal(emergency.body.kind,'emergency');assert.equal(emergency.body.generated,false);
   assert.equal((await alice.request('assistant',{...consult,image:'https://internal.test/photo'})).status,400);
   if(backend==='files'){const users=JSON.parse(await readFile(join(temp,'users.json'),'utf8'));assert.equal(users.length,2);assert.ok(users[0].password_hash);assert.ok(!JSON.stringify(users).includes('test-password-123'));assert.equal((await stat(join(temp,'users.json'))).mode&0o777,0o600);const reopened=new FileStore(temp);assert.equal((await reopened.getState(register.body.user.id)).state.dogs[0].name,'לוקה');}
   const savedCookie=alice.cookie;assert.equal((await alice.request('logout',{})).status,200);const revoked=await safeAPI(new Request(origin+'/api/state',{headers:{Cookie:savedCookie}}),store);assert.equal(revoked.status,401);
   assert.equal((await alice.request('login',{username:'alice',password:'test-password-123'})).status,200);
   assert.equal((await alice.request('state')).body.state.dogs[0].name,'לוקה');
   assert.equal((await anon.request('register',{username:'admin',password:'admin-test-password-only'})).status,200);
   assert.equal((await bob.request('entry')).body.adminExists,true);
   assert.equal((await bob.request('register',{username:'admin',password:'different-test-password'})).status,409);
  }finally{if(temp)await rm(temp,{recursive:true,force:true});if(db)db.db.close();}
 });
}
test('HTTP server: real registration, restricted file access and request limit',async()=>{const temp=await mkdtemp(join(tmpdir(),'pawpath-http-'));const server=startServer({port:0,dataDir:temp});await new Promise(r=>server.listening?r():server.once('listening',r));const base='http://127.0.0.1:'+server.address().port;try{assert.equal((await fetch(base+'/')).status,200);assert.equal((await fetch(base+'/admin')).status,200);assert.equal((await fetch(base+'/login')).status,200);assert.equal((await fetch(base+'/data/users.json')).status,404);const r=await fetch(base+'/api/register',{method:'POST',headers:{Origin:base,'Content-Type':'application/json'},body:JSON.stringify({username:'local-test',password:'long-test-password'})});assert.equal(r.status,200);const cookie=r.headers.get('set-cookie').split(';')[0];const state=await fetch(base+'/api/state',{headers:{Cookie:cookie}});assert.equal(state.status,200);const large=await fetch(base+'/api/state',{method:'PUT',headers:{Cookie:cookie,Origin:base,'Content-Type':'application/json'},body:JSON.stringify({huge:'x'.repeat(520000)})});assert.equal(large.status,413);}finally{server.closeAllConnections();await new Promise(r=>server.close(r));await rm(temp,{recursive:true,force:true});}});
test('rate limiter bounds attempts',async()=>{const dir=await mkdtemp(join(tmpdir(),'pawpath-rate-'));try{const store=new FileStore(dir);for(let i=0;i<15;i++)assert.equal(await store.allow('one-ip'),true);assert.equal(await store.allow('one-ip'),false);}finally{await rm(dir,{recursive:true,force:true});}});

const searchText='מידע לכלב 🐕 ממקור מאומת';
const searchFixture=()=>({candidates:[{finishReason:'STOP',content:{parts:[{thought:true,text:'hidden reasoning'},{text:searchText}]},groundingMetadata:{webSearchQueries:['dog care'],searchEntryPoint:{renderedContent:'<style>.chip{color:#333}</style><a class="chip" href="https://www.google.com/search?q=dog+care">dog care</a>'},groundingChunks:[{web:{uri:'https://source.test/dogs',title:'Source A'}},{web:{uri:'https://second.test/dogs',title:'Source B'}}],groundingSupports:[{segment:{startIndex:0,endIndex:new TextEncoder().encode(searchText).length,text:searchText},groundingChunkIndices:[0,1]}]}}]});
test('Gemini request uses Google Search, retains citations, and excludes private dog notes from searches',async()=>{const original=globalThis.fetch;try{let sent;globalThis.fetch=async(url,opts)=>{assert.equal(url,'https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent');assert.equal(opts.headers['x-goog-api-key'],'unit-test-placeholder');sent=JSON.parse(opts.body);return Response.json(searchFixture());};const result=await runAssistant({mode:'find',question:'חפש מוצר לכלב',city:'חיפה',sort:'price'},{notes:'private clinical note'},{GEMINI_API_KEY:'unit-test-placeholder'});assert.equal(result.kind,'search');assert.ok(sent.tools[0].google_search);assert.ok(!JSON.stringify(sent).includes('private clinical note'));assert.equal(result.blocks[0].text,searchText);assert.equal(result.blocks[0].annotations.length,2);assert.equal(result.blocks[0].annotations[0].end_index,Array.from(searchText).length);assert.ok(result.searchSuggestions.includes('google.com/search'));const noSearch=searchFixture();delete noSearch.candidates[0].groundingMetadata;globalThis.fetch=async()=>Response.json(noSearch);await assert.rejects(runAssistant({mode:'find',question:'חיפוש'},null,{GEMINI_API_KEY:'unit-test-placeholder'}),/Google Search/);}finally{globalThis.fetch=original;}});
test('Gemini image consultation uses inlineData, explicit JSON schema and validates required guidance fields',async()=>{const original=globalThis.fetch;try{const guidance={observations:'אין די מידע',possibilities:'לא ניתן לקבוע',urgency:'unclear',nextSteps:['פנייה לווטרינר'],avoid:['אין לתת תרופות'],vetSigns:['כאב או החמרה'],questions:['מתי הופיע?'],limitations:'אינו אבחון'};let sent;globalThis.fetch=async(url,opts)=>{sent=JSON.parse(opts.body);return Response.json({candidates:[{finishReason:'STOP',content:{parts:[{text:JSON.stringify(guidance)}]}}]});};const result=await runAssistant({mode:'consult',question:'תיאור סימן',image:'data:image/png;base64,aW1hZ2U='},{breed:'מעורב'},{GEMINI_API_KEY:'unit-test-placeholder'});assert.equal(result.guidance.urgency,'unclear');assert.equal(sent.contents[0].parts[1].inlineData.mimeType,'image/png');assert.equal(sent.generationConfig.responseMimeType,'application/json');assert.ok(sent.generationConfig.responseJsonSchema.required.includes('limitations'));assert.ok(!sent.tools);assert.throws(()=>parseGeminiResponse({candidates:[{finishReason:'STOP',content:{parts:[{text:'{"urgency":"unclear"}'}]}}]},false),/חלקי ההכוונה/);}finally{globalThis.fetch=original;}});
test('Gemini rejection and quota errors are actionable and do not include provider secrets',async()=>{const original=globalThis.fetch;try{for(const status of [403,429,503]){globalThis.fetch=async()=>Response.json({error:{message:'sensitive provider content'}},{status});await assert.rejects(runAssistant({mode:'find',question:'test'},null,{GEMINI_API_KEY:'unit-test-placeholder'}),e=>{assert.ok(!e.message.includes('sensitive'));return e.status===(status===403?503:status===429?429:502);});}}finally{globalThis.fetch=original;}});
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
