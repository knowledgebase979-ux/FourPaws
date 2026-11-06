import {createServer} from 'node:http';
import {readFile,mkdir,writeFile,rename,chmod} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {safeAPI,securityHeaders,blankState,assetResponse,secureResponse} from './worker/index.js';
const root=dirname(fileURLToPath(import.meta.url));
export class FileStore {
  constructor(directory){this.directory=directory;this.tail=Promise.resolve();}
  async read(name,fallback){try{return JSON.parse(await readFile(resolve(this.directory,name),'utf8'));}catch(e){if(e.code==='ENOENT')return fallback;throw e;}}
  async write(name,data){await mkdir(this.directory,{recursive:true,mode:0o700});await chmod(this.directory,0o700);const path=resolve(this.directory,name);const temp=path+'.tmp';await writeFile(temp,JSON.stringify(data,null,2),{mode:0o600});await rename(temp,path);await chmod(path,0o600);}
  async exclusive(fn){const next=this.tail.then(fn);this.tail=next.catch(()=>{});return next;}
  async userByName(username){await this.tail;return (await this.read('users.json',[])).find(u=>u.username===username);}
  async createUser(user){return this.exclusive(async()=>{const users=await this.read('users.json',[]);if(users.some(u=>u.username===user.username))return false;const records=await this.read('records.json',{});records[user.id]={state:blankState(),version:0};await this.write('records.json',records);users.push(user);await this.write('users.json',users);return true;});}
  async putSession(token_hash,user_id,expires_at){return this.exclusive(async()=>{const rows=(await this.read('sessions.json',[])).filter(s=>s.expires_at>Date.now());rows.push({token_hash,user_id,expires_at});await this.write('sessions.json',rows);});}
  async getSession(hash){await this.tail;const row=(await this.read('sessions.json',[])).find(s=>s.token_hash===hash&&s.expires_at>Date.now());if(!row)return null;const user=(await this.read('users.json',[])).find(u=>u.id===row.user_id);return user?{id:user.id,username:user.username}:null;}
  async deleteSession(hash){return this.exclusive(async()=>{await this.write('sessions.json',(await this.read('sessions.json',[])).filter(s=>s.token_hash!==hash));});}
  async getState(id){await this.tail;return (await this.read('records.json',{}))[id]||{state:blankState(),version:0};}
  async setState(id,state,version){return this.exclusive(async()=>{const records=await this.read('records.json',{});if((records[id]?.version??0)!==version)return false;records[id]={state,version:version+1};await this.write('records.json',records);return true;});}
  async allow(key){return this.exclusive(async()=>{const now=Date.now(),rows=await this.read('rate-limits.json',{});for(const k of Object.keys(rows))if(rows[k].expires<now)delete rows[k];rows[key]??={count:0,expires:now+900000};rows[key].count++;await this.write('rate-limits.json',rows);return rows[key].count<=15;});}
}
export function startServer({port=Number(process.env.PORT||3000),dataDir=process.env.DATA_DIR||resolve(root,'data')}={}) {
 const store=new FileStore(dataDir);
 const server=createServer(async (req,res)=>{
  try {
   const host=req.headers.host||'localhost';
   const origin=process.env.PUBLIC_ORIGIN||(req.headers['x-forwarded-proto']==='https'?'https://':'http://')+host;
   const path=new URL(req.url,origin).pathname;
   const headers=new Headers();for(const [k,v]of Object.entries(req.headers))if(v)headers.set(k,Array.isArray(v)?v.join(','):v);
   // Trust the actual socket, never a caller-supplied IP header in the Node deployment.
   headers.set('cf-connecting-ip',req.socket.remoteAddress||'local');
   let response;
   if(path.startsWith('/api/')){const request=new Request(new URL(req.url,origin),{method:req.method,headers,...(!['GET','HEAD'].includes(req.method)?{body:req,duplex:'half'}:{})});response=await safeAPI(request,store,process.env);}
   else{const files={'/':['index.html','text/html; charset=utf-8'],'/style.css':['style.css','text/css; charset=utf-8'],'/app.js':['app.js','text/javascript; charset=utf-8']};const asset=files[['/admin','/login'].includes(path)?'/':path];if(!asset)response=new Response('Not found',{status:404});else response=assetResponse({method:req.method},await readFile(resolve(root,'public',asset[0]),'utf8'),asset[1]);}
   secureResponse(response);res.writeHead(response.status,Object.fromEntries(response.headers));res.end(Buffer.from(await response.arrayBuffer()));
  }catch{res.writeHead(500,{'Content-Type':'application/json',...securityHeaders});res.end(JSON.stringify({error:'אירעה שגיאה בשרת.'}));}
 });
 server.requestTimeout=15000;server.headersTimeout=10000;
 server.listen(port,'0.0.0.0',()=>console.log('FourPaws listening on port '+server.address().port));return server;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){const index=process.argv.indexOf('--port');startServer(index>=0?{port:Number(process.argv[index+1])}:{});}
