'use strict';

// ════════════════════════════════════════════════════════════════
//  ACS Secure Net — Cyber Security & Intelligence Laboratory
//  Property of ACS Secure Net
//
//  IDOR CATEGORY MAP:
//  [I1]  Numeric ID IDOR              GET /api/agents/:id
//  [I2]  UUID IDOR                    GET /api/missions/uuid/:uuid
//  [I3]  Phone Number IDOR            GET /api/agents/phone/:phone
//  [I4]  Email Address IDOR           GET /api/agents/email/:email
//  [I5]  Username IDOR                GET /api/agents/u/:username
//  [I6]  Slug-Based IDOR              GET /api/intel/:slug
//  [I7]  Composite — phone+dob        POST /api/verify/identity
//  [I7]  Composite — email+code       POST /api/verify/code
//  [I7]  Composite — name+birth       POST /api/verify/personnel
//  [I8]  File Path IDOR               GET /api/files/read?path=
//  [I9]  Base64 Encoded IDOR          GET /api/access/b64/:ref
//  [I9]  Hex Encoded IDOR             GET /api/access/hex/:ref
//  [I9]  URL Encoded IDOR             GET /api/access/url/:ref
//  [I10] MD5 Hash IDOR                GET /api/agents/hash/md5/:hash
//  [I10] SHA1 Hash IDOR               GET /api/agents/hash/sha1/:hash
//  [I11] Magic Link Token             GET /api/auth/magic?token=
//  [I11] Password Reset Token         POST /api/auth/reset
//  [I11] QR Token                     GET /api/auth/qr/:code
// ════════════════════════════════════════════════════════════════

const express      = require('express');
const sqlite3      = require('sqlite3').verbose();
const jwt          = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const crypto       = require('crypto');
const path         = require('path');
const fs           = require('fs');
const { v4: uuidv4 } = require('uuid');

const app  = express();
const PORT = 3000;
const JWT_SECRET = 'acs_secure_net_ops_2026';
const FILES_ROOT = path.join(__dirname, 'files');

const DB_PATH = path.join(__dirname, 'data', 'acs_secure.db');
const db = new sqlite3.Database(DB_PATH);
const dbGet = (s,p=[]) => new Promise((r,j)=>db.get(s,p,(e,row)=>e?j(e):r(row)));
const dbAll = (s,p=[]) => new Promise((r,j)=>db.all(s,p,(e,rows)=>e?j(e):r(rows)));
const dbRun = (s,p=[]) => new Promise((r,j)=>db.run(s,p,function(e){e?j(e):r(this);}));

const md5  = s => crypto.createHash('md5').update(s).digest('hex');
const sha1 = s => crypto.createHash('sha1').update(s).digest('hex');

app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(cookieParser());
app.use(express.static(path.join(__dirname,'public')));

function requireAuth(req,res,next){
  const h=req.headers['authorization']||'';
  const token=h.startsWith('Bearer ')?h.slice(7):req.cookies['sd_token'];
  if(!token)return res.status(401).json({error:'Authentication required'});
  try{req.user=jwt.verify(token,JWT_SECRET);next();}
  catch(e){res.status(401).json({error:'Invalid or expired token'});}
}

// Secret values live in /app/secrets/* written at runtime by start.sh — not in source
const SECRET_FILES={
  numeric:'i1', uuid:'i2', phone:'i3', email:'i4', username:'i5', slug:'i6',
  comp_phone:'i7a', comp_email:'i7b', comp_name:'i7c', filepath:'i8',
  b64:'i9a', hex:'i9b', url:'i9c', md5:'i10a', sha1:'i10b',
  magic:'i11a', reset:'i11b', qr:'i11c',
};
function secretToken(id){
  const file=SECRET_FILES[id];
  if(!file)return null;
  try{ return fs.readFileSync(`/app/secrets/${file}`,'utf8').trim(); }
  catch{ return null; }
}

function sanitizeAgent(a,isSelf=false){
  if(!a)return null;
  const base={id:a.id,uuid:a.uuid,username:a.username,slug:a.slug,codename:a.codename,faction:a.faction,clearance:a.clearance,rank:a.rank,bio:a.bio};
  if(!isSelf)return base;
  return{...base,email:a.email,phone:a.phone,name:a.name,dob:a.dob,bank_account:a.bank_account,safe_location:a.safe_location,secret_note:a.secret_note};
}

app.get('/',(_,res)=>res.redirect('/login.html'));

// ════════════════════════════════════════════════════════════════
// AUTH
// ════════════════════════════════════════════════════════════════

app.post('/api/auth/login',async(req,res)=>{
  try{
    const{email,password}=req.body;
    const agent=await dbGet('SELECT * FROM agents WHERE email=? AND password=?',[email,password]);
    if(!agent)return res.status(401).json({error:'Invalid credentials'});
    const token=jwt.sign({userId:agent.id,uuid:agent.uuid,username:agent.username,email:agent.email,name:agent.name,codename:agent.codename},JWT_SECRET,{expiresIn:'24h'});
    res.cookie('sd_token',token,{httpOnly:false});
    res.json({success:true,token,agent:{id:agent.id,uuid:agent.uuid,username:agent.username,email:agent.email,name:agent.name,codename:agent.codename,faction:agent.faction,clearance:agent.clearance,rank:agent.rank}});
  }catch(e){res.status(500).json({error:e.message});}
});

app.post('/api/auth/logout',(req,res)=>{res.clearCookie('sd_token');res.json({success:true});});

app.get('/api/auth/me',requireAuth,async(req,res)=>{
  try{
    const a=await dbGet('SELECT * FROM agents WHERE id=?',[req.user.userId]);
    res.json({agent:sanitizeAgent(a,true)});
  }catch(e){res.status(500).json({error:e.message});}
});

// [I11] MAGIC LINK IDOR — token is sequential "magic-000001-acs"
app.get('/api/auth/magic',async(req,res)=>{
  const{token}=req.query;
  if(!token)return res.status(400).json({error:'token required'});
  try{
    const t=await dbGet('SELECT * FROM access_tokens WHERE token=? AND token_type="magic_link"',[token]);
    if(!t)return res.status(404).json({error:'Invalid or expired magic link'});
    const agent=await dbGet('SELECT * FROM agents WHERE id=?',[t.agent_id]);
    if(!agent)return res.status(404).json({error:'Agent not found'});
    const isSelf=(req.user&&req.user.userId===agent.id)||false;
    const acsSecret=secretToken('magic');
    res.json({success:true,agent:sanitizeAgent(agent,true),acs_secret:acsSecret,note:'Magic link token is sequential — magic-000001-acssec, magic-000002-acssec...'});
  }catch(e){res.status(500).json({error:e.message});}
});

// [I11] RESET TOKEN IDOR — token is base64("reset:{id}:acs")
app.post('/api/auth/reset',async(req,res)=>{
  const{token,new_password}=req.body;
  if(!token)return res.status(400).json({error:'token required'});
  try{
    const t=await dbGet('SELECT * FROM access_tokens WHERE token=? AND token_type="reset"',[token]);
    if(!t)return res.status(404).json({error:'Invalid or expired reset token'});
    const agent=await dbGet('SELECT * FROM agents WHERE id=?',[t.agent_id]);
    if(!agent)return res.status(404).json({error:'Agent not found'});
    if(new_password)await dbRun('UPDATE agents SET password=? WHERE id=?',[new_password,agent.id]);
    res.json({success:true,agent:sanitizeAgent(agent,true),acs_secret:secretToken('reset'),note:'Reset token is base64("reset:{id}:acssec") — trivially enumerable.'});
  }catch(e){res.status(500).json({error:e.message});}
});

// [I11] QR TOKEN IDOR — code is (agent_id * 1337) padded
app.get('/api/auth/qr/:code',async(req,res)=>{
  try{
    const t=await dbGet('SELECT * FROM qr_tokens WHERE qr_code=?',[req.params.code]);
    if(!t)return res.status(404).json({error:'Invalid QR token'});
    const agent=await dbGet('SELECT * FROM agents WHERE id=?',[t.agent_id]);
    if(!agent)return res.status(404).json({error:'Agent not found'});
    res.json({success:true,agent:sanitizeAgent(agent,true),acs_secret:secretToken('qr'),note:'QR code is agent_id * 1337 zero-padded to 8 digits.'});
  }catch(e){res.status(500).json({error:e.message});}
});

// ════════════════════════════════════════════════════════════════
// AGENTS
// ════════════════════════════════════════════════════════════════

app.get('/api/agents',requireAuth,async(_,res)=>{
  try{
    const agents=await dbAll('SELECT id,uuid,username,slug,codename,faction,clearance,rank,bio FROM agents ORDER BY id');
    res.json({agents});
  }catch(e){res.status(500).json({error:e.message});}
});

// [I1] NUMERIC ID IDOR — sequential integer, no ownership check
app.get('/api/agents/:id(\\d+)',requireAuth,async(req,res)=>{
  try{
    const a=await dbGet('SELECT * FROM agents WHERE id=?',[req.params.id]);
    if(!a)return res.status(404).json({error:'Agent not found'});
    const isSelf=a.id===req.user.userId;
    const acsSecret=!isSelf?secretToken('numeric'):null;
    res.json({agent:sanitizeAgent(a,true),...(acsSecret&&{acs_secret:acsSecret,note:'Numeric IDOR — sequential integer ID exposed full agent dossier.'})});
  }catch(e){res.status(500).json({error:e.message});}
});

// [I5] USERNAME IDOR — username in URL, no ownership check
app.get('/api/agents/u/:username',requireAuth,async(req,res)=>{
  try{
    const a=await dbGet('SELECT * FROM agents WHERE username=?',[req.params.username]);
    if(!a)return res.status(404).json({error:'Agent not found'});
    const isSelf=a.id===req.user.userId;
    const acsSecret=!isSelf?secretToken('username'):null;
    res.json({agent:sanitizeAgent(a,true),...(acsSecret&&{acs_secret:acsSecret,note:'Username IDOR — username in path reveals secret notes and safe location.'})});
  }catch(e){res.status(500).json({error:e.message});}
});

// [I3] PHONE NUMBER IDOR
app.get('/api/agents/phone/:phone',requireAuth,async(req,res)=>{
  try{
    const phone=decodeURIComponent(req.params.phone);
    const a=await dbGet('SELECT * FROM agents WHERE phone=?',[phone]);
    if(!a)return res.status(404).json({error:'Agent not found'});
    const isSelf=a.id===req.user.userId;
    const acsSecret=!isSelf?secretToken('phone'):null;
    res.json({agent:sanitizeAgent(a,true),...(acsSecret&&{acs_secret:acsSecret,note:'Phone Number IDOR — phone number used as lookup key reveals full dossier.'})});
  }catch(e){res.status(500).json({error:e.message});}
});

// [I4] EMAIL ADDRESS IDOR
app.get('/api/agents/email/:email',requireAuth,async(req,res)=>{
  try{
    const email=decodeURIComponent(req.params.email);
    const a=await dbGet('SELECT * FROM agents WHERE email=?',[email]);
    if(!a)return res.status(404).json({error:'Agent not found'});
    const isSelf=a.id===req.user.userId;
    const acsSecret=!isSelf?secretToken('email'):null;
    res.json({agent:sanitizeAgent(a,true),...(acsSecret&&{acs_secret:acsSecret,note:'Email IDOR — email address as identifier reveals classified agent data.'})});
  }catch(e){res.status(500).json({error:e.message});}
});

// ════════════════════════════════════════════════════════════════
// MISSIONS — [I2] UUID IDOR
// ════════════════════════════════════════════════════════════════

app.get('/api/missions',requireAuth,async(req,res)=>{
  try{
    const m=await dbAll('SELECT id,uuid,slug,title,classification,status,mission_date FROM missions WHERE agent_id=? ORDER BY id',[req.user.userId]);
    res.json({missions:m});
  }catch(e){res.status(500).json({error:e.message});}
});

// [I2] UUID IDOR — UUID not validated against owner
app.get('/api/missions/uuid/:uuid',requireAuth,async(req,res)=>{
  try{
    const m=await dbGet(
      `SELECT m.*,a.codename as agent_codename,a.clearance as agent_clearance FROM missions m
       JOIN agents a ON a.id=m.agent_id WHERE m.uuid=?`,
      [req.params.uuid]
    );
    if(!m)return res.status(404).json({error:'Mission not found'});
    const isSelf=m.agent_id===req.user.userId;
    const acsSecret=!isSelf?secretToken('uuid'):null;
    res.json({mission:m,...(acsSecret&&{acs_secret:acsSecret,note:'UUID IDOR — UUIDs are not secret. Mission data exposed across agents.'})});
  }catch(e){res.status(500).json({error:e.message});}
});

// ════════════════════════════════════════════════════════════════
// INTEL REPORTS — [I6] SLUG IDOR
// ════════════════════════════════════════════════════════════════

app.get('/api/intel',requireAuth,async(req,res)=>{
  try{
    const reports=await dbAll('SELECT id,slug,title,classification,created_at FROM intel_reports WHERE agent_id=? ORDER BY id',[req.user.userId]);
    res.json({reports});
  }catch(e){res.status(500).json({error:e.message});}
});

// [I6] SLUG IDOR — human-readable slug, no ownership check
app.get('/api/intel/:slug',requireAuth,async(req,res)=>{
  try{
    const r=await dbGet(
      `SELECT i.*,a.codename,a.clearance FROM intel_reports i JOIN agents a ON a.id=i.agent_id WHERE i.slug=?`,
      [req.params.slug]
    );
    if(!r)return res.status(404).json({error:'Intel report not found'});
    const isSelf=r.agent_id===req.user.userId;
    const acsSecret=!isSelf?secretToken('slug'):null;
    res.json({report:r,...(acsSecret&&{acs_secret:acsSecret,note:'Slug IDOR — human-readable slugs are guessable and expose classified intel.'})});
  }catch(e){res.status(500).json({error:e.message});}
});

// Agent profile by slug [I6 variant]
app.get('/api/agents/slug/:slug',requireAuth,async(req,res)=>{
  try{
    const a=await dbGet('SELECT * FROM agents WHERE slug=?',[req.params.slug]);
    if(!a)return res.status(404).json({error:'Agent not found'});
    const isSelf=a.id===req.user.userId;
    const acsSecret=!isSelf?secretToken('slug'):null;
    res.json({agent:sanitizeAgent(a,true),...(acsSecret&&{acs_secret:acsSecret,note:'Slug IDOR — slug reveals full agent profile.'})});
  }catch(e){res.status(500).json({error:e.message});}
});

// ════════════════════════════════════════════════════════════════
// COMPOSITE IDOR — [I7] Three composite types
// ════════════════════════════════════════════════════════════════

// [I7a] Phone + Date of Birth
app.post('/api/verify/identity',requireAuth,async(req,res)=>{
  try{
    const{phone,dob}=req.body;
    if(!phone||!dob)return res.status(400).json({error:'phone and dob required'});
    const a=await dbGet('SELECT * FROM agents WHERE phone=? AND dob=?',[phone,dob]);
    if(!a)return res.status(404).json({error:'No agent found matching these credentials'});
    const isSelf=a.id===req.user.userId;
    const acsSecret=!isSelf?secretToken('comp_phone'):null;
    res.json({verified:true,agent:sanitizeAgent(a,true),...(acsSecret&&{acs_secret:acsSecret,note:'Composite IDOR — phone+DOB combination bypasses access control.'})});
  }catch(e){res.status(500).json({error:e.message});}
});

// [I7b] Email + Verification Code
app.post('/api/verify/code',requireAuth,async(req,res)=>{
  try{
    const{email,code}=req.body;
    if(!email||!code)return res.status(400).json({error:'email and code required'});
    const a=await dbGet('SELECT * FROM agents WHERE email=?',[email]);
    if(!a)return res.status(404).json({error:'Agent not found'});
    const vc=await dbGet('SELECT * FROM verification_codes WHERE agent_id=? AND code=? AND used=0',[a.id,code]);
    if(!vc)return res.status(401).json({error:'Invalid verification code'});
    const isSelf=a.id===req.user.userId;
    const acsSecret=!isSelf?secretToken('comp_email'):null;
    res.json({verified:true,agent:sanitizeAgent(a,true),...(acsSecret&&{acs_secret:acsSecret,note:'Composite IDOR — email+code combo reveals classified agent data. Code is agent_id*1111.'})});
  }catch(e){res.status(500).json({error:e.message});}
});

// [I7c] Name + Birth Date
app.post('/api/verify/personnel',requireAuth,async(req,res)=>{
  try{
    const{name,birth_date}=req.body;
    if(!name||!birth_date)return res.status(400).json({error:'name and birth_date required'});
    const a=await dbGet('SELECT * FROM agents WHERE name=? AND dob=?',[name,birth_date]);
    if(!a)return res.status(404).json({error:'No personnel record found'});
    const isSelf=a.id===req.user.userId;
    const acsSecret=!isSelf?secretToken('comp_name'):null;
    res.json({verified:true,agent:sanitizeAgent(a,true),...(acsSecret&&{acs_secret:acsSecret,note:'Composite IDOR — name+birthdate bypass reveals full personnel file.'})});
  }catch(e){res.status(500).json({error:e.message});}
});

// ════════════════════════════════════════════════════════════════
// FILE PATH IDOR — [I8]
// ════════════════════════════════════════════════════════════════

app.get('/api/files',requireAuth,async(req,res)=>{
  try{
    const files=await dbAll('SELECT id,filename,description,classification,created_at FROM agent_files WHERE agent_id=? ORDER BY id',[req.user.userId]);
    res.json({files});
  }catch(e){res.status(500).json({error:e.message});}
});

// [I8] FILE PATH IDOR — path parameter not sanitised against ownership
app.get('/api/files/read',requireAuth,async(req,res)=>{
  const filePath=req.query.path||'';
  if(!filePath)return res.status(400).json({error:'path parameter required'});
  try{
    // No ownership check — any authenticated agent can read any file path
    const fullPath=path.join(FILES_ROOT,filePath);
    if(!fs.existsSync(fullPath))return res.status(404).json({error:'File not found'});
    const content=fs.readFileSync(fullPath,'utf8');
    const acsSecret=content.includes('SECRET_TOKEN')||content.includes('OMEGA')||content.includes('classified')?secretToken('filepath'):null;
    res.json({path:filePath,content,...(acsSecret&&{acs_secret:acsSecret,note:'File Path IDOR — path not validated against file ownership.'})});
  }catch(e){res.status(500).json({error:`Cannot read file: ${e.message}`});}
});

// ════════════════════════════════════════════════════════════════
// ENCODED IDENTIFIER IDOR — [I9]
// ════════════════════════════════════════════════════════════════

// [I9a] BASE64 — decode to get agent ID
app.get('/api/access/b64/:ref',requireAuth,async(req,res)=>{
  try{
    const decoded=Buffer.from(req.params.ref,'base64').toString('utf8');
    const agentId=parseInt(decoded);
    if(isNaN(agentId))return res.status(400).json({error:'Invalid base64 reference'});
    const a=await dbGet('SELECT * FROM agents WHERE id=?',[agentId]);
    if(!a)return res.status(404).json({error:'Agent not found'});
    const isSelf=a.id===req.user.userId;
    const acsSecret=!isSelf?secretToken('b64'):null;
    res.json({decoded,agent_id:agentId,agent:sanitizeAgent(a,true),...(acsSecret&&{acs_secret:acsSecret,note:'Base64 IDOR — base64 encoding is not encryption. Decode to enumerate IDs.'})});
  }catch(e){res.status(500).json({error:e.message});}
});

// [I9b] HEX — decode hex to get agent ID
app.get('/api/access/hex/:ref',requireAuth,async(req,res)=>{
  try{
    const decoded=Buffer.from(req.params.ref,'hex').toString('utf8');
    const agentId=parseInt(decoded);
    if(isNaN(agentId))return res.status(400).json({error:'Invalid hex reference'});
    const a=await dbGet('SELECT * FROM agents WHERE id=?',[agentId]);
    if(!a)return res.status(404).json({error:'Agent not found'});
    const isSelf=a.id===req.user.userId;
    const acsSecret=!isSelf?secretToken('hex'):null;
    res.json({decoded,agent_id:agentId,agent:sanitizeAgent(a,true),...(acsSecret&&{acs_secret:acsSecret,note:'Hex IDOR — hex encoding is trivially reversible. Enumerate all agent IDs.'})});
  }catch(e){res.status(500).json({error:e.message});}
});

// [I9c] URL ENCODED — decode to get agent reference
app.get('/api/access/url/:ref',requireAuth,async(req,res)=>{
  try{
    const decoded=decodeURIComponent(req.params.ref);
    const match=decoded.match(/agent_(\d+)/);
    if(!match)return res.status(400).json({error:'Invalid URL-encoded reference'});
    const agentId=parseInt(match[1]);
    const a=await dbGet('SELECT * FROM agents WHERE id=?',[agentId]);
    if(!a)return res.status(404).json({error:'Agent not found'});
    const isSelf=a.id===req.user.userId;
    const acsSecret=!isSelf?secretToken('url'):null;
    res.json({decoded,agent_id:agentId,agent:sanitizeAgent(a,true),...(acsSecret&&{acs_secret:acsSecret,note:'URL-encoded IDOR — URL encoding is not obfuscation. Pattern is agent_{id}.'})});
  }catch(e){res.status(500).json({error:e.message});}
});

// ════════════════════════════════════════════════════════════════
// HASHED IDENTIFIER IDOR — [I10]
// ════════════════════════════════════════════════════════════════

// [I10a] MD5(email) — hash of email as lookup key
app.get('/api/agents/hash/md5/:hash',requireAuth,async(req,res)=>{
  try{
    const agents=await dbAll('SELECT * FROM agents');
    const a=agents.find(ag=>md5(ag.email)===req.params.hash);
    if(!a)return res.status(404).json({error:'Agent not found'});
    const isSelf=a.id===req.user.userId;
    const acsSecret=!isSelf?secretToken('md5'):null;
    res.json({hash_type:'MD5',hash:req.params.hash,agent:sanitizeAgent(a,true),...(acsSecret&&{acs_secret:acsSecret,note:'MD5 Hash IDOR — MD5 of email is brute-forceable. Enumerate known emails.'})});
  }catch(e){res.status(500).json({error:e.message});}
});

// [I10b] SHA1(username) — hash of username as lookup key
app.get('/api/agents/hash/sha1/:hash',requireAuth,async(req,res)=>{
  try{
    const agents=await dbAll('SELECT * FROM agents');
    const a=agents.find(ag=>sha1(ag.username)===req.params.hash);
    if(!a)return res.status(404).json({error:'Agent not found'});
    const isSelf=a.id===req.user.userId;
    const acsSecret=!isSelf?secretToken('sha1'):null;
    res.json({hash_type:'SHA1',hash:req.params.hash,agent:sanitizeAgent(a,true),...(acsSecret&&{acs_secret:acsSecret,note:'SHA1 Hash IDOR — SHA1 of username. Crack with hashcat or enumerate known usernames.'})});
  }catch(e){res.status(500).json({error:e.message});}
});

// ════════════════════════════════════════════════════════════════
// INTERNAL / REFERENCE HELPER
// ════════════════════════════════════════════════════════════════

// Encoded refs for the current agent (shows your own refs — used to understand the pattern)
app.get('/api/my/refs',requireAuth,async(req,res)=>{
  try{
    const refs=await dbAll('SELECT ref_type,ref_value FROM encoded_refs WHERE agent_id=?',[req.user.userId]);
    const tokens=await dbAll('SELECT token_type,token FROM access_tokens WHERE agent_id=?',[req.user.userId]);
    const qr=await dbGet('SELECT qr_code FROM qr_tokens WHERE agent_id=?',[req.user.userId]);
    res.json({refs,tokens,qr_code:qr?.qr_code,note:'Your encoded identifiers. Apply same encoding to other agent IDs to enumerate.'});
  }catch(e){res.status(500).json({error:e.message});}
});

app.get('/api/my/missions',requireAuth,async(req,res)=>{
  try{
    const m=await dbAll('SELECT * FROM missions WHERE agent_id=? ORDER BY id',[req.user.userId]);
    res.json({missions:m});
  }catch(e){res.status(500).json({error:e.message});}
});

app.get('/api/my/intel',requireAuth,async(req,res)=>{
  try{
    const r=await dbAll('SELECT * FROM intel_reports WHERE agent_id=? ORDER BY id',[req.user.userId]);
    res.json({reports:r});
  }catch(e){res.status(500).json({error:e.message});}
});

// No robots.txt
app.get('/robots.txt',(_,res)=>res.status(404).send('Not found'));

app.use((_,res)=>res.status(404).json({error:'Not found'}));

app.listen(PORT,()=>console.log(`
╔═══════════════════════════════════════════════════════╗
║  ACS Secure Net — Cyber Security & Intelligence Portal║
║  Property of ACS Secure Net                           ║
║  http://localhost:${PORT}  — 18 IDOR endpoints          ║
╚═══════════════════════════════════════════════════════╝`));
