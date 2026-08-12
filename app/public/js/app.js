/* ACS Secure Net — Frontend JS */
const API=''; let currentUser=null;
function getToken(){return localStorage.getItem('sd_token')||getCookie('sd_token');}
function getCookie(n){return(document.cookie.match('(^|;)\\s*'+n+'\\s*=\\s*([^;]+)')||[]).pop()||'';}
function authHeaders(){const t=getToken();return t?{'Content-Type':'application/json','Authorization':'Bearer '+t}:{'Content-Type':'application/json'};}
async function api(method,path,body){
  const opts={method,headers:authHeaders()};
  if(body)opts.body=JSON.stringify(body);
  const r=await fetch(API+path,opts);
  const data=await r.json().catch(()=>({}));
  if(!r.ok)throw Object.assign(new Error(data.error||r.statusText),{data,status:r.status});
  return data;
}
async function loadUser(){try{const d=await api('GET','/api/auth/me');currentUser=d.agent;return d.agent;}catch{return null;}}
function requireLogin(r='/login.html'){if(!getToken()){location.href=r;return false;}return true;}
function logout(){
  fetch('/api/auth/logout',{method:'POST',headers:authHeaders()}).finally(()=>{
    localStorage.removeItem('sd_token');
    document.cookie='sd_token=;expires=Thu,01 Jan 1970 00:00:00 GMT;path=/';
    location.href='/login.html';
  });
}
async function renderNav(){
  const agent=await loadUser();if(!agent)return;
  const clrClass='clr-'+(agent.clearance||'ALPHA');
  document.querySelector('nav').innerHTML=`
    <a class="nav-brand" href="/dashboard.html">
      <div class="nav-icon">⚔</div>
      <div class="nav-brand-text">
        <span class="name">ACS SECURE NET</span>
        <span class="sub">Advanced Cyber Security</span>
      </div>
    </a>`
    <div class="nav-links">
      <a href="/dashboard.html">Dashboard</a>
      <a href="/agents.html">Agents</a>
      <a href="/missions.html">Missions</a>
      <a href="/intel.html">Intel</a>
      <a href="/files.html">Files</a>
      <a href="/access.html">Access</a>
      <a href="/tokens.html">Tokens</a>
      <a href="/verify.html">Verify</a>
    </div>
    <div class="nav-user">
      <span class="clearance-badge ${clrClass}">${agent.clearance||'ALPHA'}</span>
      <button class="btn btn-sm btn-outline" onclick="logout()">Logout</button>
    </div>`;
  document.querySelectorAll('.nav-links a').forEach(a=>{if(a.href===location.href)a.classList.add('active');});
}
function classBadge(c){const m={ALPHA:'badge-teal','TOP SECRET':'badge-omega',SECRET:'badge-crimson',CONFIDENTIAL:'badge-gold',OMEGA:'badge-omega',SIGMA:'badge-gold',DELTA:'badge-teal'};return`<span class="badge ${m[c]||'badge-grey'}">${c}</span>`;}
function fmtDate(d){if(!d)return'—';return new Date(d).toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'});}
function toast(msg,type='crimson'){const d=document.createElement('div');d.className=`alert alert-${type}`;d.style.cssText='position:fixed;top:74px;right:20px;z-index:9999;max-width:400px;box-shadow:0 4px 20px rgba(0,0,0,.5)';d.textContent=msg;document.body.appendChild(d);setTimeout(()=>d.remove(),4000);}
function $(id){return document.getElementById(id);}
function renderAgent(a,acs_secret,note){
  if(!a)return'<div style="color:var(--grey2)">No agent data</div>';
  return`<div class="card" style="border-color:var(--crimson-bd)">
    <div class="code-block" style="margin-bottom:12px">${JSON.stringify(a,null,2)}</div>
    ${acs_secret?`<div class="secret-box"><strong>🔒 EXPOSED SECRET TOKEN</strong>${acs_secret}${note?'<div style="color:var(--grey2);font-family:sans-serif;font-size:.76rem;margin-top:4px">'+note+'</div>':''}</div>`:''}
  </div>`;
}
