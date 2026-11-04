const $ = (s, root=document) => root.querySelector(s);
const $$ = (s, root=document) => [...root.querySelectorAll(s)];
const state = {
  proto: "ssh", accounts: [],
  serverId: localStorage.getItem("vpnSelectedServer") === "sg3" ? "sg3" : "sg2",
  user: null
};
const serverNames = { sg2: "Singapore 2", sg3: "Singapore 3" };
const protoNames = {ssh:"SSH",vmess:"VMess",vless:"VLESS",trojan:"Trojan",zivpn:"ZiVPN"};
const PACKAGE_DAYS = 30;
const PACKAGE_PRICE = 5000;

function serverHeader(){ return { "X-VPN-Server": state.serverId }; }
function money(value){ return `Rp${Number(value||0).toLocaleString("id-ID")}`; }
function updateServerLabel(){
  const label=$("#selectedServerName");
  if(label) label.textContent = `${state.user?.username || "Akun"} · ${serverNames[state.serverId] || "Singapore 2"}`;
  const select=$("#serverSelect");
  if(select) select.value=state.serverId;
  const balance=Number(state.user?.balance||0);
  const chip=$("#headerBalance");
  if(chip){chip.textContent=money(balance);chip.classList.toggle("hidden",!state.user||state.user.role==="admin");}
}
async function refreshCurrentUser(){
  try{
    const result=await api("/api/me");
    if(result.user){state.user=result.user;updateServerLabel();}
    if($("#statBalance") && $("#page-dashboard") && !$("#page-dashboard").classList.contains("hidden")){
      $("#statBalance").textContent=money(state.user?.balance);
    }
  }catch{}
}

function esc(s){return String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function escAttr(s){return esc(s).replace(/`/g,"&#96;");}

async function api(url, options={}) {
  const headers = {
    ...(options.body ? {"Content-Type":"application/json"} : {}),
    ...serverHeader(), ...(options.headers||{})
  };
  const res = await fetch(url, {
    ...options, headers,
    credentials: "same-origin",
    cache: "no-store"
  });
  const data = await res.json().catch(()=>({message:"Respons server tidak valid."}));
  if (!res.ok) {
    if (res.status === 401 && !["/api/auth/login", "/api/auth/me", "/api/auth/logout"].includes(url)) {
      state.user = null;
      showLogin("Sesi login sudah berakhir. Silakan login kembali.");
    }
    const error = new Error(data.message || `HTTP ${res.status}`);
    error.status = res.status;
    throw error;
  }
  return data;
}

function injectLoginStyles(){
  if($("#loginStyles")) return;
  const style=document.createElement("style");
  style.id="loginStyles";
  style.textContent=`
    #loginView{min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at 20% 10%,#172b48 0,transparent 38%),#080d17;color:#edf4ff;font-family:inherit}
    #loginView .login-card{width:min(420px,100%);padding:32px;border:1px solid #27364c;border-radius:22px;background:#101a2a;box-shadow:0 24px 80px #0008}
    #loginView .login-brand{font-size:13px;letter-spacing:2px;color:#8ba9cf;font-weight:800}
    #loginView h1{font-size:28px;margin:12px 0 8px} #loginView p{color:#9aabc2;line-height:1.6}
    #loginView label{display:block;margin:18px 0 7px;color:#b9c7d9;font-size:13px}
    #loginView input{width:100%;box-sizing:border-box;padding:13px 14px;border:1px solid #34465f;border-radius:10px;background:#0a1220;color:#fff;font:inherit;outline:none}
    #loginView input:focus{border-color:#69a7ff}
    #loginView button{width:100%;margin-top:20px;padding:13px;border:0;border-radius:10px;background:#4d91ef;color:#fff;font-weight:800;font:inherit;cursor:pointer}
    #loginError{margin-top:12px;color:#ff8585;font-size:13px;min-height:18px}
    #logoutBtn{margin-left:8px;white-space:nowrap}
    .role-chip{font-size:11px;color:#9fb8d8;margin-left:8px;text-transform:uppercase}
  `;
  document.head.appendChild(style);
}

function showLogin(message=""){
  const appView=$("#appView");
  if(appView) appView.classList.add("hidden");
  injectLoginStyles();
  let view=$("#loginView");
  if(!view){
    view=document.createElement("section");
    view.id="loginView";
    view.innerHTML=`<form class="login-card" id="loginForm" autocomplete="on">
      <div class="login-brand">VPN CONTROL</div><h1>Masuk ke panel</h1>
      <p>Login untuk mengelola akun VPN dan server.</p>
      <label for="loginUsername">Username</label><input id="loginUsername" name="username" autocomplete="username" required maxlength="32">
      <label for="loginPassword">Password</label><input id="loginPassword" name="password" type="password" autocomplete="current-password" required>
      <button type="submit" id="loginSubmit">Login</button><div id="loginError" role="alert"></div>
    </form>`;
    document.body.prepend(view);
    $("#loginForm").addEventListener("submit", async e=>{
      e.preventDefault();
      const button=$("#loginSubmit"), error=$("#loginError");
      button.disabled=true; button.textContent="Memeriksa..."; error.textContent="";
      try{
        const body={username:$("#loginUsername").value.trim(),password:$("#loginPassword").value};
        const result=await api("/api/auth/login",{method:"POST",body:JSON.stringify(body)});
        state.user=result.user;
        view.remove();
        await enterApp();
      }catch(err){error.textContent=err.message||"Login gagal.";}
      finally{button.disabled=false;button.textContent="Login";}
    });
  }
  $("#loginError").textContent=message;
  view.classList.remove("hidden");
  $("#loginUsername")?.focus();
}

function showApp(){
  $("#loginView")?.remove();
  $("#appView")?.classList.remove("hidden");
  updateServerLabel();
  const profile=$(".profile");
  if(profile){
    const isAdmin=state.user?.role==="admin";
    $("#membersNav")?.classList.toggle("hidden",!isAdmin);
    let role=$("#roleLabel");
    if(!role){role=document.createElement("small");role.id="roleLabel";role.className="role-chip";profile.appendChild(role);}
    role.textContent=state.user?.role || "member";
    let logout=$("#logoutBtn");
    if(!logout){logout=document.createElement("button");logout.id="logoutBtn";logout.className="secondary";logout.textContent="Keluar";profile.after(logout);}
    logout.onclick=async()=>{
      logout.disabled=true;
      try{await api("/api/auth/logout",{method:"POST"});}catch{}
      state.user=null; showLogin("Silakan login kembali.");
    };
  }
}
function notice(message,bad=false){
  const n=$("#notice"); if(!n)return;
  n.textContent=message; n.classList.toggle("bad",bad); n.classList.remove("hidden");
  window.scrollTo({top:0,behavior:"smooth"});
  clearTimeout(notice.timer); notice.timer=setTimeout(()=>n.classList.add("hidden"),6500);
}
function errorNotice(e){notice(e.message||"Terjadi kesalahan.",true);}
function go(page){
  if(page==="members" && state.user?.role!=="admin"){notice("Menu ini khusus Admin.",true);return;}
  $$(".page").forEach(p=>p.classList.add("hidden"));
  $(`#page-${page}`)?.classList.remove("hidden");
  $$(".nav").forEach(n=>n.classList.toggle("active",n.dataset.page===page));
  const titles={dashboard:"Dashboard",create:"Buat Akun",accounts:"Daftar Akun",online:"Pengguna Online",server:"Info Server",members:"Member & Saldo"};
  if($("#pageTitle")) $("#pageTitle").textContent=titles[page]||"Dashboard";
  if(page==="dashboard") refreshDashboard();
  if(page==="accounts") loadAccounts();
  if(page==="online") loadOnline();
  if(page==="server") loadServer();
  if(page==="members" && state.user?.role==="admin") loadMembers();
}

function bindNavigation(){
  $$('[data-page]').forEach(b=>b.addEventListener("click",()=>go(b.dataset.page)));
  $$('[data-go]').forEach(b=>b.addEventListener("click",()=>go(b.dataset.go)));
  const serverSelect=$("#serverSelect");
  if(serverSelect){
    serverSelect.value=state.serverId; updateServerLabel();
    serverSelect.addEventListener("change",()=>{
      state.serverId=serverSelect.value==="sg3"?"sg3":"sg2";
      localStorage.setItem("vpnSelectedServer",state.serverId); updateServerLabel();
      notice(`Server aktif: ${serverNames[state.serverId]}`);
      const current=$(".page:not(.hidden)")?.id.replace("page-","")||"dashboard";
      if(current==="dashboard")refreshDashboard();
      if(current==="accounts")loadAccounts();
      if(current==="online")loadOnline();
      if(current==="server")loadServer();
      if(current==="create")$("#createdResult")?.classList.add("hidden");
    });
  }
}

function updateProtoFields(){
  const p=$("#createProto")?.value;
  if(!p)return;
  const showPassword=["ssh","zivpn"].includes(p);
  $("#passwordField")?.classList.toggle("hidden",!showPassword);
  $("#uuidField")?.classList.toggle("hidden",!["vmess","vless","trojan"].includes(p));
  const input=$('input[name="password"]');
  if(input){input.required=p==="ssh";input.disabled=!showPassword;input.placeholder=p==="zivpn"?"Kosongkan untuk password otomatis":"Password SSH";}
}
function renderLinks(d){
  const links=d.links||{};
  const all={...links,Subscription:d.connection?.sub_link||d.sub_link,OpenVPN:d.connection?.openvpn_config};
  const arr=Object.entries(all).filter(([k,v])=>v);
  return arr.length?`<div class="result-links">${arr.map(([k,v])=>`<a href="${escAttr(v)}" target="_blank" rel="noopener">${esc(k)} ↗</a>`).join("")}</div>`:"";
}
function renderCreated(response){
  const d=response.result?.data||response.result||response.data||response;
  const box=$("#createdResult"); if(!box)return;
  box.classList.remove("hidden");
  const entries=[["Username",d.username], ["Password",d.password], ["UUID",d.uuid], ["Status",d.status], ["Masa aktif",d.expired], ["Host",d.connection?.host||d.domain], ["NS Domain",d.connection?.slowdns_host||d.ns_domain], ["Batas IP",d.ip_limit]];
  box.innerHTML=`<div class="result-title"><div><p class="eyebrow">ACCOUNT CREATED</p><h3>Akun berhasil dibuat</h3></div><span class="badge">ACTIVE</span></div><p class="muted">Paket ${PACKAGE_DAYS} hari · Rp${PACKAGE_PRICE.toLocaleString("id-ID")}</p><div class="result-data">${entries.filter(x=>x[1]!==undefined&&x[1]!==null&&x[1]!=="").map(([k,v])=>`<div><span>${esc(k)}</span><b>${esc(String(v))}</b></div>`).join("")}</div>${renderLinks(d)}<button class="secondary" id="copyAccount" style="margin-top:15px">Salin detail akun</button>`;
  $("#copyAccount").onclick=()=>navigator.clipboard.writeText(entries.filter(x=>x[1]).map(([k,v])=>`${k}: ${v}`).join("\n")).then(()=>notice("Detail akun disalin."));
}
function bindCreate(){
  const proto=$("#createProto"); proto?.addEventListener("change",updateProtoFields); updateProtoFields();
  let days=$('#createForm [name="days"]');
  if(days && state.user?.role==="admin") {
    days.outerHTML='<input name="days" type="number" min="1" max="3650" value="30" required>';
  } else if(days) {
    days.value="30";
  }
  const ipInput=$('#createForm [name="ip_limit"]');
  if(ipInput && state.user?.role==="member") { ipInput.min="1"; ipInput.value="2"; }
  const form=$("#createForm");
  let createRequestInProgress=false;
  form?.addEventListener("submit",async e=>{
    e.preventDefault();
    // Prevent repeated Enter/click submissions while the first request is running.
    if(createRequestInProgress)return;
    createRequestInProgress=true;
    const btn=$('button[type="submit"]',form);
    const originalButtonText=btn?.textContent;
    if(btn){btn.disabled=true;btn.textContent="Memproses…";}
    const fd=new FormData(form),p=fd.get("proto");
    const body={username:fd.get("username"),days:Number(fd.get("days")||PACKAGE_DAYS),ip_limit:Number(fd.get("ip_limit")),quota_gb:Number(fd.get("quota_gb"))};
    if(p==="ssh")body.password=fd.get("password");
    if(p==="zivpn"&&fd.get("password"))body.password=fd.get("password");
    if(fd.get("uuid"))body.uuid=fd.get("uuid");
    try{const d=await api(`/api/accounts/${p}`,{method:"POST",body:JSON.stringify(body)});renderCreated(d);await refreshCurrentUser();await loadAccounts();notice(`Akun berhasil dibuat. Biaya Rp${Number(d.charged||0).toLocaleString("id-ID")}.`);}
    catch(err){errorNotice(err);}finally{
      createRequestInProgress=false;
      if(btn){btn.disabled=false;btn.textContent=originalButtonText||"Buat Akun";}
    }
  });
  $("#trialBtn")?.addEventListener("click",async()=>{
    try{const d=await api(`/api/accounts/${proto.value}/trial`,{method:"POST",body:JSON.stringify({minutes:60})});renderCreated(d);notice("Akun trial berhasil dibuat.");}
    catch(err){errorNotice(err);}
  });
}

function accountRows(data){
  const rows=Array.isArray(data)?data:(data.accounts||data.data||[]);state.accounts=rows;
  const search=$("#accountSearch")?.value.toLowerCase()||"";
  const filtered=rows.filter(a=>String(a.username||a.user||"").toLowerCase().includes(search));
  if(!filtered.length)return '<div class="empty">Tidak ada akun yang cocok.</div>';
  return `<div class="account-card-grid">${filtered.map(a=>{
    const u=a.username||a.user||"",locked=!!a.locked,expired=a.expired||a.expires_at||"-";
    return `<article class="account-card"><div class="account-card-top"><div class="account-avatar">${esc(String(u||"?").slice(0,1).toUpperCase())}</div><div class="account-identity"><strong>${esc(u||"-")}</strong><span>VPN Account</span></div><span class="badge ${locked?"off":""}">${locked?"LOCKED":esc(a.status||"ACTIVE")}</span></div><div class="account-details"><div><span>Expired</span><b>${esc(String(expired))}</b></div><div><span>Kuota</span><b>${esc(a.quota_gb??a.quota_bytes??"-")}</b></div><div><span>Batas IP</span><b>${esc(a.ip_limit??"-")}</b></div></div><div class="account-card-actions"><button class="mini" data-action="renew" data-user="${escAttr(u)}">↻ Renew 30 hari / Rp5k</button><button class="mini" data-action="${locked?"unlock":"lock"}" data-user="${escAttr(u)}">${locked?"Unlock":"Lock"}</button><button class="mini danger" data-action="delete" data-user="${escAttr(u)}">Hapus</button></div></article>`;
  }).join("")}</div>`;
}
async function loadAccounts(){
  const p=$("#accountsProto").value;$("#accountsTable").innerHTML='<div class="empty">Memuat akun...</div>';
  try{$("#accountsTable").innerHTML=accountRows(await api(`/api/accounts/${p}`));}
  catch(e){$("#accountsTable").innerHTML=`<div class="empty">${esc(e.message)}</div>`;}
}
function bindAccounts(){
  $("#accountsProto")?.addEventListener("change",loadAccounts);
  $("#refreshAccounts")?.addEventListener("click",loadAccounts);
  $("#accountSearch")?.addEventListener("input",()=>$("#accountsTable").innerHTML=accountRows(state.accounts));
  $("#accountsTable")?.addEventListener("click",async e=>{
    const b=e.target.closest("[data-action]");if(!b)return;
    const action=b.dataset.action,user=b.dataset.user,p=$("#accountsProto").value;
    try{
      if(action==="delete"&&!confirm(`Hapus akun ${user}? Tindakan ini tidak bisa dibatalkan.`))return;
      let result;
      if(action==="renew"){
        if(!confirm(`Perpanjang ${user} selama 30 hari dengan biaya Rp5.000?`))return;
        result=await api(`/api/accounts/${p}/${encodeURIComponent(user)}/renew`,{method:"POST",body:JSON.stringify({days:PACKAGE_DAYS})});
        await refreshCurrentUser();
      }else if(action==="delete")result=await api(`/api/accounts/${p}/${encodeURIComponent(user)}`,{method:"DELETE"});
      else result=await api(`/api/accounts/${p}/${encodeURIComponent(user)}/${action}`,{method:"POST",body:JSON.stringify({})});
      notice(result.message||"Aksi berhasil.");loadAccounts();
    }catch(err){errorNotice(err);}
  });
}
async function loadOnline(){
  const p=$("#onlineProto").value;$("#onlineTable").innerHTML='<div class="empty">Memuat sesi online...</div>';
  try{
    const d=await api(`/api/online/${p}`),rows=Array.isArray(d.data)?d.data:[];
    $("#onlineTable").innerHTML=rows.length?`<div class="account-card-grid online-card-grid">${rows.map(r=>{const u=r.user||r.username||"-",ips=(r.ips||[]).join(", ")||r.ip||"-";return `<article class="account-card online-card"><div class="account-card-top"><div class="account-avatar online-avatar">◉</div><div class="account-identity"><strong>${esc(u)}</strong><span>Active session</span></div><span class="badge">ONLINE</span></div><div class="account-details online-details"><div><span>Traffic</span><b>${esc(r.usage||r.traffic||"-")}</b></div><div><span>Kuota</span><b>${esc(r.quota||"-")}</b></div><div><span>Jumlah IP</span><b>${esc(r.ip_count??r.ip_limit??"-")}</b></div><div class="ip-detail"><span>IP aktif</span><b>${esc(ips)}</b></div></div></article>`;}).join("")}</div>`:'<div class="empty">Tidak ada pengguna online.</div>';
    if($("#statOnline"))$("#statOnline").textContent=rows.length;
  }catch(e){$("#onlineTable").innerHTML=`<div class="empty">${esc(e.message)}</div>`;}
}
function bindOnline(){$("#onlineProto")?.addEventListener("change",loadOnline);$("#refreshOnline")?.addEventListener("click",loadOnline);}
async function loadServer(){
  $("#serverInfo").innerHTML='<div class="empty">Memuat info server...</div>';
  try{
    const d=await api("/api/server"),data=d.data||d.result||{};
    const pairs=Object.entries(data).filter(([k,v])=>v!==null&&v!==undefined&&typeof v!=="object");
    const ports=data.ports?Object.entries(data.ports).map(([k,v])=>`${k}: ${Array.isArray(v)?v.join(", "):v}`).join(" | "):"";
    if(ports)pairs.push(["ports",ports]);
    $("#serverInfo").innerHTML=pairs.map(([k,v])=>`<div class="server-item"><span>${esc(k.replace(/_/g," "))}</span><b>${esc(String(v))}</b></div>`).join("")||'<div class="empty">Data server tidak tersedia.</div>';
  }catch(e){$("#serverInfo").innerHTML=`<div class="empty">${esc(e.message)}</div>`;}
}
function bindServer(){$("#refreshServer")?.addEventListener("click",loadServer);}
async function refreshDashboard(){
  // Muat saldo secara terpisah agar tetap tampil meskipun API VPN sedang offline.
  try{
    const me=await api("/api/me");
    if(me.user){state.user=me.user;updateServerLabel();}
    if(state.user?.role==="admin"){
      const result=await api("/api/admin/users");
      const users=Array.isArray(result.users)?result.users:[];
      $("#balanceStatLabel").textContent="Total saldo member";
      $("#statBalance").textContent=money(users.reduce((sum,u)=>sum+Number(u.balance||0),0));
      $("#balanceStatHint").textContent=`${users.length} member terdaftar`;
    }else{
      $("#balanceStatLabel").textContent="Saldo saya";
      $("#statBalance").textContent=money(state.user?.balance);
      $("#balanceStatHint").textContent="Saldo untuk membuat / memperpanjang akun";
    }
  }catch(e){if($("#statBalance"))$("#statBalance").textContent="—";}
  try{
    const [accounts,online]=await Promise.all([
      api(`/api/accounts/${state.proto}`),api(`/api/online/${state.proto}`)
    ]);
    const arr=Array.isArray(accounts.data)?accounts.data:[];
    if($("#statAccounts"))$("#statAccounts").textContent=arr.length;
    if($("#statOnline"))$("#statOnline").textContent=Array.isArray(online.data)?online.data.length:0;
    if($("#statApi")){$("#statApi").textContent="Aktif";$("#statApi").style.color="";}
  }catch(e){if($("#statApi")){$("#statApi").textContent="Error";$("#statApi").style.color="var(--red)";}}
}

let memberCache=[];
function renderMembers(){
  const query=$("#memberSearch")?.value.trim().toLowerCase()||"";
  const users=memberCache.filter(u=>String(u.username||"").toLowerCase().includes(query));
  $("#memberCount").textContent=memberCache.length;
  $("#memberTotalBalance").textContent=money(memberCache.reduce((sum,u)=>sum+Number(u.balance||0),0));
  if(!users.length){$("#membersTable").innerHTML='<div class="empty">Belum ada member atau tidak ada hasil pencarian.</div>';return;}
  $("#membersTable").innerHTML=`<table class="data-table member-table"><thead><tr><th>Member</th><th>Saldo</th><th>Akses server</th><th>Status</th><th>Tambah saldo</th><th>Aksi</th></tr></thead><tbody>${users.map(u=>{
    const servers=Array.isArray(u.servers)?u.servers:[];
    return `<tr>
      <td data-label="Member"><span class="user">${esc(u.username)}</span><small class="member-id">${esc(String(u.id).slice(0,8))}</small></td>
      <td data-label="Saldo"><strong class="member-balance">${money(u.balance)}</strong></td>
      <td data-label="Akses server"><div class="server-toggles"><label><input type="checkbox" data-member-action="server" data-id="${escAttr(u.id)}" data-server="sg2" ${servers.includes("sg2")?"checked":""}> SG2</label><label><input type="checkbox" data-member-action="server" data-id="${escAttr(u.id)}" data-server="sg3" ${servers.includes("sg3")?"checked":""}> SG3</label></div></td>
      <td data-label="Status"><span class="badge ${u.active===false?"off":""}">${u.active===false?"NONAKTIF":"AKTIF"}</span></td>
      <td data-label="Tambah saldo"><div class="topup-control"><input type="number" min="1" step="1" inputmode="numeric" placeholder="Nominal Rp" aria-label="Nominal saldo ${escAttr(u.username)}" data-topup-amount="${escAttr(u.id)}"><button class="mini topup-btn" data-member-action="topup" data-id="${escAttr(u.id)}">＋ Tambah</button></div></td>
      <td data-label="Aksi"><div class="actions"><button class="mini" data-member-action="toggle" data-id="${escAttr(u.id)}">${u.active===false?"Aktifkan":"Nonaktifkan"}</button></div></td>
    </tr>`;
  }).join("")}</tbody></table>`;
}
async function loadMembers(){
  if(state.user?.role!=="admin")return;
  $("#membersTable").innerHTML='<div class="empty">Memuat daftar member...</div>';
  try{const d=await api("/api/admin/users");memberCache=Array.isArray(d.users)?d.users:[];renderMembers();}
  catch(e){$("#membersTable").innerHTML=`<div class="empty">${esc(e.message)}</div>`;}
}
function bindMembers(){
  const form=$("#memberForm");
  form?.addEventListener("submit",async e=>{
    e.preventDefault();
    const btn=form.querySelector('button[type="submit"]');btn.disabled=true;
    const fd=new FormData(form);const servers=fd.getAll("servers");
    try{
      await api("/api/admin/users",{method:"POST",body:JSON.stringify({username:String(fd.get("username")).trim(),password:fd.get("password"),servers})});
      form.reset();form.querySelector('[value="sg2"]').checked=true;
      notice("Member berhasil dibuat. Saldo awal Rp0.");await loadMembers();await refreshDashboard();
    }catch(err){errorNotice(err);}finally{btn.disabled=false;}
  });
  $("#refreshMembers")?.addEventListener("click",loadMembers);
  $("#memberSearch")?.addEventListener("input",renderMembers);
  $("#membersTable")?.addEventListener("click",async e=>{
    const btn=e.target.closest('[data-member-action]');if(!btn)return;
    const action=btn.dataset.memberAction,id=btn.dataset.id;
    const user=memberCache.find(u=>u.id===id);if(!user)return;
    try{
      if(action==="topup"){
        const input=$(`[data-topup-amount="${CSS.escape(id)}"]`);
        const amount=Number(input?.value);
        if(!Number.isSafeInteger(amount)||amount<=0){notice("Masukkan nominal saldo berupa angka lebih dari 0.",true);input?.focus();return;}
        if(!confirm(`Tambah ${money(amount)} ke saldo ${user.username}?`))return;
        await api(`/api/admin/users/${encodeURIComponent(id)}/balance`,{method:"POST",body:JSON.stringify({amount,note:"Top up saldo oleh admin"})});
        notice(`Saldo ${user.username} berhasil ditambah ${money(amount)}.`);
        await loadMembers();await refreshDashboard();
      }else if(action==="toggle"){
        const active=user.active===false;
        if(!confirm(`${active?"Aktifkan":"Nonaktifkan"} member ${user.username}?`))return;
        await api(`/api/admin/users/${encodeURIComponent(id)}`,{method:"PATCH",body:JSON.stringify({active})});
        notice(`Member ${user.username} sekarang ${active?"aktif":"nonaktif"}.`);await loadMembers();
      }
    }catch(err){errorNotice(err);}
  });
  $("#membersTable")?.addEventListener("change",async e=>{
    const input=e.target.closest('[data-member-action="server"]');if(!input)return;
    const id=input.dataset.id,user=memberCache.find(u=>u.id===id);if(!user)return;
    const servers=new Set(user.servers||[]);
    if(input.checked)servers.add(input.dataset.server);else servers.delete(input.dataset.server);
    if(!servers.size){input.checked=true;notice("Setiap member harus memiliki minimal satu akses server.",true);return;}
    input.disabled=true;
    try{await api(`/api/admin/users/${encodeURIComponent(id)}`,{method:"PATCH",body:JSON.stringify({servers:[...servers]})});notice(`Akses server ${user.username} diperbarui.`);await loadMembers();}
    catch(err){input.checked=!input.checked;errorNotice(err);}finally{input.disabled=false;}
  });
}

async function enterApp(){
  showApp();
  bindNavigation();bindCreate();bindAccounts();bindOnline();bindServer();bindMembers();
  go("dashboard");
}
async function bootstrap(){
  try{
    // This restores the existing HttpOnly session cookie after every reload.
    const result=await api("/api/auth/me");
    state.user=result.user;
    await enterApp();
  }catch(error){
    showLogin(error.status===401?"":"Tidak bisa memeriksa sesi. Coba login kembali.");
  }
}
$("#appView")?.classList.add("hidden");
document.addEventListener("DOMContentLoaded",bootstrap);
