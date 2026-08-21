const $=(s,r=document)=>r.querySelector(s), $$=(s,r=document)=>[...r.querySelectorAll(s)];
const enc=new TextEncoder(), dec=new TextDecoder();
const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const unb64=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
const random=n=>crypto.getRandomValues(new Uint8Array(n));
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function concat(...a){let n=a.reduce((x,y)=>x+y.length,0),o=new Uint8Array(n),p=0;a.forEach(x=>{o.set(x,p);p+=x.length});return o}
function xor(a,b){return a.map((v,i)=>v^b[i])}
async function digest(v){return new Uint8Array(await crypto.subtle.digest('SHA-256',typeof v==='string'?enc.encode(v):v))}
async function patternKey(pattern,salt){
  // WebCrypto prototype. Replace with audited Argon2id WASM before production.
  const base=await crypto.subtle.importKey('raw',enc.encode(pattern),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt:enc.encode(salt),iterations:310000},base,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
async function aesKey(raw,uses=['encrypt','decrypt']){return crypto.subtle.importKey('raw',raw,'AES-GCM',false,uses)}
async function seal(key,value,aad='MONC-V1'){let iv=random(12),ct=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:enc.encode(aad)},key,typeof value==='string'?enc.encode(value):value);return{iv:b64(iv),ct:b64(ct)}}
async function open(key,box,aad='MONC-V1'){return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(box.iv),additionalData:enc.encode(aad)},key,unb64(box.ct)))}
async function api(url,opt={}){let headers={Accept:'application/json',...(opt.body?{'Content-Type':'application/json'}:{}),...(opt.headers||{})};let r=await fetch(url,{credentials:'include',...opt,headers});let j=await r.json().catch(()=>({detail:'Request failed'}));if(!r.ok){let d=j.detail;let msg=Array.isArray(d)?d.map(x=>x.msg||JSON.stringify(x)).join(' · '):(d||j.message||'Request failed');let e=Error(typeof msg==='string'?msg:JSON.stringify(msg));e.status=r.status;throw e}return j}
function readTheme(){try{return localStorage.getItem('moncTheme')==='light'?'light':'dark'}catch(e){return 'dark'}}
function setTheme(t){const theme=t==='light'?'light':'dark';document.documentElement.dataset.theme=theme;try{localStorage.setItem('moncTheme',theme)}catch(e){}$('.theme')?.setAttribute('aria-label',theme==='dark'?'Switch to light theme':'Switch to dark theme')}
function initShell(){setTheme(readTheme());$('.theme')?.addEventListener('click',()=>setTheme(document.documentElement.dataset.theme==='dark'?'light':'dark'));window.addEventListener('storage',e=>{if(e.key==='moncTheme')setTheme(e.newValue)});let c=$('.clock');if(c){let f=()=>c.textContent=new Date().toISOString().slice(11,19)+' UTC';f();setInterval(f,1000)}if('serviceWorker' in navigator){navigator.serviceWorker.getRegistrations().then(rs=>rs.forEach(r=>r.unregister())).catch(()=>{});}}
function makePattern(root){let order=[];for(let i=0;i<16;i++){let d=document.createElement('div');d.className='dot';d.dataset.i=i;d.innerHTML='<i></i>';d.onclick=()=>{let at=order.indexOf(i);at<0?order.push(i):order.splice(at,1);render()};root.appendChild(d)}function render(){$$('.dot',root).forEach((d,i)=>{let at=order.indexOf(i);d.classList.toggle('on',at>=0);$('i',d).textContent=at>=0?at+1:''});root.dispatchEvent(new CustomEvent('patternchange'))}return{value:()=>order.join('-'),clear:()=>{order=[];render()},length:()=>order.length}}
function download(name,text){let a=document.createElement('a');a.href=URL.createObjectURL(new Blob([text],{type:'application/json'}));a.download=name;a.click();URL.revokeObjectURL(a.href)}
function tokenEncode(o){return 'MONC1.'+b64(enc.encode(JSON.stringify(o)))}
function tokenDecode(s){if(!s.startsWith('MONC1.'))throw Error('Invalid MONC token');return JSON.parse(dec.decode(unb64(s.slice(6))))}
initShell();
