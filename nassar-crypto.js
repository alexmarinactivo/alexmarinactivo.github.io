/* Cifrado de la app Nassar en vivo.
   Tu móvil genera un par de llaves RSA. La PRIVADA nunca sale del móvil
   (vive en su almacén interno). La PÚBLICA se la pasas a Nassar por el chat
   (no es secreta). Nassar cifra cada actualización con tu pública:
   solo tu móvil puede leerla. Ni GitHub, ni nadie. */

function nassar_b64u(buf){
  const b=new Uint8Array(buf); let s='';
  for(let i=0;i<b.length;i++) s+=String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function nassar_ub64u(s){
  s=s.replace(/-/g,'+').replace(/_/g,'/');
  while(s.length%4) s+='=';
  const bin=atob(s); const b=new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) b[i]=bin.charCodeAt(i);
  return b;
}
function nassar_canon(jwk){ return JSON.stringify({e:jwk.e,kty:jwk.kty,n:jwk.n}); }
async function nassar_keyId(jwk){
  const d=await crypto.subtle.digest('SHA-256', new TextEncoder().encode(nassar_canon(jwk)));
  return nassar_b64u(d).slice(0,16);
}
function nassar_idb(){
  return new Promise((res,rej)=>{
    const q=indexedDB.open('nassar',1);
    q.onupgradeneeded=()=>q.result.createObjectStore('keys');
    q.onsuccess=()=>res(q.result); q.onerror=()=>rej(q.error);
  });
}
async function nassar_idbGet(k){
  const db=await nassar_idb();
  return new Promise((res,rej)=>{
    const t=db.transaction('keys').objectStore('keys').get(k);
    t.onsuccess=()=>res(t.result); t.onerror=()=>rej(t.error);
  });
}
async function nassar_idbSet(k,v){
  const db=await nassar_idb();
  return new Promise((res,rej)=>{
    const t=db.transaction('keys').objectStore('keys').put(v,k);
    t.onsuccess=()=>res(); t.onerror=()=>rej(t.error);
  });
}
/* Devuelve {priv, pub} creándola la primera vez. */
async function nassar_getOrCreate(){
  let priv=await nassar_idbGet('priv');
  let pub=await nassar_idbGet('pubjwk');
  if(priv&&pub) return {priv,pub};
  const kp=await crypto.subtle.generateKey(
    {name:'RSA-OAEP',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},
    false,['encrypt','decrypt']);
  const exp=await crypto.subtle.exportKey('jwk',kp.publicKey);
  pub={e:exp.e,kty:exp.kty,n:exp.n};
  await nassar_idbSet('priv',kp.privateKey);
  await nassar_idbSet('pubjwk',pub);
  return {priv:kp.privateKey,pub};
}
async function nassar_decrypt(bundle){
  const priv=await nassar_idbGet('priv');
  const pub=await nassar_idbGet('pubjwk');
  if(!priv||!pub) throw new Error('no-key');
  const myId=await nassar_keyId(pub);
  const recip=(bundle.recips||[]).find(r=>r.id===myId);
  if(!recip) throw new Error('no-recip');
  const ek=await crypto.subtle.decrypt({name:'RSA-OAEP',hash:'SHA-256'},priv,nassar_ub64u(recip.ek));
  const aes=await crypto.subtle.importKey('raw',ek,{name:'AES-GCM'},false,['decrypt']);
  const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:nassar_ub64u(bundle.nonce)},aes,nassar_ub64u(bundle.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}
