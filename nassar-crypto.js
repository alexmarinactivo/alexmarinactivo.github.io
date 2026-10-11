/* Cifrado de la app Nassar en vivo.
   Tu móvil genera un par de llaves RSA. La PRIVADA nunca sale del móvil
   (vive en su almacén interno o, si tu navegador no guarda nada, en tu
   Bitwarden). La PÚBLICA se la pasas a Nassar por el chat (no es secreta).
   Nassar cifra cada actualización con tu pública: solo tu móvil puede
   leerla. Ni GitHub, ni nadie. */

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

/* --- Almacén: IndexedDB con respaldo en memoria ---
   Si IndexedDB falla (modo privado, webview capado, navegador raro),
   todo sigue funcionando en memoria durante la sesión. */
const nassar_mem=new Map();
let nassar_idbOk=null; // null=sin probar, true/false tras la prueba

function nassar_idbOpen(){
  return new Promise((res,rej)=>{
    let q;
    try{ q=indexedDB.open('nassar',1); }
    catch(e){ rej(e); return; }
    q.onupgradeneeded=()=>{ try{ q.result.createObjectStore('keys'); }catch(e){} };
    q.onsuccess=()=>res(q.result);
    q.onerror=()=>rej(q.error||new Error('idb-open'));
    q.onblocked=()=>rej(new Error('idb-blocked'));
  });
}
/* Prueba si IndexedDB funciona de verdad (apertura + escritura).
   true = persistente, false = solo memoria en esta sesión. */
async function nassar_idbProbe(){
  if(nassar_idbOk!==null) return nassar_idbOk;
  try{
    if(typeof indexedDB==='undefined') throw new Error('idb-missing');
    const db=await nassar_idbOpen();
    await new Promise((res,rej)=>{
      let t;
      try{ t=db.transaction('keys','readwrite').objectStore('keys').put('__probe','__probe'); }
      catch(e){ rej(e); return; }
      t.onsuccess=()=>res(); t.onerror=()=>rej(t.error||new Error('idb-probe-put'));
    });
    await new Promise((res,rej)=>{
      let t;
      try{ t=db.transaction('keys','readwrite').objectStore('keys').delete('__probe'); }
      catch(e){ rej(e); return; }
      t.onsuccess=()=>res(); t.onerror=()=>rej(t.error||new Error('idb-probe-del'));
    });
    db.close();
    nassar_idbOk=true;
  }catch(e){ nassar_idbOk=false; }
  return nassar_idbOk;
}
/* ¿El guardado es persistente? (sincrónico: último resultado de la prueba) */
function nassar_persistent(){ return nassar_idbOk===true; }

async function nassar_storeGet(k){
  if(await nassar_idbProbe()){
    try{
      const db=await nassar_idbOpen();
      const v=await new Promise((res,rej)=>{
        let t;
        try{ t=db.transaction('keys','readonly').objectStore('keys').get(k); }
        catch(e){ rej(e); return; }
        t.onsuccess=()=>res(t.result); t.onerror=()=>rej(t.error||new Error('idb-get'));
      });
      db.close();
      if(v!==undefined) return v;
    }catch(e){/* cae a memoria */}
  }
  return nassar_mem.get(k);
}
async function nassar_storeSet(k,v){
  nassar_mem.set(k,v); // caché en memoria siempre (write-through)
  if(await nassar_idbProbe()){
    try{
      const db=await nassar_idbOpen();
      await new Promise((res,rej)=>{
        let t;
        try{ t=db.transaction('keys','readwrite').objectStore('keys').put(v,k); }
        catch(e){ rej(e); return; }
        t.onsuccess=()=>res(); t.onerror=()=>rej(t.error||new Error('idb-put'));
      });
      db.close();
    }catch(e){/* queda en memoria */}
  }
}
/* Compatibilidad con versiones anteriores */
async function nassar_idbGet(k){ return nassar_storeGet(k); }
async function nassar_idbSet(k,v){ return nassar_storeSet(k,v); }

/* Devuelve {priv, pub} creándola la primera vez. */
async function nassar_getOrCreate(){
  let priv=await nassar_storeGet('priv');
  let pub=await nassar_storeGet('pubjwk');
  if(priv&&pub) return {priv,pub};
  const kp=await crypto.subtle.generateKey(
    {name:'RSA-OAEP',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},
    true,['encrypt','decrypt']);
  const exp=await crypto.subtle.exportKey('jwk',kp.publicKey);
  pub={e:exp.e,kty:exp.kty,n:exp.n};
  await nassar_storeSet('priv',kp.privateKey);
  await nassar_storeSet('pubjwk',pub);
  return {priv:kp.privateKey,pub};
}
/* Exporta la llave privada como JWK (para respaldo en Bitwarden). */
async function nassar_exportPrivJwk(){
  const priv=await nassar_storeGet('priv');
  if(!priv) throw new Error('no-key');
  return await crypto.subtle.exportKey('jwk',priv);
}
/* Importa una JWK privada RSA-OAEP; la pública se deriva de {kty,n,e}. */
async function nassar_importPrivJwk(jwk){
  if(!jwk||jwk.kty!=='RSA'||!jwk.n||!jwk.e||!jwk.d) throw new Error('jwk-invalida');
  const priv=await crypto.subtle.importKey('jwk',jwk,
    {name:'RSA-OAEP',hash:'SHA-256'},true,['decrypt']);
  const pub={e:jwk.e,kty:jwk.kty,n:jwk.n};
  await nassar_storeSet('priv',priv);
  await nassar_storeSet('pubjwk',pub);
  return {priv,pub};
}
async function nassar_decrypt(bundle){
  const priv=await nassar_storeGet('priv');
  const pub=await nassar_storeGet('pubjwk');
  if(!priv||!pub) throw new Error('no-key');
  const myId=await nassar_keyId(pub);
  const recip=(bundle.recips||[]).find(r=>r.id===myId);
  if(!recip) throw new Error('no-recip');
  const ek=await crypto.subtle.decrypt({name:'RSA-OAEP',hash:'SHA-256'},priv,nassar_ub64u(recip.ek));
  const aes=await crypto.subtle.importKey('raw',ek,{name:'AES-GCM'},false,['decrypt']);
  const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:nassar_ub64u(bundle.nonce)},aes,nassar_ub64u(bundle.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}
