const CACHE='nassar-v12';
const SHELL=['manifest.json','icon-192.png','icon-512.png','cerebro.html','organismo.html','nassar-crypto.js',
 'vendor/three.webgpu.js','vendor/three.core.js','vendor/three.tsl.js','avion.html',
 'vendor/fonts/inter-400.woff2','vendor/fonts/inter-600.woff2','vendor/fonts/inter-700.woff2',
 'vendor/fonts/instrument-serif-400.woff2','vendor/fonts/kode-mono-400.woff2','vendor/fonts/kode-mono-600.woff2',
 'vendor/addons/OrbitControls.js','vendor/addons/BloomNode.js'];
self.addEventListener('install',e=>{
  e.waitUntil(caches.open(CACHE).then(c=>c.addAll(SHELL)).then(()=>self.skipWaiting()));
});
self.addEventListener('activate',e=>{
  e.waitUntil(
    caches.keys()
      .then(ks=>Promise.all(ks.filter(k=>k!==CACHE).map(k=>caches.delete(k))))
      .then(()=>self.clients.claim())
  );
});
self.addEventListener('fetch',e=>{
  const url=new URL(e.request.url);
  // HTML: siempre red primero (así las actualizaciones llegan al momento)
  if(e.request.mode==='navigate'||url.pathname.endsWith('.html')){
    e.respondWith(
      fetch(e.request).then(r=>{
        const c=r.clone();
        caches.open(CACHE).then(ch=>ch.put(e.request,c));
        return r;
      }).catch(()=>caches.match(e.request))
    );
    return;
  }
  // Datos: red primero, caché como respaldo sin conexión
  if(url.pathname.endsWith('status.json')||url.pathname.endsWith('data.enc.json')){
    e.respondWith(fetch(e.request).catch(()=>caches.match(e.request)));
    return;
  }
  // Resto (iconos, js): caché primero
  e.respondWith(
    caches.match(e.request).then(r=>r||fetch(e.request).then(res=>{
      const c=res.clone();
      caches.open(CACHE).then(ch=>ch.put(e.request,c));
      return res;
    }))
  );
});
