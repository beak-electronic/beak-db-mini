// BEAK DB mini – Service Worker: speichert NUR den Programmcode (offline nutzbar). Die Datenbank liegt verschlüsselt in IndexedDB.
const CACHE = 'beak-db-mini-v33';
const DATEIEN = ['./', './index.html', './app.css', './app.js', './suche.js', './stkllayout.js', './pdfbreiten.js', './stkldruck.js', './manifest.webmanifest', './icon-180.png', './icon-192.png', './icon-512.png', './logo-db-mini.svg', './logo-db-mini-hell.svg', './fonts/Aeonis.subset.ttf', './fonts/Constantia-Bold.subset.ttf'];
self.addEventListener('install', e => e.waitUntil(caches.open(CACHE).then(c => c.addAll(DATEIEN)).then(() => self.skipWaiting())));
self.addEventListener('activate', e => e.waitUntil(caches.keys().then(k => Promise.all(k.filter(n => n !== CACHE).map(n => caches.delete(n)))).then(() => self.clients.claim())));
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET' || new URL(e.request.url).origin !== location.origin) return;
  // Netz zuerst (Updates), sonst Cache (offline)
  e.respondWith(fetch(e.request).then(r => { const k = r.clone(); caches.open(CACHE).then(c => c.put(e.request, k)); return r; }).catch(() => caches.match(e.request)));
});
