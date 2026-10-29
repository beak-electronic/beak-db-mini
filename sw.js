// BEAK DB mini – Service Worker: speichert NUR den Programmcode (offline nutzbar). Die Datenbank liegt verschlüsselt in IndexedDB.
const CACHE = 'beak-db-mini-1.11';   // ← bei JEDEM Release hochzählen (sonst kein Update-Hinweis)
const DATEIEN = ['./', './index.html', './app.css', './app.js', './theme.js', './update.js', './suche.js', './stkllayout.js', './pdfbreiten.js', './stkldruck.js', './punkt.js', './spiel/beak-breakout.html', './manifest.webmanifest', './icon-180.png', './icon-192.png', './icon-512.png', './logo-db-mini.svg', './logo-db-mini-hell.svg', './fonts/Aeonis.subset.ttf', './fonts/Constantia-Bold.subset.ttf'];
const istNav = r => r.mode === 'navigate' || r.destination === 'document' || (!r.destination && (r.headers.get('accept') || '').includes('text/html'));
const istIcon = u => /\/icon-\d+\.png$/i.test(u.pathname) || /apple-touch|favicon/i.test(u.pathname);
const istCode = u => /\.(m?js|css|json|webmanifest)$/i.test(u.pathname);
const ausCache = r => caches.match(r, { ignoreSearch: true });
const offline = () => new Response('', { status: 503, statusText: 'Offline' });
const merke = (k, r) => { if (r.ok) { const c = r.clone(); caches.open(CACHE).then(x => x.put(k, c)); } return r; };
self.addEventListener('install', e => e.waitUntil((async () => {
  const c = await caches.open(CACHE);
  await Promise.all(DATEIEN.map(async u => { try { const r = await fetch(u, { cache: 'reload' }); if (r.ok) await c.put(u, r); } catch (_) {} }));
  await self.skipWaiting();
})()));
self.addEventListener('activate', e => e.waitUntil(caches.keys().then(k => Promise.all(k.filter(n => n !== CACHE).map(n => caches.delete(n)))).then(() => self.clients.claim())));
self.addEventListener('fetch', e => {
  const r = e.request; if (r.method !== 'GET') return;
  const u = new URL(r.url); if (u.origin !== location.origin) return;
  if (istIcon(u)) return;                       // Home-Bildschirm-Icons nie abfangen (iOS)
  if (/\/sw\.js$/i.test(u.pathname)) return;
  if (istNav(r)) {                              // Seite: Netz zuerst, offline die gespeicherte Hülle
    e.respondWith(fetch(r).then(res => { if (res.ok) { const c = res.clone(); caches.open(CACHE).then(x => { x.put('./index.html', c.clone()); x.put('./', c); }); } return res; })
      .catch(async () => (await ausCache('./index.html')) || (await ausCache('./')) || offline()));
    return;
  }
  if (istCode(u)) { e.respondWith(fetch(r, { cache: 'no-cache' }).then(res => merke(r, res)).catch(async () => (await ausCache(r)) || offline())); return; }
  e.respondWith(ausCache(r).then(c => c || fetch(r).then(res => merke(r, res)).catch(offline)));   // Schriften/Bilder: Cache zuerst
});
