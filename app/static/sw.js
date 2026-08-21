// MONC - placeholder service worker. Previous stray registrations caused clone errors.
// This worker immediately unregisters itself; MONC does not use offline caching.
self.addEventListener('install', event => self.skipWaiting());
self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    try { await self.registration.unregister(); } catch(e) {}
    const clients = await self.clients.matchAll();
    clients.forEach(c => c.navigate(c.url));
  })());
});
self.addEventListener('fetch', event => {
  // No cache — just pass through. Clone correctly if ever used.
  event.respondWith(fetch(event.request).then(res => {
    // clone before body is consumed
    const clone = res.clone();
    return res;
  }));
});
