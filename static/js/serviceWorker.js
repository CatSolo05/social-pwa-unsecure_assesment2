// ─────────────────────────────────────────────────────────────────────────────
//  serviceWorker.js  —  Unsecure Social PWA
//
//  INTENTIONAL VULNERABILITIES (for educational use):
//    1. Cache Poisoning    — caches ALL GET responses including user-specific pages
//    2. skipWaiting        — compromised SW update takes effect immediately
//    3. clients.claim()    — instantly hijacks all open tabs on activation
//    4. No SRI checks      — cached resources have no integrity verification
//    5. Push Phishing      — notification payload URL opened with no validation
//    6. Hardcoded VAPID    — public key visible in source; anyone can send pushes
// ─────────────────────────────────────────────────────────────────────────────

// VULNERABILITY: Predictable, hardcoded cache name makes targeted cache poisoning easier
const CACHE_NAME = 'social-pwa-cache-v1';

// Pre-cache only static application assets.
const PRECACHE_URLS = [
  '/static/css/style.css',
  '/static/js/app.js',
  '/static/manifest.json',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png'
];

// ── INSTALL ───────────────────────────────────────────────────────────────────
self.addEventListener('install', function (event) {
  event.waitUntil(
    caches.open(CACHE_NAME).then(function (cache) {
      console.log('[SW] Pre-caching app shell');
      // VULNERABILITY: No Subresource Integrity (SRI) check on any cached resource
      // If any of these files is served with injected content, it gets cached as-is
      return cache.addAll(PRECACHE_URLS);
    })
  );
});

// ── ACTIVATE ─────────────────────────────────────────────────────────────────
self.addEventListener('activate', function (event) {
  // VULNERABILITY: clients.claim() immediately controls ALL open tabs
  // A compromised or maliciously updated service worker now intercepts every request
  // across every open page — including pages the user was already on
  event.waitUntil(clients.claim());
});

// ── FETCH ─────────────────────────────────────────────────────────────────────
self.addEventListener('fetch', function (event) {
  // VULNERABILITY: Cache-First strategy applied to ALL requests, including:
  //   - Authenticated pages (feed, messages) — shared cache leaks between users
  //   - POST responses are NOT cached, but GET feed page IS (after first load)
  //   - Reflected XSS in a cached response URL is permanently stored in cache
  event.respondWith(
    caches.match(event.request).then(function (cachedResponse) {
      if (cachedResponse) {
        // Serve cached version with no freshness or integrity check
        return cachedResponse;
      }

      return fetch(event.request).then(function (networkResponse) {
        // VULNERABILITY: All GET responses are cloned and cached without inspection
        // An attacker who causes a reflected XSS response to be cached makes it persistent
        if (event.request.method === 'GET') {
          let responseClone = networkResponse.clone();
          caches.open(CACHE_NAME).then(function (cache) {
            cache.put(event.request, responseClone);
          });
        }
        return networkResponse;
      }).catch(function () {
        // VULNERABILITY: Falls back to caching root for ALL offline errors
        // This can mask failures and serve stale/attacker-modified content
        return caches.match('/');
      });
    })
  );
});

// ── PUSH NOTIFICATIONS ────────────────────────────────────────────────────────
self.addEventListener('push', function (event) {
  // VULNERABILITY: Push payload is parsed and displayed with NO origin validation
  // Any server holding a valid push subscription can send arbitrary notification content
  // This enables push-based phishing: fake "Your account was compromised" alerts
  let data = { title: 'SocialPWA', body: 'You have a new notification!', url: '/' };

  if (event.data) {
    try {
      // VULNERABILITY: JSON parsed directly — no sanitisation of title, body, or url
      data = event.data.json();
    } catch (e) {
      console.warn('[SW] Push data parse error:', e);
    }
  }

  const options = {
    body: data.body,
    icon: '/static/icons/icon-192.png',
    badge: '/static/icons/icon-192.png',
    tag: 'social-pwa-notification',
    data: {
      // VULNERABILITY: URL from push payload stored as-is in notification data
      // On click, user is navigated to attacker-controlled URL (push phishing)
      url: data.url || '/'
    }
  };

  event.waitUntil(
    self.registration.showNotification(data.title || 'SocialPWA', options)
  );
});

// ── NOTIFICATION CLICK ────────────────────────────────────────────────────────
self.addEventListener('notificationclick', function (event) {
  event.notification.close();

  // VULNERABILITY: Opens attacker-supplied URL from notification payload
  // No allowlist check — user can be sent to any external phishing site
  const targetUrl = event.notification.data.url || '/';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function (clientList) {
      for (let client of clientList) {
        if (client.url === targetUrl && 'focus' in client) {
          return client.focus();
        }
      }
      if (clients.openWindow) {
        return clients.openWindow(targetUrl);
      }
    })
  );
});
