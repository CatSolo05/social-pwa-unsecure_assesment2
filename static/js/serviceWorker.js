// ─────────────────────────────────────────────────────────────────────────────
//  serviceWorker.js  —  Unsecure Social PWA
//
//  INTENTIONAL VULNERABILITIES (for educational use):
//    1. Cache Poisoning    — caches ALL GET responses including user-specific pages
//    2. skipWaiting        — compromised SW update takes effect immediately
//    3. Service worker scope — newly activated workers wait for future navigations
//    4. No SRI checks      — cached resources have no integrity verification
//    5. Push Phishing      — notification payload URL opened with no validation
//    6. Hardcoded VAPID    — public key visible in source; anyone can send pushes
// ─────────────────────────────────────────────────────────────────────────────

// Use a versioned cache name so stale assets from older service workers are not reused.
const CACHE_NAME = 'social-pwa-cache-v2';

// Pre-cache only static application assets.
const PRECACHE_URLS = [
  '/static/css/style.css',
  '/static/js/app.js',
  '/static/manifest.json',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png'
];
const PRECACHE_PATHS = new Set(PRECACHE_URLS);
const ALLOWED_NOTIFICATION_PATHS = new Set([
  '/',
  '/index.html',
  '/signup.html',
  '/feed.html',
  '/profile',
  '/messages',
  '/success.html'
]);
const MAX_NOTIFICATION_TITLE_LENGTH = 80;
const MAX_NOTIFICATION_BODY_LENGTH = 200;

function sanitizeNotificationText(value, fallbackValue, maxLength) {
  if (typeof value !== 'string') {
    return fallbackValue;
  }

  const trimmedValue = value.trim();
  if (!trimmedValue) {
    return fallbackValue;
  }

  return trimmedValue.slice(0, maxLength);
}

function sanitizeNotificationUrl(value) {
  if (typeof value !== 'string') {
    return '/';
  }

  try {
    const parsedUrl = new URL(value, self.location.origin);
    if (
      parsedUrl.origin === self.location.origin &&
      ALLOWED_NOTIFICATION_PATHS.has(parsedUrl.pathname)
    ) {
      return parsedUrl.pathname + parsedUrl.search + parsedUrl.hash;
    }
  } catch (error) {
    console.warn('[SW] Notification URL parse error:', error);
  }

  return '/';
}

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
  event.waitUntil(
    caches.keys().then(function (cacheNames) {
      return Promise.all(
        cacheNames
          .filter(function (cacheName) {
            return cacheName !== CACHE_NAME;
          })
          .map(function (cacheName) {
            return caches.delete(cacheName);
          })
      );
    })
  );
});

// ── FETCH ─────────────────────────────────────────────────────────────────────
self.addEventListener('fetch', function (event) {
  if (event.request.method !== 'GET') {
    return;
  }

  const requestUrl = new URL(event.request.url);
  const isStaticAsset = requestUrl.origin === self.location.origin &&
    PRECACHE_PATHS.has(requestUrl.pathname);

  if (!isStaticAsset) {
    event.respondWith(fetch(event.request));
    return;
  }

  event.respondWith(
    caches.match(event.request).then(function (cachedResponse) {
      if (cachedResponse) {
        return cachedResponse;
      }

      return fetch(event.request);
    })
  );
});

// ── PUSH NOTIFICATIONS ────────────────────────────────────────────────────────
self.addEventListener('push', function (event) {
  let data = { title: 'SocialPWA', body: 'You have a new notification!', url: '/' };

  if (event.data) {
    try {
      data = event.data.json();
    } catch (e) {
      console.warn('[SW] Push data parse error:', e);
    }
  }

  const title = sanitizeNotificationText(
    data.title,
    'SocialPWA',
    MAX_NOTIFICATION_TITLE_LENGTH
  );
  const body = sanitizeNotificationText(
    data.body,
    'You have a new notification!',
    MAX_NOTIFICATION_BODY_LENGTH
  );
  const url = sanitizeNotificationUrl(data.url);

  const options = {
    body: body,
    icon: '/static/icons/icon-192.png',
    badge: '/static/icons/icon-192.png',
    tag: 'social-pwa-notification',
    data: {
      url: url
    }
  };

  event.waitUntil(
    self.registration.showNotification(title, options)
  );
});

// ── NOTIFICATION CLICK ────────────────────────────────────────────────────────
self.addEventListener('notificationclick', function (event) {
  event.notification.close();

  const targetUrl = sanitizeNotificationUrl(event.notification.data.url);
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
