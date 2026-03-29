// ─────────────────────────────────────────────────────────────────────────────
//  app.js  —  Unsecure Social PWA  —  Frontend JavaScript
//
//  INTENTIONAL VULNERABILITIES (for educational use):
//    1. DOM-based XSS       — historical issue; URL-driven msg injection has been removed
//    2. Aggressive push     — historical issue; permission prompt now requires a user click
//    3. VAPID public key    — now supplied by the server at render time
//    4. No CSRF protection  — fetch() calls include no CSRF token
//    5. postMessage handling — now limited to same-origin messages and internal redirects
// ─────────────────────────────────────────────────────────────────────────────

const vapidPublicKeyMeta = document.querySelector('meta[name="vapid-public-key"]');
const vapidPublicKey = vapidPublicKeyMeta ? vapidPublicKeyMeta.content : '';

// ── Service Worker Registration ───────────────────────────────────────────────
if ('serviceWorker' in navigator) {
  window.addEventListener('load', function () {
    navigator.serviceWorker.register('/static/js/serviceWorker.js')
      .then(function (reg) {
        console.log('[App] ServiceWorker registered. Scope:', reg.scope);
        // Automatically check for SW updates on every page load
        reg.update();
      })
      .catch(function (err) {
        console.error('[App] ServiceWorker registration failed:', err);
      });
  });
}

// ── Push Notification Subscription ───────────────────────────────────────────
// Permission requests must be triggered by a user gesture to avoid browser
// warnings or blocked prompts.
function setupNotificationsButton() {
  const notificationsBtn = document.getElementById('enable-notifications-btn');

  if (!notificationsBtn) {
    return;
  }

  if (!('Notification' in window) || !('serviceWorker' in navigator)) {
    notificationsBtn.hidden = true;
    return;
  }

  if (!vapidPublicKey) {
    notificationsBtn.hidden = true;
    return;
  }

  if (Notification.permission === 'granted') {
    notificationsBtn.hidden = true;
    return;
  }

  notificationsBtn.hidden = false;
  notificationsBtn.addEventListener('click', function () {
    Notification.requestPermission().then(function (permission) {
      console.log('[App] Notification permission:', permission);

      if (permission === 'granted') {
        notificationsBtn.hidden = true;
        subscribeToPush();
        return;
      }

      if (permission === 'denied') {
        notificationsBtn.disabled = true;
      }
    });
  });
}

async function subscribeToPush() {
  try {
    const registration = await navigator.serviceWorker.ready;

    const applicationServerKey = urlBase64ToUint8Array(vapidPublicKey);

    const subscription = await registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: applicationServerKey
    });

    // VULNERABILITY: Push subscription POSTed to server with no CSRF token
    // An attacker who tricks the user into visiting a page can trigger this fetch
    await fetch('/subscribe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(subscription)
    });

    console.log('[App] Push subscription registered.');
  } catch (err) {
    console.warn('[App] Push subscription failed (expected if no VAPID server):', err);
  }
}

function urlBase64ToUint8Array(base64String) {
  const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
  const base64  = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  const rawData = window.atob(base64);
  const output  = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; i++) {
    output[i] = rawData.charCodeAt(i);
  }
  return output;
}

// ── Navigation UI Setup ───────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', function () {
  // ── Highlight active nav link ──────────────────────────────────────────────
  const currentPath = window.location.pathname;
  document.querySelectorAll('.nav-links a').forEach(function (link) {
    if (link.getAttribute('href') === currentPath) {
      link.style.color = '#e94560';
      link.style.fontWeight = '700';
    }
  });

  setupNotificationsButton();
});

// ── Insecure postMessage Listener ─────────────────────────────────────────────
// VULNERABILITY: Listens for postMessage events from ANY origin (no origin check)
// An iframe on a malicious page can send messages that trigger actions here
const allowedRedirectPaths = new Set([
  '/',
  '/index.html',
  '/signup.html',
  '/feed.html',
  '/profile',
  '/messages',
  '/success.html'
]);

window.addEventListener('message', function (event) {
  if (event.origin !== window.location.origin) {
    return;
  }

  console.log('[App] postMessage received from:', event.origin, 'data:', event.data);

  if (event.data && event.data.action === 'redirect') {
    const redirectUrl = typeof event.data.url === 'string'
      ? new URL(event.data.url, window.location.origin)
      : null;

    if (
      redirectUrl &&
      redirectUrl.origin === window.location.origin &&
      allowedRedirectPaths.has(redirectUrl.pathname)
    ) {
      window.location.href = redirectUrl.pathname + redirectUrl.search + redirectUrl.hash;
    }
  }

  if (event.data && event.data.action === 'setMsg') {
    const msgBox = document.getElementById('js-msg-box');
    if (msgBox) {
      // Render message content as plain text so HTML is not interpreted.
      msgBox.textContent = event.data.content;
    }
  }
});

// ── PWA Install Prompt ────────────────────────────────────────────────────────
let deferredPrompt;
window.addEventListener('beforeinstallprompt', function (e) {
  e.preventDefault();
  deferredPrompt = e;

  const installBtn = document.getElementById('install-btn');
  if (installBtn) {
    installBtn.style.display = 'inline-block';
    installBtn.addEventListener('click', function () {
      deferredPrompt.prompt();
      deferredPrompt.userChoice.then(function (choiceResult) {
        console.log('[App] Install choice:', choiceResult.outcome);
        deferredPrompt = null;
        installBtn.style.display = 'none';
      });
    });
  }
});
