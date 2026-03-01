self.addEventListener('install', (event) => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('message', (event) => {
  const data = event.data || {};
  if (data.type !== 'SHOW_NOTIFICATION') return;
  const title = data.title || 'ChessOK';
  const tag = data.tag || `${title}:${data.body || ''}:${data.url || ''}`;
  const options = {
    body: data.body || '',
    icon: '/static/images/icons/favicon.svg',
    badge: '/static/images/icons/favicon.svg',
    tag,
    renotify: false,
    data: data.url ? { url: data.url } : {},
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const targetUrl = event.notification.data?.url || '/';
  const targetAbs = new URL(targetUrl, self.location.origin).href;
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(async (clients) => {
      // 1) 이미 같은 URL 창이 있으면 즉시 포커스
      for (const client of clients) {
        if (client.url === targetAbs && 'focus' in client) {
          return client.focus();
        }
      }

      // 2) 같은 오리진 창이 하나라도 있으면 그 창을 재사용해 이동 후 포커스
      const reusable = clients.find((client) => client.url.startsWith(self.location.origin));
      if (reusable) {
        if ('navigate' in reusable) {
          await reusable.navigate(targetAbs);
        }
        if ('focus' in reusable) {
          return reusable.focus();
        }
      }

      // 3) 창이 없으면 새 창(PWA) 열기
      return self.clients.openWindow(targetAbs);
    })
  );
});

self.addEventListener('push', (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch {
    data = { title: 'ChessOK', body: event.data?.text?.() || '' };
  }
  const title = data.title || 'ChessOK';
  const tag = data.id
    ? `notif:${data.id}`
    : `${title}:${data.body || ''}:${data.url || ''}`;
  const options = {
    body: data.body || '',
    icon: '/static/images/icons/favicon.svg',
    badge: '/static/images/icons/favicon.svg',
    tag,
    renotify: false,
    data: data.url ? { url: data.url } : {},
  };
  event.waitUntil(self.registration.showNotification(title, options));
});
