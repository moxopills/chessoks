(function() {
    'use strict';

    const STORAGE_KEY = 'chessok-push-enabled';
    let swRegistration = null;

    function hasPushSupport() {
        return 'serviceWorker' in navigator && 'Notification' in window && 'PushManager' in window;
    }

    function getPublicKey() {
        const meta = document.querySelector('meta[name="chessok-web-push-public-key"]');
        return (meta?.content || '').trim();
    }

    function urlBase64ToUint8Array(base64String) {
        const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
        const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
        const rawData = window.atob(base64);
        const outputArray = new Uint8Array(rawData.length);
        for (let i = 0; i < rawData.length; ++i) {
            outputArray[i] = rawData.charCodeAt(i);
        }
        return outputArray;
    }

    async function init() {
        if (!hasPushSupport()) return;

        try {
            swRegistration = await navigator.serviceWorker.register('/static/sw.js');
            window.__chessokSW = swRegistration;
        } catch {
            return;
        }

        const bell = document.getElementById('notification-bell');
        bell?.addEventListener('click', async () => {
            const granted = await ensurePermission();
            if (granted) {
                await ensureSubscription();
            }
        });

        const preferred = localStorage.getItem(STORAGE_KEY) === '1';
        if (preferred && Notification.permission === 'default') {
            const granted = await ensurePermission();
            if (granted) {
                await ensureSubscription();
            }
            return;
        }
        if (Notification.permission === 'granted') {
            await ensureSubscription();
        }
    }

    async function ensurePermission() {
        if (!('Notification' in window)) return false;
        if (Notification.permission === 'granted') return true;
        if (Notification.permission === 'denied') return false;
        const permission = await Notification.requestPermission();
        if (permission === 'granted') {
            localStorage.setItem(STORAGE_KEY, '1');
            return true;
        }
        return false;
    }

    async function ensureSubscription() {
        const publicKey = getPublicKey();
        if (!publicKey || !swRegistration?.pushManager) return false;

        let sub = await swRegistration.pushManager.getSubscription();
        if (!sub) {
            try {
                sub = await swRegistration.pushManager.subscribe({
                    userVisibleOnly: true,
                    applicationServerKey: urlBase64ToUint8Array(publicKey),
                });
            } catch {
                return false;
            }
        }
        return syncSubscription(sub);
    }

    async function syncSubscription(subscription) {
        if (!subscription) return false;
        const json = subscription.toJSON();
        const endpoint = json.endpoint;
        const p256dh = json.keys?.p256dh;
        const auth = json.keys?.auth;
        if (!endpoint || !p256dh || !auth) return false;
        try {
            await API.post('/notifications/push/subscribe/', {
                endpoint,
                p256dh,
                auth,
                user_agent: navigator.userAgent || '',
            });
            return true;
        } catch {
            return false;
        }
    }

    async function unsubscribe() {
        if (!swRegistration?.pushManager) return false;
        const sub = await swRegistration.pushManager.getSubscription();
        if (!sub) return true;
        const endpoint = sub.endpoint;
        try {
            await API.post('/notifications/push/unsubscribe/', { endpoint });
        } catch {
            // ignore server unsubscribe failure
        }
        try {
            await sub.unsubscribe();
        } catch {
            return false;
        }
        return true;
    }

    async function show(title, body, url = '/') {
        if (!('Notification' in window) || Notification.permission !== 'granted') return;
        const reg = swRegistration || window.__chessokSW;
        if (reg?.active) {
            reg.active.postMessage({ type: 'SHOW_NOTIFICATION', title, body, url });
            return;
        }
        new Notification(title, {
            body,
            icon: '/static/images/icons/favicon.svg',
        });
    }

    window.ChessokPush = { ensurePermission, ensureSubscription, unsubscribe, show };
    init();
})();
