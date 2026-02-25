(function() {
    'use strict';

    const STORAGE_KEY = 'chessok-push-enabled';

    async function init() {
        if (!('serviceWorker' in navigator) || !('Notification' in window)) return;

        try {
            const reg = await navigator.serviceWorker.register('/static/sw.js');
            window.__chessokSW = reg;
        } catch {
            return;
        }

        const bell = document.getElementById('notification-bell');
        bell?.addEventListener('click', async () => {
            await ensurePermission();
        });

        const preferred = localStorage.getItem(STORAGE_KEY) === '1';
        if (preferred && Notification.permission === 'default') {
            await ensurePermission();
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

    async function show(title, body, url = '/') {
        if (!('Notification' in window) || Notification.permission !== 'granted') return;
        const reg = window.__chessokSW;
        if (reg?.active) {
            reg.active.postMessage({ type: 'SHOW_NOTIFICATION', title, body, url });
            return;
        }
        new Notification(title, {
            body,
            icon: '/static/images/icons/favicon.svg',
        });
    }

    window.ChessokPush = { ensurePermission, show };
    init();
})();
