(function() {
    'use strict';

    const ENDPOINT = '/accounts/presence/';
    const DEFAULT_ACTIVE_INTERVAL = 25000;
    const DEFAULT_HIDDEN_INTERVAL = 45000;
    const PRESENCE_SESSION_KEY = 'chessok_presence_scope_seed';

    function getScopeSeed() {
        let seed = sessionStorage.getItem(PRESENCE_SESSION_KEY);
        if (!seed) {
            seed = Math.random().toString(36).slice(2, 10);
            sessionStorage.setItem(PRESENCE_SESSION_KEY, seed);
        }
        return seed;
    }

    function buildScopeId(name) {
        return `${name}-${getScopeSeed()}`;
    }

    async function sendPresence(payload, options = {}) {
        const requestInit = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': window.CSRF_TOKEN || '',
            },
            credentials: 'same-origin',
            body: JSON.stringify(payload),
        };
        if (options.keepalive) {
            requestInit.keepalive = true;
        }
        try {
            await fetch(`/api${ENDPOINT}`, requestInit);
            return true;
        } catch {
            return false;
        }
    }

    function start(config = {}) {
        const status = config.status || 'online';
        const scopeId = config.scopeId || buildScopeId(status);
        const payload = {
            status,
            scope_id: scopeId,
        };
        if (config.roomId) payload.room_id = config.roomId;
        if (config.gameId) payload.game_id = config.gameId;

        const poller = Utils.createAdaptivePoller({
            callback: () => sendPresence(payload),
            activeInterval: config.activeInterval || DEFAULT_ACTIVE_INTERVAL,
            hiddenInterval: config.hiddenInterval || DEFAULT_HIDDEN_INTERVAL,
            enabled: () => true,
            immediate: false,
        });

        const clear = () => {
            sendPresence({ ...payload, active: false }, { keepalive: true });
        };

        sendPresence(payload);
        poller.start();
        window.addEventListener('pagehide', clear);

        return {
            stop() {
                poller.stop();
                window.removeEventListener('pagehide', clear);
                clear();
            },
            refresh() {
                return sendPresence(payload);
            },
        };
    }

    function autostart() {
        const body = document.body;
        if (!body) return null;
        if (body.dataset.authenticated !== 'true' || body.dataset.guest === 'true') {
            return null;
        }
        return start({ status: 'online', scopeId: buildScopeId('online') });
    }

    window.Presence = {
        start,
        autostart,
        buildScopeId,
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            window.__basePresenceController = autostart();
        }, { once: true });
    } else {
        window.__basePresenceController = autostart();
    }
})();
