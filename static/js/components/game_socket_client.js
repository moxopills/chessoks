(function() {
    'use strict';

    function buildUrl(roomId) {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        let wsUrl = `${protocol}//${window.location.host}/ws/chess/${roomId}/`;
        const guestToken = localStorage.getItem('guest_token');
        if (guestToken) {
            wsUrl += `?guest_token=${encodeURIComponent(guestToken)}`;
        }
        return wsUrl;
    }

    function connect({ roomId, onOpen, onMessage, onClose, onError }) {
        const socket = new WebSocket(buildUrl(roomId));

        socket.onopen = (event) => {
            onOpen?.(event, socket);
        };

        socket.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                onMessage?.(data, event, socket);
            } catch (error) {
                onError?.(error, socket);
            }
        };

        socket.onclose = (event) => {
            onClose?.(event, socket);
        };

        socket.onerror = (event) => {
            onError?.(event, socket);
        };

        return socket;
    }

    function sendJson(socket, payload) {
        if (!socket || socket.readyState !== WebSocket.OPEN) {
            return false;
        }
        socket.send(JSON.stringify(payload));
        return true;
    }

    window.GameSocketClient = {
        buildUrl,
        connect,
        sendJson,
    };
})();
