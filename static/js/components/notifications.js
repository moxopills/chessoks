(function() {
    'use strict';

    const state = {
        initialized: false,
        items: [],
        unreadCount: 0,
        socket: null,
    };

    function init() {
        if (state.initialized) return;
        state.initialized = true;

        const bell = document.getElementById('notification-bell');
        if (!bell) return;

        const listEl = document.getElementById('notification-list');
        const countEl = document.getElementById('notification-count');
        const markAllBtn = document.getElementById('mark-all-read');
        const dropdown = document.getElementById('notification-dropdown');

        markAllBtn?.addEventListener('click', async () => {
            const unreadIds = state.items.filter((item) => !item.is_read).map((item) => item.id);
            if (!unreadIds.length) return;
            try {
                await API.post('/notifications/read/', { ids: unreadIds });
                state.items = state.items.map((item) => ({ ...item, is_read: true }));
                state.unreadCount = 0;
                renderList(listEl, countEl);
            } catch (error) {
                Toast.error(error.data?.message || '알림 읽음 처리에 실패했습니다.');
            }
        });

        dropdown?.addEventListener('click', (event) => event.stopPropagation());

        loadInitial(listEl, countEl);
        connectSocket(listEl, countEl);
    }

    async function loadInitial(listEl, countEl) {
        try {
            const [listData, unreadData] = await Promise.all([
                API.get('/notifications/', { limit: 10, offset: 0 }),
                API.get('/notifications/unread/'),
            ]);
            state.items = listData.results || [];
            state.unreadCount = unreadData.count || 0;
            renderList(listEl, countEl);
        } catch (error) {
            // Silent fail: bell just stays empty for unauthenticated users.
        }
    }

    function renderList(listEl, countEl) {
        if (!listEl || !countEl) return;
        const unreadCount = state.items.filter((item) => !item.is_read).length;
        state.unreadCount = unreadCount;
        countEl.textContent = unreadCount;
        countEl.classList.toggle('hidden', unreadCount === 0);

        if (!state.items.length) {
            listEl.innerHTML = '<div class="notification-empty">새 알림이 없습니다</div>';
            return;
        }

        listEl.innerHTML = state.items.map((item) => {
            const createdAt = item.created_at ? Utils.formatRelativeTime(item.created_at) : '';
            const safeTitle = Utils.escapeHtml(item.title || '알림');
            const safeMessage = Utils.escapeHtml(item.message || '');
            return `
                <div class="notification-item ${item.is_read ? '' : 'unread'}" data-id="${item.id}">
                    <div class="notification-item-title">${safeTitle}</div>
                    <div class="notification-item-message">${safeMessage}</div>
                    <div class="notification-item-time">${createdAt}</div>
                </div>
            `;
        }).join('');

        listEl.querySelectorAll('.notification-item').forEach((itemEl) => {
            itemEl.addEventListener('click', async () => {
                const id = parseInt(itemEl.dataset.id, 10);
                if (!id) return;
                const item = state.items.find((entry) => entry.id === id);
                if (!item || item.is_read) return;
                try {
                    await API.post('/notifications/read/', { ids: [id] });
                    item.is_read = true;
                    renderList(listEl, countEl);
                    if (item.type === 'friend_request') {
                        window.location.href = '/friends/?tab=requests';
                        return;
                    }
                    if (item.type === 'rematch' && item.payload?.game_id) {
                        try {
                            const data = await API.post(`/chess/games/${item.payload.game_id}/rematch/`);
                            if (data.room_id) {
                                Toast.success('리매치가 시작됩니다.');
                                window.location.href = `/games/${data.room_id}/`;
                                return;
                            }
                        } catch {
                            Toast.error('리매치에 실패했습니다.');
                        }
                    }
                    if (item.payload?.room_id) {
                        const roomId = item.payload.room_id;
                        if (item.type === 'match_found' || item.type === 'rematch') {
                            window.location.href = `/games/${roomId}/`;
                        } else {
                            window.location.href = `/rooms/${roomId}/`;
                        }
                    }
                } catch (error) {
                    Toast.error(error.data?.message || '알림 읽음 처리에 실패했습니다.');
                }
            });
        });
    }

    function connectSocket(listEl, countEl) {
        const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
        const wsUrl = `${protocol}://${window.location.host}/ws/notifications/`;
        try {
            state.socket = new WebSocket(wsUrl);
        } catch {
            return;
        }

        state.socket.addEventListener('message', (event) => {
            try {
                const payload = JSON.parse(event.data);
                state.items.unshift(payload);
                state.items = state.items.slice(0, 20);
                renderList(listEl, countEl);
                if (payload.title || payload.message) {
                    Toast.info(payload.message || payload.title);
                }
            } catch {
                // ignore invalid payloads
            }
        });
    }

    window.Notifications = { init };
})();
