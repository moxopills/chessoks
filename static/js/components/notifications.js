(function() {
    'use strict';

    const state = {
        initialized: false,
        items: [],
        unreadCount: 0,
        socket: null,
        noticeSoundReadyAt: 0,
    };

    function init() {
        if (state.initialized) return;
        state.initialized = true;

        const bell = document.getElementById('notification-bell');
        if (!bell) return;

        const listEl = document.getElementById('notification-list');
        const countEl = document.getElementById('notification-count');
        const markAllBtn = document.getElementById('mark-all-read');
        const messageBadge = document.getElementById('message-count');
        const messageLink = document.getElementById('message-link');
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
        setupGlobalNoticeModal();

        messageLink?.addEventListener('click', () => {
            if (messageBadge) {
                messageBadge.textContent = '0';
                messageBadge.classList.add('hidden');
            }
        });

        state.noticeSoundReadyAt = Date.now() + 2000;
        loadInitial(listEl, countEl, messageBadge);
        connectSocket(listEl, countEl, messageBadge);
    }

    async function loadInitial(listEl, countEl, messageBadge) {
        try {
            const [listData, unreadData] = await Promise.all([
                API.get('/notifications/', { limit: 10, offset: 0, no_count: 1 }),
                API.get('/notifications/unread/'),
            ]);
            state.items = listData.results || [];
            state.unreadCount = unreadData.count || 0;
            renderList(listEl, countEl);
            updateMessageBadge(messageBadge);
            await openInviteFromQueryIfPresent();
        } catch (error) {
            // Silent fail: bell just stays empty for unauthenticated users.
        }
    }

    async function openInviteFromQueryIfPresent() {
        const params = new URLSearchParams(window.location.search);
        const inviteId = parseInt(params.get('invite_id'), 10);
        if (!inviteId) return;

        const inviteNotification = state.items.find(
            (item) =>
                item.type === 'game_invite' &&
                Number(item.payload?.invite_id) === inviteId
        );
        if (!inviteNotification) return;

        try {
            if (!inviteNotification.is_read) {
                await API.post('/notifications/read/', { ids: [inviteNotification.id] });
                inviteNotification.is_read = true;
                const countEl = document.getElementById('notification-count');
                renderList(document.getElementById('notification-list'), countEl);
            }
        } catch {
            // ignore mark-read failure
        }

        openGameInviteModal({
            payload: inviteNotification.payload || {},
            title: inviteNotification.title,
            message: inviteNotification.message,
        });

        params.delete('invite_id');
        const query = params.toString();
        const newUrl = `${window.location.pathname}${query ? `?${query}` : ''}${window.location.hash || ''}`;
        window.history.replaceState({}, '', newUrl);
    }

    function renderList(listEl, countEl) {
        if (!listEl || !countEl) return;
        const visibleItems = state.items.filter((item) => item.type !== 'direct_message');
        const unreadCount = visibleItems.filter((item) => !item.is_read).length;
        state.unreadCount = unreadCount;
        countEl.textContent = unreadCount;
        countEl.classList.toggle('hidden', unreadCount === 0);
        updateMessageBadge(document.getElementById('message-count'));

        if (!visibleItems.length) {
            listEl.innerHTML = '<div class="notification-empty">새 알림이 없습니다</div>';
            return;
        }

        listEl.innerHTML = visibleItems.map((item) => {
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
                    if (item.type === 'game_invite') {
                        openGameInviteModal({
                            payload: item.payload || {},
                            title: item.title,
                            message: item.message,
                        });
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

    function connectSocket(listEl, countEl, messageBadge) {
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
                if (payload?.type === 'account_suspended') {
                    const message = payload.message || '정지된 계정입니다.';
                    Toast.error(message);
                    forceLogout(message);
                    return;
                }
                if (payload?.type === 'admin_notice') {
                    openGlobalNotice(payload);
                    if (Date.now() > state.noticeSoundReadyAt) {
                        Utils?.Sounds?.notice?.();
                    }
                    if (document.hidden) {
                        ChessokPush?.show?.(payload.title || '공지', payload.message || '', '/');
                    }
                }
                if (payload?.type === 'game_invite') {
                    openGameInviteModal(payload);
                    if (Date.now() > state.noticeSoundReadyAt) {
                        Utils?.Sounds?.notice?.();
                    }
                    if (document.hidden) {
                        ChessokPush?.show?.('게임 초대', payload.message || '게임 초대가 도착했습니다.', '/');
                    }
                    return; // Don't show toast for invite
                }
                state.items = [payload, ...state.items].slice(0, 20);
                renderList(listEl, countEl);
                updateMessageBadge(messageBadge);
                if (payload.title || payload.message) {
                    Toast.info(payload.message || payload.title);
                }
                if (document.hidden && (payload.title || payload.message)) {
                    const targetUrl = payload.payload?.room_id
                        ? `/rooms/${payload.payload.room_id}/`
                        : '/';
                    ChessokPush?.show?.(payload.title || '알림', payload.message || '', targetUrl);
                }
            } catch {
                // ignore invalid payloads
            }
        });
    }

    function updateMessageBadge(messageBadge) {
        if (!messageBadge) return;
        const dmCount = state.items.filter(
            (item) => item.type === 'direct_message' && !item.is_read
        ).length;
        messageBadge.textContent = dmCount;
        messageBadge.classList.toggle('hidden', dmCount === 0);
    }

    async function markDirectMessageRead({ senderId = null, threadId = null } = {}) {
        if (!state.initialized) init();
        const messageBadge = document.getElementById('message-count');
        const ids = state.items
            .filter((item) => item.type === 'direct_message' && !item.is_read)
            .filter((item) => {
                if (!senderId && !threadId) return true;
                if (senderId && item.payload?.sender_id === senderId) return true;
                if (threadId && item.payload?.thread_id === threadId) return true;
                return false;
            })
            .map((item) => item.id);
        if (!ids.length) {
            updateMessageBadge(messageBadge);
            return;
        }
        try {
            await API.post('/notifications/read/', { ids });
            state.items = state.items.map((item) =>
                ids.includes(item.id) ? { ...item, is_read: true } : item
            );
            updateMessageBadge(messageBadge);
        } catch {
            // ignore
        }
    }

    async function forceLogout(message) {
        try {
            await API.post('/accounts/logout/', {});
        } catch {
            // ignore
        }
        const encoded = encodeURIComponent(message || '정지된 계정입니다.');
        window.location.href = `/login/?reason=${encoded}`;
    }

    function setupGlobalNoticeModal() {
        const modal = document.getElementById('global-notice-modal');
        const closeBtn = document.getElementById('global-notice-close');
        closeBtn?.addEventListener('click', () => modal?.classList.add('hidden'));
        modal?.addEventListener('click', (event) => {
            if (event.target === modal) modal.classList.add('hidden');
        });
    }

    function openGlobalNotice(payload) {
        const modal = document.getElementById('global-notice-modal');
        const titleEl = document.getElementById('global-notice-title');
        const messageEl = document.getElementById('global-notice-message');
        if (!modal || !messageEl || !titleEl) return;
        const title = payload?.title || '공지';
        const message = payload?.message || '';
        titleEl.textContent = `📣 ${title}`;
        messageEl.textContent = message;
        modal.classList.remove('hidden');
    }

    function openGameInviteModal(payload) {
        const modal = document.getElementById('game-invite-modal');
        const avatarEl = document.getElementById('invite-avatar');
        const nicknameEl = document.getElementById('invite-nickname');
        const ratingEl = document.getElementById('invite-rating');
        const timeLimitEl = document.getElementById('invite-time-limit');
        const acceptBtn = document.getElementById('invite-accept');
        const declineBtn = document.getElementById('invite-decline');

        if (!modal || !acceptBtn || !declineBtn) return;

        const inviteId = payload.payload?.invite_id;
        const nickname = payload.payload?.from_user_nickname || '알 수 없음';
        const avatar = payload.payload?.from_user_avatar;
        const rating = payload.payload?.from_user_rating || 1500;
        const timeLimit = payload.payload?.time_limit || 10;

        if (avatarEl) {
            avatarEl.innerHTML = avatar
                ? `<img src="${Utils.escapeHtml(avatar)}" alt="${Utils.escapeHtml(nickname)}">`
                : '👤';
        }
        if (nicknameEl) nicknameEl.textContent = nickname;
        if (ratingEl) ratingEl.textContent = `레이팅: ${rating}`;
        if (timeLimitEl) timeLimitEl.textContent = `시간 제한: ${timeLimit}분`;

        // Remove old listeners
        const newAcceptBtn = acceptBtn.cloneNode(true);
        const newDeclineBtn = declineBtn.cloneNode(true);
        acceptBtn.parentNode.replaceChild(newAcceptBtn, acceptBtn);
        declineBtn.parentNode.replaceChild(newDeclineBtn, declineBtn);
        newAcceptBtn.disabled = false;
        newDeclineBtn.disabled = false;

        newAcceptBtn.addEventListener('click', async () => {
            newAcceptBtn.disabled = true;
            newDeclineBtn.disabled = true;
            try {
                const result = await API.post(`/chess/invite/${inviteId}/accept/`);
                modal.classList.add('hidden');
                Toast.success('초대를 수락했습니다.');
                if (result.room_id) {
                    window.location.href = `/rooms/${result.room_id}/`;
                }
            } catch (error) {
                Toast.error(extractErrorMessage(error, '초대 수락에 실패했습니다.'));
                newAcceptBtn.disabled = false;
                newDeclineBtn.disabled = false;
            }
        });

        newDeclineBtn.addEventListener('click', async () => {
            newAcceptBtn.disabled = true;
            newDeclineBtn.disabled = true;
            try {
                await API.post(`/chess/invite/${inviteId}/decline/`);
                modal.classList.add('hidden');
                Toast.info('초대를 거절했습니다.');
            } catch (error) {
                Toast.error(extractErrorMessage(error, '초대 거절에 실패했습니다.'));
                newAcceptBtn.disabled = false;
                newDeclineBtn.disabled = false;
            }
        });

        modal.classList.remove('hidden');
    }

    async function sendGameInvite(userId, timeLimit = 10, roomId = null) {
        try {
            const payload = { user_id: userId, time_limit: timeLimit };
            if (roomId) payload.room_id = roomId;
            await API.post('/chess/invite/', payload);
            Toast.success('초대를 보냈습니다.');
            return true;
        } catch (error) {
            Toast.error(extractErrorMessage(error, '초대 전송에 실패했습니다.'));
            return false;
        }
    }

    function extractErrorMessage(error, fallback) {
        let msg = error?.data?.error?.message || error?.data?.detail || error?.data?.message;
        if (Array.isArray(msg)) msg = msg[0];
        if (msg && typeof msg === 'object') {
            msg = msg.string || msg.message || Object.values(msg)[0];
            if (Array.isArray(msg)) msg = msg[0];
        }
        if (typeof msg === 'string') {
            const m = msg.match(/^\[?ErrorDetail\(string='(.+?)',\s*code='[^']+'\)\]?$/);
            if (m?.[1]) msg = m[1];
        }
        return typeof msg === 'string' && msg.trim() ? msg.trim() : fallback;
    }

    window.Notifications = { init, markDirectMessageRead, sendGameInvite };
})();
