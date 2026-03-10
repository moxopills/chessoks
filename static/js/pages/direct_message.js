(function() {
    'use strict';

    const messagesEl = document.getElementById('dm-messages');
    const formEl = document.getElementById('dm-form');
    const inputEl = document.getElementById('dm-input');
    const titleEl = document.getElementById('dm-title');
    const subtitleEl = document.getElementById('dm-subtitle');
    const backBtn = document.getElementById('dm-back');

    const targetUserId = parseInt(Utils.getPathParam(/\/messages\/(\d+)/), 10);
    let currentUser = null;
    let pollTimer = null;
    let lastCount = 0;
    let lastLatestId = 0;

    init();

    async function init() {
        if (!targetUserId) {
            Toast.error('잘못된 접근입니다.');
            window.location.href = '/friends/';
            return;
        }
        try {
            currentUser = await API.get('/accounts/me/');
        } catch {
            Toast.error('로그인 시 가능합니다.');
            window.location.href = '/login/';
            return;
        }
        await loadTargetInfo();
        await loadMessages(true);
        await markDirectMessageNotificationsRead();
        bindEvents();
        startPolling();
    }

    function bindEvents() {
        backBtn?.addEventListener('click', () => window.history.back());
        inputEl.addEventListener('focus', () => {
            inputEl.value = '';
        });
        formEl.addEventListener('submit', async (e) => {
            e.preventDefault();
            const message = inputEl.value.trim();
            if (!message) return;
            try {
                const created = await API.post(`/accounts/messages/${targetUserId}/`, { message });
                inputEl.value = '';
                appendMessage(created, true);
            } catch (error) {
                Toast.error(error.data?.detail || error.data?.message || '전송에 실패했습니다.');
            }
        });
    }

    async function loadTargetInfo() {
        try {
            const data = await API.get(`/accounts/users/${targetUserId}/profile/`);
            const nickname = data?.nickname || data?.user?.nickname || '상대';
            const rating = data.stats?.rating
                ?? data.user?.stats?.rating
                ?? data.rating
                ?? data.user?.rating
                ?? '-';
            const tier = data.stats?.rank_tier
                ?? data.user?.stats?.rank_tier
                ?? data.rank_tier
                ?? data.user?.rank_tier
                ?? '-';
            titleEl.textContent = `${nickname}님과의 채팅`;
            subtitleEl.textContent = `레이팅 ${rating} · ${tier}`;
        } catch {
            titleEl.textContent = '상대님과의 채팅';
        }
    }

    async function loadMessages(forceScroll = false) {
        try {
            const data = await API.get(`/accounts/messages/${targetUserId}/`, { limit: 200, offset: 0, no_count: 1 });
            const items = data.results || [];
            const reversedItems = items.slice().reverse();
            const latestId = reversedItems.length ? (reversedItems[reversedItems.length - 1]?.id || 0) : 0;
            const newCount = data.count || 0;
            const changed = latestId !== lastLatestId || newCount !== lastCount;

            if (!changed && !forceScroll) {
                return;
            }

            renderMessages(reversedItems);
            messagesEl.scrollTop = messagesEl.scrollHeight;
            if (newCount > lastCount && reversedItems.length) {
                const lastItem = reversedItems[reversedItems.length - 1];
                if (lastItem.sender?.id !== currentUser.id) {
                    Utils?.Sounds?.chat?.();
                }
            }
            lastCount = newCount;
            lastLatestId = latestId;
        } catch (error) {
            renderEmpty('메시지를 불러오지 못했습니다.');
        }
    }

    function appendMessage(item, forceScroll = false) {
        if (!item || !item.id) {
            return;
        }
        const currentCount = messagesEl.querySelectorAll('.dm-message').length;
        if (!currentCount || messagesEl.querySelector('.history-empty')) {
            renderMessages([item]);
        } else {
            messagesEl.appendChild(renderSingleMessage(item));
        }
        if (forceScroll) {
            messagesEl.scrollTop = messagesEl.scrollHeight;
        }
        lastCount += 1;
        lastLatestId = item.id;
    }

    function renderMessages(items) {
        if (!items.length) {
            renderEmpty('아직 메시지가 없습니다.');
            return;
        }
        const fragment = document.createDocumentFragment();
        items.forEach((item) => fragment.appendChild(renderSingleMessage(item)));
        messagesEl.replaceChildren(fragment);
    }

    function renderEmpty(message) {
        const empty = document.createElement('div');
        empty.className = 'history-empty';
        empty.textContent = message;
        messagesEl.replaceChildren(empty);
    }

    function renderSingleMessage(item) {
        const isMe = item.sender?.id === currentUser.id;
        const time = formatTime(item.created_at);
        const row = document.createElement('div');
        row.className = `dm-message ${isMe ? 'me' : 'other'}`;

        if (!isMe) {
            const avatarWrap = document.createElement('div');
            avatarWrap.className = 'dm-avatar';
            Utils.setAvatar(avatarWrap, {
                url: item.sender?.avatar_url || '',
                alt: item.sender?.nickname || '',
                placeholder: '?',
                placeholderClass: 'avatar-placeholder',
            });
            row.appendChild(avatarWrap);
        }

        const content = document.createElement('div');
        content.className = 'dm-content';

        const text = document.createElement('div');
        text.className = 'dm-message-text';
        text.textContent = item.message || '';

        const timeEl = document.createElement('div');
        timeEl.className = 'dm-message-time';
        timeEl.textContent = time;

        content.append(text, timeEl);
        row.appendChild(content);
        return row;
    }

    function startPolling() {
        if (pollTimer) clearInterval(pollTimer);
        pollTimer = setInterval(() => {
            if (document.hidden) return;
            loadMessages();
        }, 4000);
        window.addEventListener('beforeunload', () => pollTimer && clearInterval(pollTimer));
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden) loadMessages();
        });
    }

    async function markDirectMessageNotificationsRead() {
        if (window.Notifications?.markDirectMessageRead) {
            window.Notifications.markDirectMessageRead({ senderId: targetUserId });
            return;
        }
        try {
            const data = await API.get('/notifications/', { limit: 50, offset: 0, no_count: 1 });
            const ids = (data.results || [])
                .filter((item) => item.type === 'direct_message' && !item.is_read)
                .filter((item) => item.payload?.sender_id === targetUserId)
                .map((item) => item.id);
            if (ids.length) {
                await API.post('/notifications/read/', { ids });
            }
        } catch {
            // ignore
        }
    }

    function formatTime(value) {
        if (!value) return '';
        const d = new Date(value);
        const hh = String(d.getHours()).padStart(2, '0');
        const mm = String(d.getMinutes()).padStart(2, '0');
        return `${hh}:${mm}`;
    }
})();
