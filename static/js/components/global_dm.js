(function() {
    'use strict';

    let currentUser = null;
    let pollTimer = null;
    let currentRoomUserId = null;
    let lastMessageCount = 0;
    let threadPollTimer = null;
    
    // DOM Elements
    const fabBtn = document.getElementById('global-dm-fab');
    const fabBadge = document.getElementById('global-dm-badge');
    const panel = document.getElementById('global-dm-panel');
    
    const threadsView = document.getElementById('global-dm-threads-view');
    const roomView = document.getElementById('global-dm-room-view');
    
    const closeBtn = document.getElementById('global-dm-close');
    const roomCloseBtn = document.getElementById('global-dm-room-close');
    const backBtn = document.getElementById('global-dm-back');
    
    const threadListEl = document.getElementById('global-dm-threads-list');
    
    const messagesEl = document.getElementById('global-dm-messages');
    const formEl = document.getElementById('global-dm-form');
    const inputEl = document.getElementById('global-dm-input');
    const roomTitle = document.getElementById('global-dm-room-title');
    const roomSubtitle = document.getElementById('global-dm-room-subtitle');

    if (!fabBtn || !panel) return;

    init();

    window.addEventListener('user:updated', (event) => {
        const user = event.detail?.user;
        if (user && !user.is_guest) {
            currentUser = user;
            fabBtn.style.display = 'flex';
            document.body.classList.remove('is-guest');
            startThreadPolling();
        } else {
            currentUser = null;
            fabBtn.style.display = 'none';
            document.body.classList.add('is-guest');
            stopPolling();
        }
    });

    // Custom Event Listener to open chat from outside
    window.addEventListener('global-dm:open-room', (event) => {
        openRoomFromExternal(event.detail || {});
    });

    bindEvents();

    async function init() {
        await ensureCurrentUser();
        if (currentUser) {
            fabBtn.style.display = 'flex';
            document.body.classList.remove('is-guest');
            startThreadPolling();
        } else {
            fabBtn.style.display = 'none';
            document.body.classList.add('is-guest');
        }
    }

    async function ensureCurrentUser() {
        if (currentUser) return currentUser;
        try {
            const me = await API.get('/accounts/me/');
            if (!me?.id || me?.is_guest) {
                currentUser = null;
                return null;
            }
            currentUser = me;
            return currentUser;
        } catch {
            currentUser = null;
            return null;
        }
    }

    async function openRoomFromExternal(detail) {
        if (!currentUser) {
            await ensureCurrentUser();
        }
        if (!currentUser) {
            Toast.error('로그인 시 가능합니다.');
            return;
        }
        const { userId, nickname } = detail;
        if (userId) {
            panel.classList.remove('hidden');
            fabBtn.classList.add('is-active');
            showRoomView(userId, nickname || '상대');
        }
    }

    function bindEvents() {
        fabBtn.addEventListener('click', () => {
            Utils?.Sounds?.unlock?.();
            const isHidden = panel.classList.contains('hidden');
            if (isHidden) {
                openPanel();
            } else {
                closePanel();
            }
        });

        closeBtn.addEventListener('click', closePanel);
        roomCloseBtn.addEventListener('click', closePanel);

        backBtn.addEventListener('click', () => {
            stopRoomPolling();
            showThreadsView();
        });

        formEl.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (!currentRoomUserId) return;
            const message = inputEl.value.trim();
            if (!message) return;
            Utils?.Sounds?.unlock?.();
            
            try {
                await API.post(`/accounts/messages/${currentRoomUserId}/`, { message });
                inputEl.value = '';
                await loadMessages(true);
                // Also trigger thread refresh
                loadThreads();
            } catch (error) {
                Toast.error(error.data?.detail || error.data?.message || '메시지 전송에 실패했습니다.');
            }
        });
    }

    function openPanel() {
        if (!currentUser) {
            Toast.error('로그인 시 가능합니다.');
            return;
        }
        panel.classList.remove('hidden');
        fabBtn.classList.add('is-active');
        if (currentRoomUserId) {
            showRoomView(currentRoomUserId);
        } else {
            showThreadsView();
        }
    }

    function closePanel() {
        panel.classList.add('hidden');
        fabBtn.classList.remove('is-active');
    }

    function showThreadsView() {
        threadsView.classList.remove('hidden');
        roomView.classList.add('hidden');
        currentRoomUserId = null;
        loadThreads();
    }

    function showRoomView(userId, nickname = '상대') {
        threadsView.classList.add('hidden');
        roomView.classList.remove('hidden');
        currentRoomUserId = userId;
        roomTitle.textContent = nickname;
        roomSubtitle.textContent = '';
        
        loadTargetInfo(userId);
        loadMessages(true);
        startRoomPolling();
    }

    // Thread List Logic
    async function loadThreads() {
        try {
            const [data, notifications] = await Promise.all([
                API.get('/accounts/messages/threads/', { limit: 20, offset: 0, no_count: 1 }),
                API.get('/notifications/', { limit: 100, offset: 0, no_count: 1 }),
            ]);
            
            const threads = data.results || [];
            const unreadMap = buildUnreadMap(notifications.results || []);
            
            updateGlobalBadge(unreadMap);

            if (!threads.length) {
                threadListEl.innerHTML = '<div class="global-dm-empty">대화가 없습니다. 새로운 대화를 시작해보세요.</div>';
                return;
            }

            threadListEl.innerHTML = threads.map(t => renderThreadItem(t, unreadMap)).join('');
            
            threadListEl.querySelectorAll('.global-dm-thread').forEach(item => {
                item.addEventListener('click', () => {
                    const uid = item.dataset.userId;
                    const name = item.dataset.nickname;
                    showRoomView(uid, name);
                });
            });

        } catch (e) {
            threadListEl.innerHTML = '<div class="global-dm-empty">목록을 불러오지 못했습니다.</div>';
        }
    }

    function buildUnreadMap(items) {
        return items
            .filter((item) => item.type === 'direct_message' && !item.is_read)
            .reduce((acc, item) => {
                const senderId = item.payload?.sender_id;
                if (!senderId) return acc;
                acc[senderId] = (acc[senderId] || 0) + 1;
                return acc;
            }, {});
    }

    function updateGlobalBadge(unreadMap) {
        const totalUnread = Object.values(unreadMap).reduce((a, b) => a + b, 0);
        if (totalUnread > 0) {
            fabBadge.textContent = totalUnread;
            fabBadge.classList.remove('hidden');
        } else {
            fabBadge.textContent = '0';
            fabBadge.classList.add('hidden');
        }
    }

    function renderThreadItem(thread, unreadMap) {
        const user = thread.other_user || {};
        const nickname = user.nickname || '알 수 없음';
        const avatar = user.avatar_url
            ? `<img src="${Utils.escapeHtml(user.avatar_url)}" alt="${Utils.escapeHtml(nickname)}">`
            : '<span class="avatar-placeholder">?</span>';
        const time = thread.last_message_at ? formatRelativeTimeShort(thread.last_message_at) : '';
        const message = thread.last_message || '대화를 시작해보세요.';
        const unreadCount = unreadMap[user.id] || 0;

        return `
            <div class="global-dm-thread" data-user-id="${user.id}" data-nickname="${Utils.escapeHtml(nickname)}">
                <div class="global-dm-thread-avatar">${avatar}</div>
                <div class="global-dm-thread-info">
                    <div class="global-dm-thread-name">${Utils.escapeHtml(nickname)}</div>
                    <div class="global-dm-thread-msg">${Utils.escapeHtml(message)}</div>
                </div>
                <div class="global-dm-thread-meta">
                    <div class="global-dm-thread-time">${time}</div>
                    ${unreadCount ? `<div class="global-dm-thread-badge">${unreadCount}</div>` : ''}
                </div>
            </div>
        `;
    }

    // Room Logic
    async function loadTargetInfo(userId) {
        try {
            const data = await API.get(`/accounts/users/${userId}/profile/`);
            const nickname = data?.nickname || data?.user?.nickname || '상대';
            const tier = data.stats?.rank_tier ?? data.user?.stats?.rank_tier ?? '-';
            roomTitle.textContent = nickname;
            roomSubtitle.textContent = tier;
        } catch {
            // ignore
        }
    }

    async function loadMessages(forceScroll = false) {
        if (!currentRoomUserId) return;
        try {
            const data = await API.get(`/accounts/messages/${currentRoomUserId}/`, { limit: 100, offset: 0, no_count: 1 });
            const items = data.results || [];
            
            if (!items.length) {
                messagesEl.innerHTML = '<div class="global-dm-empty">아직 메시지가 없습니다.</div>';
            } else {
                const reversedItems = items.slice().reverse();
                // To avoid flickering, check if we need a full re-render or just append. 
                // A simple approach is just re-render but manage scroll smartly.
                const shouldScroll = forceScroll || (messagesEl.scrollTop + messagesEl.clientHeight >= messagesEl.scrollHeight - 50);
                
                messagesEl.innerHTML = reversedItems.map(item => renderMessageItem(item)).join('');
                
                if (shouldScroll) {
                    messagesEl.scrollTop = messagesEl.scrollHeight;
                }

                if (data.count > lastMessageCount && reversedItems.length) {
                    const lastItem = reversedItems[reversedItems.length - 1];
                    if (lastItem.sender?.id !== currentUser?.id) {
                        Utils?.Sounds?.chat?.();
                    }
                }
            }
            lastMessageCount = data.count || 0;
            
            // Mark read if panel is open and focused
            if (!panel.classList.contains('hidden')) {
                markDirectMessageNotificationsRead(currentRoomUserId);
            }
        } catch (e) {
            console.error('Failed to load messages:', e);
            messagesEl.innerHTML = '<div class="global-dm-empty">메시지를 불러오지 못했습니다.</div>';
        }
    }

    function renderMessageItem(item) {
        const isMe = item.sender?.id === currentUser?.id;
        const time = formatTimeOnly(item.created_at);
        const avatar = !isMe
            ? (item.sender?.avatar_url
                ? `<img src="${Utils.escapeHtml(item.sender.avatar_url)}" alt="">`
                : '<span class="avatar-placeholder">?</span>')
            : '';
        return `
            <div class="global-dm-message ${isMe ? 'me' : 'other'}">
                ${!isMe ? `<div class="global-dm-message-avatar">${avatar}</div>` : ''}
                <div class="global-dm-message-content">
                    <div class="global-dm-message-text">${Utils.escapeHtml(item.message)}</div>
                    <div class="global-dm-message-time">${time}</div>
                </div>
            </div>
        `;
    }

    async function markDirectMessageNotificationsRead(userId) {
        try {
            const data = await API.get('/notifications/', { limit: 50, offset: 0, no_count: 1 });
            const ids = (data.results || [])
                .filter((item) => item.type === 'direct_message' && !item.is_read)
                .filter((item) => item.payload?.sender_id == userId)
                .map((item) => item.id);
            if (ids.length) {
                await API.post('/notifications/read/', { ids });
                loadThreads(); // update badge
            }
        } catch {
            // ignore
        }
    }

    // Polling
    function startThreadPolling() {
        if (threadPollTimer) clearInterval(threadPollTimer);
        loadThreads();
        threadPollTimer = setInterval(() => {
            if (document.hidden) return;
            loadThreads();
        }, 10000);
    }

    function startRoomPolling() {
        if (pollTimer) clearInterval(pollTimer);
        pollTimer = setInterval(() => {
            if (document.hidden) return;
            loadMessages();
        }, 3000);
    }

    function stopRoomPolling() {
        if (pollTimer) clearInterval(pollTimer);
        pollTimer = null;
    }

    function stopPolling() {
        if (threadPollTimer) clearInterval(threadPollTimer);
        threadPollTimer = null;
        stopRoomPolling();
    }

    // Formatters
    function formatTimeOnly(value) {
        if (!value) return '';
        const d = new Date(value);
        const hh = String(d.getHours()).padStart(2, '0');
        const mm = String(d.getMinutes()).padStart(2, '0');
        return `${hh}:${mm}`;
    }

    function formatRelativeTimeShort(dateString) {
        const date = new Date(dateString);
        const now = new Date();
        const diffMs = now - date;
        const diffSec = Math.floor(diffMs / 1000);
        const diffMin = Math.floor(diffSec / 60);
        const diffHour = Math.floor(diffMin / 60);

        if (diffSec < 60) return '방금';
        if (diffMin < 60) return `${diffMin}분`;
        if (diffHour < 24) return `${diffHour}시간`;
        
        const mm = String(date.getMonth() + 1).padStart(2, '0');
        const dd = String(date.getDate()).padStart(2, '0');
        return `${mm}/${dd}`;
    }

    window.addEventListener('beforeunload', stopPolling);
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden && currentUser) {
            loadThreads();
            if (currentRoomUserId) loadMessages();
        }
    });

})();
