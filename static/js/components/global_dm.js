(function() {
    'use strict';

    function isGamePage() {
        return /^\/games\/\d+(?:\/spectate)?\/?$/.test(window.location.pathname);
    }
    function isMobileLobbyPage() {
        const isLobbyPath = window.location.pathname === '/' || window.location.pathname === '/lobby/';
        return isLobbyPath && window.innerWidth <= 768;
    }

    let currentUser = null;
    let pollTimer = null;
    let currentRoomUserId = null;
    let lastMessageCount = 0;
    let threadPollTimer = null;
    let lobbyChatMoved = false;
    
    // DOM Elements
    const fabBtn = document.getElementById('global-dm-fab');
    const fabBadge = document.getElementById('global-dm-badge');
    const panel = document.getElementById('global-dm-panel');
    
    const threadsView = document.getElementById('global-dm-threads-view');
    const lobbyView = document.getElementById('global-dm-lobby-view');
    const roomView = document.getElementById('global-dm-room-view');
    
    const closeBtn = document.getElementById('global-dm-close');
    const lobbyCloseBtn = document.getElementById('global-dm-lobby-close');
    const roomCloseBtn = document.getElementById('global-dm-room-close');
    const backBtn = document.getElementById('global-dm-back');
    
    const threadListEl = document.getElementById('global-dm-threads-list');
    const lobbySlot = document.getElementById('global-dm-lobby-slot');
    const tabs = document.getElementById('global-dm-tabs');
    const tabsMirror = document.getElementById('global-dm-tabs-mirror');
    const tabLobby = document.getElementById('global-dm-tab-lobby');
    const tabDirect = document.getElementById('global-dm-tab-direct');
    const tabLobbyMirror = document.getElementById('global-dm-tab-lobby-mirror');
    const tabDirectMirror = document.getElementById('global-dm-tab-direct-mirror');
    
    const messagesEl = document.getElementById('global-dm-messages');
    const formEl = document.getElementById('global-dm-form');
    const inputEl = document.getElementById('global-dm-input');
    const roomTitle = document.getElementById('global-dm-room-title');
    const roomSubtitle = document.getElementById('global-dm-room-subtitle');
    const lobbyChatContainer = document.getElementById('lobby-chat');
    const lobbyChatSection = document.querySelector('.lobby-chat-section');

    if (!fabBtn || !panel) return;

    init();

    window.addEventListener('user:updated', (event) => {
        const user = event.detail?.user;
        if (isGamePage()) {
            currentUser = user && !user.is_guest ? user : null;
            fabBtn.style.display = 'none';
            panel.classList.add('hidden');
            fabBtn.classList.remove('is-active');
            return;
        }
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
    window.addEventListener('global-dm:open-panel', async () => {
        if (!currentUser) {
            await ensureCurrentUser();
        }
        if (!currentUser) {
            Toast.error('로그인 시 가능합니다.');
            return;
        }
        openPanel();
    });

    bindEvents();

    async function init() {
        if (isGamePage()) {
            fabBtn.style.display = 'none';
            panel.classList.add('hidden');
            return;
        }
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
        lobbyCloseBtn?.addEventListener('click', closePanel);
        roomCloseBtn.addEventListener('click', closePanel);

        backBtn.addEventListener('click', () => {
            stopRoomPolling();
            showThreadsView();
        });
        tabLobby?.addEventListener('click', showLobbyView);
        tabDirect?.addEventListener('click', showThreadsView);
        tabLobbyMirror?.addEventListener('click', showLobbyView);
        tabDirectMirror?.addEventListener('click', showThreadsView);

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

        // Emoji buttons logic
        panel.querySelectorAll('.emoji-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const emoji = btn.textContent;
                inputEl.value += emoji;
                inputEl.focus();
                Utils?.Sounds?.unlock?.();
            });
        });
    }

    function openPanel() {
        if (isGamePage()) return;
        if (!currentUser) {
            Toast.error('로그인 시 가능합니다.');
            return;
        }
        panel.classList.remove('hidden');
        fabBtn.classList.add('is-active');
        fabBtn.classList.add('is-panel-open');
        syncLobbyTabsVisibility();
        if (currentRoomUserId) {
            showRoomView(currentRoomUserId);
        } else if (isMobileLobbyPage() && lobbyChatContainer && lobbySlot) {
            showLobbyView();
        } else {
            showThreadsView();
        }
    }

    function closePanel() {
        restoreLobbyChatContainer();
        panel.classList.add('hidden');
        fabBtn.classList.remove('is-active');
        fabBtn.classList.remove('is-panel-open');
    }

    function showThreadsView() {
        threadsView.classList.remove('hidden');
        lobbyView?.classList.add('hidden');
        roomView.classList.add('hidden');
        currentRoomUserId = null;
        setTabActive('direct');
        loadThreads();
    }

    function showLobbyView() {
        if (!isMobileLobbyPage() || !lobbyChatContainer || !lobbySlot || !lobbyView) {
            showThreadsView();
            return;
        }
        moveLobbyChatContainer();
        threadsView.classList.add('hidden');
        roomView.classList.add('hidden');
        lobbyView.classList.remove('hidden');
        currentRoomUserId = null;
        setTabActive('lobby');
    }

    async function showRoomView(userId, nickname = '상대') {
        if (!currentUser) {
            await ensureCurrentUser();
        }
        threadsView.classList.add('hidden');
        lobbyView?.classList.add('hidden');
        roomView.classList.remove('hidden');
        currentRoomUserId = userId;
        setTabActive('direct');
        roomTitle.textContent = nickname;
        roomSubtitle.textContent = '';
        
        loadTargetInfo(userId);
        loadMessages(true);
        startRoomPolling();
    }

    function syncLobbyTabsVisibility() {
        const enabled = isMobileLobbyPage() && !!lobbyChatContainer && !!lobbySlot;
        tabs?.classList.toggle('hidden', !enabled);
        tabsMirror?.classList.toggle('hidden', !enabled);
        if (!enabled) {
            restoreLobbyChatContainer();
            setTabActive('direct');
        }
    }

    function setTabActive(type) {
        const lobbyActive = type === 'lobby';
        tabLobby?.classList.toggle('is-active', lobbyActive);
        tabLobbyMirror?.classList.toggle('is-active', lobbyActive);
        tabDirect?.classList.toggle('is-active', !lobbyActive);
        tabDirectMirror?.classList.toggle('is-active', !lobbyActive);
    }

    function moveLobbyChatContainer() {
        if (lobbyChatMoved || !lobbyChatContainer || !lobbySlot) return;
        lobbySlot.appendChild(lobbyChatContainer);
        lobbyChatMoved = true;
        lobbyChatSection?.classList.add('is-hidden');
    }

    function restoreLobbyChatContainer() {
        if (!lobbyChatMoved || !lobbyChatContainer || !lobbyChatSection) return;
        lobbyChatSection.appendChild(lobbyChatContainer);
        lobbyChatMoved = false;
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
                setThreadListEmpty('대화가 없습니다. 새로운 대화를 시작해보세요.');
                return;
            }

            const fragment = document.createDocumentFragment();
            threads.forEach((thread) => {
                fragment.appendChild(renderThreadItem(thread, unreadMap));
            });
            threadListEl.replaceChildren(fragment);

        } catch (e) {
            setThreadListEmpty('목록을 불러오지 못했습니다.');
        }
    }

    function setThreadListEmpty(message) {
        const empty = document.createElement('div');
        empty.className = 'global-dm-empty';
        empty.textContent = message;
        threadListEl.replaceChildren(empty);
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
        const time = thread.last_message_at ? formatRelativeTimeShort(thread.last_message_at) : '';
        const message = thread.last_message || '대화를 시작해보세요.';
        const unreadCount = unreadMap[user.id] || 0;
        const row = document.createElement('div');
        row.className = 'global-dm-thread';
        row.dataset.userId = String(user.id || '');
        row.dataset.nickname = nickname;
        row.addEventListener('click', () => {
            showRoomView(user.id, nickname);
        });

        const avatarWrap = document.createElement('div');
        avatarWrap.className = 'global-dm-thread-avatar';
        Utils.setAvatar(avatarWrap, {
            url: user.avatar_url || '',
            alt: nickname,
            placeholder: '?',
            placeholderClass: 'avatar-placeholder',
        });

        const info = document.createElement('div');
        info.className = 'global-dm-thread-info';
        const nameEl = document.createElement('div');
        nameEl.className = 'global-dm-thread-name';
        nameEl.textContent = nickname;
        const msgEl = document.createElement('div');
        msgEl.className = 'global-dm-thread-msg';
        msgEl.textContent = message;
        info.append(nameEl, msgEl);

        const meta = document.createElement('div');
        meta.className = 'global-dm-thread-meta';
        const timeEl = document.createElement('div');
        timeEl.className = 'global-dm-thread-time';
        timeEl.textContent = time;
        meta.appendChild(timeEl);
        if (unreadCount) {
            const badge = document.createElement('div');
            badge.className = 'global-dm-thread-badge';
            badge.textContent = String(unreadCount);
            meta.appendChild(badge);
        }

        row.append(avatarWrap, info, meta);
        return row;
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
        if (!currentUser) await ensureCurrentUser();

        try {
            const data = await API.get(`/accounts/messages/${currentRoomUserId}/`, { limit: 100, offset: 0, no_count: 1 });
            const items = data.results || [];
            
            if (!items.length) {
                setMessagesEmpty('아직 메시지가 없습니다.');
            } else {
                const reversedItems = items.slice().reverse();
                // To avoid flickering, check if we need a full re-render or just append. 
                // A simple approach is just re-render but manage scroll smartly.
                const shouldScroll = forceScroll || (messagesEl.scrollTop + messagesEl.clientHeight >= messagesEl.scrollHeight - 50);
                
                const fragment = document.createDocumentFragment();
                reversedItems.forEach((item) => {
                    fragment.appendChild(renderMessageItem(item));
                });
                messagesEl.replaceChildren(fragment);
                
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
            setMessagesEmpty('메시지를 불러오지 못했습니다.');
        }
    }

    function setMessagesEmpty(message) {
        const empty = document.createElement('div');
        empty.className = 'global-dm-empty';
        empty.textContent = message;
        messagesEl.replaceChildren(empty);
    }

    function renderMessageItem(item) {
        const isMe = currentUser && item.sender?.id === currentUser.id;
        const time = formatTimeOnly(item.created_at);
        const messageText = item.message || '';
        const emojiOnlyClass = isEmojiOnly(item.message || '') ? ' emoji-only' : '';
        const row = document.createElement('div');
        row.className = `global-dm-message ${isMe ? 'me' : 'other'}`;

        if (!isMe) {
            const avatarWrap = document.createElement('div');
            avatarWrap.className = 'global-dm-message-avatar';
            Utils.setAvatar(avatarWrap, {
                url: item.sender?.avatar_url || '',
                alt: item.sender?.nickname || '',
                placeholder: '?',
                placeholderClass: 'avatar-placeholder',
            });
            row.appendChild(avatarWrap);
        }

        const content = document.createElement('div');
        content.className = 'global-dm-message-content';

        const text = document.createElement('div');
        text.className = `global-dm-message-text${emojiOnlyClass}`;
        text.textContent = messageText;

        const timeEl = document.createElement('div');
        timeEl.className = 'global-dm-message-time';
        timeEl.textContent = time;

        content.append(text, timeEl);
        row.appendChild(content);
        return row;
    }

    function isEmojiOnly(text) {
        if (!text || typeof text !== 'string') return false;
        try {
            const compact = text.replace(/\s+/g, '');
            return compact.length > 0 && /^[\p{Extended_Pictographic}\uFE0F\u200D]+$/u.test(compact);
        } catch {
            return false;
        }
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
    window.addEventListener('resize', () => {
        syncLobbyTabsVisibility();
        if (!isMobileLobbyPage()) {
            restoreLobbyChatContainer();
            if (!panel.classList.contains('hidden') && lobbyView && !lobbyView.classList.contains('hidden')) {
                showThreadsView();
            }
        }
    });
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden && currentUser) {
            loadThreads();
            if (currentRoomUserId) loadMessages();
        }
    });

})();
