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
    let roomPoller = null;
    let groupPoller = null;
    let currentRoomUserId = null;
    let currentGuildId = null;
    let currentPartyId = null;
    let lastMessageCount = 0;
    let guildSummaryCache = null;
    let partySummaryCache = null;
    let guildSummaryLoadedAt = 0;
    let partySummaryLoadedAt = 0;
    let threadPoller = null;
    let lobbyChatMoved = false;
    const SUMMARY_CACHE_TTL = 30000;
    const messageRenderState = {
        direct: { signature: '', ids: [] },
        guild: { signature: '', ids: [] },
        party: { signature: '', ids: [] },
    };
    
    // DOM Elements
    const fabBtn = document.getElementById('global-dm-fab');
    const fabBadge = document.getElementById('global-dm-badge');
    const panel = document.getElementById('global-dm-panel');
    
    const threadsView = document.getElementById('global-dm-threads-view');
    const lobbyView = document.getElementById('global-dm-lobby-view');
    const guildView = document.getElementById('global-dm-guild-view');
    const partyView = document.getElementById('global-dm-party-view');
    const roomView = document.getElementById('global-dm-room-view');
    
    const closeBtn = document.getElementById('global-dm-close');
    const lobbyCloseBtn = document.getElementById('global-dm-lobby-close');
    const guildBackBtn = document.getElementById('global-dm-guild-back');
    const guildCloseBtn = document.getElementById('global-dm-guild-close');
    const partyBackBtn = document.getElementById('global-dm-party-back');
    const partyCloseBtn = document.getElementById('global-dm-party-close');
    const roomCloseBtn = document.getElementById('global-dm-room-close');
    const backBtn = document.getElementById('global-dm-back');
    
    const threadListEl = document.getElementById('global-dm-threads-list');
    const lobbySlot = document.getElementById('global-dm-lobby-slot');
    const tabs = document.getElementById('global-dm-tabs');
    const tabsMirror = document.getElementById('global-dm-tabs-mirror');
    const tabLobby = document.getElementById('global-dm-tab-lobby');
    const tabDirect = document.getElementById('global-dm-tab-direct');
    const tabGuild = document.getElementById('global-dm-tab-guild');
    const tabParty = document.getElementById('global-dm-tab-party');
    const tabLobbyMirror = document.getElementById('global-dm-tab-lobby-mirror');
    const tabDirectMirror = document.getElementById('global-dm-tab-direct-mirror');
    const tabGuildMirror = document.getElementById('global-dm-tab-guild-mirror');
    const tabPartyMirror = document.getElementById('global-dm-tab-party-mirror');
    
    const messagesEl = document.getElementById('global-dm-messages');
    const formEl = document.getElementById('global-dm-form');
    const inputEl = document.getElementById('global-dm-input');
    const roomTitle = document.getElementById('global-dm-room-title');
    const roomSubtitle = document.getElementById('global-dm-room-subtitle');
    const guildTitle = document.getElementById('global-dm-guild-title');
    const guildSubtitle = document.getElementById('global-dm-guild-subtitle');
    const guildMessagesEl = document.getElementById('global-dm-guild-messages');
    const guildFormEl = document.getElementById('global-dm-guild-form');
    const guildInputEl = document.getElementById('global-dm-guild-input');
    const partyTitle = document.getElementById('global-dm-party-title');
    const partySubtitle = document.getElementById('global-dm-party-subtitle');
    const partyMessagesEl = document.getElementById('global-dm-party-messages');
    const partyFormEl = document.getElementById('global-dm-party-form');
    const partyInputEl = document.getElementById('global-dm-party-input');
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
            currentRoomUserId = null;
            invalidateGroupChannel('guild');
            invalidateGroupChannel('party');
            messageRenderState.direct = { signature: '', ids: [] };
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
        guildCloseBtn?.addEventListener('click', closePanel);
        partyCloseBtn?.addEventListener('click', closePanel);
        roomCloseBtn.addEventListener('click', closePanel);

        backBtn.addEventListener('click', () => {
            stopRoomPolling();
            showThreadsView();
        });
        guildBackBtn?.addEventListener('click', () => {
            stopGroupPolling();
            showThreadsView();
        });
        partyBackBtn?.addEventListener('click', () => {
            stopGroupPolling();
            showThreadsView();
        });
        tabLobby?.addEventListener('click', showLobbyView);
        tabDirect?.addEventListener('click', showThreadsView);
        tabGuild?.addEventListener('click', showGuildView);
        tabParty?.addEventListener('click', showPartyView);
        tabLobbyMirror?.addEventListener('click', showLobbyView);
        tabDirectMirror?.addEventListener('click', showThreadsView);
        tabGuildMirror?.addEventListener('click', showGuildView);
        tabPartyMirror?.addEventListener('click', showPartyView);

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

        ChatUI?.bindEmojiButtons(panel, inputEl);
        ChatUI?.bindEmojiButtons(document.getElementById('global-dm-guild-emojis'), guildInputEl);
        ChatUI?.bindEmojiButtons(document.getElementById('global-dm-party-emojis'), partyInputEl);

        guildFormEl?.addEventListener('submit', async (e) => {
            e.preventDefault();
            const content = guildInputEl?.value?.trim() || '';
            if (!content || !currentGuildId) return;
            try {
                await API.post(`/community/guilds/${currentGuildId}/chat/`, { content });
                guildInputEl.value = '';
                messageRenderState.guild = { signature: '', ids: [] };
                await loadGuildMessages(true);
            } catch (error) {
                Toast.error(error.data?.detail || error.data?.message || '길드 채팅 전송에 실패했습니다.');
            }
        });

        partyFormEl?.addEventListener('submit', async (e) => {
            e.preventDefault();
            const content = partyInputEl?.value?.trim() || '';
            if (!content || !currentPartyId) return;
            try {
                await API.post(`/community/parties/${currentPartyId}/chat/`, { content });
                partyInputEl.value = '';
                messageRenderState.party = { signature: '', ids: [] };
                await loadPartyMessages(true);
            } catch (error) {
                Toast.error(error.data?.detail || error.data?.message || '파티 채팅 전송에 실패했습니다.');
            }
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
        stopRoomPolling();
        stopGroupPolling();
    }

    function showThreadsView() {
        threadsView.classList.remove('hidden');
        lobbyView?.classList.add('hidden');
        guildView?.classList.add('hidden');
        partyView?.classList.add('hidden');
        roomView.classList.add('hidden');
        currentRoomUserId = null;
        stopRoomPolling();
        stopGroupPolling();
        setTabActive('direct');
        loadThreads();
    }

    function showLobbyView() {
        if (!lobbyChatContainer || !lobbySlot || !lobbyView) {
            showThreadsView();
            return;
        }
        moveLobbyChatContainer();
        threadsView.classList.add('hidden');
        guildView?.classList.add('hidden');
        partyView?.classList.add('hidden');
        roomView.classList.add('hidden');
        lobbyView.classList.remove('hidden');
        currentRoomUserId = null;
        stopRoomPolling();
        stopGroupPolling();
        setTabActive('lobby');
    }

    async function showGuildView() {
        threadsView.classList.add('hidden');
        lobbyView?.classList.add('hidden');
        partyView?.classList.add('hidden');
        roomView.classList.add('hidden');
        guildView?.classList.remove('hidden');
        currentRoomUserId = null;
        setTabActive('guild');
        stopRoomPolling();
        await loadGuildMessages(true, { refreshSummary: true });
        startGroupPolling(() => loadGuildMessages(), () => Boolean(currentUser?.id && currentGuildId));
    }

    async function showPartyView() {
        threadsView.classList.add('hidden');
        lobbyView?.classList.add('hidden');
        guildView?.classList.add('hidden');
        roomView.classList.add('hidden');
        partyView?.classList.remove('hidden');
        currentRoomUserId = null;
        setTabActive('party');
        stopRoomPolling();
        await loadPartyMessages(true, { refreshSummary: true });
        startGroupPolling(() => loadPartyMessages(), () => Boolean(currentUser?.id && currentPartyId));
    }

    async function showRoomView(userId, nickname = '상대') {
        if (!currentUser) {
            await ensureCurrentUser();
        }
        threadsView.classList.add('hidden');
        lobbyView?.classList.add('hidden');
        guildView?.classList.add('hidden');
        partyView?.classList.add('hidden');
        roomView.classList.remove('hidden');
        currentRoomUserId = userId;
        messageRenderState.direct = { signature: '', ids: [] };
        lastMessageCount = 0;
        stopGroupPolling();
        setTabActive('direct');
        roomTitle.textContent = nickname;
        roomSubtitle.textContent = '';
        
        loadTargetInfo(userId);
        loadMessages(true);
        startRoomPolling();
    }

    function syncLobbyTabsVisibility() {
        const enabled = Boolean(currentUser?.id);
        tabs?.classList.toggle('hidden', !enabled);
        tabsMirror?.classList.toggle('hidden', !enabled);
        const lobbyAvailable = !!lobbyChatContainer && !!lobbySlot;
        [tabLobby, tabLobbyMirror].forEach((button) => {
            if (!button) return;
            button.disabled = !lobbyAvailable;
            button.classList.toggle('is-disabled', !lobbyAvailable);
        });
        if (!lobbyAvailable) {
            restoreLobbyChatContainer();
        }
    }

    function setTabActive(type) {
        const states = {
            lobby: type === 'lobby',
            direct: type === 'direct',
            guild: type === 'guild',
            party: type === 'party',
        };
        const pairs = [
            [tabLobby, tabLobbyMirror, states.lobby],
            [tabDirect, tabDirectMirror, states.direct],
            [tabGuild, tabGuildMirror, states.guild],
            [tabParty, tabPartyMirror, states.party],
        ];
        pairs.forEach(([a, b, active]) => {
            a?.classList.toggle('is-active', active);
            b?.classList.toggle('is-active', active);
            a?.setAttribute('aria-selected', String(active));
            b?.setAttribute('aria-selected', String(active));
        });
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

    function setChannelEmpty(messagesRoot, titleRoot, subtitleRoot, inputRoot, text, title) {
        if (titleRoot) titleRoot.textContent = title;
        if (subtitleRoot) subtitleRoot.textContent = text;
        if (messagesRoot) {
            const empty = document.createElement('div');
            empty.className = 'global-dm-empty';
            empty.textContent = text;
            messagesRoot.replaceChildren(empty);
        }
        if (inputRoot) {
            inputRoot.value = '';
            inputRoot.disabled = true;
            inputRoot.placeholder = text;
        }
        const form = inputRoot?.closest('form');
        form?.querySelector('button[type="submit"]')?.toggleAttribute('disabled', true);
    }

    function setChannelReady(inputRoot, placeholder) {
        if (!inputRoot) return;
        inputRoot.disabled = false;
        inputRoot.placeholder = placeholder;
        const form = inputRoot.closest('form');
        form?.querySelector('button[type="submit"]')?.toggleAttribute('disabled', false);
    }

    function buildMessageSignature(items) {
        return items.map((item) => `${item.id}:${item.created_at || ''}`).join('|');
    }

    function invalidateGroupChannel(type) {
        if (type === 'guild') {
            currentGuildId = null;
            guildSummaryCache = null;
            guildSummaryLoadedAt = 0;
            messageRenderState.guild = { signature: '', ids: [] };
            return;
        }
        currentPartyId = null;
        partySummaryCache = null;
        partySummaryLoadedAt = 0;
        messageRenderState.party = { signature: '', ids: [] };
    }

    function syncMessageList(root, items, renderItem, forceScroll, emptyText, state) {
        if (!root) return false;
        const orderedItems = items.slice().reverse();

        if (!orderedItems.length) {
            if (state.signature !== 'empty') {
                const empty = document.createElement('div');
                empty.className = 'global-dm-empty';
                empty.textContent = emptyText;
                root.replaceChildren(empty);
                state.signature = 'empty';
                state.ids = [];
            }
            return false;
        }

        const nextIds = orderedItems.map((item) => String(item.id ?? ''));
        const nextSignature = buildMessageSignature(orderedItems);
        const shouldScroll = forceScroll || (root.scrollTop + root.clientHeight >= root.scrollHeight - 50);

        if (nextSignature === state.signature) {
            if (shouldScroll) {
                ChatUI?.scrollToBottom(root);
            }
            return false;
        }

        const canAppendOnly =
            state.ids.length > 0 &&
            nextIds.length > state.ids.length &&
            state.ids.every((id, index) => id === nextIds[index]);

        if (canAppendOnly) {
            const fragment = document.createDocumentFragment();
            orderedItems.slice(state.ids.length).forEach((item) => {
                fragment.appendChild(renderItem(item));
            });
            root.appendChild(fragment);
        } else {
            const fragment = document.createDocumentFragment();
            orderedItems.forEach((item) => {
                fragment.appendChild(renderItem(item));
            });
            root.replaceChildren(fragment);
        }

        state.signature = nextSignature;
        state.ids = nextIds;

        if (shouldScroll) {
            ChatUI?.scrollToBottom(root);
        }

        return true;
    }

    async function loadGuildSummary(force = false) {
        if (!currentUser) await ensureCurrentUser();
        const now = Date.now();
        if (!force && guildSummaryCache && now - guildSummaryLoadedAt < SUMMARY_CACHE_TTL) {
            return guildSummaryCache;
        }
        const summary = await API.get('/community/guilds/me/current/').catch(() => null);
        guildSummaryCache = summary;
        guildSummaryLoadedAt = now;
        return guildSummaryCache;
    }

    async function loadPartySummary(force = false) {
        if (!currentUser) await ensureCurrentUser();
        const now = Date.now();
        if (!force && partySummaryCache && now - partySummaryLoadedAt < SUMMARY_CACHE_TTL) {
            return partySummaryCache;
        }
        const summary = await API.get('/community/parties/me/active/').catch(() => null);
        partySummaryCache = summary;
        partySummaryLoadedAt = now;
        return partySummaryCache;
    }

    function renderGroupMessageItem(item) {
        const isMe = currentUser && item.user?.id === currentUser.id;
        const time = formatTimeOnly(item.created_at);
        const messageText = item.content || '';
        const emojiOnlyClass = isEmojiOnly(messageText) ? ' emoji-only' : '';
        const row = document.createElement('div');
        row.className = `global-dm-message ${isMe ? 'me' : 'other'}`;

        if (!isMe) {
            const avatarWrap = document.createElement('div');
            avatarWrap.className = 'global-dm-message-avatar';
            Utils.setAvatar(avatarWrap, {
                url: item.user?.avatar_url || '',
                alt: item.user?.nickname || '',
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
        timeEl.textContent = `${item.user?.nickname || ''} · ${time}`.trim();

        content.append(text, timeEl);
        row.appendChild(content);
        return row;
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

    async function loadGuildMessages(forceScroll = false, { refreshSummary = false } = {}) {
        if (!currentUser) await ensureCurrentUser();
        const summary = await loadGuildSummary(refreshSummary || !currentGuildId);
        if (!summary?.id) {
            invalidateGroupChannel('guild');
            setChannelEmpty(
                guildMessagesEl,
                guildTitle,
                guildSubtitle,
                guildInputEl,
                summary?.message || '가입 중인 길드가 없습니다.',
                '길드 채팅'
            );
            return;
        }
        currentGuildId = summary.id;
        guildTitle.textContent = summary.name || '길드 채팅';
        guildSubtitle.textContent = `길드장 ${summary.owner?.nickname || '-'} · 멤버 ${summary.member_count || 0}명`;
        setChannelReady(guildInputEl, '길드 채팅 입력...');
        const data = await API.get(`/community/guilds/${currentGuildId}/chat/`).catch((error) => {
            if (error?.status === 403 || error?.status === 404) {
                invalidateGroupChannel('guild');
            }
            return { results: [] };
        });
        syncMessageList(
            guildMessagesEl,
            data.results || [],
            renderGroupMessageItem,
            forceScroll,
            '아직 채팅이 없습니다.',
            messageRenderState.guild
        );
    }

    async function loadPartyMessages(forceScroll = false, { refreshSummary = false } = {}) {
        if (!currentUser) await ensureCurrentUser();
        const summary = await loadPartySummary(refreshSummary || !currentPartyId);
        if (!summary?.party_id) {
            invalidateGroupChannel('party');
            setChannelEmpty(
                partyMessagesEl,
                partyTitle,
                partySubtitle,
                partyInputEl,
                summary?.message || '참가 중인 파티가 없습니다.',
                '파티 채팅'
            );
            return;
        }
        currentPartyId = summary.party_id;
        partyTitle.textContent = summary.title || '파티 채팅';
        partySubtitle.textContent = `상태 ${summary.status || '-'} · ${summary.is_leader ? '파티장' : '참가자'}`;
        setChannelReady(partyInputEl, '파티 채팅 입력...');
        const data = await API.get(`/community/parties/${currentPartyId}/chat/`).catch((error) => {
            if (error?.status === 403 || error?.status === 404) {
                invalidateGroupChannel('party');
            }
            return { results: [] };
        });
        syncMessageList(
            partyMessagesEl,
            data.results || [],
            renderGroupMessageItem,
            forceScroll,
            '아직 채팅이 없습니다.',
            messageRenderState.party
        );
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
                const didRender = syncMessageList(
                    messagesEl,
                    items,
                    renderMessageItem,
                    forceScroll,
                    '아직 메시지가 없습니다.',
                    messageRenderState.direct
                );
                const orderedItems = items.slice().reverse();

                if (didRender && data.count > lastMessageCount && orderedItems.length) {
                    const lastItem = orderedItems[orderedItems.length - 1];
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
        messageRenderState.direct = { signature: 'empty', ids: [] };
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
        threadPoller?.stop?.();
        threadPoller = Utils.createAdaptivePoller({
            callback: () => loadThreads(),
            activeInterval: 10000,
            hiddenInterval: 30000,
            enabled: () => Boolean(currentUser?.id),
            immediate: true,
        });
        threadPoller.start();
    }

    function startRoomPolling() {
        roomPoller?.stop?.();
        roomPoller = Utils.createAdaptivePoller({
            callback: () => loadMessages(),
            activeInterval: 3000,
            hiddenInterval: 10000,
            enabled: () => Boolean(currentUser?.id && currentRoomUserId),
            immediate: false,
        });
        roomPoller.start();
    }

    function startGroupPolling(callback, enabled) {
        groupPoller?.stop?.();
        groupPoller = Utils.createAdaptivePoller({
            callback,
            activeInterval: 4000,
            hiddenInterval: 12000,
            enabled,
            immediate: false,
        });
        groupPoller.start();
    }

    function stopRoomPolling() {
        roomPoller?.stop?.();
        roomPoller = null;
    }

    function stopGroupPolling() {
        groupPoller?.stop?.();
        groupPoller = null;
    }

    function stopPolling() {
        threadPoller?.stop?.();
        threadPoller = null;
        stopRoomPolling();
        stopGroupPolling();
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
        if (!lobbyChatContainer || !lobbySlot) {
            restoreLobbyChatContainer();
            if (!panel.classList.contains('hidden') && lobbyView && !lobbyView.classList.contains('hidden')) {
                showThreadsView();
            }
        }
    });
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden && currentUser) {
            threadPoller?.trigger?.();
            if (currentRoomUserId) roomPoller?.trigger?.();
            groupPoller?.trigger?.();
        }
    });

})();
