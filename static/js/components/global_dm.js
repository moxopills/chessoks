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
    let hasLoadedThreads = false;
    let hasLoadedGuildView = false;
    let hasLoadedPartyView = false;
    let lastThreadsSignature = '';
    const tabUnread = {
        direct: 0,
        guild: 0,
        party: 0,
    };
    let directUnreadMap = {};
    const messageRenderState = {
        direct: { signature: '', ids: [] },
        guild: { signature: '', ids: [] },
        party: { signature: '', ids: [] },
    };
    const dmUI = window.GlobalDMUI;
    const channels = window.GlobalDMChannels;
    
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
    const tabDirectBadge = document.getElementById('global-dm-tab-direct-badge');
    const tabGuildBadge = document.getElementById('global-dm-tab-guild-badge');
    const tabPartyBadge = document.getElementById('global-dm-tab-party-badge');
    const tabDirectBadgeMirror = document.getElementById('global-dm-tab-direct-badge-mirror');
    const tabGuildBadgeMirror = document.getElementById('global-dm-tab-guild-badge-mirror');
    const tabPartyBadgeMirror = document.getElementById('global-dm-tab-party-badge-mirror');
    
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
                threadPoller?.trigger?.();
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
        threadPoller?.trigger?.();
        if (currentRoomUserId) {
            showRoomView(currentRoomUserId);
        } else if (isMobileLobbyPage() && lobbyChatContainer && lobbySlot) {
            showLobbyView();
        } else {
            showThreadsView({ force: !hasLoadedThreads });
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

    function showThreadsView(options = {}) {
        const { force = false } = options;
        threadsView.classList.remove('hidden');
        lobbyView?.classList.add('hidden');
        guildView?.classList.add('hidden');
        partyView?.classList.add('hidden');
        roomView.classList.add('hidden');
        currentRoomUserId = null;
        stopRoomPolling();
        stopGroupPolling();
        setTabActive('direct');
        if (force || !hasLoadedThreads) {
            loadThreads({ force: true });
        }
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
        await loadGuildMessages(true, { refreshSummary: !hasLoadedGuildView });
        hasLoadedGuildView = true;
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
        await loadPartyMessages(true, { refreshSummary: !hasLoadedPartyView });
        hasLoadedPartyView = true;
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
        await loadMessages(true);
        if (directUnreadMap[userId]) {
            await markDirectMessageNotificationsRead(userId);
            directUnreadMap[userId] = 0;
        }
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

    function setBadgeValue(elements, count) {
        elements.forEach((element) => {
            if (!element) return;
            if (count > 0) {
                element.textContent = String(count);
                element.classList.remove('hidden');
            } else {
                element.textContent = '0';
                element.classList.add('hidden');
            }
        });
    }

    function syncTabBadges() {
        setBadgeValue([tabDirectBadge, tabDirectBadgeMirror], tabUnread.direct);
        setBadgeValue([tabGuildBadge, tabGuildBadgeMirror], tabUnread.guild);
        setBadgeValue([tabPartyBadge, tabPartyBadgeMirror], tabUnread.party);
    }

    function buildThreadsSignature(threads, unreadMap) {
        return channels?.buildThreadsSignature(threads, unreadMap) || '';
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
    async function loadThreads(options = {}) {
        const { force = false } = options;
        try {
            const [data, notifications] = await Promise.all([
                API.get('/accounts/messages/threads/', { limit: 20, offset: 0, no_count: 1 }),
                API.get('/notifications/', { limit: 100, offset: 0, no_count: 1 }),
            ]);
            
            const threads = data.results || [];
            const unreadMap = dmUI.buildUnreadMap(notifications.results || []);
            directUnreadMap = unreadMap;
            
            dmUI.updateGlobalBadge(fabBadge, unreadMap);
            tabUnread.direct = Object.values(unreadMap).reduce((acc, value) => acc + value, 0);
            syncTabBadges();

            if (!threads.length) {
                hasLoadedThreads = true;
                lastThreadsSignature = 'empty';
                dmUI.setThreadListEmpty(threadListEl, '대화가 없습니다. 새로운 대화를 시작해보세요.');
                return;
            }

            const nextSignature = buildThreadsSignature(threads, unreadMap);
            if (force || nextSignature !== lastThreadsSignature) {
                const fragment = document.createDocumentFragment();
                threads.forEach((thread) => {
                    fragment.appendChild(dmUI.renderThreadItem(thread, unreadMap, showRoomView));
                });
                threadListEl.replaceChildren(fragment);
                lastThreadsSignature = nextSignature;
            }
            hasLoadedThreads = true;

        } catch (e) {
            dmUI.setThreadListEmpty(threadListEl, '목록을 불러오지 못했습니다.');
        }
    }

    function invalidateGroupChannel(type) {
        if (type === 'guild') {
            currentGuildId = null;
            guildSummaryCache = null;
            guildSummaryLoadedAt = 0;
            hasLoadedGuildView = false;
            tabUnread.guild = 0;
            messageRenderState.guild = { signature: '', ids: [] };
            syncTabBadges();
            return;
        }
        currentPartyId = null;
        partySummaryCache = null;
        partySummaryLoadedAt = 0;
        hasLoadedPartyView = false;
        tabUnread.party = 0;
        messageRenderState.party = { signature: '', ids: [] };
        syncTabBadges();
    }

    async function loadGuildSummary(force = false) {
        const result = await channels?.loadGroupSummary({
            ensureCurrentUser,
            cache: guildSummaryCache,
            loadedAt: guildSummaryLoadedAt,
            endpoint: '/community/guilds/me/current/',
            force,
        });
        guildSummaryCache = result?.summary || null;
        guildSummaryLoadedAt = result?.loadedAt || guildSummaryLoadedAt;
        return guildSummaryCache;
    }

    async function loadPartySummary(force = false) {
        const result = await channels?.loadGroupSummary({
            ensureCurrentUser,
            cache: partySummaryCache,
            loadedAt: partySummaryLoadedAt,
            endpoint: '/community/parties/me/active/',
            force,
        });
        partySummaryCache = result?.summary || null;
        partySummaryLoadedAt = result?.loadedAt || partySummaryLoadedAt;
        return partySummaryCache;
    }

    // Room Logic
    async function loadTargetInfo(userId) {
        await channels?.loadTargetInfo({ userId, roomTitle, roomSubtitle });
    }

    async function loadGuildMessages(forceScroll = false, { refreshSummary = false } = {}) {
        const summary = await loadGuildSummary(refreshSummary || !currentGuildId);
        const result = await channels?.loadGuildMessages({
            ensureCurrentUser,
            summary,
            invalidate: () => invalidateGroupChannel('guild'),
            guildTitle,
            guildSubtitle,
            guildInputEl,
            guildMessagesEl,
            currentUser,
            forceScroll,
            messageRenderState: messageRenderState.guild,
        });
        currentGuildId = result?.currentGuildId || null;
    }

    async function loadPartyMessages(forceScroll = false, { refreshSummary = false } = {}) {
        const summary = await loadPartySummary(refreshSummary || !currentPartyId);
        const result = await channels?.loadPartyMessages({
            ensureCurrentUser,
            summary,
            invalidate: () => invalidateGroupChannel('party'),
            partyTitle,
            partySubtitle,
            partyInputEl,
            partyMessagesEl,
            currentUser,
            forceScroll,
            messageRenderState: messageRenderState.party,
        });
        currentPartyId = result?.currentPartyId || null;
    }

    async function loadMessages(forceScroll = false) {
        const result = await channels?.loadDirectMessages({
            ensureCurrentUser,
            currentRoomUserId,
            currentUser,
            messagesEl,
            forceScroll,
            messageRenderState: messageRenderState.direct,
            lastMessageCount,
            onNewIncomingMessage: async () => {
                await markDirectMessageNotificationsRead(currentRoomUserId);
                directUnreadMap[currentRoomUserId] = 0;
            },
        });
        lastMessageCount = result?.lastMessageCount ?? lastMessageCount;
    }


    async function markDirectMessageNotificationsRead(userId) {
        await channels?.markDirectMessageNotificationsRead({
            userId,
            onAfterMark: () => loadThreads(),
        });
    }

    // Polling
    function startThreadPolling() {
        threadPoller?.stop?.();
        threadPoller = Utils.createAdaptivePoller({
            callback: () => {
                if (panel.classList.contains('hidden')) return;
                return loadThreads();
            },
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
            if (!panel.classList.contains('hidden')) {
                threadPoller?.trigger?.();
            }
            if (currentRoomUserId) roomPoller?.trigger?.();
            groupPoller?.trigger?.();
        }
    });

})();
