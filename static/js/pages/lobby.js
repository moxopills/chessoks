/**
 * Lobby Page Logic
 * - 방 목록 로드
 * - 빠른 대전
 * - 로비 채팅 (WebSocket)
 */

(function() {
    'use strict';

    const quickMatchBtn = document.getElementById('quick-match-btn');
    const randomMatchBtn = document.getElementById('random-match-btn');
    const aiMatchBtn = document.getElementById('ai-match-btn');
    const roomList = document.getElementById('room-list');
    const roomMoreWrap = document.getElementById('room-more-wrap');
    const chatMessages = document.getElementById('chat-messages');
    const chatForm = document.getElementById('chat-form');
    const chatInput = document.getElementById('chat-input');
    const usersList = document.getElementById('users-list');
    const userCount = document.getElementById('user-count');
    const userSearchInput = document.getElementById('lobby-user-search-input');
    const userSearchBtn = document.getElementById('lobby-user-search-btn');
    const userSearchReset = document.getElementById('lobby-user-search-reset');
    const mobileTabbar = document.getElementById('mobile-tabbar');
    const chatBadge = document.getElementById('chat-badge');
    const chatSection = document.querySelector('.lobby-chat-section');
    const waitingRoomCard = document.getElementById('waiting-room-card');
    const waitingRoomInfo = document.getElementById('waiting-room-info');
    const waitingRoomEnter = document.getElementById('waiting-room-enter');
    const activeGameCard = document.getElementById('active-game-card');
    const activeGameInfo = document.getElementById('active-game-info');
    const activeGameEnter = document.getElementById('active-game-enter');
    const tierToggle = document.getElementById('tier-toggle');
    const tierPanel = document.getElementById('tier-panel');
    const modeToggle = document.getElementById('mode-toggle');
    const modePanel = document.getElementById('mode-panel');
    const installToggle = document.getElementById('install-toggle');
    const installPanel = document.getElementById('install-panel');
    const pointsToggle = document.getElementById('points-toggle');
    const pointsPanel = document.getElementById('points-panel');
    const gameStartOpen = document.getElementById('game-start-open');
    const gameStartModal = document.getElementById('game-start-modal');
    const gameStartClose = document.getElementById('game-start-close');
    const aiMatchModal = document.getElementById('ai-match-modal');
    const aiMatchCancel = document.getElementById('ai-match-cancel');
    const quickMatchModal = document.getElementById('quick-match-modal');
    const randomMatchModal = document.getElementById('random-match-modal');
    const quickMatchCancel = document.getElementById('quick-match-cancel');
    const randomMatchCancel = document.getElementById('random-match-cancel');
    const quickMatchWait = document.getElementById('quick-match-wait');
    const randomMatchWait = document.getElementById('random-match-wait');
    const matchToast = document.getElementById('match-toast');
    const aiLevelButtons = Array.from(document.querySelectorAll('.ai-level-card'));
    const aiLevelLoading = document.getElementById('ai-level-loading');
    const guestPlayBtn = document.getElementById('guest-play-btn');
    const guestStatusBar = document.getElementById('guest-status-bar');
    const guestStatusName = document.getElementById('guest-status-name');
    const guestStatusTimer = document.getElementById('guest-status-timer');
    const guestLogoutBtn = document.getElementById('guest-logout-btn');

    let isMatching = false;
    let isRandomMatching = false;
    let isAiMatching = false;
    let lobbySocket = null;
    let currentUserId = null;
    let currentMe = null;
    let isGuestUser = false;
    let isSuspended = false;
    let friendIds = new Set();
    let lobbyUsers = {};
    let lobbyRooms = [];
    let roomRefreshPoller = null;
    let lobbyPresencePoller = null;
    let activeRoomId = null;
    let chatUnread = 0;
    let isChatOpen = true;
    let longPressTimer = null;
    const isTouchDevice = 'ontouchstart' in window || navigator.maxTouchPoints > 0;
    const NOTIFICATION_TYPES = Object.freeze({
        CHAT_MUTE: 'chat_mute',
        CHAT_UNMUTE: 'chat_unmute',
        ACCOUNT_SUSPENDED: 'account_suspended',
        ACCOUNT_UNSUSPENDED: 'account_unsuspended',
    });
    let isUserSearchMode = false;
    let lastRoomsSignature = null;
    let lastWaitingSignature = '';
    let waitingTick = 0;
    const MATCH_ROOM_TYPES = new Set(['quick', 'random']);
    let activeMatchToast = null;
    let lobbyWsReconnectAttempts = 0;
    const LOBBY_WS_MAX_RECONNECT = 10;
    const LOBBY_WS_BASE_DELAY = 1000;
    let quickMatchTimerInterval = null;
    let quickMatchStartTime = null;
    let randomMatchTimerInterval = null;
    let randomMatchStartTime = null;
    let quickMatchPollInterval = null;
    let randomMatchPollInterval = null;
    let notificationEventBound = false;
    let notificationEventHandler = null;
    let hasShownLobbyOnboarding = false;

    // 초기화
    init();

    async function init() {
        showStatus('로비를 불러오는 중...', 'pending', 1200);
        const isMobile = window.innerWidth <= 768;
        const globalDmFab = document.getElementById('global-dm-fab');
        globalDmFab?.classList.remove('hidden');
        if (chatSection) {
            if (isMobile) {
                chatSection.classList.add('is-hidden');
                isChatOpen = false;
            } else {
                chatSection.classList.remove('is-hidden');
                isChatOpen = true;
            }
        }
        await loadRooms();
        await loadWaitingRoom();
        await loadActiveGame();
        await checkAuthAndSetupChat();
        startRoomAutoRefresh();
        setupMobileTabs();
        setupChatToggle();
        setupTierToggle();
        setupGameStartLauncher();
        setupQuickMatch();
        setupRandomMatch();
        setupAiMatch();
        setupUserContextMenu();
        setupUserSearch();
        setupGuestMode();
        showLobbyOnboardingTip();
        warmupNextViews();
    }

    function showStatus(message, type = 'info', duration = 1800) {
        if (window.StatusBadge) {
            window.StatusBadge.show(message, { type, duration });
            return;
        }
        if (type === 'error') {
            Toast.error(message);
            return;
        }
        if (type === 'success') {
            Toast.success(message);
            return;
        }
        Toast.info(message);
    }

    function showLobbyOnboardingTip() {
        if (hasShownLobbyOnboarding) return;
        hasShownLobbyOnboarding = true;
        const key = 'lobby_onboarding_seen_v2';
        if (Utils.Storage.get(key, false)) return;
        showStatus('상단 대전 버튼으로 시작하고, 가이드 버튼에서 설치/포인트 안내를 확인하세요.', 'info', 3800);
        Utils.Storage.set(key, true);
    }

    function warmupNextViews() {
        const warm = () => {
            ['/rooms/', '/leaderboard/', '/friends/', '/customize/'].forEach((href) => {
                const link = document.createElement('link');
                link.rel = 'prefetch';
                link.href = href;
                document.head.appendChild(link);
            });
        };
        if ('requestIdleCallback' in window) {
            window.requestIdleCallback(warm, { timeout: 1200 });
        } else {
            setTimeout(warm, 800);
        }
    }

    function setupGameStartLauncher() {
        window.ModalLauncher?.bind({
            openButton: gameStartOpen,
            modal: gameStartModal,
            closeButton: gameStartClose,
        });
    }

    /**
     * 방 목록 로드
     */
    async function loadRooms() {
        try {
            const data = await API.get('/chess/rooms/', { status: 'waiting', limit: 6, no_count: 1 });
            const rawRooms = Array.isArray(data?.results)
                ? data.results
                : (Array.isArray(data) ? data : []);
            const rooms = rawRooms.filter((room) => !isHiddenRoomType(room));
            const visibleRooms = rooms.slice(0, 5);
            const signature = rooms
                .map((room) => `${room.id}:${room.status}:${room.guest?.id || 0}:${room.current_game_id || 0}`)
                .join('|');
            const isLoading = roomList && roomList.querySelector('.loading-placeholder');
            if (signature !== lastRoomsSignature || isLoading) {
                lastRoomsSignature = signature;
                lobbyRooms = visibleRooms;
                try {
                    renderRooms(lobbyRooms);
                    roomMoreWrap?.classList.toggle('hidden', rooms.length <= 5);
                } catch (renderError) {
                    console.error('Failed to render rooms:', renderError);
                    roomList.innerHTML = '<div class="room-empty">방 목록을 불러올 수 없습니다.</div>';
                    roomMoreWrap?.classList.add('hidden');
                }
            }
        } catch (error) {
            roomList.innerHTML = '<div class="room-empty">방 목록을 불러올 수 없습니다.</div>';
            roomMoreWrap?.classList.add('hidden');
            showStatus('방 목록을 불러오지 못했습니다.', 'error', 2000);
        }
    }

    async function loadWaitingRoom() {
        if (!waitingRoomCard) return;
        if (!currentUserId || isMatching || isRandomMatching) {
            waitingRoomCard.classList.add('hidden');
            return;
        }
        try {
            const data = await API.get('/chess/rooms/waiting/');
            const room = data.room;
            if (!room || isHiddenRoomType(room)) {
                lastWaitingSignature = '';
                waitingRoomCard.classList.add('hidden');
                return;
            }
            const signature = `${room.id}:${room.status}:${room.time_limit || 0}:${room.title || ''}`;
            if (signature === lastWaitingSignature) {
                return;
            }
            lastWaitingSignature = signature;
            waitingRoomCard.classList.remove('hidden');
            const title = room.title || '빠른 대전';
            const timeText = room.time_limit ? `${room.time_limit}분` : '무제한';
            waitingRoomInfo.textContent = '';
            const titleRow = document.createElement('div');
            titleRow.style.fontWeight = '700';
            titleRow.style.marginBottom = '4px';
            titleRow.textContent = `${title} · ${timeText}`;
            waitingRoomInfo.appendChild(titleRow);
            const hostRow = document.createElement('div');
            hostRow.style.opacity = '0.95';
            hostRow.appendChild(styledUserInline(room.host));
            waitingRoomInfo.appendChild(hostRow);
            waitingRoomEnter.onclick = () => {
                window.location.href = `/rooms/${room.id}/`;
            };
            waitingRoomCard.onclick = () => {
                window.location.href = `/rooms/${room.id}/`;
            };
        } catch (error) {
            waitingRoomCard.classList.add('hidden');
        }
    }

    async function loadActiveGame() {
        if (!activeGameCard) return;
        if (!currentUserId) {
            activeGameCard.classList.add('hidden');
            return;
        }
        try {
            const data = await API.get('/chess/rooms/active/');
            const room = data.room;
            if (!room || !room.current_game_id) {
                activeGameCard.classList.add('hidden');
                activeRoomId = null;
                return;
            }
            if (activeRoomId !== room.id) {
                activeRoomId = room.id;
            }
            activeGameCard.classList.remove('hidden');
            activeGameInfo.textContent = '';
            const row = document.createElement('div');
            row.style.display = 'flex';
            row.style.alignItems = 'center';
            row.style.gap = '8px';
            row.style.flexWrap = 'wrap';
            row.appendChild(styledUserInline(room.host, '화이트'));
            const vs = document.createElement('span');
            vs.style.opacity = '0.7';
            vs.textContent = 'vs';
            row.appendChild(vs);
            row.appendChild(styledUserInline(room.guest, '블랙'));
            activeGameInfo.appendChild(row);
            activeGameEnter.onclick = () => {
                window.location.href = `/games/${room.id}/`;
            };
            activeGameCard.onclick = () => {
                window.location.href = `/games/${room.id}/`;
            };
        } catch (error) {
            activeGameCard.classList.add('hidden');
        }
    }

    /**
     * 방 목록 렌더링
     */
    function renderRooms(rooms) {
        const visibleRooms = (rooms || []).filter((room) => !isHiddenRoomType(room));
        if (!visibleRooms.length) {
            roomList.innerHTML = '<div class="room-empty">대기 중인 방이 없습니다.</div>';
            return;
        }

        roomList.innerHTML = visibleRooms.map(room => `
            <div class="room-item" data-room-id="${room.id}">
                <div class="room-info">
                    <div class="room-title">${Utils.escapeHtml(room.title || '빠른 대전')}</div>
                    <div class="room-meta">
                        <span style="color:${Utils.getNicknameColorValue(room.host?.nickname_color || '')}">
                            ${Utils.escapeHtml(room.host?.nickname || '호스트')}
                        </span> ·
                        ${room.time_limit ? `${room.time_limit}분` : '무제한'}
                        ${room.spectator_count > 0 ? ` · 👁 ${room.spectator_count}` : ''}
                    </div>
                </div>
                <span class="room-status ${room.status}">${room.status === 'waiting' ? '대기 중' : '게임 중'}</span>
            </div>
        `).join('');

        // 방 클릭 이벤트
        roomList.querySelectorAll('.room-item').forEach(item => {
            item.addEventListener('click', () => {
                handleRoomClick(item);
            });
        });
    }

    function startRoomAutoRefresh() {
        roomRefreshPoller?.stop?.();
        roomRefreshPoller = Utils.createAdaptivePoller({
            callback: async () => {
            if (document.hidden) return;
            await loadRooms();
            waitingTick += 1;
            if (isMatching || waitingTick % 3 === 0) {
                await loadWaitingRoom();
            }
            await loadActiveGame();
            },
            activeInterval: 5000,
            hiddenInterval: 15000,
            enabled: () => true,
            immediate: false,
        });
        roomRefreshPoller.start();

        window.addEventListener('beforeunload', () => {
            roomRefreshPoller?.stop?.();
        });

        document.addEventListener('visibilitychange', () => {
            if (document.hidden) return;
            roomRefreshPoller?.trigger?.();
        });
    }

    async function handleRoomClick(item) {
        if (isSuspended) {
            Toast.error('계정이 정지되어 이용할 수 없습니다.');
            return;
        }
        const roomId = parseInt(item.dataset.roomId, 10);
        if (!roomId) return;

        const room = lobbyRooms.find(r => r.id === roomId);
        if (!room) {
            window.location.href = `/rooms/${roomId}/`;
            return;
        }

        if (room.status === 'playing') {
            if (room.current_game_id) {
                window.location.href = `/games/${room.id}/`;
            } else {
                Toast.error('관전 가능한 게임 정보를 찾을 수 없습니다.');
            }
            return;
        }

        const isParticipant = room.host?.id === currentUserId || room.guest?.id === currentUserId;
        if (!isParticipant && (room.guest || room.player_count >= 2)) {
            Toast.error('이미 인원이 찬 방입니다.');
            return;
        }

        let payload = {};
        if (room.is_private) {
            const password = await Modal.prompt('비밀번호를 입력하세요:', {
                title: '비공개 방 입장',
                inputType: 'password',
                placeholder: '비밀번호'
            });
            if (!password) return;
            payload = { password };
        }

        try {
            const joined = await API.post(`/chess/rooms/${roomId}/join/`, payload);
            if (isHiddenRoomType(joined) || joined.status === 'playing') {
                const joinedGameId = joined.current_game_id;
                if (joinedGameId) {
                    window.location.href = `/games/${joinedGameId}/`;
                } else {
                    Toast.error('게임 정보를 찾을 수 없습니다.');
                }
            } else {
                window.location.href = `/rooms/${roomId}/`;
            }
        } catch (error) {
            Toast.error(error.data?.message || '입장에 실패했습니다.');
        }
    }

    /**
     * 인증 확인 및 채팅 설정
     */
    async function checkAuthAndSetupChat() {
        try {
            const user = await API.get('/accounts/me/');
            currentUserId = user.id;
            currentMe = user;

            // 게스트 유저인지 확인
            if (user.is_guest) {
                isGuestUser = true;
                setupGuestSession();
                return;
            }

            isGuestUser = false;
            await loadFriendIds();
            setupChat();
            // lobby report removed; using profile report actions instead
            if (user.is_muted) {
                setChatMutedState(true, user.mute_reason || '');
            }
            if (user.is_suspended) {
                setSuspendedState(true, user.suspension_reason || '');
            }
            setupNotificationEvents();
            startLobbyPresenceRefresh();
            // 로그인 유저는 게스트 버튼 숨김
            guestPlayBtn?.classList.add('hidden');
            guestStatusBar?.classList.add('hidden');
        } catch (error) {
            // 비로그인 상태 - 게스트 체크
            if (typeof Guest !== 'undefined' && Guest.isGuest()) {
                isGuestUser = true;
                setupGuestSession();
            } else {
                // 게스트도 아닌 순수 비로그인
                chatInput.disabled = true;
                chatForm.querySelector('button').disabled = true;
                if (chatMessages) {
                    chatMessages.innerHTML = '<div class="chat-notice">로그인 또는 게스트로 시작하세요.</div>';
                }
                // 게스트 플레이 버튼 표시
                guestPlayBtn?.classList.remove('hidden');
            }
        }
    }

    async function loadFriendIds() {
        if (!currentUserId) return;
        try {
            const data = await API.get('/accounts/friends/');
            const friends = data.results || data || [];
            friendIds = new Set(friends.map((friend) => friend.friend?.id ?? friend.user?.id ?? friend.id).filter(Boolean));
        } catch {
            friendIds = new Set();
        }
    }

    function isFriendUser(userId) {
        return friendIds.has(userId);
    }

    /**
     * 빠른 대전 설정
     */
    function setupQuickMatch() {
        if (!quickMatchBtn || quickMatchBtn.dataset.bound === '1') return;
        quickMatchBtn.dataset.bound = '1';
        quickMatchBtn.addEventListener('click', async function() {
            gameStartModal?.classList.add('hidden');
            if (!currentUserId && !isGuestUser) {
                Toast.error('로그인 후 이용 가능합니다.');
                return;
            }
            if (isGuestUser) {
                Toast.error('게스트는 경쟁전을 이용할 수 없습니다.');
                return;
            }
            if (isSuspended) {
                Toast.error('계정이 정지되어 이용할 수 없습니다.');
                return;
            }
            if (isRandomMatching || isAiMatching) {
                Toast.error('다른 매칭이 진행 중입니다.');
                return;
            }
            if (isMatching) {
                await cancelMatch();
            } else {
                await startMatch();
            }
        });
        quickMatchCancel?.addEventListener('click', async () => {
            if (!isMatching) return;
            await cancelMatch();
        });
        quickMatchWait?.addEventListener('click', () => {
            if (!isMatching) return;
            quickMatchModal?.classList.add('hidden');
            showMatchToast('경쟁전 매칭 중...', 'quick');
        });
        quickMatchModal?.addEventListener('click', (event) => {
            if (event.target === quickMatchModal && isMatching) return;
            if (event.target === quickMatchModal) quickMatchModal.classList.add('hidden');
        });

        // ESC 키로 매칭 모달 닫기 (매칭 취소는 하지 않고 모달만 숨김)
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                if (quickMatchModal && !quickMatchModal.classList.contains('hidden') && isMatching) {
                    quickMatchModal.classList.add('hidden');
                    showMatchToast('경쟁전 매칭 중...', 'quick');
                }
            }
        });
    }

    /**
     * 랜덤 대전 설정
     */
    function setupRandomMatch() {
        if (!randomMatchBtn || randomMatchBtn.dataset.bound === '1') return;
        randomMatchBtn.dataset.bound = '1';
        randomMatchBtn.addEventListener('click', async function() {
            gameStartModal?.classList.add('hidden');
            if (!currentUserId && !isGuestUser) {
                Toast.error('로그인 또는 게스트로 시작하세요.');
                return;
            }
            if (isSuspended) {
                Toast.error('계정이 정지되어 이용할 수 없습니다.');
                return;
            }
            if (isMatching || isAiMatching) {
                Toast.error('다른 매칭이 진행 중입니다.');
                return;
            }
            if (isRandomMatching) {
                await cancelRandomMatch();
            } else {
                await startRandomMatch();
            }
        });
        randomMatchCancel?.addEventListener('click', async () => {
            if (!isRandomMatching) return;
            await cancelRandomMatch();
        });
        randomMatchWait?.addEventListener('click', () => {
            if (!isRandomMatching) return;
            randomMatchModal?.classList.add('hidden');
            showMatchToast('빠른 대전 매칭 중...', 'random');
        });
        randomMatchModal?.addEventListener('click', (event) => {
            if (event.target === randomMatchModal && isRandomMatching) return;
            if (event.target === randomMatchModal) randomMatchModal.classList.add('hidden');
        });

        // ESC 키로 매칭 모달 닫기 (매칭 취소는 하지 않고 모달만 숨김)
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                if (randomMatchModal && !randomMatchModal.classList.contains('hidden') && isRandomMatching) {
                    randomMatchModal.classList.add('hidden');
                    showMatchToast('빠른 대전 매칭 중...', 'random');
                }
            }
        });
    }

    function setupAiMatch() {
        if (!aiMatchBtn || aiMatchBtn.dataset.bound === '1') return;
        aiMatchBtn.dataset.bound = '1';
        const closeModal = () => aiMatchModal?.classList.add('hidden');
        const openModal = () => aiMatchModal?.classList.remove('hidden');
        const setAiLoading = (loading) => {
            isAiMatching = loading;
            aiLevelLoading?.classList.toggle('hidden', !loading);
            aiLevelButtons.forEach((btn) => {
                btn.disabled = loading;
                btn.classList.toggle('btn-disabled', loading);
            });
            aiMatchCancel?.classList.toggle('btn-disabled', loading);
            if (aiMatchCancel) aiMatchCancel.disabled = loading;
        };

        aiMatchBtn.addEventListener('click', () => {
            gameStartModal?.classList.add('hidden');
            if (!currentUserId && !isGuestUser) {
                Toast.error('로그인 또는 게스트로 시작하세요.');
                return;
            }
            if (isSuspended) {
                Toast.error('계정이 정지되어 이용할 수 없습니다.');
                return;
            }
            if (isMatching || isRandomMatching) {
                Toast.error('다른 매칭이 진행 중입니다.');
                return;
            }
            if (isAiMatching) return;
            openModal();
        });

        aiMatchCancel?.addEventListener('click', () => {
            if (isAiMatching) return;
            closeModal();
        });
        aiMatchModal?.addEventListener('click', (event) => {
            if (event.target === aiMatchModal && !isAiMatching) closeModal();
        });

        aiLevelButtons.forEach((btn) => {
            btn.addEventListener('click', async () => {
                const level = btn.dataset.level;
                if (!level) return;
                setAiLoading(true);
                try {
                    const result = await API.post('/chess/ai-match/', { level });
                    if (result.room_id) {
                        window.location.href = `/games/${result.room_id}/`;
                        return;
                    }
                    Toast.error('AI 대전을 시작할 수 없습니다.');
                } catch (error) {
                    Toast.error(error.data?.detail || 'AI 대전 시작에 실패했습니다.');
                } finally {
                    setAiLoading(false);
                    closeModal();
                }
            });
        });

        // ESC 키로 모달 닫기
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                if (aiMatchModal && !aiMatchModal.classList.contains('hidden') && !isAiMatching) {
                    closeModal();
                }
            }
        });
    }

    /**
     * 매칭 시작
     */
    async function startMatch() {
        setMatchingState(true);

        try {
            const result = await API.post('/chess/quick-match/');

            if (result.status === 'matched') {
                // 매칭 성공 - 게임 페이지로 이동
                showStatus('매칭되었습니다. 게임으로 이동합니다.', 'success', 1800);
                window.location.href = `/games/${result.room_id}/`;
            } else if (result.status === 'waiting') {
                // 대기 중 - 폴링 시작
                showStatus('상대를 찾는 중입니다.', 'pending', 1500);
                pollMatchStatus();
            }
        } catch (error) {
            setMatchingState(false);
            showStatus(error.data?.message || '매칭 시작에 실패했습니다.', 'error', 2000);
        }
    }

    async function startRandomMatch() {
        setRandomMatchingState(true);

        try {
            const result = await API.post('/chess/random-match/');

            if (result.status === 'matched') {
                showStatus('매칭되었습니다. 게임으로 이동합니다.', 'success', 1800);
                window.location.href = `/games/${result.room_id}/`;
            } else if (result.status === 'waiting') {
                showStatus('상대를 찾는 중입니다.', 'pending', 1500);
                pollRandomMatchStatus();
            }
        } catch (error) {
            setRandomMatchingState(false);
            showStatus(error.data?.message || '매칭 시작에 실패했습니다.', 'error', 2000);
        }
    }

    /**
     * 매칭 취소
     */
    async function cancelMatch() {
        try {
            await API.post('/chess/quick-match/cancel/');
            setMatchingState(false);
            showStatus('매칭이 취소되었습니다.', 'info', 1600);
        } catch (error) {
            showStatus('매칭 취소에 실패했습니다.', 'error', 2000);
        }
    }

    async function cancelRandomMatch() {
        try {
            await API.post('/chess/random-match/cancel/');
            setRandomMatchingState(false);
            showStatus('매칭이 취소되었습니다.', 'info', 1600);
        } catch (error) {
            showStatus('매칭 취소에 실패했습니다.', 'error', 2000);
        }
    }

    /**
     * 매칭 상태 폴링
     */
    function pollMatchStatus() {
        if (!isMatching) return;
        if (quickMatchPollInterval) clearInterval(quickMatchPollInterval);

        quickMatchPollInterval = setInterval(async () => {
            if (!isMatching) {
                clearInterval(quickMatchPollInterval);
                quickMatchPollInterval = null;
                return;
            }

            try {
                const result = await API.post('/chess/quick-match/');

                if (result.status === 'matched') {
                    clearInterval(quickMatchPollInterval);
                    quickMatchPollInterval = null;
                    showStatus('매칭되었습니다. 게임으로 이동합니다.', 'success', 1800);
                    window.location.href = `/games/${result.room_id}/`;
                }
            } catch (error) {
                clearInterval(quickMatchPollInterval);
                quickMatchPollInterval = null;
                setMatchingState(false);
                showStatus('매칭 중 오류가 발생했습니다. 다시 시도해주세요.', 'error', 2200);
            }
        }, 2000);
    }

    function pollRandomMatchStatus() {
        if (!isRandomMatching) return;
        if (randomMatchPollInterval) clearInterval(randomMatchPollInterval);

        randomMatchPollInterval = setInterval(async () => {
            if (!isRandomMatching) {
                clearInterval(randomMatchPollInterval);
                randomMatchPollInterval = null;
                return;
            }

            try {
                const result = await API.post('/chess/random-match/');

                if (result.status === 'matched') {
                    clearInterval(randomMatchPollInterval);
                    randomMatchPollInterval = null;
                    showStatus('매칭되었습니다. 게임으로 이동합니다.', 'success', 1800);
                    window.location.href = `/games/${result.room_id}/`;
                }
            } catch (error) {
                clearInterval(randomMatchPollInterval);
                randomMatchPollInterval = null;
                setRandomMatchingState(false);
                showStatus('매칭 중 오류가 발생했습니다. 다시 시도해주세요.', 'error', 2200);
            }
        }, 2000);
    }

    /**
     * 매칭 상태 UI 업데이트
     */
    function setMatchingState(matching) {
        isMatching = matching;
        quickMatchBtn.classList.toggle('btn-danger', matching);
        quickMatchBtn.classList.toggle('btn-primary', !matching);
        // 버튼 텍스트 변경 (취소 가능하도록 disabled 해제)
        const btnText = quickMatchBtn.querySelector('.btn-text') || quickMatchBtn;
        if (matching) {
            btnText.textContent = '매칭 취소';
            quickMatchModal?.classList.remove('hidden');
            showMatchToast('경쟁전 매칭 중...', 'quick');
            showStatus('경쟁전 매칭 대기 중...', 'pending', 1400);
            waitingRoomCard?.classList.add('hidden');
            startMatchTimer('quick');
        } else {
            btnText.textContent = '경쟁전';
            quickMatchModal?.classList.add('hidden');
            hideMatchToast();
            stopMatchTimer('quick');
            if (quickMatchPollInterval) {
                clearInterval(quickMatchPollInterval);
                quickMatchPollInterval = null;
            }
        }
    }

    function setRandomMatchingState(matching) {
        isRandomMatching = matching;
        if (!randomMatchBtn) return;
        randomMatchBtn.classList.toggle('btn-danger', matching);
        // 버튼 텍스트 변경 (취소 가능하도록 disabled 해제)
        const btnText = randomMatchBtn.querySelector('.btn-text') || randomMatchBtn;
        if (matching) {
            btnText.textContent = '매칭 취소';
            randomMatchModal?.classList.remove('hidden');
            showMatchToast('빠른 대전 매칭 중...', 'random');
            showStatus('빠른 대전 매칭 대기 중...', 'pending', 1400);
            waitingRoomCard?.classList.add('hidden');
            startMatchTimer('random');
        } else {
            btnText.textContent = '빠른 대전';
            randomMatchModal?.classList.add('hidden');
            hideMatchToast();
            stopMatchTimer('random');
            if (randomMatchPollInterval) {
                clearInterval(randomMatchPollInterval);
                randomMatchPollInterval = null;
            }
        }
    }

    function startMatchTimer(type) {
        const timerEl = document.getElementById(`${type}-match-timer`);
        if (type === 'quick') {
            quickMatchStartTime = Date.now();
            if (quickMatchTimerInterval) clearInterval(quickMatchTimerInterval);
            quickMatchTimerInterval = setInterval(() => updateMatchTimer('quick'), 1000);
        } else {
            randomMatchStartTime = Date.now();
            if (randomMatchTimerInterval) clearInterval(randomMatchTimerInterval);
            randomMatchTimerInterval = setInterval(() => updateMatchTimer('random'), 1000);
        }
        if (timerEl) timerEl.textContent = '⏱️ 대기 시간: 0:00';
    }

    function stopMatchTimer(type) {
        if (type === 'quick') {
            if (quickMatchTimerInterval) {
                clearInterval(quickMatchTimerInterval);
                quickMatchTimerInterval = null;
            }
            quickMatchStartTime = null;
        } else {
            if (randomMatchTimerInterval) {
                clearInterval(randomMatchTimerInterval);
                randomMatchTimerInterval = null;
            }
            randomMatchStartTime = null;
        }
    }

    function updateMatchTimer(type) {
        const startTime = type === 'quick' ? quickMatchStartTime : randomMatchStartTime;
        if (!startTime) return;
        const elapsed = Math.floor((Date.now() - startTime) / 1000);
        const minutes = Math.floor(elapsed / 60);
        const seconds = elapsed % 60;
        const timerEl = document.getElementById(`${type}-match-timer`);
        if (timerEl) {
            timerEl.textContent = `⏱️ 대기 시간: ${minutes}:${seconds.toString().padStart(2, '0')}`;
        }
    }

    function showMatchToast(text, type) {
        if (!matchToast) return;
        matchToast.textContent = text;
        activeMatchToast = type || null;
        matchToast.classList.remove('hidden');
    }

    function hideMatchToast() {
        if (!matchToast) return;
        matchToast.classList.add('hidden');
        activeMatchToast = null;
    }

    /**
     * 로비 채팅 설정
     */
    function setupChat() {
        chatInput.disabled = false;
        chatForm.querySelector('button').disabled = false;
        chatMessages.innerHTML = '';
        injectChatEmojiBar();
        const switchToDmBtn = document.getElementById('switch-to-dm-btn');
        switchToDmBtn?.classList.remove('hidden');

        // WebSocket 연결
        connectLobbyChat();

        // 메시지 전송
        chatForm.addEventListener('submit', function(e) {
            e.preventDefault();
            sendChatMessage();
        });
    }

    function injectChatEmojiBar() {
        ChatUI?.ensureEmojiBar(chatForm, chatInput);
    }

    if (matchToast) {
        matchToast.addEventListener('click', () => {
            if (activeMatchToast === 'quick' && isMatching) {
                quickMatchModal?.classList.remove('hidden');
                hideMatchToast();
                return;
            }
            if (activeMatchToast === 'random' && isRandomMatching) {
                randomMatchModal?.classList.remove('hidden');
                hideMatchToast();
                return;
            }
        });
    }

    /**
     * 로비 채팅 WebSocket 연결
     */
    function connectLobbyChat() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        let wsUrl = `${protocol}//${window.location.host}/ws/lobby/`;

        // 게스트 토큰이 있으면 쿼리 파라미터로 추가
        const guestToken = localStorage.getItem('guest_token');
        if (guestToken) {
            wsUrl += `?guest_token=${encodeURIComponent(guestToken)}`;
        }

        lobbySocket = new WebSocket(wsUrl);

        lobbySocket.onopen = function() {
            addChatNotice('채팅에 연결되었습니다.');
            lobbyWsReconnectAttempts = 0;
            showStatus('로비 실시간 연결 완료', 'success', 1200);
        };

        lobbySocket.onmessage = function(e) {
            const data = JSON.parse(e.data);
            handleChatMessage(data);
        };

        lobbySocket.onclose = function() {
            addChatNotice('채팅 연결이 끊어졌습니다.');
            if (lobbyWsReconnectAttempts >= LOBBY_WS_MAX_RECONNECT) {
                addChatNotice('재연결 실패. 페이지를 새로고침해 주세요.');
                showStatus('실시간 연결 복구 실패. 새로고침해주세요.', 'error', 2600);
                return;
            }
            lobbyWsReconnectAttempts += 1;
            const delay = Math.min(LOBBY_WS_BASE_DELAY * Math.pow(2, lobbyWsReconnectAttempts - 1), 30000);
            showStatus(`${Math.round(delay / 1000)}초 후 실시간 연결 재시도`, 'pending', 1500);
            setTimeout(connectLobbyChat, delay);
        };

        lobbySocket.onerror = function() {
            addChatNotice('채팅 연결 오류가 발생했습니다.');
        };
    }

    /**
     * 채팅 메시지 전송
     */
    function sendChatMessage() {
        const message = chatInput.value.trim();
        if (!message || !lobbySocket) return;
        Utils?.Sounds?.unlock?.();

        lobbySocket.send(JSON.stringify({
            action: 'chat',
            message: message
        }));

        chatInput.value = '';
    }

    /**
     * 채팅 메시지 처리
     */
    function handleChatMessage(data) {
        if (data.type === 'chat') {
            addChatMessage(data);
            handleChatBadge(data);
        } else if (data.type === 'reaction_update') {
            applyReactionUpdate(data.message_id, data.reactions || {}, data.my_reactions);
        } else if (data.type === 'recent_messages') {
            // 최근 메시지 로드
            chatMessages.innerHTML = '';
            const messages = (data.messages || []).slice().sort((a, b) => {
                return new Date(a.sent_at) - new Date(b.sent_at);
            });
            messages.forEach(msg => addChatMessage(msg));
            ChatUI?.scrollToBottom(chatMessages);
        } else if (data.type === 'lobby_users') {
            // 접속자 목록 초기화
            lobbyUsers = {};
            data.users.forEach(user => {
                lobbyUsers[user.id] = user;
            });
            renderUsers();
        } else if (data.type === 'user_joined') {
            // 유저 입장
            lobbyUsers[data.user.id] = data.user;
            addUserToList(data.user);
        } else if (data.type === 'user_left') {
            // 유저 퇴장
            delete lobbyUsers[data.user_id];
            removeUserFromList(data.user_id);
        } else if (data.type === 'room_update') {
            upsertRoom(data.room);
            loadActiveGame();
        } else if (data.type === 'room_removed') {
            removeRoom(data.room_id);
            loadActiveGame();
        } else if (data.type === 'error') {
            Toast.error(data.message);
        }
    }

    function setupNotificationEvents() {
        if (!currentUserId || notificationEventBound) return;
        notificationEventHandler = (event) => {
            const data = event.detail || {};
            const reason = data.payload?.reason || '';
            const handlers = {
                [NOTIFICATION_TYPES.CHAT_MUTE]: () => {
                    setChatMutedState(true, reason);
                    Toast.error(data.message || '채팅이 제한되었습니다.');
                },
                [NOTIFICATION_TYPES.ACCOUNT_SUSPENDED]: () => {
                    setSuspendedState(true, reason);
                    Toast.error(data.message || '계정이 정지되었습니다.');
                },
                [NOTIFICATION_TYPES.CHAT_UNMUTE]: () => {
                    setChatMutedState(false);
                    Toast.success(data.message || '채팅 제한이 해제되었습니다.');
                },
                [NOTIFICATION_TYPES.ACCOUNT_UNSUSPENDED]: () => {
                    setSuspendedState(false);
                    Toast.success(data.message || '계정 정지가 해제되었습니다.');
                },
            };
            handlers[data.type]?.();
        };
        window.addEventListener('chessok:notification', notificationEventHandler);
        notificationEventBound = true;
    }

    function setChatMutedState(muted, reason = '') {
        if (!chatInput || !chatForm) return;
        const submitBtn = chatForm.querySelector('button');
        if (!submitBtn) return;
        if (muted) {
            chatInput.disabled = true;
            submitBtn.disabled = true;
            if (reason) {
                addChatNotice(`채팅 제한됨: ${reason}`);
            } else {
                addChatNotice('채팅이 제한되었습니다.');
            }
        } else {
            chatInput.disabled = false;
            submitBtn.disabled = false;
        }
    }

    function setSuspendedState(suspended, reason = '') {
        isSuspended = suspended;
        if (suspended) {
            quickMatchBtn?.classList.add('btn-disabled');
            randomMatchBtn?.classList.add('btn-disabled');
            if (reason) {
                addChatNotice(`계정 정지됨: ${reason}`);
            } else {
                addChatNotice('계정이 정지되었습니다.');
            }
        } else {
            quickMatchBtn?.classList.remove('btn-disabled');
            randomMatchBtn?.classList.remove('btn-disabled');
        }
    }

    /**
     * 채팅 메시지 추가
     */
    function addChatMessage(data) {
        const isMine = data.user_id === currentUserId;
        const emojiOnlyClass = isEmojiOnlyMessage(data.message) ? ' emoji-only' : '';
        const messageEl = document.createElement('div');
        messageEl.className = `chat-message ${isMine ? 'mine' : 'others'}`;
        if (data.message_id) {
            messageEl.dataset.messageId = String(data.message_id);
        }
        if (!isMine) {
            const avatarWrap = document.createElement('div');
            avatarWrap.className = 'chat-avatar';
            Utils.setAvatar(avatarWrap, {
                url: data.avatar_url,
                alt: data.nickname || '',
                placeholder: '?',
                placeholderClass: 'avatar-placeholder',
            });
            messageEl.appendChild(avatarWrap);
        }

        const contentEl = document.createElement('div');
        contentEl.className = 'chat-content';

        const nicknameEl = document.createElement('span');
        nicknameEl.className = 'chat-nickname';
        nicknameEl.textContent = data.nickname || '';
        contentEl.appendChild(nicknameEl);

        const bubbleEl = document.createElement('div');
        bubbleEl.className = `chat-bubble${emojiOnlyClass}`;
        bubbleEl.textContent = data.message || '';
        contentEl.appendChild(bubbleEl);

        ChatReactions?.ensureReactionBar(contentEl, {
            reactions: data.reactions || {},
            myReactions: data.my_reactions || [],
        });
        messageEl.appendChild(contentEl);

        const timeEl = document.createElement('span');
        timeEl.className = 'chat-time';
        timeEl.textContent = formatChatTime(data.sent_at);
        messageEl.appendChild(timeEl);
        chatMessages.appendChild(messageEl);
        ChatUI?.scrollToBottom(chatMessages);
        ChatReactions?.bindReactionButtons(messageEl, {
            onReact: ({ messageId, reaction, button }) => {
                if (!messageId || !reaction || lobbySocket?.readyState !== WebSocket.OPEN) return;
                button?.classList.toggle('active');
                lobbySocket.send(JSON.stringify({
                    action: 'reaction',
                    message_id: Number(messageId),
                    reaction,
                }));
            },
        });
    }

    function isEmojiOnlyMessage(text) {
        const value = (text || '').trim();
        if (!value) return false;
        const stripped = value.replace(
            /[\p{Emoji}\p{Extended_Pictographic}\uFE0F\u200D\s]/gu,
            ''
        );
        return stripped.length === 0;
    }

    function applyReactionUpdate(messageId, reactions, myReactions) {
        const target = chatMessages.querySelector(`.chat-message[data-message-id="${messageId}"]`);
        if (!target) return;
        ChatReactions?.applyReactionUpdate(target, reactions, myReactions);
    }


    function setupMobileTabs() {
        if (!mobileTabbar) return;
        document.body.classList.add('has-mobile-tabbar');
        const tabs = mobileTabbar.querySelectorAll('.mobile-tab');
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const target = tab.dataset.tab;
                tabs.forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                if (target === 'chat') {
                    isChatOpen = true;
                    if (chatSection) {
                        chatSection.classList.remove('is-hidden');
                    }
                    ChatUI?.scrollToBottom(chatMessages);
                    resetChatBadge();
                } else {
                    isChatOpen = false;
                    if (chatSection) {
                        chatSection.classList.add('is-hidden');
                    }
                }
            });
        });
        
    }

    function setupChatToggle() {
        const switchToDmBtn = document.getElementById('switch-to-dm-btn');
        if (switchToDmBtn) {
            switchToDmBtn.addEventListener('click', () => {
                if (chatSection) {
                    chatSection.classList.remove('is-hidden');
                }
                window.dispatchEvent(new CustomEvent('global-dm:open-panel'));
            });
        }
    }

    function setupTierToggle() {
        const guidePairs = [
            [tierToggle, tierPanel],
            [modeToggle, modePanel],
            [installToggle, installPanel],
            [pointsToggle, pointsPanel],
        ].filter(([toggle, panel]) => Boolean(toggle && panel));

        if (!guidePairs.length) return;

        guidePairs.forEach(([toggle, panel]) => {
            panel.classList.remove('hidden');
            panel.classList.remove('is-open');
            toggle.setAttribute('aria-expanded', 'false');
            toggle.classList.remove('is-active');
        });

        guidePairs.forEach(([toggle, panel]) => {
            toggle.addEventListener('click', () => {
                const willOpen = !panel.classList.contains('is-open');
                guidePairs.forEach(([otherToggle, otherPanel]) => {
                    const isCurrent = otherToggle === toggle;
                    otherPanel.classList.toggle('is-open', isCurrent && willOpen);
                    otherToggle.setAttribute('aria-expanded', String(isCurrent && willOpen));
                    otherToggle.classList.toggle('is-active', isCurrent && willOpen);
                });
            });
        });
    }

    function handleChatBadge(data) {
        if (isChatOpen || !chatSection?.classList.contains('is-hidden')) {
            resetChatBadge();
            return;
        }
        if (data.user_id === currentUserId) return;
        chatUnread += 1;
        if (chatBadge) {
            chatBadge.textContent = chatUnread;
            chatBadge.classList.remove('hidden');
        }
    }

    function resetChatBadge() {
        chatUnread = 0;
        if (chatBadge) {
            chatBadge.textContent = '0';
            chatBadge.classList.add('hidden');
        }
    }

    /**
     * 채팅 알림 추가
     */
    function addChatNotice(text) {
        const noticeEl = document.createElement('div');
        noticeEl.className = 'chat-notice';
        noticeEl.textContent = text;
        chatMessages.appendChild(noticeEl);
        ChatUI?.scrollToBottom(chatMessages);
    }

    /**
     * 채팅 시간 포맷
     */
    function formatChatTime(isoString) {
        const date = new Date(isoString);
        return date.toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit' });
    }

    /**
     * 접속자 목록 렌더링
     */
    function renderUsers() {
        if (isUserSearchMode) return;
        const users = Object.values(lobbyUsers);
        userCount.textContent = users.length;

        if (users.length === 0) {
            usersList.innerHTML = '<div class="users-empty">접속자가 없습니다.</div>';
            return;
        }

        usersList.textContent = '';
        const fragment = document.createDocumentFragment();
        users.forEach((user) => {
            const row = createUserRowElement(user);
            fragment.appendChild(row);
        });
        usersList.appendChild(fragment);
        usersList.querySelectorAll('.user-item').forEach(bindUserItemEvents);
    }

    function setupUserContextMenu() {
        // ContextMenu 컴포넌트가 이벤트 처리
    }

    function openUserContextMenu(event, userId) {
        if (!userId) return;
        const items = ContextMenu.buildUserMenuItems({
            currentUserId,
            targetUserId: userId,
            isFriend: isFriendUser(userId),
        });
        ContextMenu.show(event, userId, items, handleUserContextAction);
    }

    function handleUserContextAction(action, targetId) {
        if (action === 'profile') window.location.href = `/users/${targetId}/`;
        else if (action === 'invite') Notifications.sendGameInvite(targetId);
        else if (action === 'friend') sendFriendRequest(targetId);
        else if (action === 'chat') {
            const globalDmFab = document.getElementById('global-dm-fab');
            if (globalDmFab) {
                if (chatSection && !chatSection.classList.contains('is-hidden')) {
                    chatSection.classList.add('is-hidden');
                }
                window.dispatchEvent(new CustomEvent('global-dm:open-room', { detail: { userId: targetId } }));
            } else {
                window.location.href = `/messages/${targetId}/`;
            }
        }
        else if (action === 'report') openReportForUser(targetId);
    }

    async function sendFriendRequest(targetId) {
        const res = await Utils.sendFriendRequest(targetId, currentUserId);
        if (res.success && res.accepted) {
            friendIds.add(targetId);
        }
    }

    async function openReportForUser(targetId) {
        if (!currentUserId) {
            Toast.error('로그인 시 가능합니다.');
            return;
        }
        if (targetId === currentUserId) {
            Toast.error('자기 자신은 신고할 수 없습니다.');
            return;
        }
        Utils.ReportModal.open(targetId);
    }

    function addUserToList(user) {
        if (isUserSearchMode) return;
        const existing = usersList.querySelector(`[data-user-id="${user.id}"]`);
        if (existing) return;

        const empty = usersList.querySelector('.users-empty');
        if (empty) {
            usersList.innerHTML = '';
        }

        const row = createUserRowElement(user);
        usersList.appendChild(row);
        const newItem = usersList.querySelector(`[data-user-id="${user.id}"]`);
        if (newItem) bindUserItemEvents(newItem);
        userCount.textContent = Object.keys(lobbyUsers).length;
    }

    function bindUserItemEvents(item) {
        const userId = parseInt(item.dataset.userId, 10);
        if (!userId) return;
        if (isTouchDevice) {
            item.addEventListener('click', (event) => {
                event.preventDefault();
                window.location.href = `/users/${userId}/`;
            });
        } else {
            item.addEventListener('contextmenu', (event) => {
                event.preventDefault();
                openUserContextMenu(event, userId);
            });
        }

        const menuBtn = item.querySelector('.user-menu-btn');
        if (menuBtn) {
            menuBtn.addEventListener('click', (event) => {
                event.stopPropagation();
                const rect = menuBtn.getBoundingClientRect();
                const fakeEvent = {
                    clientX: rect.left + rect.width / 2,
                    clientY: rect.bottom + 6,
                };
                openUserContextMenu(fakeEvent, userId);
            });
        }
    }

    function removeUserFromList(userId) {
        if (isUserSearchMode) return;
        const userEl = usersList.querySelector(`[data-user-id="${userId}"]`);
        if (userEl) {
            userEl.remove();
        }

        const remaining = Object.keys(lobbyUsers).length;
        userCount.textContent = remaining;
        if (remaining === 0) {
            usersList.innerHTML = '<div class="users-empty">접속자가 없습니다.</div>';
        }
    }

    function getPresenceViewModel(source, onlineFallback = true) {
        const isOnline = typeof source?.online === 'boolean' ? source.online : onlineFallback;
        return {
            online: isOnline,
            status: source?.status || (isOnline ? 'online' : 'offline'),
            label: source?.status_label || (isOnline ? '온라인' : '오프라인'),
        };
    }

    function getPresenceCssClass(status, online) {
        if (!online) return 'offline';
        const normalized = String(status || 'online');
        const supported = new Set([
            'online',
            'lobby',
            'room_waiting',
            'playing',
            'competitive',
            'quick',
            'ai_playing',
            'spectating',
            'puzzle',
        ]);
        return supported.has(normalized) ? normalized : 'online';
    }

    function createAchievementLabel(achievement) {
        if (!achievement?.title) return null;
        const badge = document.createElement('div');
        badge.className = `user-achievement user-achievement--${achievement.tone || 'info'}`;
        badge.textContent = `${achievement.icon || '🏅'} ${achievement.title}`;
        return badge;
    }

    function createUserRowElement(user, presenceSource = null) {
        const presence = getPresenceViewModel(presenceSource || user, true);
        const statusText = presence.label;
        const statusClass = getPresenceCssClass(presence.status, presence.online);
        const tier = user.rank_tier || user.stats?.rank_tier || 'Junior';
        const tierIcon = Utils.getTierIcon(tier);
        const nicknameColor = Utils.getNicknameColorValue(user.nickname_color || user.stats?.nickname_color || '');
        const profileRing = Utils.getProfileBorderValue(user.profile_border || user.stats?.profile_border || '');
        const row = document.createElement('div');
        row.className = 'user-item';
        row.dataset.userId = String(user.id);

        const avatar = document.createElement('div');
        avatar.className = 'user-avatar';
        if (profileRing) avatar.style.boxShadow = profileRing;
        Utils.setAvatar(avatar, {
            url: user.avatar_url,
            alt: user.nickname || '',
            placeholder: '👤',
            placeholderClass: 'avatar-placeholder',
        });
        row.appendChild(avatar);

        const info = document.createElement('div');
        info.className = 'user-info';

        const nick = document.createElement('div');
        nick.className = 'user-nickname';
        if (nicknameColor) nick.style.color = nicknameColor;
        nick.appendChild(document.createTextNode(user.nickname || ''));
        nick.appendChild(document.createTextNode(' '));
        const badge = document.createElement('span');
        badge.className = 'user-tier-icon';
        badge.title = tier;
        badge.textContent = tierIcon;
        nick.appendChild(badge);
        info.appendChild(nick);

        const achievement = createAchievementLabel(user.featured_achievement);
        if (achievement) {
            info.appendChild(achievement);
        }

        const status = document.createElement('div');
        status.className = `user-status ${statusClass}`;
        status.textContent = statusText;
        info.appendChild(status);
        row.appendChild(info);
        return row;
    }

    function styledUserInline(user, fallback = '플레이어') {
        const nickname = user?.nickname || fallback;
        const color = Utils.getNicknameColorValue(user?.nickname_color || user?.stats?.nickname_color || '');
        const ring = Utils.getProfileBorderValue(user?.profile_border || user?.stats?.profile_border || '');
        const wrapper = document.createElement('span');
        wrapper.style.display = 'inline-flex';
        wrapper.style.alignItems = 'center';
        wrapper.style.gap = '6px';

        const avatar = document.createElement('span');
        avatar.style.width = '20px';
        avatar.style.height = '20px';
        avatar.style.borderRadius = '50%';
        avatar.style.display = 'inline-flex';
        avatar.style.alignItems = 'center';
        avatar.style.justifyContent = 'center';
        avatar.style.overflow = 'hidden';
        avatar.style.background = 'rgba(255,255,255,.08)';
        if (ring) avatar.style.boxShadow = ring;
        Utils.setAvatar(avatar, {
            url: user?.avatar_url,
            alt: nickname,
            placeholder: '👤',
            placeholderClass: 'avatar-placeholder',
        });

        const name = document.createElement('span');
        name.style.fontWeight = '600';
        if (color) name.style.color = color;
        name.textContent = nickname;

        wrapper.appendChild(avatar);
        wrapper.appendChild(name);
        return wrapper;
    }

    function setupUserSearch() {
        if (!userSearchInput || !userSearchBtn || !userSearchReset) return;
        userSearchBtn.addEventListener('click', () => runUserSearch());
        userSearchInput.addEventListener('keydown', (event) => {
            if (event.key === 'Enter') runUserSearch();
        });
        userSearchReset.addEventListener('click', () => resetUserSearch());
    }

    async function runUserSearch() {
        const query = userSearchInput.value.trim();
        if (!query) {
            resetUserSearch();
            return;
        }
        try {
            const data = await API.get('/accounts/users/search/', { q: query });
            const results = data.results || [];
            isUserSearchMode = true;
            userCount.textContent = results.length;
            if (!results.length) {
                usersList.innerHTML = '<div class="users-empty">검색 결과가 없습니다.</div>';
                return;
            }
            const statusMap = await fetchOnlineStatusMap(results.map(user => user.id));
            usersList.textContent = '';
            const fragment = document.createDocumentFragment();
            results.forEach((user) => {
                fragment.appendChild(createUserRowElement(user, statusMap[user.id]));
            });
            usersList.appendChild(fragment);
            usersList.querySelectorAll('.user-item').forEach(bindUserItemEvents);
        } catch (error) {
            Toast.error(error.data?.message || '검색에 실패했습니다.');
        }
    }

    async function fetchOnlineStatusMap(ids) {
        if (!ids.length) return {};
        try {
            const data = await API.get('/accounts/online-status/', { ids: ids.join(',') });
            return (data.results || []).reduce((acc, entry) => {
                acc[entry.id] = entry;
                return acc;
            }, {});
        } catch (error) {
            return {};
        }
    }

    async function fetchOnlineUsersSnapshot() {
        try {
            const data = await API.get('/accounts/online-users/');
            return Array.isArray(data?.results) ? data.results : [];
        } catch (error) {
            return null;
        }
    }

    function mergeLobbyUsersSnapshot(users) {
        const nextUsers = {};
        Object.values(lobbyUsers).forEach((user) => {
            if (user?.is_guest) {
                nextUsers[user.id] = user;
            }
        });
        users.forEach((user) => {
            if (!user?.id) return;
            nextUsers[user.id] = user;
        });
        return nextUsers;
    }

    function buildLobbyUsersSignature(users) {
        return Object.values(users)
            .map((user) => {
                const id = user?.id ?? '';
                const status = user?.status ?? '';
                const label = user?.status_label ?? '';
                const guest = user?.is_guest ? 'guest' : 'user';
                return `${guest}:${id}:${status}:${label}`;
            })
            .sort()
            .join('|');
    }

    function startLobbyPresenceRefresh() {
        lobbyPresencePoller?.stop?.();
        lobbyPresencePoller = Utils.createAdaptivePoller({
            callback: refreshLobbyUsersSnapshot,
            activeInterval: 8000,
            hiddenInterval: 18000,
            enabled: () => Boolean(currentUserId),
            immediate: false,
        });
        lobbyPresencePoller.start();
        lobbyPresencePoller.trigger?.();
        window.addEventListener('beforeunload', () => lobbyPresencePoller?.stop?.(), { once: true });
    }

    async function refreshLobbyUsersSnapshot() {
        const onlineUsers = await fetchOnlineUsersSnapshot();
        if (!Array.isArray(onlineUsers)) return;
        const nextUsers = mergeLobbyUsersSnapshot(onlineUsers);
        const currentSignature = buildLobbyUsersSignature(lobbyUsers);
        const nextSignature = buildLobbyUsersSignature(nextUsers);
        if (currentSignature === nextSignature) return;
        lobbyUsers = nextUsers;
        if (!isUserSearchMode) {
            renderUsers();
        }
    }

    function resetUserSearch() {
        isUserSearchMode = false;
        if (userSearchInput) userSearchInput.value = '';
        renderUsers();
    }

    function upsertRoom(room) {
        if (!room || room.status !== 'waiting') {
            removeRoom(room?.id);
            return;
        }
        if (isHiddenRoomType(room)) {
            removeRoom(room.id);
            return;
        }

        const index = lobbyRooms.findIndex(item => item.id === room.id);
        if (index === -1) {
            lobbyRooms.unshift(room);
        } else {
            lobbyRooms[index] = room;
        }
        lobbyRooms = lobbyRooms.slice(0, 5);
        renderRooms(lobbyRooms);
    }

    function removeRoom(roomId) {
        if (!roomId) return;
        const nextRooms = lobbyRooms.filter(room => room.id !== roomId);
        if (nextRooms.length === lobbyRooms.length) return;
        lobbyRooms = nextRooms;
        renderRooms(lobbyRooms);
    }

    function isHiddenRoomType(room) {
        if (!room?.room_type) return false;
        // 매칭형 방은 대기/준비 상태만 숨기고, 게임 중은 관전 가능하게 노출
        if (MATCH_ROOM_TYPES.has(room.room_type)) {
            return room.status === 'waiting' || room.status === 'ready';
        }
        return false;
    }

    /**
     * 게스트 모드 설정
     */
    function setupGuestMode() {
        // 게스트 플레이 버튼 클릭
        guestPlayBtn?.addEventListener('click', async () => {
            gameStartModal?.classList.add('hidden');
            if (typeof Guest === 'undefined') return;

            const result = await Guest.showLoginModal();
            if (result) {
                // 게스트 세션 생성 성공 - 페이지 새로고침
                Toast.success('게스트로 시작합니다!');
                setTimeout(() => window.location.reload(), 500);
            }
        });

        // 게스트 로그아웃 버튼
        guestLogoutBtn?.addEventListener('click', async () => {
            if (typeof Guest === 'undefined') return;

            const confirmed = await Modal.confirm('게스트 세션을 종료하시겠습니까?', {
                title: '게스트 종료',
                confirmText: '종료',
                cancelText: '취소'
            });

            if (confirmed) {
                await Guest.endSession();
                Toast.info('게스트 세션이 종료되었습니다.');
                setTimeout(() => window.location.reload(), 500);
            }
        });

        // 게스트 타이머 업데이트 이벤트 리스너
        window.addEventListener('guest:timer-update', (e) => {
            if (guestStatusTimer) {
                guestStatusTimer.textContent = e.detail.remaining;
            }
        });
    }

    /**
     * 게스트 세션 초기화
     */
    function setupGuestSession() {
        if (typeof Guest === 'undefined') return;

        const session = Guest.getSession();
        if (!session) return;

        // 로비 전용 게스트 상태바 표시 (글로벌은 숨김)
        const globalStatusBar = document.getElementById('guest-status-bar-global');
        globalStatusBar?.classList.add('hidden');

        if (guestStatusBar) {
            guestStatusBar.classList.remove('hidden');
        }
        if (guestStatusName) {
            guestStatusName.textContent = session.display_name;
        }
        if (guestStatusTimer) {
            guestStatusTimer.textContent = Guest.getRemainingText();
        }

        // 게스트 플레이 버튼 숨김
        guestPlayBtn?.classList.add('hidden');

        // 채팅 비활성화 (게스트는 채팅 불가)
        chatInput.disabled = true;
        chatForm.querySelector('button').disabled = true;
        if (chatMessages) {
            chatMessages.innerHTML = '<div class="chat-notice">게스트는 채팅을 이용할 수 없습니다.</div>';
        }

        // 경쟁전만 비활성화 (레이팅 게임)
        quickMatchBtn?.classList.add('btn-disabled');
        quickMatchBtn?.setAttribute('title', '게스트는 경쟁전을 이용할 수 없습니다.');

        // 빠른 대전 이벤트 설정 (AI 대전은 init에서 이미 설정됨)
        // WebSocket 연결 (접속자 목록용)
        connectLobbyChat();
    }

})();
