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
    const reportModal = document.getElementById('report-modal');
    const aiMatchModal = document.getElementById('ai-match-modal');
    const aiMatchCancel = document.getElementById('ai-match-cancel');
    const quickMatchModal = document.getElementById('quick-match-modal');
    const randomMatchModal = document.getElementById('random-match-modal');
    const quickMatchCancel = document.getElementById('quick-match-cancel');
    const randomMatchCancel = document.getElementById('random-match-cancel');
    const quickMatchWait = document.getElementById('quick-match-wait');
    const randomMatchWait = document.getElementById('random-match-wait');
    const quickMatchLoading = document.getElementById('quick-match-loading');
    const randomMatchLoading = document.getElementById('random-match-loading');
    const matchToast = document.getElementById('match-toast');
    const aiLevelButtons = Array.from(document.querySelectorAll('.ai-level-btn'));
    const aiLevelLoading = document.getElementById('ai-level-loading');

    let isMatching = false;
    let isRandomMatching = false;
    let isAiMatching = false;
    let lobbySocket = null;
    let notificationSocket = null;
    let currentUserId = null;
    let isSuspended = false;
    let friendIds = new Set();
    let lobbyUsers = {};
    let lobbyRooms = [];
    let roomRefreshInterval = null;
    let chatUnread = 0;
    let isChatOpen = true;
    let userContextMenu = null;
    let longPressTimer = null;
    const isTouchDevice = 'ontouchstart' in window || navigator.maxTouchPoints > 0;
    let isUserSearchMode = false;
    let lastRoomsSignature = null;
    let lastWaitingSignature = '';
    let waitingTick = 0;
    const HIDDEN_ROOM_TYPES = new Set(['quick', 'random']);
    let activeMatchToast = null;

    // 초기화
    init();

    async function init() {
        await loadRooms();
        await loadWaitingRoom();
        await loadActiveGame();
        await checkAuthAndSetupChat();
        startRoomAutoRefresh();
        setupMobileTabs();
        setupTierToggle();
        setupAiMatch();
        setupReportModal();
        setupUserContextMenu();
        setupUserSearch();
    }

    /**
     * 방 목록 로드
     */
    async function loadRooms() {
        try {
            const data = await API.get('/chess/rooms/', { status: 'waiting', limit: 5, no_count: 1 });
            const rawRooms = Array.isArray(data?.results)
                ? data.results
                : (Array.isArray(data) ? data : []);
            const rooms = rawRooms.filter((room) => !isHiddenRoomType(room));
            const signature = rooms
                .map((room) => `${room.id}:${room.status}:${room.guest?.id || 0}:${room.current_game_id || 0}`)
                .join('|');
            const isLoading = roomList && roomList.querySelector('.loading-placeholder');
            if (signature !== lastRoomsSignature || isLoading) {
                lastRoomsSignature = signature;
                lobbyRooms = rooms;
                try {
                    renderRooms(lobbyRooms);
                } catch (renderError) {
                    console.error('Failed to render rooms:', renderError);
                    roomList.innerHTML = '<div class="room-empty">방 목록을 불러올 수 없습니다.</div>';
                }
            }
        } catch (error) {
            roomList.innerHTML = '<div class="room-empty">방 목록을 불러올 수 없습니다.</div>';
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
            waitingRoomInfo.textContent = `${Utils.escapeHtml(title)} · ${timeText}`;
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
                return;
            }
            activeGameCard.classList.remove('hidden');
            const white = room.host?.nickname || '화이트';
            const black = room.guest?.nickname || '블랙';
            activeGameInfo.textContent = `${white} vs ${black}`;
            activeGameEnter.onclick = () => {
                window.location.href = `/games/${room.current_game_id}/`;
            };
            activeGameCard.onclick = () => {
                window.location.href = `/games/${room.current_game_id}/`;
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
                        ${Utils.escapeHtml(room.host?.nickname || '호스트')} ·
                        ${room.time_limit ? `${room.time_limit}분` : '무제한'}
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
        roomRefreshInterval = setInterval(() => {
            if (document.hidden) return;
            loadRooms();
            waitingTick += 1;
            if (isMatching || waitingTick % 3 === 0) {
                loadWaitingRoom();
            }
            if (waitingTick % 3 === 0) {
                loadActiveGame();
            }
        }, 5000);

        window.addEventListener('beforeunload', () => {
            if (roomRefreshInterval) clearInterval(roomRefreshInterval);
        });

        document.addEventListener('visibilitychange', () => {
            if (document.hidden) return;
            loadRooms();
            loadWaitingRoom();
            loadActiveGame();
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
                window.location.href = `/games/${room.current_game_id}/`;
            } else {
                Toast.error('관전 가능한 게임 정보를 찾을 수 없습니다.');
            }
            return;
        }

        if (room.guest || room.player_count >= 2) {
            Toast.error('이미 인원이 찬 방입니다.');
            return;
        }

        let payload = {};
        if (room.is_private) {
            const password = prompt('비밀번호를 입력하세요:');
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
            await loadFriendIds();
            setupChat();
            setupQuickMatch();
            setupRandomMatch();
            // lobby report removed; using profile report actions instead
            if (user.is_muted) {
                setChatMutedState(true, user.mute_reason || '');
            }
            if (user.is_suspended) {
                setSuspendedState(true, user.suspension_reason || '');
            }
            connectNotificationSocket();
        } catch (error) {
            // 비로그인 상태 - 채팅 비활성화
            chatInput.disabled = true;
            chatForm.querySelector('button').disabled = true;
            if (chatMessages) {
                chatMessages.innerHTML = '<div class="chat-notice">로그인 시 가능합니다.</div>';
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
        quickMatchBtn.addEventListener('click', async function() {
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
    }

    /**
     * 랜덤 대전 설정
     */
    function setupRandomMatch() {
        if (!randomMatchBtn) return;
        randomMatchBtn.addEventListener('click', async function() {
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
    }

    function setupAiMatch() {
        if (!aiMatchBtn) return;
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
            if (!currentUserId) {
                Toast.error('로그인 시 가능합니다.');
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
                Toast.success('매칭되었습니다!');
                window.location.href = `/games/${result.room_id}/`;
            } else if (result.status === 'waiting') {
                // 대기 중 - 폴링 시작
                Toast.info('상대를 찾는 중...');
                pollMatchStatus();
            }
        } catch (error) {
            setMatchingState(false);
            Toast.error(error.data?.message || '매칭 시작에 실패했습니다.');
        }
    }

    async function startRandomMatch() {
        setRandomMatchingState(true);

        try {
            const result = await API.post('/chess/random-match/');

            if (result.status === 'matched') {
                Toast.success('매칭되었습니다!');
                window.location.href = `/games/${result.room_id}/`;
            } else if (result.status === 'waiting') {
                Toast.info('상대를 찾는 중...');
                pollRandomMatchStatus();
            }
        } catch (error) {
            setRandomMatchingState(false);
            Toast.error(error.data?.message || '매칭 시작에 실패했습니다.');
        }
    }

    /**
     * 매칭 취소
     */
    async function cancelMatch() {
        try {
            await API.post('/chess/quick-match/cancel/');
            setMatchingState(false);
            Toast.info('매칭이 취소되었습니다.');
        } catch (error) {
            Toast.error('매칭 취소에 실패했습니다.');
        }
    }

    async function cancelRandomMatch() {
        try {
            await API.post('/chess/random-match/cancel/');
            setRandomMatchingState(false);
            Toast.info('매칭이 취소되었습니다.');
        } catch (error) {
            Toast.error('매칭 취소에 실패했습니다.');
        }
    }

    /**
     * 매칭 상태 폴링
     */
    function pollMatchStatus() {
        if (!isMatching) return;

        const pollInterval = setInterval(async () => {
            if (!isMatching) {
                clearInterval(pollInterval);
                return;
            }

            try {
                const result = await API.post('/chess/quick-match/');

                if (result.status === 'matched') {
                    clearInterval(pollInterval);
                    Toast.success('매칭되었습니다!');
                    window.location.href = `/games/${result.room_id}/`;
                }
            } catch (error) {
                clearInterval(pollInterval);
                setMatchingState(false);
            }
        }, 2000);
    }

    function pollRandomMatchStatus() {
        if (!isRandomMatching) return;

        const pollInterval = setInterval(async () => {
            if (!isRandomMatching) {
                clearInterval(pollInterval);
                return;
            }

            try {
                const result = await API.post('/chess/random-match/');

                if (result.status === 'matched') {
                    clearInterval(pollInterval);
                    Toast.success('매칭되었습니다!');
                    window.location.href = `/games/${result.room_id}/`;
                }
            } catch (error) {
                clearInterval(pollInterval);
                setRandomMatchingState(false);
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
        quickMatchBtn.disabled = matching;
        quickMatchLoading?.classList.toggle('hidden', !matching);
        if (matching) {
            quickMatchModal?.classList.remove('hidden');
            showMatchToast('경쟁전 매칭 중...', 'quick');
            waitingRoomCard?.classList.add('hidden');
        } else {
            quickMatchModal?.classList.add('hidden');
            hideMatchToast();
        }
    }

    function setRandomMatchingState(matching) {
        isRandomMatching = matching;
        if (!randomMatchBtn) return;
        randomMatchBtn.classList.toggle('btn-danger', matching);
        randomMatchBtn.disabled = matching;
        randomMatchLoading?.classList.toggle('hidden', !matching);
        if (matching) {
            randomMatchModal?.classList.remove('hidden');
            showMatchToast('빠른 대전 매칭 중...', 'random');
            waitingRoomCard?.classList.add('hidden');
        } else {
            randomMatchModal?.classList.add('hidden');
            hideMatchToast();
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

        // WebSocket 연결
        connectLobbyChat();

        // 메시지 전송
        chatForm.addEventListener('submit', function(e) {
            e.preventDefault();
            sendChatMessage();
        });
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
        const wsUrl = `${protocol}//${window.location.host}/ws/lobby/`;

        lobbySocket = new WebSocket(wsUrl);

        lobbySocket.onopen = function() {
            addChatNotice('채팅에 연결되었습니다.');
        };

        lobbySocket.onmessage = function(e) {
            const data = JSON.parse(e.data);
            handleChatMessage(data);
        };

        lobbySocket.onclose = function() {
            addChatNotice('채팅 연결이 끊어졌습니다.');
            // 재연결 시도
            setTimeout(connectLobbyChat, 3000);
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
        } else if (data.type === 'recent_messages') {
            // 최근 메시지 로드
            chatMessages.innerHTML = '';
            const messages = (data.messages || []).slice().sort((a, b) => {
                return new Date(a.sent_at) - new Date(b.sent_at);
            });
            messages.forEach(msg => addChatMessage(msg));
            chatMessages.scrollTop = chatMessages.scrollHeight;
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
        } else if (data.type === 'room_removed') {
            removeRoom(data.room_id);
        } else if (data.type === 'error') {
            Toast.error(data.message);
        }
    }

    function connectNotificationSocket() {
        if (notificationSocket || !currentUserId) return;
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/notifications/`;
        notificationSocket = new WebSocket(wsUrl);

        notificationSocket.onmessage = function(e) {
            const data = JSON.parse(e.data);
            if (data.type === 'chat_mute') {
                setChatMutedState(true, data.payload?.reason || '');
                Toast.error(data.message || '채팅이 제한되었습니다.');
            } else if (data.type === 'account_suspended') {
                setSuspendedState(true, data.payload?.reason || '');
                Toast.error(data.message || '계정이 정지되었습니다.');
            } else if (data.type === 'chat_unmute') {
                setChatMutedState(false);
                Toast.success(data.message || '채팅 제한이 해제되었습니다.');
            } else if (data.type === 'account_unsuspended') {
                setSuspendedState(false);
                Toast.success(data.message || '계정 정지가 해제되었습니다.');
            }
        };
    }

    function setChatMutedState(muted, reason = '') {
        if (muted) {
            chatInput.disabled = true;
            chatForm.querySelector('button').disabled = true;
            if (reason) {
                addChatNotice(`채팅 제한됨: ${reason}`);
            } else {
                addChatNotice('채팅이 제한되었습니다.');
            }
        } else {
            chatInput.disabled = false;
            chatForm.querySelector('button').disabled = false;
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
        const avatar = !isMine
            ? (data.avatar_url
                ? `<img src="${Utils.escapeHtml(data.avatar_url)}" alt="">`
                : '<span class="avatar-placeholder">?</span>')
            : '';
        const messageEl = document.createElement('div');
        messageEl.className = `chat-message ${isMine ? 'mine' : 'others'}`;
        messageEl.innerHTML = `
            ${!isMine ? `<div class="chat-avatar">${avatar}</div>` : ''}
            <div class="chat-content">
                <span class="chat-nickname">${Utils.escapeHtml(data.nickname)}</span>
                <div class="chat-bubble">${Utils.escapeHtml(data.message)}</div>
            </div>
            <span class="chat-time">${formatChatTime(data.sent_at)}</span>
        `;
        chatMessages.appendChild(messageEl);
        chatMessages.scrollTop = chatMessages.scrollHeight;
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
                    if (chatSection) chatSection.classList.remove('is-hidden');
                    chatMessages.scrollTop = chatMessages.scrollHeight;
                    resetChatBadge();
                } else {
                    isChatOpen = false;
                    if (chatSection) chatSection.classList.add('is-hidden');
                }
            });
        });
        isChatOpen = false;
        if (chatSection) chatSection.classList.add('is-hidden');
    }

    function setupTierToggle() {
        if (!tierToggle || !tierPanel) return;
        tierToggle.addEventListener('click', () => {
            const willOpen = tierPanel.classList.contains('hidden');
            tierPanel.classList.toggle('hidden', !willOpen);
            tierToggle.setAttribute('aria-expanded', String(willOpen));
        });
        if (!modeToggle || !modePanel) return;
        modeToggle.addEventListener('click', () => {
            const willOpen = modePanel.classList.contains('hidden');
            modePanel.classList.toggle('hidden', !willOpen);
            modeToggle.setAttribute('aria-expanded', String(willOpen));
        });
    }

    function setupReportModal() {
        if (!reportModal) return;
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

        usersList.innerHTML = users.map(user => userRowHtml(user, true)).join('');

        usersList.querySelectorAll('.user-item').forEach(bindUserItemEvents);
    }

    function setupUserContextMenu() {
        document.addEventListener('click', hideUserContextMenu);
        document.addEventListener('scroll', hideUserContextMenu, true);
        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape') hideUserContextMenu();
        });
    }

    function openUserContextMenu(event, userId) {
        if (!userId) return;
        if (!userContextMenu) {
            userContextMenu = document.createElement('div');
            userContextMenu.className = 'context-menu hidden';
            document.body.appendChild(userContextMenu);
            userContextMenu.addEventListener('click', (e) => {
                const action = e.target.closest('.context-menu-item')?.dataset.action;
                const targetId = parseInt(userContextMenu.dataset.userId, 10);
                if (!action || !targetId) return;
                if (action === 'profile') {
                    window.location.href = `/users/${targetId}/`;
                } else if (action === 'friend') {
                    sendFriendRequest(targetId);
                } else if (action === 'chat') {
                    window.location.href = `/messages/${targetId}/`;
                } else if (action === 'report') {
                    openReportForUser(targetId);
                }
                hideUserContextMenu();
            });
        }

        const canFriend = currentUserId && userId !== currentUserId && !isFriendUser(userId);
        const canChat = currentUserId && userId !== currentUserId;
        const canReport = currentUserId && userId !== currentUserId;
        const items = [
            { action: 'profile', label: '프로필 보기' },
            ...(canFriend ? [{ action: 'friend', label: '친구 추가' }] : []),
            ...(canChat ? [{ action: 'chat', label: '1:1 채팅' }] : []),
            ...(canReport ? [{ action: 'report', label: '신고하기' }] : []),
        ];
        userContextMenu.innerHTML = items.map(item => (
            `<div class="context-menu-item" data-action="${item.action}">${item.label}</div>`
        )).join('');

        userContextMenu.dataset.userId = `${userId}`;
        positionUserContextMenu(event);
        userContextMenu.classList.remove('hidden');
    }

    function positionUserContextMenu(event) {
        if (!userContextMenu) return;
        const padding = 8;
        const rect = userContextMenu.getBoundingClientRect();
        const clientX = event.touches?.[0]?.clientX ?? event.clientX;
        const clientY = event.touches?.[0]?.clientY ?? event.clientY;
        const maxX = window.innerWidth - rect.width - padding;
        const maxY = window.innerHeight - rect.height - padding;
        const left = Math.min(clientX, maxX);
        const top = Math.min(clientY, maxY);
        userContextMenu.style.left = `${left}px`;
        userContextMenu.style.top = `${top}px`;
    }

    function hideUserContextMenu() {
        if (userContextMenu) userContextMenu.classList.add('hidden');
    }

    async function sendFriendRequest(targetId) {
        if (!currentUserId) {
            Toast.error('로그인 시 가능합니다.');
            return;
        }
        if (targetId === currentUserId) {
            Toast.error('자기 자신에게 요청할 수 없습니다.');
            return;
        }
        try {
            const result = await API.post('/accounts/friends/requests/', { user_id: targetId });
            if (result.status === 'accepted') {
                friendIds.add(targetId);
                Toast.success('친구 요청이 자동 수락되었습니다.');
            } else {
                Toast.success('친구 요청을 보냈습니다.');
            }
        } catch (error) {
            Toast.error(error.data?.message || '친구 요청에 실패했습니다.');
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

        usersList.insertAdjacentHTML('beforeend', userRowHtml(user, true));
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

    function userRowHtml(user, online = true) {
        const statusText = online ? '온라인' : '오프라인';
        const statusClass = online ? 'online' : 'offline';
        const tier = user.rank_tier || user.stats?.rank_tier || 'Junior';
        const tierIcon = Utils.getTierIcon(tier);
        return `
            <div class="user-item" data-user-id="${user.id}">
                <div class="user-avatar">
                    ${user.avatar_url
                        ? `<img src="${Utils.escapeHtml(user.avatar_url)}" alt="">`
                        : '👤'}
                </div>
                <div class="user-info">
                    <div class="user-nickname">
                        ${Utils.escapeHtml(user.nickname)}
                        <span class="user-tier-icon" title="${Utils.escapeHtml(tier)}">${tierIcon}</span>
                    </div>
                    <div class="user-status ${statusClass}">${statusText}</div>
                </div>
            </div>
        `;
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
            usersList.innerHTML = results.map(user => userRowHtml(user, statusMap[user.id] === true)).join('');
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
                acc[entry.id] = entry.online;
                return acc;
            }, {});
        } catch (error) {
            return {};
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
        return HIDDEN_ROOM_TYPES.has(room?.room_type);
    }
})();
