/**
 * Room Waiting Page Logic
 * - 방 정보 로드/실시간 업데이트
 * - 준비/시작 플로우
 * - 대기실 채팅
 */

(function() {
    'use strict';

    // DOM Elements
    const roomTitle = document.getElementById('room-title');
    const roomTime = document.getElementById('room-time');
    const roomSpectators = document.getElementById('room-spectators');
    const hostSlot = document.getElementById('host-slot');
    const guestSlot = document.getElementById('guest-slot');
    const vsRecord = document.getElementById('vs-record');
    const actionButtons = document.getElementById('action-buttons');
    const leaveBtn = document.getElementById('leave-btn');
    const chatMessages = document.getElementById('chat-messages');
    const chatForm = document.getElementById('chat-form');
    const chatInput = document.getElementById('chat-input');
    const mobileTabbar = document.getElementById('mobile-tabbar');
    const chatBadge = document.getElementById('chat-badge');
    const chatSection = document.querySelector('.room-chat-section');
    const lobbyWaitBtn = document.getElementById('lobby-wait-btn');
    const inviteFriendSelect = document.getElementById('invite-friend-select');
    const inviteFriendBtn = document.getElementById('invite-friend-btn');

    // State
    const roomId = Utils.getPathParam(/\/rooms\/(\d+)/);
    let room = null;
    let currentUser = null;
    let socket = null;
    let isHost = false;
    let heartbeatInterval = null;
    let roomPollInterval = null;
    let chatUnread = 0;
    let isChatOpen = true;
    let lastRoomState = null;
    let wsReconnectAttempts = 0;
    const WS_MAX_RECONNECT = 10;
    const WS_BASE_DELAY = 1000;

    // Init
    init();

    async function init() {
        if (!roomId) {
            Toast.error('잘못된 접근입니다.');
            window.location.href = '/rooms/';
            return;
        }

        try {
            currentUser = await API.get('/accounts/me/');
        } catch {
            Toast.error('로그인 시 가능합니다.');
            window.location.href = '/login/';
            return;
        }

        await loadRoom();
        setupLeaveButton();
        setupLobbyWait();
        setupInvitePanel();
        setupChat();
        setupExitGuard();
        startRoomPolling();
        setupMobileTabs();
        connectWebSocket();
    }

    async function setupInvitePanel() {
        if (!inviteFriendSelect || !inviteFriendBtn) return;
        if (!currentUser?.id) return;
        try {
            const data = await API.get('/accounts/friends/');
            const list = data?.results || [];
            const options = list
                .map((item) => item?.friend)
                .filter(Boolean)
                .map((user) => `<option value="${user.id}">${Utils.escapeHtml(user.nickname)} (${user.rating ?? 1200})</option>`)
                .join('');
            inviteFriendSelect.innerHTML = `<option value="">친구 선택</option>${options}`;
        } catch {
            inviteFriendSelect.innerHTML = '<option value="">친구 목록 불러오기 실패</option>';
        }

        inviteFriendBtn.addEventListener('click', async () => {
            const targetId = parseInt(inviteFriendSelect.value, 10);
            if (!targetId) {
                Toast.error('초대할 친구를 선택해주세요.');
                return;
            }
            const ok = await Notifications?.sendGameInvite?.(targetId, room?.time_limit || 10);
            if (ok) Toast.success('게임 초대를 보냈습니다.');
        });
    }

    /**
     * 방 정보 로드
     */
    async function loadRoom() {
        try {
            const newRoom = await API.get(`/chess/rooms/${roomId}/`);
            applyRoomUpdate(newRoom);
        } catch (error) {
            Toast.error('방을 찾을 수 없습니다.');
            window.location.href = '/rooms/';
        }
    }

    /**
     * 방 정보 렌더링
     */
    function renderRoom() {
        // Header
        const defaultTitle = room.room_type === 'random' ? '랜덤 대전' : '빠른 대전';
        roomTitle.textContent = room.title || defaultTitle;
        roomTime.textContent = `⏱ ${room.time_limit ? room.time_limit + '분' : '무제한'}`;
        roomSpectators.textContent = room.allow_spectators ? '👁 관전 가능' : '👁 관전 불가';

        // Host
        renderPlayer(hostSlot, room.host, room.host_ready, room.host_start_confirmed, true);

        // Guest
        if (room.guest) {
            renderPlayer(guestSlot, room.guest, room.guest_ready, room.guest_start_confirmed, false);
        } else {
            guestSlot.innerHTML = `
                <div class="player-card empty">
                    <div class="avatar avatar-lg">
                        <span class="avatar-placeholder">?</span>
                    </div>
                    <div class="player-info">
                        <div class="player-name">상대 대기 중...</div>
                        <div class="player-rating">--</div>
                    </div>
                    <div class="player-status">
                        <span class="status-badge">--</span>
                    </div>
                </div>
            `;
        }

        // Action Buttons
        renderActionButtons();

        // 1:1 전적 로드
        loadVsRecord();

        // 게임 시작 체크
        if (room.status === 'playing') {
            Toast.success('게임이 시작됩니다!');
            window.location.href = `/games/${room.id}/`;
        }
    }

    function applyRoomUpdate(newRoom) {
        const prev = room;
        room = newRoom;
        isHost = room.host?.id === currentUser.id;
        if (prev) {
            handleRoomStateChange(prev, room);
        }
        renderRoom();
        lastRoomState = {
            host_ready: room.host_ready,
            guest_ready: room.guest_ready,
            host_start_confirmed: room.host_start_confirmed,
            guest_start_confirmed: room.guest_start_confirmed,
        };
    }

    function handleRoomStateChange(prev, next) {
        const opponent = isHost ? next.guest : next.host;
        if (!opponent) return;

        const prevOpponentReady = isHost ? prev.guest_ready : prev.host_ready;
        const nextOpponentReady = isHost ? next.guest_ready : next.host_ready;
        if (prevOpponentReady === false && nextOpponentReady === true) {
            showStatusModal('상대가 준비 완료했습니다.');
        }

        const prevOpponentConfirm = isHost ? prev.guest_start_confirmed : prev.host_start_confirmed;
        const nextOpponentConfirm = isHost ? next.guest_start_confirmed : next.host_start_confirmed;
        if (prevOpponentConfirm === false && nextOpponentConfirm === true) {
            showStatusModal('상대가 게임 시작을 눌렀습니다. 시작 버튼을 눌러주세요.');
        }
    }

    /**
     * 1:1 전적 로드
     */
    async function loadVsRecord() {
        if (!vsRecord || !room.guest) {
            vsRecord?.classList.add('hidden');
            return;
        }

        const opponentId = isHost ? room.guest.id : room.host.id;
        if (!opponentId) {
            vsRecord.classList.add('hidden');
            return;
        }

        try {
            const data = await API.get(`/accounts/users/${opponentId}/profile/`);
            const vs = data.vs_summary;
            if (!vs || (vs.wins === 0 && vs.losses === 0 && vs.draws === 0)) {
                vsRecord.classList.add('hidden');
                return;
            }

            vsRecord.classList.remove('hidden');
            vsRecord.innerHTML = `
                <div class="record-label">1:1 전적</div>
                <div class="record-stat">
                    <span class="win">${vs.wins}승</span>
                    <span class="lose">${vs.losses}패</span>
                    <span class="draw">${vs.draws}무</span>
                </div>
            `;
        } catch {
            vsRecord.classList.add('hidden');
        }
    }

    /**
     * 플레이어 렌더링
     */
    function renderPlayer(slot, player, isReady, isConfirmed, isHostPlayer) {
        const cardClass = isConfirmed ? 'confirmed' : (isReady ? 'ready' : '');
        const statusClass = isConfirmed ? 'confirmed' : (isReady ? 'ready' : '');
        const statusText = isConfirmed ? '시작 확인' : (isReady ? '준비 완료' : '대기');

        slot.innerHTML = `
            <div class="player-card ${cardClass}">
                <div class="avatar avatar-lg">
                    ${player?.avatar_url
                        ? `<img src="${Utils.escapeHtml(player.avatar_url)}" alt="${Utils.escapeHtml(player?.nickname || '플레이어')}">`
                        : '<span class="avatar-placeholder">?</span>'}
                </div>
                <div class="player-info">
                    <div class="player-name">${Utils.escapeHtml(player?.nickname || '플레이어')}</div>
                    <div class="player-rating">${player?.rating || 1500} ${player?.rank_tier ? '(' + player.rank_tier + ')' : ''}</div>
                </div>
                <div class="player-status">
                    <span class="status-badge ${statusClass}">${statusText}</span>
                </div>
            </div>
        `;
    }

    /**
     * 액션 버튼 렌더링
     */
    function renderActionButtons() {
        const isGuest = room.guest?.id === currentUser.id;
        const isPlayer = isHost || isGuest;
        const myReady = isHost ? room.host_ready : room.guest_ready;
        const bothReady = room.host_ready && room.guest_ready;
        const myConfirmed = isHost ? room.host_start_confirmed : room.guest_start_confirmed;

        let html = '';

        if (!isPlayer) {
            // 관전자
            html = '<span class="text-muted">관전 중입니다</span>';
        } else if (!room.guest) {
            // 게스트 없음
            html = '<span class="text-muted">상대를 기다리는 중...</span>';
        } else if (!bothReady) {
            // 준비 단계
            if (myReady) {
                html = `<button class="btn btn-secondary btn-lg" id="unready-btn">준비 취소</button>`;
            } else {
                html = `<button class="btn btn-success btn-arcade btn-lg" id="ready-btn">준비</button>`;
            }
        } else {
            // 시작 확인 단계
            if (myConfirmed) {
                html = `<span class="text-muted">상대의 시작 확인을 기다리는 중...</span>`;
            } else {
                html = `<button class="btn btn-primary btn-arcade btn-lg" id="start-btn">게임 시작</button>`;
            }
        }

        actionButtons.innerHTML = html;

        // 이벤트 바인딩
        const readyBtn = document.getElementById('ready-btn');
        const unreadyBtn = document.getElementById('unready-btn');
        const startBtn = document.getElementById('start-btn');

        if (readyBtn) {
            readyBtn.addEventListener('click', () => setReady(true));
        }
        if (unreadyBtn) {
            unreadyBtn.addEventListener('click', () => setReady(false));
        }
        if (startBtn) {
            startBtn.addEventListener('click', confirmStart);
        }
    }

    /**
     * 준비 상태 설정
     */
    async function setReady(ready) {
        try {
            const result = await API.post(`/chess/rooms/${roomId}/ready/`, { ready });
            room.host_ready = result.host_ready;
            room.guest_ready = result.guest_ready;
            room.status = result.status;
            renderRoom();
            Toast.info(ready ? '준비 완료!' : '준비 취소');
        } catch (error) {
            Toast.error(error.data?.message || '준비 상태 변경에 실패했습니다.');
        }
    }

    /**
     * 게임 시작 확인
     */
    async function confirmStart() {
        try {
            const result = await API.post(`/chess/rooms/${roomId}/start/`);
            room.host_start_confirmed = result.host_start_confirmed;
            room.guest_start_confirmed = result.guest_start_confirmed;
            room.status = result.status;

            if (result.game_id) {
                Toast.success('게임이 시작됩니다!');
                window.location.href = `/games/${roomId}/`;
            } else {
                renderRoom();
                Toast.info('상대의 시작 확인을 기다리는 중...');
            }
        } catch (error) {
            Toast.error(error.data?.message || '게임 시작에 실패했습니다.');
        }
    }

    /**
     * 나가기 버튼 설정
     */
    function setupLeaveButton() {
        leaveBtn.addEventListener('click', async () => {
            if (!confirm('정말 방을 나가시겠습니까?')) return;

            try {
                await API.post(`/chess/rooms/${roomId}/leave/`);
                Toast.info('방을 나갔습니다.');
                window.location.href = '/rooms/';
            } catch (error) {
                Toast.error(error.data?.message || '나가기에 실패했습니다.');
            }
        });
    }

    function setupLobbyWait() {
        if (!lobbyWaitBtn) return;
        lobbyWaitBtn.addEventListener('click', () => {
            window.location.href = '/';
        });
    }

    /**
     * 채팅 설정
     */
    function setupChat() {
        chatForm.addEventListener('submit', (e) => {
            e.preventDefault();
            sendChatMessage();
        });
    }

    function showStatusModal(message) {
        Toast.info(message);
        playStatusTone();
    }

    function playStatusTone() {
        try {
            const context = new (window.AudioContext || window.webkitAudioContext)();
            const osc = context.createOscillator();
            const gain = context.createGain();
            osc.type = 'triangle';
            osc.frequency.setValueAtTime(880, context.currentTime);
            osc.frequency.exponentialRampToValueAtTime(660, context.currentTime + 0.18);
            gain.gain.setValueAtTime(0.0001, context.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.2, context.currentTime + 0.02);
            gain.gain.exponentialRampToValueAtTime(0.0001, context.currentTime + 0.2);
            osc.connect(gain).connect(context.destination);
            osc.start();
            osc.stop(context.currentTime + 0.22);
        } catch {
            // noop
        }
    }

    /**
     * WebSocket 연결
     */
    function connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        let wsUrl = `${protocol}//${window.location.host}/ws/chess/${roomId}/`;

        // 게스트 토큰이 있으면 쿼리 파라미터로 추가
        const guestToken = localStorage.getItem('guest_token');
        if (guestToken) {
            wsUrl += `?guest_token=${encodeURIComponent(guestToken)}`;
        }

        socket = new WebSocket(wsUrl);

        socket.onopen = () => {
            addChatNotice('연결되었습니다.');
            wsReconnectAttempts = 0;
            startHeartbeat();
        };

        socket.onmessage = (e) => {
            const data = JSON.parse(e.data);
            handleSocketMessage(data);
        };

        socket.onclose = () => {
            addChatNotice('연결이 끊어졌습니다.');
            stopHeartbeat();
            if (wsReconnectAttempts >= WS_MAX_RECONNECT) {
                addChatNotice('재연결 실패. 페이지를 새로고침해 주세요.');
                return;
            }
            wsReconnectAttempts += 1;
            const delay = Math.min(WS_BASE_DELAY * Math.pow(2, wsReconnectAttempts - 1), 30000);
            setTimeout(connectWebSocket, delay);
        };

        socket.onerror = () => {
            addChatNotice('연결 오류가 발생했습니다.');
        };
    }

    /**
     * WebSocket 메시지 처리
     */
    function handleSocketMessage(data) {
        switch (data.type) {
            case 'chat':
                addChatMessage(data);
                handleChatBadge(data);
                break;
            case 'room_update':
                // 방 상태 업데이트
                applyRoomUpdate(data.room);
                break;
            case 'game_start':
                Toast.success('게임이 시작됩니다!');
                window.location.href = `/games/${roomId}/`;
                break;
            case 'player_joined':
                Toast.info(`${data.player.nickname}님이 입장했습니다.`);
                loadRoom(); // 방 정보 새로고침
                break;
            case 'player_left':
                Toast.info('상대가 나갔습니다.');
                loadRoom();
                break;
            case 'error':
                Toast.error(data.message);
                break;
            case 'heartbeat_ack':
                // Heartbeat 응답
                break;
        }
    }

    /**
     * 채팅 메시지 전송
     */
    function sendChatMessage() {
        const message = chatInput.value.trim();
        if (!message || !socket || socket.readyState !== WebSocket.OPEN) return;

        socket.send(JSON.stringify({
            action: 'chat',
            message: message
        }));

        chatInput.value = '';
    }

    /**
     * 채팅 메시지 추가
     */
    function addChatMessage(data) {
        const isMine = data.user_id === currentUser.id;
        const avatar = !isMine
            ? (data.avatar_url
                ? `<img src="${Utils.escapeHtml(data.avatar_url)}" alt="${Utils.escapeHtml(data.nickname || '')}">`
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
        `;
        chatMessages.appendChild(messageEl);
        chatMessages.scrollTop = chatMessages.scrollHeight;
        if (!isMine) Utils?.Sounds?.chat?.();
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
     * Heartbeat
     */
    function startHeartbeat() {
        heartbeatInterval = setInterval(() => {
            if (socket && socket.readyState === WebSocket.OPEN) {
                socket.send(JSON.stringify({ action: 'heartbeat' }));
            }
        }, 30000);
    }

    function stopHeartbeat() {
        if (heartbeatInterval) {
            clearInterval(heartbeatInterval);
            heartbeatInterval = null;
        }
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

    function handleChatBadge(data) {
        if (isChatOpen || !chatSection?.classList.contains('is-hidden')) {
            resetChatBadge();
            return;
        }
        if (data.user_id === currentUser.id) return;
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

    function startRoomPolling() {
        roomPollInterval = setInterval(() => {
            loadRoom();
        }, 3000);

        window.addEventListener('beforeunload', () => {
            if (roomPollInterval) clearInterval(roomPollInterval);
        });
    }

    function setupExitGuard() {
        const logo = document.querySelector('.navbar-logo');
        if (!logo) return;
        logo.addEventListener('click', (e) => {
            const leave = confirm('대기실을 나가시겠습니까?');
            if (!leave) {
                e.preventDefault();
            }
        });
    }

    // 페이지 떠날 때 정리
    window.addEventListener('beforeunload', () => {
        stopHeartbeat();
        if (socket) {
            socket.close();
        }
    });
})();
