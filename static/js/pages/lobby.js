/**
 * Lobby Page Logic
 * - 방 목록 로드
 * - 빠른 대전
 * - 로비 채팅 (WebSocket)
 */

(function() {
    'use strict';

    const quickMatchBtn = document.getElementById('quick-match-btn');
    const roomList = document.getElementById('room-list');
    const chatMessages = document.getElementById('chat-messages');
    const chatForm = document.getElementById('chat-form');
    const chatInput = document.getElementById('chat-input');
    const usersList = document.getElementById('users-list');
    const userCount = document.getElementById('user-count');
    const mobileTabbar = document.getElementById('mobile-tabbar');
    const chatBadge = document.getElementById('chat-badge');
    const chatSection = document.querySelector('.lobby-chat-section');
    const waitingRoomCard = document.getElementById('waiting-room-card');
    const waitingRoomInfo = document.getElementById('waiting-room-info');
    const waitingRoomEnter = document.getElementById('waiting-room-enter');
    const reportForm = document.getElementById('lobby-report-form');
    const reportTarget = document.getElementById('lobby-report-target');
    const reportCategory = document.getElementById('lobby-report-category');
    const reportMessage = document.getElementById('lobby-report-message');
    const reportHint = document.getElementById('lobby-report-hint');

    let isMatching = false;
    let lobbySocket = null;
    let notificationSocket = null;
    let currentUserId = null;
    let isSuspended = false;
    let lobbyUsers = {};
    let lobbyRooms = [];
    let roomRefreshInterval = null;
    let chatUnread = 0;
    let isChatOpen = true;

    // 초기화
    init();

    async function init() {
        await loadRooms();
        await loadWaitingRoom();
        await checkAuthAndSetupChat();
        startRoomAutoRefresh();
        setupMobileTabs();
    }

    /**
     * 방 목록 로드
     */
    async function loadRooms() {
        try {
            const data = await API.get('/chess/rooms/', { status: 'waiting', limit: 5 });
            lobbyRooms = data.results || data || [];
            renderRooms(lobbyRooms);
        } catch (error) {
            roomList.innerHTML = '<div class="room-empty">방 목록을 불러올 수 없습니다.</div>';
        }
    }

    async function loadWaitingRoom() {
        if (!waitingRoomCard) return;
        try {
            const data = await API.get('/chess/rooms/waiting/');
            const room = data.room;
            if (!room) {
                waitingRoomCard.classList.add('hidden');
                return;
            }
            waitingRoomCard.classList.remove('hidden');
            const title = room.title || '빠른 대전';
            const timeText = room.time_limit ? `${room.time_limit}분` : '무제한';
            waitingRoomInfo.textContent = `${Utils.escapeHtml(title)} · ${timeText}`;
            waitingRoomEnter.onclick = () => {
                window.location.href = `/rooms/${room.id}/`;
            };
        } catch (error) {
            waitingRoomCard.classList.add('hidden');
        }
    }

    /**
     * 방 목록 렌더링
     */
    function renderRooms(rooms) {
        if (!rooms || rooms.length === 0) {
            roomList.innerHTML = '<div class="room-empty">대기 중인 방이 없습니다.</div>';
            return;
        }

        roomList.innerHTML = rooms.map(room => `
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
            loadRooms();
            loadWaitingRoom();
        }, 5000);

        window.addEventListener('beforeunload', () => {
            if (roomRefreshInterval) clearInterval(roomRefreshInterval);
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
            window.location.href = `/games/${roomId}/`;
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
            if (joined.room_type === 'quick' || joined.status === 'playing') {
                window.location.href = `/games/${roomId}/`;
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
            setupChat();
            setupQuickMatch();
            setupLobbyReport();
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
            setReportEnabled(false, '로그인 후 신고할 수 있습니다.');
        }
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
            if (isMatching) {
                await cancelMatch();
            } else {
                await startMatch();
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

    /**
     * 매칭 상태 UI 업데이트
     */
    function setMatchingState(matching) {
        isMatching = matching;
        quickMatchBtn.querySelector('.btn-text').classList.toggle('hidden', matching);
        quickMatchBtn.querySelector('.btn-loading').classList.toggle('hidden', !matching);

        if (matching) {
            quickMatchBtn.classList.remove('btn-primary');
            quickMatchBtn.classList.add('btn-danger');
        } else {
            quickMatchBtn.classList.remove('btn-danger');
            quickMatchBtn.classList.add('btn-primary');
        }
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
            updateReportTargets();
        } else if (data.type === 'user_joined') {
            // 유저 입장
            lobbyUsers[data.user.id] = data.user;
            addUserToList(data.user);
            updateReportTargets();
        } else if (data.type === 'user_left') {
            // 유저 퇴장
            delete lobbyUsers[data.user_id];
            removeUserFromList(data.user_id);
            updateReportTargets();
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
            if (reason) {
                addChatNotice(`계정 정지됨: ${reason}`);
            } else {
                addChatNotice('계정이 정지되었습니다.');
            }
        } else {
            quickMatchBtn?.classList.remove('btn-disabled');
        }
    }

    /**
     * 채팅 메시지 추가
     */
    function addChatMessage(data) {
        const isMine = data.user_id === currentUserId;
        const messageEl = document.createElement('div');
        messageEl.className = `chat-message ${isMine ? 'mine' : 'others'}`;
        messageEl.innerHTML = `
            <span class="chat-nickname">${Utils.escapeHtml(data.nickname)}</span>
            <div class="chat-bubble">${Utils.escapeHtml(data.message)}</div>
            <span class="chat-time">${formatChatTime(data.sent_at)}</span>
        `;
        chatMessages.appendChild(messageEl);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    function setupLobbyReport() {
        if (!reportForm) return;
        setReportEnabled(true);
        updateReportTargets();

        reportForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const targetId = reportTarget?.value;
            if (!targetId) {
                Toast.error('신고할 유저를 선택해주세요.');
                return;
            }
            const category = reportCategory?.value || 'other';
            const description = reportMessage?.value.trim() || '';
            try {
                await API.post('/reports/', {
                    target_id: parseInt(targetId, 10),
                    category,
                    description
                });
                Toast.success('신고가 접수되었습니다.');
                if (reportMessage) reportMessage.value = '';
            } catch (error) {
                Toast.error(error.data?.message || '신고에 실패했습니다.');
            }
        });
    }

    function updateReportTargets() {
        if (!reportTarget) return;
        if (!currentUserId) {
            reportTarget.innerHTML = '<option value="">로그인 후 이용 가능</option>';
            return;
        }
        const candidates = Object.values(lobbyUsers).filter(user => user.id !== currentUserId);
        if (!candidates.length) {
            reportTarget.innerHTML = '<option value="">신고할 유저 없음</option>';
            return;
        }
        reportTarget.innerHTML = '<option value="">신고할 유저 선택</option>' + candidates.map(user => {
            return `<option value="${user.id}">${Utils.escapeHtml(user.nickname)}</option>`;
        }).join('');
    }

    function setReportEnabled(enabled, hintText = '') {
        if (!reportForm) return;
        const controls = reportForm.querySelectorAll('select, input, button');
        controls.forEach(el => {
            el.disabled = !enabled;
        });
        if (reportHint) {
            reportHint.textContent = hintText || reportHint.textContent;
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
        if (isChatOpen) return;
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
        const users = Object.values(lobbyUsers);
        userCount.textContent = users.length;

        if (users.length === 0) {
            usersList.innerHTML = '<div class="users-empty">접속자가 없습니다.</div>';
            return;
        }

        usersList.innerHTML = users.map(user => userRowHtml(user)).join('');
    }

    function addUserToList(user) {
        const existing = usersList.querySelector(`[data-user-id="${user.id}"]`);
        if (existing) return;

        const empty = usersList.querySelector('.users-empty');
        if (empty) {
            usersList.innerHTML = '';
        }

        usersList.insertAdjacentHTML('beforeend', userRowHtml(user));
        userCount.textContent = Object.keys(lobbyUsers).length;
    }

    function removeUserFromList(userId) {
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

    function userRowHtml(user) {
        return `
            <div class="user-item" data-user-id="${user.id}">
                <div class="user-avatar">
                    ${user.avatar_url
                        ? `<img src="${Utils.escapeHtml(user.avatar_url)}" alt="">`
                        : '👤'}
                </div>
                <div class="user-info">
                    <div class="user-nickname">${Utils.escapeHtml(user.nickname)}</div>
                    <div class="user-status">온라인</div>
                </div>
            </div>
        `;
    }

    function upsertRoom(room) {
        if (!room || room.status !== 'waiting') {
            removeRoom(room?.id);
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
})();
