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
    const userSearchInput = document.getElementById('lobby-user-search-input');
    const userSearchBtn = document.getElementById('lobby-user-search-btn');
    const userSearchReset = document.getElementById('lobby-user-search-reset');
    const mobileTabbar = document.getElementById('mobile-tabbar');
    const chatBadge = document.getElementById('chat-badge');
    const chatSection = document.querySelector('.lobby-chat-section');
    const waitingRoomCard = document.getElementById('waiting-room-card');
    const waitingRoomInfo = document.getElementById('waiting-room-info');
    const waitingRoomEnter = document.getElementById('waiting-room-enter');
    const tierToggle = document.getElementById('tier-toggle');
    const tierPanel = document.getElementById('tier-panel');
    const modeToggle = document.getElementById('mode-toggle');
    const modePanel = document.getElementById('mode-panel');

    let isMatching = false;
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

    // 초기화
    init();

    async function init() {
        await loadRooms();
        await loadWaitingRoom();
        await checkAuthAndSetupChat();
        startRoomAutoRefresh();
        setupMobileTabs();
        setupTierToggle();
        setupUserContextMenu();
        setupUserSearch();
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
            waitingRoomCard.onclick = () => {
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
            await loadFriendIds();
            setupChat();
            setupQuickMatch();
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
        const items = [
            { action: 'profile', label: '프로필 보기' },
            ...(canFriend ? [{ action: 'friend', label: '친구 추가' }] : []),
            ...(canChat ? [{ action: 'chat', label: '1:1 채팅' }] : []),
            { action: 'report', label: '신고하기' },
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
            Toast.error('로그인 후 이용할 수 있습니다.');
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
            Toast.error('로그인 후 이용할 수 있습니다.');
            return;
        }
        const reason = prompt('신고 사유를 입력하세요 (선택)') || '';
        try {
            await API.post('/reports/', {
                target_id: targetId,
                category: 'other',
                description: reason.trim(),
            });
            Toast.success('신고가 접수되었습니다.');
        } catch (error) {
            Toast.error(error.data?.message || '신고에 실패했습니다.');
        }
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
                openUserContextMenu(event, userId);
            });
            item.addEventListener('touchstart', (event) => {
                longPressTimer = setTimeout(() => openUserContextMenu(event, userId), 450);
            });
            item.addEventListener('touchend', () => clearTimeout(longPressTimer));
        } else {
            item.addEventListener('contextmenu', (event) => {
                event.preventDefault();
                openUserContextMenu(event, userId);
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
