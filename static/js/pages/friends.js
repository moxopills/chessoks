(function() {
    'use strict';

    const isTouchDevice = 'ontouchstart' in window || navigator.maxTouchPoints > 0;

    const friendListEl = document.getElementById('friend-list');
    const incomingListEl = document.getElementById('incoming-list');
    const outgoingListEl = document.getElementById('outgoing-list');
    const refreshBtn = document.getElementById('friends-refresh');

    const tabButtons = document.querySelectorAll('.tab-btn');
    const friendsPanel = document.getElementById('friends-panel');
    const requestsPanel = document.getElementById('requests-panel');

    const searchInput = document.getElementById('friend-search-input');
    const searchBtn = document.getElementById('friend-search-btn');
    const searchResultsEl = document.getElementById('search-results');

    const friendsGrid = document.querySelector('.friends-grid');
    const drawer = document.getElementById('profile-drawer');
    const drawerClose = document.getElementById('profile-close');
    const avatarEl = document.getElementById('profile-avatar');
    const nameEl = document.getElementById('profile-name');
    const ratingEl = document.getElementById('profile-rating');
    const tierEl = document.getElementById('profile-tier');
    const statGames = document.getElementById('stat-games');
    const statWins = document.getElementById('stat-wins');
    const statLosses = document.getElementById('stat-losses');
    const statDraws = document.getElementById('stat-draws');
    const vsBox = document.getElementById('profile-vs');
    const vsWins = document.getElementById('vs-wins');
    const vsLosses = document.getElementById('vs-losses');
    const vsDraws = document.getElementById('vs-draws');
    const recentList = document.getElementById('profile-recent-list');
    const friendBtn = document.getElementById('profile-friend-btn');
    const reportToggle = document.getElementById('profile-report-toggle');
    const chatBtn = document.getElementById('profile-chat-btn');
    const guestbookList = document.getElementById('guestbook-list');
    const guestbookInput = document.getElementById('guestbook-input');
    const guestbookSubmit = document.getElementById('guestbook-submit');

    let currentUserId = null;
    let friendIds = new Set();
    let outgoingRequestUserIds = new Set();
    let selectedUserId = null;

    init();

    async function init() {
        Guestbook.init({
            listEl: guestbookList,
            inputEl: guestbookInput,
            getCurrentUserId: () => currentUserId,
            getTargetUserId: () => selectedUserId,
        });
        await loadCurrentUser();
        bindEvents();
        await refreshAll();
        applyTabFromUrl();
        syncDrawerState();
        startOnlineRefresh();
    }

    function bindEvents() {
        refreshBtn?.addEventListener('click', refreshAll);

        // Close drawer with both click and touch
        if (drawerClose) {
            const closeDrawer = (e) => {
                e.preventDefault();
                e.stopPropagation();
                drawer.classList.add('hidden');
                syncDrawerState();
            };
            drawerClose.addEventListener('click', closeDrawer);
            drawerClose.addEventListener('touchend', closeDrawer);
        }

        // Close drawer when clicking backdrop on mobile
        if (isTouchDevice && drawer) {
            drawer.addEventListener('click', (e) => {
                if (e.target === drawer) {
                    drawer.classList.add('hidden');
                    syncDrawerState();
                }
            });
        }

        reportToggle?.addEventListener('click', () => {
            if (!selectedUserId) return;
            if (currentUserId && selectedUserId === currentUserId) {
                Toast.error('자기 자신은 신고할 수 없습니다.');
                return;
            }
            Utils.ReportModal.open(selectedUserId);
        });
        friendBtn?.addEventListener('click', sendFriendRequest);
        chatBtn?.addEventListener('click', () => openDirectMessage(selectedUserId));
        guestbookSubmit?.addEventListener('click', () => Guestbook.submit());
        searchBtn?.addEventListener('click', searchUsers);
        searchInput?.addEventListener('keydown', (event) => {
            if (event.key === 'Enter') searchUsers();
        });

        tabButtons.forEach((btn) => {
            btn.addEventListener('click', () => {
                switchTab(btn.dataset.tab);
            });
        });

        // 모바일 스와이프 제스처
        setupSwipeGestures();
    }

    function switchTab(tab) {
        tabButtons.forEach((item) => item.classList.remove('active'));
        const targetBtn = document.querySelector(`.tab-btn[data-tab="${tab}"]`);
        targetBtn?.classList.add('active');
        friendsPanel.classList.toggle('hidden', tab !== 'friends');
        requestsPanel.classList.toggle('hidden', tab !== 'requests');
    }

    function setupSwipeGestures() {
        const container = document.querySelector('.friends-card');
        if (!container) return;

        let touchStartX = 0;
        let touchEndX = 0;
        const minSwipeDistance = 50;

        container.addEventListener('touchstart', (e) => {
            touchStartX = e.changedTouches[0].screenX;
        }, { passive: true });

        container.addEventListener('touchend', (e) => {
            touchEndX = e.changedTouches[0].screenX;
            handleSwipe();
        }, { passive: true });

        function handleSwipe() {
            const diff = touchStartX - touchEndX;
            if (Math.abs(diff) < minSwipeDistance) return;

            const currentTab = document.querySelector('.tab-btn.active')?.dataset.tab;
            if (diff > 0 && currentTab === 'friends') {
                // 왼쪽 스와이프 -> 요청 탭
                switchTab('requests');
            } else if (diff < 0 && currentTab === 'requests') {
                // 오른쪽 스와이프 -> 친구 탭
                switchTab('friends');
            }
        }
    }

    function applyTabFromUrl() {
        const params = Utils.getUrlParams();
        if (params.tab === 'requests') {
            tabButtons.forEach((item) => item.classList.remove('active'));
            const targetBtn = document.querySelector('.tab-btn[data-tab=\"requests\"]');
            targetBtn?.classList.add('active');
            friendsPanel.classList.add('hidden');
            requestsPanel.classList.remove('hidden');
        }
    }

    async function loadCurrentUser() {
        try {
            const me = await API.get('/accounts/me/');
            currentUserId = me.id;
        } catch {
            currentUserId = null;
        }
    }

    async function refreshAll() {
        if (!currentUserId) {
            friendListEl.innerHTML = '<div class="table-empty">로그인 후 사용할 수 있습니다.</div>';
            incomingListEl.innerHTML = '<div class="table-empty">로그인 후 사용할 수 있습니다.</div>';
            outgoingListEl.innerHTML = '<div class="table-empty">로그인 후 사용할 수 있습니다.</div>';
            return;
        }
        await Promise.all([loadFriends(), loadRequests('incoming'), loadRequests('outgoing')]);
    }

    async function loadFriends() {
        try {
            const data = await API.get('/accounts/friends/');
            const friends = data.results || [];
            friendIds = new Set(friends.map((item) => item.friend.id));
            await applyOnlineStatus(friends.map((item) => item.friend.id));
            renderFriends(friends);
        } catch {
            friendListEl.innerHTML = '<div class="table-empty">불러오기 실패</div>';
        }
    }

    async function applyOnlineStatus(ids) {
        if (!ids.length) return;
        try {
            const data = await API.get('/accounts/online-status/', { ids: ids.join(',') });
            const map = new Map();
            (data.results || []).forEach((entry) => {
                map.set(entry.id, entry.online);
            });
            friendListEl.dataset.statusMap = JSON.stringify(Object.fromEntries(map));
        } catch {
            friendListEl.dataset.statusMap = '{}';
        }
    }

    function startOnlineRefresh() {
        setInterval(() => {
            if (!currentUserId) return;
            const friendIdsArr = Array.from(friendIds);
            if (!friendIdsArr.length) return;
            applyOnlineStatus(friendIdsArr).then(() => {
                const rows = Array.from(friendListEl.querySelectorAll('.friend-item'));
                if (!rows.length) return;
                const statusMap = JSON.parse(friendListEl.dataset.statusMap || '{}');
                rows.forEach((row) => {
                    const userId = parseInt(row.dataset.userId, 10);
                    const dot = row.querySelector('.status-dot');
                    if (!dot) return;
                    dot.classList.toggle('online', !!statusMap[userId]);
                });
            });
        }, 5000);
    }

    function renderFriends(friends) {
        if (!friends.length) {
            friendListEl.innerHTML = '<div class="empty-state"><span class="empty-state-icon">👥</span><span class="empty-state-text">아직 친구가 없습니다</span><span class="empty-state-hint">닉네임으로 친구를 검색해보세요</span></div>';
            return;
        }
        const statusMap = JSON.parse(friendListEl.dataset.statusMap || '{}');
        friendListEl.innerHTML = friends.map((item) => {
            const friend = item.friend;
            const online = statusMap[friend.id];
            return `
                <div class="friend-item" data-user-id="${friend.id}">
                    <div class="friend-meta">
                        <div class="avatar avatar-sm">${friend.avatar_url ? `<img src="${friend.avatar_url}" alt="${Utils.escapeHtml(friend.nickname)}">` : '<span class="avatar-placeholder">?</span>'}</div>
                        <div class="friend-name">
                            <strong>${Utils.escapeHtml(friend.nickname)}</strong>
                            <small>레이팅 ${friend.rating} · ${Utils.escapeHtml(friend.rank_tier)}</small>
                        </div>
                    </div>
                    <div class="status-dot ${online ? 'online' : ''}"></div>
                </div>
            `;
        }).join('');

        friendListEl.querySelectorAll('.friend-item').forEach((item) => {
            const userId = parseInt(item.dataset.userId, 10);
            if (isTouchDevice) {
                Utils.bindDoubleTap(item, {
                    single: (event) => {
                        event.preventDefault();
                        openContextMenu(event, userId, { isFriend: true });
                    },
                    double: (event) => {
                        event.preventDefault();
                        openProfileDrawer(userId);
                    }
                });
                return;
            }
            item.addEventListener('click', () => openProfileDrawer(userId));
            item.addEventListener('contextmenu', (event) => {
                event.preventDefault();
                openContextMenu(event, userId, { isFriend: true });
            });
        });
    }

    async function loadRequests(direction) {
        const targetEl = direction === 'incoming' ? incomingListEl : outgoingListEl;
        try {
            const data = await API.get('/accounts/friends/requests/', { type: direction });
            if (direction === 'outgoing') {
                outgoingRequestUserIds = new Set((data.results || []).map((req) => req.to_user.id));
            }
            renderRequests(targetEl, data.results || [], direction);
        } catch {
            targetEl.innerHTML = '<div class="table-empty">불러오기 실패</div>';
        }
    }

    function renderRequests(container, requests, direction) {
        if (!requests.length) {
            const icon = direction === 'incoming' ? '📬' : '📤';
            const text = direction === 'incoming' ? '받은 요청이 없습니다' : '보낸 요청이 없습니다';
            container.innerHTML = `<div class="empty-state"><span class="empty-state-icon">${icon}</span><span class="empty-state-text">${text}</span></div>`;
            return;
        }
        container.innerHTML = requests.map((req) => {
            const user = direction === 'incoming' ? req.from_user : req.to_user;
            const actions = direction === 'incoming'
                ? `
                    <div class="request-actions">
                        <button class="btn btn-success btn-sm" data-action="accept" data-request-id="${req.id}">수락</button>
                        <button class="btn btn-secondary btn-sm" data-action="reject" data-request-id="${req.id}">거절</button>
                    </div>
                `
                : `
                    <div class="request-actions">
                        <button class="btn btn-secondary btn-sm" data-action="cancel" data-request-id="${req.id}">요청 취소</button>
                    </div>
                `;
            return `
                <div class="request-item">
                    <div class="friend-meta" data-user-id="${user.id}">
                        <div class="avatar avatar-sm">${user.avatar_url ? `<img src="${user.avatar_url}" alt="${Utils.escapeHtml(user.nickname)}">` : '<span class="avatar-placeholder">?</span>'}</div>
                        <div class="friend-name">
                            <strong>${Utils.escapeHtml(user.nickname)}</strong>
                            <small>레이팅 ${user.rating} · ${Utils.escapeHtml(user.rank_tier)}</small>
                        </div>
                    </div>
                    ${actions}
                </div>
            `;
        }).join('');

        container.querySelectorAll('[data-action]').forEach((btn) => {
            btn.addEventListener('click', async () => {
                const action = btn.dataset.action;
                const requestId = btn.dataset.requestId;
                if (action === 'accept') await acceptRequest(requestId);
                if (action === 'reject') await rejectRequest(requestId);
                if (action === 'cancel') await cancelRequest(requestId);
            });
        });

        container.querySelectorAll('.friend-meta').forEach((meta) => {
            const userId = parseInt(meta.dataset.userId, 10);
            if (isTouchDevice) {
                Utils.bindDoubleTap(meta, {
                    single: (event) => {
                        event.preventDefault();
                        openContextMenu(event, userId, { isFriend: false });
                    },
                    double: (event) => {
                        event.preventDefault();
                        openProfileDrawer(userId);
                    }
                });
                return;
            }
            meta.addEventListener('click', () => openProfileDrawer(userId));
            meta.addEventListener('contextmenu', (event) => {
                event.preventDefault();
                openContextMenu(event, userId, { isFriend: false });
            });
        });
    }

    async function acceptRequest(requestId) {
        try {
            await API.post(`/accounts/friends/requests/${requestId}/accept/`);
            Toast.success('친구 요청을 수락했습니다.');
            await refreshAll();
        } catch (error) {
            Toast.error(error.data?.message || '수락에 실패했습니다.');
        }
    }

    async function rejectRequest(requestId) {
        try {
            await API.post(`/accounts/friends/requests/${requestId}/reject/`);
            Toast.success('친구 요청을 거절했습니다.');
            await refreshAll();
        } catch (error) {
            Toast.error(error.data?.message || '거절에 실패했습니다.');
        }
    }

    async function cancelRequest(requestId) {
        try {
            await API.post(`/accounts/friends/requests/${requestId}/cancel/`);
            Toast.success('친구 요청을 취소했습니다.');
            await refreshAll();
        } catch (error) {
            Toast.error(error.data?.message || '취소에 실패했습니다.');
        }
    }

    async function removeFriend(userId) {
        if (!confirm('친구를 삭제할까요?')) return;
        try {
            await API.post(`/accounts/friends/${userId}/remove/`);
            Toast.success('친구가 삭제되었습니다.');
            await refreshAll();
        } catch (error) {
            Toast.error(error.data?.message || '삭제에 실패했습니다.');
        }
    }

    async function searchUsers() {
        if (!currentUserId) {
            Toast.error('로그인 시 가능합니다.');
            return;
        }
        const query = searchInput.value.trim();
        if (!query) {
            searchResultsEl.innerHTML = '<div class="table-empty">검색어를 입력하세요.</div>';
            return;
        }
        try {
            const data = await API.get('/accounts/users/search/', { q: query });
            const results = data.results || [];
            const statusMap = await fetchOnlineStatusMap(results.map((user) => user.id));
            renderSearchResults(results, statusMap);
        } catch (error) {
            searchResultsEl.innerHTML = '<div class="table-empty">검색 실패</div>';
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

    function renderSearchResults(results, statusMap = {}) {
        if (!results.length) {
            searchResultsEl.innerHTML = '<div class="empty-state"><span class="empty-state-icon">🔍</span><span class="empty-state-text">검색 결과가 없습니다</span></div>';
            return;
        }
        searchResultsEl.innerHTML = results.map((user) => {
            const isSelf = user.id === currentUserId;
            const isFriend = friendIds.has(user.id);
            const isPending = outgoingRequestUserIds.has(user.id);
            const online = statusMap[user.id] === true;
            let buttonLabel = '친구 요청';
            let disabled = false;
            if (isSelf) {
                buttonLabel = '나';
                disabled = true;
            } else if (isFriend) {
                buttonLabel = '친구';
                disabled = true;
            } else if (isPending) {
                buttonLabel = '요청 보냄';
                disabled = true;
            }
            return `
                <div class="search-item" data-user-id="${user.id}">
                    <div class="friend-meta">
                        <div class="avatar avatar-sm">${user.avatar_url ? `<img src="${user.avatar_url}" alt="${Utils.escapeHtml(user.nickname)}">` : '<span class="avatar-placeholder">?</span>'}</div>
                        <div class="friend-name">
                            <strong>${Utils.escapeHtml(user.nickname)}</strong>
                            <small>레이팅 ${user.stats?.rating ?? '-'} · ${Utils.escapeHtml(user.stats?.rank_tier ?? '-')} · <span class="friend-status ${online ? 'online' : 'offline'}">${online ? '온라인' : '오프라인'}</span></small>
                        </div>
                    </div>
                    <button class="btn btn-secondary btn-sm" data-action="request" ${disabled ? 'disabled' : ''}>${buttonLabel}</button>
                </div>
            `;
        }).join('');

        searchResultsEl.querySelectorAll('[data-action="request"]').forEach((btn) => {
            btn.addEventListener('click', async () => {
                const userId = parseInt(btn.closest('.search-item').dataset.userId, 10);
                await sendFriendRequestTo(userId);
            });
        });

        searchResultsEl.querySelectorAll('.search-item .friend-meta').forEach((meta) => {
            const userId = parseInt(meta.closest('.search-item').dataset.userId, 10);
            const isFriend = friendIds.has(userId);
            const isPending = outgoingRequestUserIds.has(userId);
            if (isTouchDevice) {
                Utils.bindDoubleTap(meta, {
                    single: (event) => {
                        event.preventDefault();
                        openContextMenu(event, userId, { isFriend, isPending });
                    },
                    double: (event) => {
                        event.preventDefault();
                        openProfileDrawer(userId);
                    }
                });
                return;
            }
            meta.addEventListener('click', () => {
                openProfileDrawer(userId);
            });
            meta.addEventListener('contextmenu', (event) => {
                event.preventDefault();
                openContextMenu(event, userId, { isFriend, isPending });
            });
        });
    }

    async function sendFriendRequestTo(userId) {
        if (!userId) return;
        const res = await Utils.sendFriendRequest(userId, currentUserId);
        if (res.success) {
            await refreshAll();
        }
    }

    function openDirectMessage(userId) {
        if (!userId) return;
        window.location.href = `/messages/${userId}/`;
    }

    async function openProfileDrawer(userId) {
        if (!userId) return;
        selectedUserId = userId;
        drawer.classList.remove('hidden');
        syncDrawerState();
        updateFriendButtonState(userId);

        try {
            const data = await API.get(`/accounts/users/${userId}/profile/`);
            const user = data.user;
            renderDrawerUser(user);
            renderDrawerStats(user.stats);
            renderRecentGames(data.recent_games || []);
            await Guestbook.load(userId);
            if (data.vs_summary) {
                vsBox.classList.remove('hidden');
                vsWins.textContent = data.vs_summary.wins;
                vsLosses.textContent = data.vs_summary.losses;
                vsDraws.textContent = data.vs_summary.draws;
            } else {
                vsBox.classList.add('hidden');
            }
        } catch {
            Toast.error('프로필 정보를 불러올 수 없습니다.');
        }
    }

    function syncDrawerState() {
        if (!friendsGrid) return;
        const isHidden = drawer.classList.contains('hidden');
        friendsGrid.classList.toggle('drawer-collapsed', isHidden);
    }

    function openContextMenu(event, userId, { isFriend = false, isPending = false } = {}) {
        if (!userId) return;
        selectedUserId = userId;
        const items = ContextMenu.buildUserMenuItems({
            currentUserId,
            targetUserId: userId,
            isFriend,
            isPending,
            showRemove: true,
        });
        ContextMenu.show(event, userId, items, handleContextAction);
    }

    function handleContextAction(action, targetId) {
        if (action === 'profile') openProfileDrawer(targetId);
        else if (action === 'invite') Notifications.sendGameInvite(targetId);
        else if (action === 'friend') sendFriendRequestTo(targetId);
        else if (action === 'remove') removeFriend(targetId);
        else if (action === 'chat') openDirectMessage(targetId);
        else if (action === 'report') Utils.ReportModal.open(targetId);
    }

    function updateFriendButtonState(userId) {
        if (!friendBtn) return;
        if (!currentUserId) {
            friendBtn.disabled = true;
            friendBtn.textContent = '로그인 시 가능합니다.';
            reportToggle.disabled = true;
            return;
        }
        if (userId === currentUserId) {
            friendBtn.disabled = true;
            friendBtn.textContent = '나';
            reportToggle.disabled = true;
            return;
        }
        if (friendIds.has(userId)) {
            friendBtn.disabled = true;
            friendBtn.textContent = '친구';
            reportToggle.disabled = false;
            return;
        }
        if (outgoingRequestUserIds.has(userId)) {
            friendBtn.disabled = true;
            friendBtn.textContent = '요청 보냄';
            reportToggle.disabled = false;
            return;
        }
        friendBtn.disabled = false;
        friendBtn.textContent = '친구 요청';
        reportToggle.disabled = false;
    }

    function renderDrawerUser(user) {
        nameEl.textContent = user.nickname;
        ratingEl.textContent = `레이팅 ${user.stats?.rating ?? '-'}`;
        tierEl.textContent = user.stats?.rank_tier ?? '-';
        if (user.avatar_url) {
            avatarEl.innerHTML = `<img src="${user.avatar_url}" alt="${Utils.escapeHtml(user.nickname)}">`;
        } else {
            avatarEl.innerHTML = '<span class="avatar-placeholder">?</span>';
        }
    }

    function renderDrawerStats(stats) {
        statGames.textContent = stats?.games_played ?? 0;
        statWins.textContent = stats?.games_won ?? 0;
        statLosses.textContent = stats?.games_lost ?? 0;
        statDraws.textContent = stats?.games_draw ?? 0;
    }

    function renderRecentGames(games) {
        if (!games.length) {
            recentList.innerHTML = '<div class="text-muted">최근 전적 없음</div>';
            return;
        }
        recentList.innerHTML = games.slice(0, 5).map((game) => {
            const opponent = game.white_player.id === selectedUserId ? game.black_player.nickname : game.white_player.nickname;
            const resultLabel = Utils.getGameResultLabel(
                game.result,
                Number(game.white_player?.id) === Number(selectedUserId)
            );
            const playedAt = game.created_at ? Utils.formatDate(game.created_at, {
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
            }).replace(/\./g, '').trim() : '';
            return `
                <div class="recent-item">
                    <span class="recent-opponent">${Utils.escapeHtml(opponent)}</span>
                    <span class="recent-result">${resultLabel}</span>
                    <span class="recent-meta text-muted">${playedAt}</span>
                </div>
            `;
        }).join('');
    }

    async function sendFriendRequest() {
        if (!selectedUserId) return;
        await sendFriendRequestTo(selectedUserId);
    }

 
})();
