(function() {
    'use strict';

    const isTouchDevice = 'ontouchstart' in window || navigator.maxTouchPoints > 0;

    const leaderboardBody = document.getElementById('leaderboard-body');
    const leaderboardGrid = document.querySelector('.leaderboard-grid');
    const paginationEl = document.getElementById('leaderboard-pagination');
    const refreshBtn = document.getElementById('leaderboard-refresh');
    const myRankBody = document.getElementById('my-rank-body');

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

    let currentPage = 1;
    let totalPages = 1;
    let currentUserId = null;
    let selectedUserId = null;
    let friendIds = new Set();

    init();

    async function init() {
        Guestbook.init({
            listEl: guestbookList,
            inputEl: guestbookInput,
            getCurrentUserId: () => currentUserId,
            getTargetUserId: () => selectedUserId,
        });
        await loadCurrentUser();
        await loadLeaderboard();
        syncDrawerState();
        bindEvents();
    }

    function bindEvents() {
        refreshBtn?.addEventListener('click', () => loadLeaderboard());

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

        // Close drawer when clicking backdrop on mobile
        if (isTouchDevice && drawer) {
            drawer.addEventListener('click', (e) => {
                if (e.target === drawer) {
                    drawer.classList.add('hidden');
                    syncDrawerState();
                }
            });
        }
    }

    async function loadCurrentUser() {
        try {
            const me = await API.get('/accounts/me/');
            currentUserId = me.id;
            await loadFriendIds();
        } catch {
            currentUserId = null;
        }
    }

    async function loadFriendIds() {
        if (!currentUserId) return;
        try {
            const data = await API.get('/accounts/friends/');
            const friends = data.results || [];
            friendIds = new Set(friends.map((item) => item.friend?.id).filter(Boolean));
        } catch {
            friendIds = new Set();
        }
    }

    function isFriendUser(userId) {
        return friendIds.has(userId);
    }

    async function loadLeaderboard(page = currentPage) {
        currentPage = page;
        try {
            const data = await API.get('/accounts/leaderboard/', { page, page_size: 9 });
            totalPages = data.total_pages || 1;
            renderRows(data.results || [], data.my_rank);
            renderPagination();
            renderMyRank(data.my_rank);
        } catch (error) {
            leaderboardBody.innerHTML = '<tr><td colspan="5" class="table-empty"><span class="empty-state"><span class="empty-state-icon">⚠️</span><span class="empty-state-text">불러오기 실패</span></span></td></tr>';
            if (myRankBody) myRankBody.textContent = '로그인 시 가능합니다.';
        }
    }

    function renderRows(rows, myRank) {
        if (!rows.length) {
            leaderboardBody.innerHTML = '<tr><td colspan="5" class="table-empty"><span class="empty-state"><span class="empty-state-icon">🏆</span><span class="empty-state-text">표시할 랭킹이 없습니다</span></span></td></tr>';
            return;
        }

        const myId = myRank?.id || currentUserId;
        leaderboardBody.innerHTML = rows.map((row) => {
            const isMe = myId && row.id === myId;
            const winRate = Utils.calculateWinRate(row.games_won, row.games_played || 0);
            const nameColor = Utils.getNicknameColorValue(row.nickname_color);
            const avatarRing = Utils.getProfileBorderValue(row.profile_border);
            return `
                <tr class="leaderboard-row ${isMe ? 'is-me' : ''}" data-user-id="${row.id}">
                    <td>${row.rank}</td>
                    <td>
                        <div class="user-cell">
                            <div class="avatar avatar-sm">
                                ${row.avatar_url
                                    ? `<img src="${row.avatar_url}" alt="${Utils.escapeHtml(row.nickname)}" style="${avatarRing ? `box-shadow:${avatarRing};` : ''}">`
                                    : '<span class="avatar-placeholder">?</span>'}
                            </div>
                            <div class="user-name">
                                <strong style="${nameColor ? `color:${nameColor};` : ''}">
                                    ${Utils.escapeHtml(row.nickname)}
                                    <span class="user-tier-icon" title="${Utils.escapeHtml(row.rank_tier)}">${Utils.getTierIcon(row.rank_tier)}</span>
                                </strong>
                                <span class="user-tier">승률 ${winRate}%</span>
                            </div>
                        </div>
                    </td>
                    <td>${row.rating}</td>
                    <td>${row.games_won}승 ${row.games_lost}패 ${row.games_draw}무</td>
                    <td><span class="badge">${Utils.escapeHtml(row.rank_tier)}</span></td>
                </tr>
            `;
        }).join('');

        leaderboardBody.querySelectorAll('.leaderboard-row').forEach((row) => {
            const userId = parseInt(row.dataset.userId, 10);
            if (isTouchDevice) {
                row.addEventListener('click', (event) => {
                    event.preventDefault();
                    openProfileDrawer(userId);
                });
                return;
            }
            row.addEventListener('click', () => openProfileDrawer(userId));
            row.addEventListener('contextmenu', (event) => {
                event.preventDefault();
                openContextMenu(event, userId);
            });
        });

    }

    function renderPagination() {
        if (!paginationEl) return;
        paginationEl.innerHTML = '';
        if (totalPages <= 1) return;

        const prevBtn = createPageButton('이전', currentPage > 1, () => loadLeaderboard(currentPage - 1));
        paginationEl.appendChild(prevBtn);

        const pageInfo = document.createElement('span');
        pageInfo.className = 'pagination-info';
        pageInfo.textContent = `${currentPage} / ${totalPages}`;
        paginationEl.appendChild(pageInfo);

        const nextBtn = createPageButton('다음', currentPage < totalPages, () => loadLeaderboard(currentPage + 1));
        paginationEl.appendChild(nextBtn);
    }

    function createPageButton(label, enabled, handler) {
        const btn = document.createElement('button');
        btn.className = 'btn btn-secondary btn-sm';
        btn.textContent = label;
        btn.disabled = !enabled;
        if (enabled) btn.addEventListener('click', handler);
        return btn;
    }

    function renderMyRank(myRank) {
        if (!myRankBody) return;
        if (!myRank) {
            myRankBody.textContent = '로그인 시 가능합니다.';
            return;
        }
        myRankBody.innerHTML = `
            <div>랭킹 #${myRank.rank}</div>
            <div>${Utils.escapeHtml(myRank.nickname)} (${myRank.rating})</div>
            <div>${myRank.games_won}승 ${myRank.games_lost}패 ${myRank.games_draw}무</div>
        `;
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
            updateFriendButtonState(userId, data.friend_status);
            if (data.vs_summary) {
                vsBox.classList.remove('hidden');
                vsWins.textContent = data.vs_summary.wins;
                vsLosses.textContent = data.vs_summary.losses;
                vsDraws.textContent = data.vs_summary.draws;
            } else {
                vsBox.classList.add('hidden');
            }
        } catch (error) {
            Toast.error('프로필 정보를 불러올 수 없습니다.');
        }
    }

    function syncDrawerState() {
        if (!leaderboardGrid) return;
        const isHidden = drawer.classList.contains('hidden');
        leaderboardGrid.classList.toggle('drawer-collapsed', isHidden);
    }

    function openContextMenu(event, userId) {
        if (!userId) return;
        selectedUserId = userId;
        const items = ContextMenu.buildUserMenuItems({
            currentUserId,
            targetUserId: userId,
            isFriend: isFriendUser(userId),
        });
        ContextMenu.show(event, userId, items, handleContextAction);
    }

    function handleContextAction(action, targetId) {
        if (action === 'profile') openProfileDrawer(targetId);
        else if (action === 'invite') Notifications.sendGameInvite(targetId);
        else if (action === 'friend') sendFriendRequestTo(targetId);
        else if (action === 'chat') openDirectMessage(targetId);
        else if (action === 'report') Utils.ReportModal.open(targetId);
    }

    function updateFriendButtonState(userId, status = null) {
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
        if (status?.is_friend) {
            friendBtn.disabled = true;
            friendBtn.textContent = '친구';
            reportToggle.disabled = false;
            return;
        }
        if (status?.is_request_sent) {
            friendBtn.disabled = true;
            friendBtn.textContent = '요청 중';
            reportToggle.disabled = false;
            return;
        }
        if (status?.is_request_received) {
            friendBtn.disabled = false;
            friendBtn.textContent = '요청 확인';
            friendBtn.addEventListener('click', () => {
                window.location.href = '/friends/?tab=requests';
            }, { once: true });
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
            const isWhite = Number(game.white_player?.id) === Number(selectedUserId);
            const opponent = isWhite ? game.black_player.nickname : game.white_player.nickname;
            const resultLabel = Utils.getGameResultLabel(game.result, isWhite);
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

    async function sendFriendRequestTo(userId) {
        if (!userId) return;
        const res = await Utils.sendFriendRequest(userId, currentUserId);
        if (res.success && res.accepted) {
            friendIds.add(userId);
        }
    }

    function openDirectMessage(userId) {
        if (!userId) return;
        window.location.href = `/messages/${userId}/`;
    }

 
})();
