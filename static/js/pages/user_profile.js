(function() {
    'use strict';

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
    const recentList = document.getElementById('recent-list');
    const friendBtn = document.getElementById('friend-request-btn');
    const reportBtn = document.getElementById('report-btn');

    const userId = Utils.getPathParam('/users/(\\d+)/');
    let currentUserId = null;

    init();

    async function init() {
        await loadCurrentUser();
        await loadProfile();
        bindActions();
    }

    async function loadCurrentUser() {
        try {
            const me = await API.get('/accounts/me/');
            currentUserId = me.id;
        } catch {
            currentUserId = null;
        }
    }

    async function loadProfile() {
        if (!userId) return;
        try {
            const data = await API.get(`/accounts/users/${userId}/profile/`);
            const user = data.user;
            renderUser(user);
            renderStats(user.stats);
            renderRecent(data.recent_games || []);
            if (data.vs_summary) {
                vsBox.classList.remove('hidden');
                vsWins.textContent = data.vs_summary.wins;
                vsLosses.textContent = data.vs_summary.losses;
                vsDraws.textContent = data.vs_summary.draws;
            } else {
                vsBox.classList.add('hidden');
            }
        } catch (error) {
            Toast.error('프로필을 불러올 수 없습니다.');
        }
    }

    function renderUser(user) {
        nameEl.textContent = user.nickname;
        ratingEl.textContent = `레이팅 ${user.stats?.rating ?? '-'}`;
        tierEl.textContent = user.stats?.rank_tier ?? '-';
        if (user.avatar_url) {
            avatarEl.innerHTML = `<img src="${user.avatar_url}" alt="${Utils.escapeHtml(user.nickname)}">`;
        } else {
            avatarEl.innerHTML = '<span class="avatar-placeholder">?</span>';
        }
    }

    function renderStats(stats) {
        statGames.textContent = stats?.games_played ?? 0;
        statWins.textContent = stats?.games_won ?? 0;
        statLosses.textContent = stats?.games_lost ?? 0;
        statDraws.textContent = stats?.games_draw ?? 0;
    }

    function renderRecent(games) {
        if (!games.length) {
            recentList.innerHTML = '<div class="text-muted">최근 전적 없음</div>';
            return;
        }
        const targetId = parseInt(userId, 10);
        recentList.innerHTML = games.slice(0, 6).map((game) => {
            const isWhite = game.white_player.id === targetId;
            const opponent = isWhite ? game.black_player.nickname : game.white_player.nickname;
            const resultLabel = getResultLabel(game.result, isWhite);
            const playedAt = game.created_at ? Utils.formatDate(game.created_at, {
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit',
            }).replace(/\./g, '').trim() : '';
            const moveText = typeof game.move_count === 'number' ? `${game.move_count}수` : '';
            return `
                <div class="recent-item">
                    <span>${Utils.escapeHtml(opponent)}</span>
                    <span>${resultLabel}</span>
                    <span class="text-muted">${[playedAt, moveText].filter(Boolean).join(' · ')}</span>
                </div>
            `;
        }).join('');
    }

    function getResultLabel(result, isWhite) {
        if (result.startsWith('draw') || result === 'draw' || result === 'stalemate') return '무';
        if (result.includes('white')) return isWhite ? '승' : '패';
        if (result.includes('black')) return isWhite ? '패' : '승';
        if (result === 'playing') return '진행';
        return '종료';
    }

    function bindActions() {
        friendBtn?.addEventListener('click', async () => {
            if (!currentUserId) {
                Toast.error('로그인 후 이용할 수 있습니다.');
                return;
            }
            if (parseInt(userId, 10) === currentUserId) {
                Toast.error('자기 자신에게 요청할 수 없습니다.');
                return;
            }
            try {
                const result = await API.post('/accounts/friends/requests/', { user_id: parseInt(userId, 10) });
                if (result.status === 'accepted') {
                    Toast.success('친구 요청이 자동 수락되었습니다.');
                } else {
                    Toast.success('친구 요청을 보냈습니다.');
                }
            } catch (error) {
                Toast.error(error.data?.message || '친구 요청에 실패했습니다.');
            }
        });

        reportBtn?.addEventListener('click', async () => {
            if (!currentUserId) {
                Toast.error('로그인 후 이용할 수 있습니다.');
                return;
            }
            const reason = prompt('신고 사유를 입력하세요 (선택)') || '';
            try {
                await API.post('/reports/', {
                    target_id: parseInt(userId, 10),
                    category: 'other',
                    description: reason.trim(),
                });
                Toast.success('신고가 접수되었습니다.');
            } catch (error) {
                Toast.error(error.data?.message || '신고에 실패했습니다.');
            }
        });
    }
})();
