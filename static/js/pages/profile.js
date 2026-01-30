/* Profile Page Logic */
(function() {
    'use strict';

    const avatarEl = document.getElementById('profile-avatar');
    const nicknameEl = document.getElementById('profile-nickname');
    const emailEl = document.getElementById('profile-email');
    const bioEl = document.getElementById('profile-bio');
    const tierEl = document.getElementById('profile-tier');

    const ratingEl = document.getElementById('stat-rating');
    const winrateEl = document.getElementById('stat-winrate');
    const winsEl = document.getElementById('stat-wins');
    const lossesEl = document.getElementById('stat-losses');
    const drawsEl = document.getElementById('stat-draws');
    const totalEl = document.getElementById('stat-total');
    const recentEl = document.getElementById('recent-games');

    init();

    async function init() {
        try {
            const me = await API.get('/accounts/me/');
            renderProfile(me);
        } catch (error) {
            Toast.error('프로필 정보를 불러올 수 없습니다.');
        }

        try {
            const dashboard = await API.get('/accounts/dashboard/');
            renderDashboard(dashboard);
        } catch (error) {
            if (recentEl) recentEl.textContent = '전적을 불러오지 못했습니다.';
        }
    }

    function renderProfile(user) {
        if (!user) return;
        nicknameEl.textContent = user.nickname || '닉네임 없음';
        emailEl.textContent = user.email || '';
        bioEl.textContent = user.bio || '소개가 없습니다.';
        const tier = user.stats?.rank_tier || 'Junior';
        tierEl.textContent = `티어 · ${tier}`;
        tierEl.style.color = Utils.getTierColor(tier);

        if (avatarEl) {
            avatarEl.innerHTML = '';
            if (user.avatar_url) {
                const img = document.createElement('img');
                img.src = user.avatar_url;
                img.alt = user.nickname;
                avatarEl.appendChild(img);
            } else {
                const span = document.createElement('span');
                span.className = 'profile-avatar-placeholder';
                span.textContent = user.nickname?.[0] || '?';
                avatarEl.appendChild(span);
            }
        }
    }

    function renderDashboard(data) {
        if (!data || !data.summary) return;
        const summary = data.summary;
        ratingEl.textContent = Utils.formatNumber(summary.rating ?? 0);
        winsEl.textContent = summary.games_won ?? 0;
        lossesEl.textContent = summary.games_lost ?? 0;
        drawsEl.textContent = summary.games_draw ?? 0;
        totalEl.textContent = summary.games_played ?? 0;
        winrateEl.textContent = `${summary.win_rate ?? 0}%`;

        const games = data.recent_games || [];
        const userId = data.user?.id;
        if (!games.length) {
            recentEl.innerHTML = '<div class="helper-text">최근 경기가 없습니다.</div>';
            return;
        }
        recentEl.innerHTML = games.map(game => {
            const resultInfo = getResultInfo(game, userId);
            const resultClass = resultInfo.className;
            const resultText = resultInfo.label;
            const title = `${game.white_player?.nickname || '화이트'} vs ${game.black_player?.nickname || '블랙'}`;
            const meta = `${Utils.formatDate(game.created_at)} · ${game.room_type}`;
            return `
                <div class="game-row">
                    <div class="game-meta">
                        <div class="game-title">${Utils.escapeHtml(title)}</div>
                        <div>${Utils.escapeHtml(meta)}</div>
                    </div>
                    <span class="game-result ${resultClass}">${resultText}</span>
                </div>
            `;
        }).join('');
    }

    function getResultInfo(game, userId) {
        const result = game.result || '';
        if (result.includes('draw') || result === 'draw' || result === 'stalemate') {
            return { className: 'draw', label: '무승부' };
        }
        if (!userId || !game.white_player || !game.black_player) {
            return { className: 'draw', label: '종료' };
        }
        const isWhite = game.white_player.id === userId;
        const winSet = new Set([
            'white_win',
            'black_win',
            'checkmate_white',
            'checkmate_black',
            'timeout_white',
            'timeout_black',
            'resignation_white',
            'resignation_black',
        ]);
        if (!winSet.has(result)) {
            return { className: 'draw', label: '종료' };
        }
        const whiteWin = new Set(['white_win', 'checkmate_white', 'timeout_black', 'resignation_black']);
        const didWin = whiteWin.has(result) ? isWhite : !isWhite;
        return { className: didWin ? 'win' : 'lose', label: didWin ? '승리' : '패배' };
    }
})();
