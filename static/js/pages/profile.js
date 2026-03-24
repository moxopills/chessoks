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
    const activityTimelineEl = document.getElementById('activity-timeline');
    const guestbookList = document.getElementById('guestbook-list');
    const guestbookInput = document.getElementById('guestbook-input');
    const guestbookSubmit = document.getElementById('guestbook-submit');
    const winrateChart = document.getElementById('winrate-chart');
    const winrateLegend = document.getElementById('winrate-legend');
    const ratingChart = document.getElementById('rating-chart');
    let currentUserId = null;
    let currentUser = null;

    init();

    async function init() {
        try {
            const me = await API.get('/accounts/me/');
            currentUserId = me?.id;
            currentUser = me;
            renderProfile(me);
            await loadGuestbook();
        } catch (error) {
            Toast.error('프로필 정보를 불러올 수 없습니다.');
            // 에러 상태 표시
            if (nicknameEl) nicknameEl.textContent = '불러오기 실패';
            if (emailEl) emailEl.textContent = '';
            if (tierEl) tierEl.textContent = '-';
            if (avatarEl) {
                avatarEl.innerHTML = '<span class="profile-avatar-placeholder">!</span>';
            }
        }

        try {
            const dashboard = await API.get('/accounts/dashboard/');
            renderDashboard(dashboard);
        } catch (error) {
            if (recentEl) recentEl.textContent = '전적을 불러오지 못했습니다.';
            if (activityTimelineEl) activityTimelineEl.innerHTML = '<div class="helper-text">최근 활동을 불러오지 못했습니다.</div>';
        }

        guestbookSubmit?.addEventListener('click', submitGuestbook);
    }

    function renderProfile(user) {
        if (!user) return;
        const nickname = user.nickname || '닉네임 없음';
        nicknameEl.textContent = nickname;
        emailEl.textContent = user.email || '';
        bioEl.textContent = user.bio || '소개가 없습니다.';
        const rating = user.stats?.rating ?? user.rating ?? 0;
        const tier = user.stats?.rank_tier || deriveTierFromRating(rating);
        tierEl.textContent = `티어 · ${tier}`;
        tierEl.style.color = Utils.getTierColor(tier);
        const tierIcon = Utils.getTierIcon(tier);
        nicknameEl.textContent = '';
        nicknameEl.appendChild(document.createTextNode(nickname));
        nicknameEl.appendChild(document.createTextNode(' '));
        const tierIconEl = document.createElement('span');
        tierIconEl.className = 'profile-tier-icon-inline';
        tierIconEl.title = tier;
        tierIconEl.textContent = tierIcon;
        nicknameEl.appendChild(tierIconEl);
        applyProfileCustomization({
            nicknameColor: user.stats?.nickname_color || '',
            profileBorder: user.stats?.profile_border || '',
        });

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

    function applyProfileCustomization({ nicknameColor, profileBorder }) {
        if (nicknameEl) {
            nicknameEl.style.color = Utils.getNicknameColorValue(nicknameColor);
        }
        if (avatarEl) {
            avatarEl.style.boxShadow = Utils.getProfileBorderValue(profileBorder);
        }
    }

    function deriveTierFromRating(rating) {
        const value = Number(rating) || 0;
        if (value >= 3000) return 'Master';
        if (value >= 2500) return 'Expert';
        if (value >= 2000) return 'Advanced';
        if (value >= 1500) return 'Intermediate';
        if (value >= 1000) return 'Junior';
        return 'Beginner';
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

        // 파이차트 렌더링
        renderWinratePieChart(
            summary.games_won ?? 0,
            summary.games_lost ?? 0,
            summary.games_draw ?? 0
        );

        // 레이팅 추이 차트 렌더링
        renderRatingLineChart(data.rating_history || []);

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

        renderActivityTimeline(summary, games);
    }

    function renderActivityTimeline(summary, games) {
        if (!activityTimelineEl) return;
        const items = [];
        const seasonTitle = currentUser?.stats?.season_title || '';
        const stylePoints = Number(summary?.style_points ?? currentUser?.stats?.style_points ?? 0);

        if (seasonTitle) {
            items.push({
                badge: '🏆',
                title: '현재 시즌 칭호',
                body: seasonTitle,
                meta: '시즌 래더 보상'
            });
        }

        if (stylePoints > 0) {
            items.push({
                badge: '🎨',
                title: '보유 포인트',
                body: `${Utils.formatNumber(stylePoints)}P`,
                meta: '커스터마이징에서 사용 가능'
            });
        }

        games.slice(0, 4).forEach((game) => {
            const resultInfo = getResultInfo(game, currentUserId);
            const opponent = game.white_player?.id === currentUserId
                ? game.black_player?.nickname
                : game.white_player?.nickname;
            items.push({
                badge: resultInfo.className === 'win' ? '✅' : (resultInfo.className === 'lose' ? '⚠️' : '🤝'),
                title: `${resultInfo.label} · ${opponent || '상대'}`,
                body: `${game.white_player?.nickname || '화이트'} vs ${game.black_player?.nickname || '블랙'}`,
                meta: `${game.room_type || '대국'} · ${formatDate(game.created_at)}`
            });
        });

        if (!items.length) {
            activityTimelineEl.innerHTML = '<div class="helper-text">표시할 최근 활동이 없습니다.</div>';
            return;
        }

        activityTimelineEl.innerHTML = items.map((item) => `
            <article class="activity-item">
                <div class="activity-badge">${item.badge}</div>
                <div class="activity-content">
                    <strong class="activity-title">${Utils.escapeHtml(item.title)}</strong>
                    <div class="activity-body">${Utils.escapeHtml(item.body)}</div>
                    <div class="activity-meta">${Utils.escapeHtml(item.meta)}</div>
                </div>
            </article>
        `).join('');
    }

    function renderWinratePieChart(wins, losses, draws) {
        if (!winrateChart) return;
        const ctx = winrateChart.getContext('2d');
        const total = wins + losses + draws;

        if (total === 0) {
            ctx.fillStyle = '#ccc';
            ctx.beginPath();
            ctx.arc(60, 60, 50, 0, Math.PI * 2);
            ctx.fill();
            if (winrateLegend) winrateLegend.innerHTML = '<span class="helper-text">데이터 없음</span>';
            return;
        }

        const data = [
            { value: wins, color: '#27ae60', label: '승' },
            { value: losses, color: '#c0392b', label: '패' },
            { value: draws, color: '#f39c12', label: '무' },
        ];

        let startAngle = -Math.PI / 2;
        const centerX = 60;
        const centerY = 60;
        const radius = 50;

        data.forEach(item => {
            if (item.value === 0) return;
            const sliceAngle = (item.value / total) * Math.PI * 2;
            ctx.beginPath();
            ctx.moveTo(centerX, centerY);
            ctx.arc(centerX, centerY, radius, startAngle, startAngle + sliceAngle);
            ctx.closePath();
            ctx.fillStyle = item.color;
            ctx.fill();
            startAngle += sliceAngle;
        });

        // 가운데 구멍 (도넛 차트)
        ctx.beginPath();
        ctx.arc(centerX, centerY, 30, 0, Math.PI * 2);
        ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--color-bg-card').trim() || '#fff';
        ctx.fill();

        // 레전드
        if (winrateLegend) {
            winrateLegend.innerHTML = data.map(item => `
                <span class="chart-legend-item">
                    <span class="chart-legend-color" style="background:${item.color}"></span>
                    ${item.label} ${item.value}
                </span>
            `).join('');
        }
    }

    function renderRatingLineChart(history) {
        if (!ratingChart) return;
        const ctx = ratingChart.getContext('2d');
        const width = ratingChart.width;
        const height = ratingChart.height;
        const padding = { top: 10, right: 10, bottom: 20, left: 35 };

        ctx.clearRect(0, 0, width, height);

        if (!history || history.length < 2) {
            ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--color-text-muted').trim() || '#888';
            ctx.font = '11px sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText('데이터 부족', width / 2, height / 2);
            return;
        }

        const ratings = history.map(h => h.rating);
        const minRating = Math.min(...ratings) - 50;
        const maxRating = Math.max(...ratings) + 50;
        const chartWidth = width - padding.left - padding.right;
        const chartHeight = height - padding.top - padding.bottom;

        // 배경 그리드
        ctx.strokeStyle = getComputedStyle(document.documentElement).getPropertyValue('--color-border').trim() || '#ddd';
        ctx.lineWidth = 0.5;
        for (let i = 0; i <= 4; i++) {
            const y = padding.top + (chartHeight / 4) * i;
            ctx.beginPath();
            ctx.moveTo(padding.left, y);
            ctx.lineTo(width - padding.right, y);
            ctx.stroke();
        }

        // 라인 그래프
        ctx.strokeStyle = getComputedStyle(document.documentElement).getPropertyValue('--color-accent-primary').trim() || '#38bdf8';
        ctx.lineWidth = 2;
        ctx.beginPath();

        history.forEach((point, i) => {
            const x = padding.left + (chartWidth / (history.length - 1)) * i;
            const y = padding.top + chartHeight - ((point.rating - minRating) / (maxRating - minRating)) * chartHeight;
            if (i === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        });
        ctx.stroke();

        // Y축 레이블
        ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--color-text-muted').trim() || '#888';
        ctx.font = '9px sans-serif';
        ctx.textAlign = 'right';
        ctx.fillText(Math.round(maxRating), padding.left - 5, padding.top + 10);
        ctx.fillText(Math.round(minRating), padding.left - 5, height - padding.bottom);
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

    async function loadGuestbook() {
        if (!guestbookList || !currentUserId) return;
        guestbookList.innerHTML = '<div class="helper-text">불러오는 중...</div>';
        try {
            const data = await API.get(`/accounts/users/${currentUserId}/guestbook/`);
            renderGuestbook(data || []);
        } catch {
            guestbookList.innerHTML = '<div class="helper-text">방명록을 불러오지 못했습니다.</div>';
        }
    }

    function renderGuestbook(entries) {
        if (!guestbookList) return;
        if (!entries.length) {
            guestbookList.innerHTML = '<div class="helper-text">방명록이 없습니다.</div>';
            return;
        }
        guestbookList.innerHTML = entries.map((entry) => {
            const canDelete = entry.author?.id === currentUserId;
            const time = formatDate(entry.created_at);
            return `
                <div class="guestbook-item" data-entry-id="${entry.id}">
                    <div>${Utils.escapeHtml(entry.message)}</div>
                    <div class="guestbook-meta">
                        <span>${Utils.escapeHtml(entry.author?.nickname || '알 수 없음')}</span>
                        <span>${time}</span>
                    </div>
                    ${canDelete ? '<button class="btn btn-secondary btn-sm" data-action="delete">삭제</button>' : ''}
                </div>
            `;
        }).join('');

        guestbookList.querySelectorAll('[data-action="delete"]').forEach((btn) => {
            btn.addEventListener('click', async () => {
                const entryId = btn.closest('.guestbook-item')?.dataset.entryId;
                if (!entryId) return;
                await deleteGuestbook(entryId);
            });
        });
    }

    async function submitGuestbook() {
        if (!guestbookInput || !currentUserId) return;
        const message = guestbookInput.value.trim();
        if (!message) return;
        try {
            await API.post(`/accounts/users/${currentUserId}/guestbook/`, { message });
            guestbookInput.value = '';
            await loadGuestbook();
        } catch (error) {
            Toast.error(error.data?.message || '방명록 등록에 실패했습니다.');
        }
    }

    async function deleteGuestbook(entryId) {
        try {
            await API.delete(`/accounts/guestbook/${entryId}/`);
            await loadGuestbook();
        } catch (error) {
            Toast.error(error.data?.message || '삭제에 실패했습니다.');
        }
    }

    function formatDate(value) {
        if (!value) return '-';
        const d = new Date(value);
        const y = d.getFullYear();
        const m = String(d.getMonth() + 1).padStart(2, '0');
        const day = String(d.getDate()).padStart(2, '0');
        const hh = String(d.getHours()).padStart(2, '0');
        const mm = String(d.getMinutes()).padStart(2, '0');
        return `${y}-${m}-${day} ${hh}:${mm}`;
    }
})();
