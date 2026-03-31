(function() {
    'use strict';

    const DRAW_RESULTS = new Set([
        'draw',
        'draw_agreement',
        'draw_insufficient',
        'draw_repetition',
        'draw_fifty_move',
        'stalemate',
    ]);
    const WHITE_WIN_RESULTS = new Set([
        'white_win',
        'checkmate_white',
        'timeout_black',
        'resignation_black',
    ]);
    const BLACK_WIN_RESULTS = new Set([
        'black_win',
        'checkmate_black',
        'timeout_white',
        'resignation_white',
    ]);

    function getTierName(user) {
        const rating = Number(user?.stats?.rating ?? user?.rating ?? 0);
        return user?.stats?.rank_tier || user?.rank_tier || deriveTierFromRating(rating);
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

    function applyProfileFrame(profileCardEl, frameKey) {
        if (!profileCardEl) return;
        profileCardEl.classList.remove(
            'season-frame-champion',
            'season-frame-runnerup',
            'season-frame-third',
            'season-frame-top10'
        );
        const frameClass = Utils.getProfileCardFrameClass(frameKey || '');
        if (frameClass) {
            profileCardEl.classList.add(frameClass);
        }
    }

    function renderIdentity(config = {}) {
        const {
            user,
            avatarEl,
            nicknameEl,
            nameEl,
            emailEl,
            bioEl,
            tierEl,
            ratingEl,
            seasonTitleEl,
            profileCardEl,
            placeholderClass = 'avatar-placeholder',
        } = config;

        if (!user) return;

        const tier = getTierName(user);
        const nickname = user.nickname || '닉네임 없음';
        const nicknameColor = user.stats?.nickname_color || '';
        const profileBorder = user.stats?.profile_border || '';

        if (nicknameEl) {
            nicknameEl.textContent = '';
            nicknameEl.style.color = Utils.getNicknameColorValue(nicknameColor);
            nicknameEl.appendChild(document.createTextNode(nickname));
            nicknameEl.appendChild(document.createTextNode(' '));
            const tierIconEl = document.createElement('span');
            tierIconEl.className = 'profile-tier-icon-inline';
            tierIconEl.title = tier;
            tierIconEl.textContent = Utils.getTierIcon(tier);
            nicknameEl.appendChild(tierIconEl);
        }

        if (nameEl) {
            nameEl.textContent = nickname;
            nameEl.style.color = Utils.getNicknameColorValue(nicknameColor);
        }

        if (emailEl) {
            emailEl.textContent = user.email || '';
        }

        if (bioEl) {
            bioEl.textContent = user.bio || '소개가 없습니다.';
        }

        if (tierEl) {
            tierEl.textContent = ratingEl ? tier : `티어 · ${tier}`;
            tierEl.style.color = Utils.getTierColor(tier);
        }

        if (ratingEl) {
            ratingEl.textContent = `레이팅 ${user.stats?.rating ?? user.rating ?? '-'}`;
        }

        if (seasonTitleEl) {
            seasonTitleEl.textContent = user.stats?.season_title
                ? `시즌 칭호: ${user.stats.season_title}`
                : '시즌 칭호 없음';
        }

        applyProfileFrame(profileCardEl, user.stats?.profile_card_frame || '');

        if (avatarEl) {
            avatarEl.style.boxShadow = Utils.getProfileBorderValue(profileBorder);
            Utils.setAvatar(avatarEl, {
                url: user.avatar_url,
                alt: nickname,
                placeholder: user.nickname?.[0] || '?',
                placeholderClass,
            });

            if (!avatarEl.querySelector('.tier-badge')) {
                avatarEl.insertAdjacentHTML(
                    'beforeend',
                    `<span class="tier-badge" title="${Utils.escapeHtml(tier)}">${Utils.getTierIcon(tier)}</span>`
                );
            } else {
                avatarEl.querySelector('.tier-badge').textContent = Utils.getTierIcon(tier);
                avatarEl.querySelector('.tier-badge').title = tier;
            }
        }
    }

    function renderStats(stats, nodes = {}) {
        if (!stats) return;
        if (nodes.games) nodes.games.textContent = stats.games_played ?? 0;
        if (nodes.wins) nodes.wins.textContent = stats.games_won ?? 0;
        if (nodes.losses) nodes.losses.textContent = stats.games_lost ?? 0;
        if (nodes.draws) nodes.draws.textContent = stats.games_draw ?? 0;
        if (nodes.rating) nodes.rating.textContent = Utils.formatNumber(stats.rating ?? 0);
        if (nodes.winrate) nodes.winrate.textContent = `${stats.win_rate ?? 0}%`;
        if (nodes.total) nodes.total.textContent = stats.games_played ?? 0;
    }

    function renderPreviousSeason(container, season) {
        if (!container) return;
        if (!season) {
            container.textContent = '지난 시즌 기록이 없습니다.';
            return;
        }
        const rankText = season.final_rank ? `#${season.final_rank}` : '-';
        container.innerHTML = `
            <div class="season-summary-item"><span>시즌명</span><strong>${Utils.escapeHtml(season.season_name)}</strong></div>
            <div class="season-summary-item"><span>최종 순위</span><strong>${rankText}</strong></div>
            <div class="season-summary-item"><span>전적</span><strong>${season.wins}승 ${season.losses}패 ${season.draws}무</strong></div>
            <div class="season-summary-item"><span>승률/판수</span><strong>${season.win_rate}% · ${season.games_played}판</strong></div>
        `;
    }

    function getResultInfo(game, targetUserId) {
        const targetId = Number(targetUserId);
        const isWhite = Number(game.white_player?.id) === targetId;
        if (game.result === 'playing') {
            return { label: '진행', className: 'draw' };
        }
        if (DRAW_RESULTS.has(game.result)) {
            return { label: '무승부', className: 'draw' };
        }
        if (WHITE_WIN_RESULTS.has(game.result)) {
            return isWhite ? { label: '승리', className: 'win' } : { label: '패배', className: 'lose' };
        }
        if (BLACK_WIN_RESULTS.has(game.result)) {
            return isWhite ? { label: '패배', className: 'lose' } : { label: '승리', className: 'win' };
        }
        return { label: '종료', className: 'draw' };
    }

    function renderRecentGames(container, games, targetUserId, options = {}) {
        if (!container) return;
        const {
            emptyText = '최근 전적이 없습니다.',
            compact = false,
        } = options;

        if (!Array.isArray(games) || !games.length) {
            container.innerHTML = `<div class="helper-text">${Utils.escapeHtml(emptyText)}</div>`;
            return;
        }

        if (compact) {
            container.innerHTML = games.slice(0, 6).map((game) => {
                const isWhite = Number(game.white_player?.id) === Number(targetUserId);
                const opponent = isWhite ? game.black_player?.nickname : game.white_player?.nickname;
                const resultInfo = getResultInfo(game, targetUserId);
                const playedAt = game.created_at
                    ? Utils.formatDate(game.created_at, {
                        year: 'numeric',
                        month: '2-digit',
                        day: '2-digit',
                    }).replace(/\./g, '').trim()
                    : '';

                return `
                    <div class="recent-item">
                        <span class="recent-opponent">${Utils.escapeHtml(opponent || '상대')}</span>
                        <span class="recent-result">${resultInfo.label}</span>
                        <span class="recent-meta text-muted">${playedAt}</span>
                    </div>
                `;
            }).join('');
            return;
        }

        container.innerHTML = games.map((game) => {
            const resultInfo = getResultInfo(game, targetUserId);
            const title = `${game.white_player?.nickname || '화이트'} vs ${game.black_player?.nickname || '블랙'}`;
            const meta = `${Utils.formatDate(game.created_at)} · ${game.room_type}`;
            return `
                <div class="game-row">
                    <div class="game-meta">
                        <div class="game-title">${Utils.escapeHtml(title)}</div>
                        <div>${Utils.escapeHtml(meta)}</div>
                    </div>
                    <span class="game-result ${resultInfo.className}">${resultInfo.label}</span>
                </div>
            `;
        }).join('');
    }

    window.ProfileView = {
        deriveTierFromRating,
        renderIdentity,
        renderStats,
        renderPreviousSeason,
        renderRecentGames,
        getResultInfo,
    };
})();
