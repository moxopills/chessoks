(function() {
    'use strict';

    function renderPlayerBars({
        game,
        myColor,
        opponentBar,
        myBar,
    }) {
        if (!game) return;

        const whitePlayer = game.white_player;
        const blackPlayer = game.black_player;
        const isFlipped = myColor === 'black';
        const topPlayer = isFlipped ? whitePlayer : blackPlayer;
        const bottomPlayer = isFlipped ? blackPlayer : whitePlayer;

        renderPlayerBar({
            container: opponentBar,
            player: topPlayer,
            fallbackName: '상대',
            nicknameColor: Utils.getNicknameColorValue(topPlayer?.nickname_color || ''),
            profileRing: Utils.getProfileBorderValue(topPlayer?.profile_border || ''),
            tier: topPlayer?.rank_tier || 'Junior',
            timerId: 'opponent-timer',
        });

        renderPlayerBar({
            container: myBar,
            player: bottomPlayer,
            fallbackName: '나',
            nicknameColor: Utils.getNicknameColorValue(bottomPlayer?.nickname_color || ''),
            profileRing: Utils.getProfileBorderValue(bottomPlayer?.profile_border || ''),
            tier: bottomPlayer?.rank_tier || 'Junior',
            timerId: 'my-timer',
        });
    }

    function renderPlayerBar({
        container,
        player,
        fallbackName,
        nicknameColor,
        profileRing,
        tier,
        timerId,
    }) {
        if (!container) return;
        container.textContent = '';

        const info = document.createElement('div');
        info.className = 'player-bar-info';

        const avatar = document.createElement('div');
        avatar.className = 'avatar avatar-sm';
        if (profileRing) avatar.style.boxShadow = profileRing;
        Utils.setAvatar(avatar, {
            url: player?.avatar_url,
            alt: player?.nickname || fallbackName,
            placeholder: '?',
            placeholderClass: 'avatar-placeholder',
        });
        info.appendChild(avatar);

        const details = document.createElement('div');
        details.className = 'player-bar-details';

        const name = document.createElement('span');
        name.className = 'player-bar-name';
        if (nicknameColor) name.style.color = nicknameColor;
        name.appendChild(document.createTextNode(player?.nickname || fallbackName));
        name.appendChild(document.createTextNode(' '));
        const badge = document.createElement('span');
        badge.className = 'tier-badge';
        badge.title = tier || '';
        badge.textContent = Utils.getTierIcon(tier || '');
        name.appendChild(badge);
        details.appendChild(name);

        const rating = document.createElement('span');
        rating.className = 'player-bar-rating';
        rating.textContent = String(player?.rating || '--');
        details.appendChild(rating);

        if (player?.featured_achievement?.title) {
            const achievement = document.createElement('span');
            achievement.className = `player-bar-achievement player-bar-achievement--${player.featured_achievement.tone || 'info'}`;
            achievement.textContent = `${player.featured_achievement.icon || '🏅'} ${player.featured_achievement.title}`;
            details.appendChild(achievement);
        }

        info.appendChild(details);
        container.appendChild(info);

        const timer = document.createElement('div');
        timer.className = 'player-bar-timer';
        timer.id = timerId;
        timer.textContent = '--:--';
        container.appendChild(timer);
    }

    function setUiStateBadge(element, tone, text) {
        if (!element) return;
        const nextClass = ['ui-state-badge'];
        if (tone === 'success') nextClass.push('ui-state-badge--success');
        if (tone === 'pending') nextClass.push('ui-state-badge--pending');
        if (tone === 'warning') nextClass.push('ui-state-badge--warning');
        element.className = nextClass.join(' ');
        element.textContent = text;
    }

    function getModeBadgeText({ game, replayOnly, isAiRoom, myColor }) {
        if (replayOnly) return '기보 다시보기';
        if (!game) return '실시간 대국';
        if (isAiRoom) return 'AI 대전';
        if (!myColor) return '관전 중';
        if (game.room_type === 'competitive') return '경쟁전';
        if (game.room_type === 'quick') return '빠른 대전';
        return '실시간 대국';
    }

    function updateStatusStrip({
        game,
        replayOnly,
        isAiRoom,
        myColor,
        isMyTurn,
        lastMove,
        gameModeBadge,
        gameTurnBadge,
        gameAlertBadge,
        getOutcome,
    }) {
        if (!game) return;

        const modeTone = replayOnly ? 'warning' : (!myColor ? 'pending' : 'success');
        setUiStateBadge(
            gameModeBadge,
            modeTone,
            getModeBadgeText({ game, replayOnly, isAiRoom, myColor })
        );

        if (game.result && game.result !== 'playing') {
            const outcome = getOutcome(game.result, myColor);
            if (outcome === 'win') {
                setUiStateBadge(gameTurnBadge, 'success', '결과: 승리');
            } else if (outcome === 'loss') {
                setUiStateBadge(gameTurnBadge, 'warning', '결과: 패배');
            } else if (outcome === 'draw') {
                setUiStateBadge(gameTurnBadge, 'pending', '결과: 무승부');
            } else {
                setUiStateBadge(gameTurnBadge, '', '결과 확정');
            }
        } else if (!myColor) {
            setUiStateBadge(gameTurnBadge, 'pending', game.current_turn === 'white' ? '백 차례' : '흑 차례');
        } else {
            setUiStateBadge(gameTurnBadge, isMyTurn ? 'success' : '', isMyTurn ? '내 차례' : '상대 차례');
        }

        if (lastMove?.is_checkmate) {
            setUiStateBadge(gameAlertBadge, 'warning', '체크메이트');
        } else if (lastMove?.is_check && game.result === 'playing') {
            setUiStateBadge(
                gameAlertBadge,
                'warning',
                !myColor ? '체크 발생' : (game.current_turn === myColor ? '체크 경고' : '상대 킹 체크')
            );
        } else if (replayOnly) {
            setUiStateBadge(gameAlertBadge, '', '기보를 단계별로 다시볼 수 있습니다');
        } else if (!myColor) {
            setUiStateBadge(gameAlertBadge, '', '우측 패널에서 기보·관전자·채팅 확인');
        } else {
            setUiStateBadge(gameAlertBadge, '', '우측 패널에서 기보·채팅·액션 확인');
        }
    }

    function updateTurnPresentation({
        game,
        myColor,
        isMyTurn,
        opponentBar,
        myBar,
        gameActions,
        turnIndicator,
        hasShownStartGuide,
        showStatusModal,
    }) {
        if (!game) {
            return { hasShownStartGuide };
        }

        const isFlipped = myColor === 'black';
        const isWhiteTurn = game.current_turn === 'white';
        const isTopPlayerTurn = isFlipped ? isWhiteTurn : !isWhiteTurn;

        opponentBar?.classList.toggle('active', isTopPlayerTurn);
        myBar?.classList.toggle('active', !isTopPlayerTurn);

        if (!myColor && gameActions) {
            gameActions.style.display = 'none';
        }

        const whiteName = game.white_player?.nickname || '화이트';
        const blackName = game.black_player?.nickname || '블랙';
        const currentName = game.current_turn === 'white' ? whiteName : blackName;

        if (turnIndicator) {
            if (!hasShownStartGuide && game.move_count === 0) {
                turnIndicator.textContent = `${currentName}님부터 시작합니다. 번갈아가며 한 번씩 수를 둡니다.`;
            } else {
                turnIndicator.textContent = `지금은 ${currentName}님의 차례입니다.`;
            }
        }

        if (!hasShownStartGuide && game.move_count === 0) {
            showStatusModal?.(`${currentName}님부터 시작합니다. 번갈아가며 한 번씩 수를 둡니다.`, 2500);
            hasShownStartGuide = true;
        }

        return { hasShownStartGuide };
    }

    function getLiveTimeSnapshot({ game }) {
        if (!game) {
            return { white: 0, black: 0 };
        }
        let white = Number(game.white_time_remaining || 0);
        let black = Number(game.black_time_remaining || 0);
        if (game.result === 'playing' && game.turn_started_at) {
            const startedAt = new Date(game.turn_started_at).getTime();
            if (!Number.isNaN(startedAt)) {
                const elapsed = Math.max(0, (Date.now() - startedAt) / 1000);
                if (game.current_turn === 'white') {
                    white = Math.max(0, white - elapsed);
                } else {
                    black = Math.max(0, black - elapsed);
                }
            }
        }
        return { white, black };
    }

    function updateTimerDisplay({
        game,
        myColor,
        opponentBar,
        myBar,
    }) {
        if (!game) return;

        const isFlipped = myColor === 'black';
        const liveTimes = getLiveTimeSnapshot({ game });
        const topTime = isFlipped ? liveTimes.white : liveTimes.black;
        const bottomTime = isFlipped ? liveTimes.black : liveTimes.white;

        const opponentTimerEl = opponentBar?.querySelector('.player-bar-timer');
        const myTimerEl = myBar?.querySelector('.player-bar-timer');

        if (opponentTimerEl) {
            opponentTimerEl.textContent = Utils.formatTime(topTime);
            opponentTimerEl.classList.toggle('low', topTime < 30);
        }
        if (myTimerEl) {
            myTimerEl.textContent = Utils.formatTime(bottomTime);
            myTimerEl.classList.toggle('low', bottomTime < 30);
        }
    }

    window.GameStatusUI = {
        renderPlayerBars,
        updateStatusStrip,
        updateTurnPresentation,
        getLiveTimeSnapshot,
        updateTimerDisplay,
    };
})();
