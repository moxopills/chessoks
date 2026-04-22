(function() {
    'use strict';

    function buildMovePage({
        pageMoves = [],
        startIndex = 0,
        emptyMessage = '아직 착수가 없습니다.',
    } = {}) {
        if (!pageMoves.length) {
            return `<div class="move-list-empty">${emptyMessage}</div>`;
        }

        let html = '';
        let moveNum = startIndex + 1;

        for (const movePair of pageMoves) {
            const parts = movePair.trim().split(/\s+/);
            html += `
                <div class="move-row">
                    <span class="move-number">${moveNum}.</span>
                    <span class="move-san">${parts[0] || ''}</span>
                    <span class="move-san">${parts[1] || ''}</span>
                </div>
            `;
            moveNum += 1;
        }

        return html || `<div class="move-list-empty">${emptyMessage}</div>`;
    }

    function bindPager({ prevBtn, nextBtn, labelEl, page, totalPages, onPrev, onNext }) {
        if (labelEl && Number.isFinite(page) && Number.isFinite(totalPages)) {
            labelEl.textContent = `${page} / ${totalPages}`;
        }
        if (prevBtn) prevBtn.disabled = page <= 1;
        if (nextBtn) nextBtn.disabled = page >= totalPages;

        if (prevBtn && onPrev && prevBtn.dataset.boundPager !== 'true') {
            prevBtn.dataset.boundPager = 'true';
            prevBtn.addEventListener('click', onPrev);
        }
        if (nextBtn && onNext && nextBtn.dataset.boundPager !== 'true') {
            nextBtn.dataset.boundPager = 'true';
            nextBtn.addEventListener('click', onNext);
        }
    }

    function bindReplayControls({
        replayBtn,
        replayPrev,
        replayNext,
        replayPlay,
        replayClose,
        replayPrevDock,
        replayNextDock,
        replayPlayDock,
        replayCloseDock,
        onOpen,
        onPrev,
        onNext,
        onPlayPause,
        onClose,
    }) {
        const pairs = [
            [replayBtn, onOpen],
            [replayPrev, onPrev],
            [replayNext, onNext],
            [replayPlay, onPlayPause],
            [replayClose, onClose],
            [replayPrevDock, onPrev],
            [replayNextDock, onNext],
            [replayPlayDock, onPlayPause],
            [replayCloseDock, onClose],
        ];
        pairs.forEach(([button, handler]) => {
            if (!button || !handler || button.dataset.boundReplay === 'true') return;
            button.dataset.boundReplay = 'true';
            button.addEventListener('click', handler);
        });
    }

    function applyReplayPosition({
        replayMoves = [],
        replayIndex = 0,
        replayStatus,
        replayStatusDock,
        replayPrev,
        replayNext,
        replayPlay,
        replayPrevDock,
        replayNextDock,
        replayPlayDock,
        onApplyFen,
    }) {
        if (!replayMoves.length) {
            if (replayStatus) replayStatus.textContent = '기보가 없습니다.';
            replayPrev && (replayPrev.disabled = true);
            replayNext && (replayNext.disabled = true);
            replayPlay && (replayPlay.disabled = true);
            replayPrevDock && (replayPrevDock.disabled = true);
            replayNextDock && (replayNextDock.disabled = true);
            replayPlayDock && (replayPlayDock.disabled = true);
            return false;
        }

        replayPrev && (replayPrev.disabled = false);
        replayNext && (replayNext.disabled = false);
        replayPlay && (replayPlay.disabled = false);
        replayPrevDock && (replayPrevDock.disabled = false);
        replayNextDock && (replayNextDock.disabled = false);
        replayPlayDock && (replayPlayDock.disabled = false);

        const total = replayMoves.length;
        const statusText = replayIndex === 0 ? '시작 위치' : `${replayIndex}/${total} 수`;
        if (replayStatus) replayStatus.textContent = statusText;
        if (replayStatusDock) replayStatusDock.textContent = statusText;

        const fen = replayIndex === 0
            ? 'rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1'
            : replayMoves[replayIndex - 1]?.fen_after_move;
        if (fen && onApplyFen) {
            onApplyFen({
                fen,
                lastMove: replayIndex === 0
                    ? null
                    : {
                        from: replayMoves[replayIndex - 1].from_square,
                        to: replayMoves[replayIndex - 1].to_square,
                    },
            });
        }
        return true;
    }

    window.GameReplayUI = {
        buildMovePage,
        bindPager,
        bindReplayControls,
        applyReplayPosition,
    };
})();
