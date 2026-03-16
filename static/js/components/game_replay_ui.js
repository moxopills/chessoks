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

    window.GameReplayUI = {
        buildMovePage,
        bindPager,
        bindReplayControls,
    };
})();
