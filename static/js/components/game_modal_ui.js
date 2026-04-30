(function() {
    'use strict';

    function setupStatusModal({ statusModal, statusModalOk }) {
        if (!statusModalOk) return;
        statusModalOk.addEventListener('click', () => {
            statusModal?.classList.add('hidden');
        });
    }

    function showStatusModal({ statusModal, statusModalMessage, message, autoCloseMs = null }) {
        if (!statusModal || !statusModalMessage) return;
        statusModalMessage.textContent = message;
        statusModal.classList.remove('hidden');
        if (autoCloseMs) {
            setTimeout(() => {
                statusModal.classList.add('hidden');
            }, autoCloseMs);
        }
    }

    function showPendingEnd({ gameEndModal, message }) {
        if (!gameEndModal) return;
        gameEndModal.classList.remove('outcome-win', 'outcome-loss', 'outcome-draw');
        const iconEl = document.getElementById('game-end-icon');
        const titleEl = document.getElementById('game-end-title');
        const resultEl = document.getElementById('game-end-result');
        const ratingEl = document.getElementById('game-end-rating');

        if (iconEl) iconEl.textContent = '⏳';
        if (titleEl) titleEl.textContent = '처리 중...';
        if (resultEl) resultEl.textContent = message;
        if (ratingEl) ratingEl.textContent = '';

        gameEndModal.classList.remove('hidden');
        gameEndModal.style.display = 'flex';
    }

    function applyGameEndPresentation({
        gameEndModal,
        result,
        myColor,
        getOutcome,
        analysisLoading,
        analysisContent,
        analysisSummary,
    }) {
        if (!gameEndModal) return;
        gameEndModal.classList.remove('outcome-win', 'outcome-loss', 'outcome-draw');

        const iconEl = document.getElementById('game-end-icon');
        const titleEl = document.getElementById('game-end-title');
        const resultEl = document.getElementById('game-end-result');

        if (analysisLoading) analysisLoading.classList.remove('hidden');
        if (analysisContent) analysisContent.classList.add('hidden');
        if (analysisSummary) analysisSummary.textContent = '';

        let icon = '🎮';
        let title = '게임 종료';
        let resultText = result;

        const outcome = getOutcome(result, myColor);
        const isWin = outcome === 'win';

        if (result.includes('checkmate')) {
            icon = isWin ? '👑' : '💀';
            title = isWin ? '승리!' : '패배';
            resultText = '체크메이트';
        } else if (result.includes('resignation')) {
            if (outcome === 'win') {
                icon = '🏆';
                title = '승리!';
                resultText = '상대 기권';
            } else if (outcome === 'loss') {
                icon = '🏳️';
                title = '패배';
                resultText = '내 기권';
            } else {
                icon = '🏳️';
                title = '패배';
                resultText = '기권';
            }
        } else if (result.includes('timeout')) {
            icon = isWin ? '⏰' : '⏱️';
            title = isWin ? '승리!' : '패배';
            resultText = '시간 초과';
        } else if (result.includes('draw') || result === 'stalemate') {
            icon = '🤝';
            title = '무승부';
            resultText = result === 'stalemate' ? '스테일메이트' : '합의 무승부';
        }

        if (outcome === 'win') {
            gameEndModal.classList.add('outcome-win');
        } else if (outcome === 'loss') {
            gameEndModal.classList.add('outcome-loss');
        } else if (outcome === 'draw') {
            gameEndModal.classList.add('outcome-draw');
        }

        if (iconEl) iconEl.textContent = icon;
        if (titleEl) titleEl.textContent = title;
        if (resultEl) resultEl.textContent = resultText;

        gameEndModal.classList.remove('hidden');
        gameEndModal.style.display = 'flex';
    }

    window.GameModalUI = {
        setupStatusModal,
        showStatusModal,
        showPendingEnd,
        applyGameEndPresentation,
    };
})();
