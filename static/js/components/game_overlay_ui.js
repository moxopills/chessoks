(function() {
    'use strict';

    function mountReplayDock({ replayDock, sidePanel, spectatorSection, chatSection }) {
        if (!replayDock || !sidePanel) return;
        if (replayDock.parentElement === sidePanel) return;
        const anchor = spectatorSection || chatSection || null;
        sidePanel.insertBefore(replayDock, anchor);
    }

    function bindStatusModal({ statusModal, statusModalOk }) {
        if (!statusModalOk || !statusModal) return;
        statusModalOk.addEventListener('click', () => {
            statusModal.classList.add('hidden');
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

    function showPromotionModal({
        promotionModal,
        pendingPromotion,
        myColor,
        moveConfirmEnabled,
        getPieceSvgMarkup,
        getPieceTypeClass,
        onPendingConfirmedMove,
        onSendMove,
        onPromotionResolved,
    }) {
        if (!promotionModal || !pendingPromotion) return;
        promotionModal.classList.remove('hidden');

        document.querySelectorAll('.promotion-piece').forEach((btn) => {
            const piece = btn.dataset.piece;
            const pieceChar = myColor === 'white' ? piece.toUpperCase() : piece.toLowerCase();
            btn.innerHTML = getPieceSvgMarkup(pieceChar);
            btn.classList.remove(
                'piece-type-p',
                'piece-type-r',
                'piece-type-n',
                'piece-type-b',
                'piece-type-q',
                'piece-type-k',
                'white',
                'black',
            );
            btn.classList.add(getPieceTypeClass(pieceChar));
            btn.classList.add(myColor === 'white' ? 'white' : 'black');
            btn.onclick = () => {
                const uci = pendingPromotion.from + pendingPromotion.to;
                if (moveConfirmEnabled) {
                    onPendingConfirmedMove?.({ uci, promotion: piece });
                    document.getElementById('move-confirm-overlay')?.classList.remove('hidden');
                } else {
                    onSendMove?.(uci, piece);
                }
                promotionModal.classList.add('hidden');
                onPromotionResolved?.();
            };
        });
    }

    function showGameEndModal({
        result,
        myColor,
        clearTimer,
        gameEndModal,
        iconEl,
        titleEl,
        resultEl,
        analysisLoading,
        analysisContent,
        analysisSummary,
        getOutcome,
        onLoadSummary,
        onLoadAnalysis,
        onUpdateStatusStrip,
    }) {
        clearTimer?.();
        gameEndModal?.classList.remove('outcome-win', 'outcome-loss', 'outcome-draw');

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
            gameEndModal?.classList.add('outcome-win');
        } else if (outcome === 'loss') {
            gameEndModal?.classList.add('outcome-loss');
        } else if (outcome === 'draw') {
            gameEndModal?.classList.add('outcome-draw');
        }

        if (iconEl) iconEl.textContent = icon;
        if (titleEl) titleEl.textContent = title;
        if (resultEl) resultEl.textContent = resultText;

        onLoadSummary?.();
        gameEndModal?.classList.remove('hidden');
        if (gameEndModal) gameEndModal.style.display = 'flex';
        onUpdateStatusStrip?.();
        onLoadAnalysis?.();
    }

    window.GameOverlayUI = {
        mountReplayDock,
        bindStatusModal,
        showStatusModal,
        showPromotionModal,
        showGameEndModal,
    };
})();
