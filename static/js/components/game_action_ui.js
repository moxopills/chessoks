(function() {
    'use strict';

    function bindPrimaryActions({
        myColor,
        replayOnly,
        isAiRoom,
        gameActions,
        drawBtn,
        resignBtn,
        leaveBtn,
        confirmOverlay,
        confirmYes,
        confirmNo,
        onConfirmMove,
        onCancelMove,
        onAiLeave,
        onOfferDraw,
        onResign,
        onLeave,
    }) {
        if (!myColor || replayOnly) {
            gameActions?.classList.add('hidden');
            return;
        }

        if (confirmYes && confirmYes.dataset.boundAction !== 'true') {
            confirmYes.dataset.boundAction = 'true';
            confirmYes.addEventListener('click', () => {
                onConfirmMove?.();
                confirmOverlay?.classList.add('hidden');
            });
        }

        if (confirmNo && confirmNo.dataset.boundAction !== 'true') {
            confirmNo.dataset.boundAction = 'true';
            confirmNo.addEventListener('click', () => {
                onCancelMove?.();
                confirmOverlay?.classList.add('hidden');
            });
        }

        if (isAiRoom) {
            gameActions?.classList.remove('hidden');
            drawBtn?.remove();
            resignBtn?.remove();
            if (leaveBtn && leaveBtn.dataset.boundAction !== 'true') {
                leaveBtn.dataset.boundAction = 'true';
                leaveBtn.addEventListener('click', onAiLeave);
            }
            return;
        }

        if (drawBtn && drawBtn.dataset.boundAction !== 'true') {
            drawBtn.dataset.boundAction = 'true';
            drawBtn.addEventListener('click', async () => {
                const confirmed = await Modal.confirm('무승부를 제안하시겠습니까?', {
                    title: '무승부 제안',
                    confirmText: '제안하기',
                });
                if (!confirmed) return;
                onOfferDraw?.();
            });
        }

        if (resignBtn && resignBtn.dataset.boundAction !== 'true') {
            resignBtn.dataset.boundAction = 'true';
            resignBtn.addEventListener('click', async () => {
                const confirmed = await Modal.confirm('정말 기권하시겠습니까?', {
                    title: '기권',
                    confirmText: '기권하기',
                    danger: true,
                });
                if (!confirmed) return;
                onResign?.();
            });
        }

        if (leaveBtn && leaveBtn.dataset.boundAction !== 'true') {
            leaveBtn.dataset.boundAction = 'true';
            leaveBtn.addEventListener('click', async () => {
                const confirmed = await Modal.confirm('나가면 기권 처리됩니다. 나가시겠습니까?', {
                    title: '게임 나가기',
                    confirmText: '나가기',
                    danger: true,
                });
                if (!confirmed) return;
                onLeave?.();
            });
        }
    }

    function bindModalActions({
        replayOnly,
        isCompetitive,
        isAiRoom,
        rematchBtn,
        rematchModal,
        drawModal,
        historyBtn,
        lobbyBtn,
        onHistory,
        onLobby,
        onRematch,
        onAcceptDraw,
        onDeclineDraw,
        onAcceptRematch,
        onDeclineRematch,
    }) {
        if (replayOnly) {
            rematchBtn?.classList.add('hidden');
            if (lobbyBtn) lobbyBtn.textContent = '전적 보기';
        }

        if (isCompetitive || isAiRoom) {
            rematchBtn?.remove();
            rematchModal?.remove();
            document.getElementById('accept-rematch-btn')?.remove();
            document.getElementById('decline-rematch-btn')?.remove();
        }

        if (historyBtn && historyBtn.dataset.boundAction !== 'true') {
            historyBtn.dataset.boundAction = 'true';
            historyBtn.addEventListener('click', onHistory);
        }

        if (lobbyBtn && lobbyBtn.dataset.boundAction !== 'true') {
            lobbyBtn.dataset.boundAction = 'true';
            lobbyBtn.addEventListener('click', onLobby);
        }

        if (!replayOnly && !isCompetitive && rematchBtn && rematchBtn.dataset.boundAction !== 'true') {
            rematchBtn.dataset.boundAction = 'true';
            rematchBtn.addEventListener('click', onRematch);
        }

        const acceptDrawBtn = document.getElementById('accept-draw-btn');
        const declineDrawBtn = document.getElementById('decline-draw-btn');
        if (drawModal && acceptDrawBtn && declineDrawBtn) {
            if (acceptDrawBtn.dataset.boundAction !== 'true') {
                acceptDrawBtn.dataset.boundAction = 'true';
                acceptDrawBtn.addEventListener('click', onAcceptDraw);
            }
            if (declineDrawBtn.dataset.boundAction !== 'true') {
                declineDrawBtn.dataset.boundAction = 'true';
                declineDrawBtn.addEventListener('click', onDeclineDraw);
            }
        }

        if (!replayOnly && !isCompetitive) {
            const acceptRematchBtn = document.getElementById('accept-rematch-btn');
            const declineRematchBtn = document.getElementById('decline-rematch-btn');
            if (acceptRematchBtn && acceptRematchBtn.dataset.boundAction !== 'true') {
                acceptRematchBtn.dataset.boundAction = 'true';
                acceptRematchBtn.addEventListener('click', onAcceptRematch);
            }
            if (declineRematchBtn && declineRematchBtn.dataset.boundAction !== 'true') {
                declineRematchBtn.dataset.boundAction = 'true';
                declineRematchBtn.addEventListener('click', onDeclineRematch);
            }
        }
    }

    function showDrawOfferModal(drawModal) {
        drawModal?.classList.remove('hidden');
    }

    function showRematchOfferModal(rematchModal) {
        rematchModal?.classList.remove('hidden');
    }

    window.GameActionUI = {
        bindPrimaryActions,
        bindModalActions,
        showDrawOfferModal,
        showRematchOfferModal,
    };
})();
