(function() {
    'use strict';

    async function handle(data, ctx) {
        switch (data.type) {
            case 'move':
                if (data.last_move && !ctx.replayActive) {
                    await ctx.animateIncomingMove(data.last_move);
                }
                ctx.game.fen = data.fen;
                if (data.pgn_append) {
                    ctx.game.pgn = ctx.appendPgnMove(ctx.game.pgn, data.pgn_append);
                } else if (typeof data.pgn === 'string') {
                    ctx.game.pgn = data.pgn;
                }
                ctx.game.current_turn = data.current_turn;
                ctx.game.result = data.result;
                ctx.game.white_time_remaining = data.white_time_remaining;
                ctx.game.black_time_remaining = data.black_time_remaining;
                ctx.game.turn_started_at = data.turn_started_at;
                if (data.last_move) {
                    ctx.onMoveSound?.();
                }
                window.GameMovesCache?.invalidate(ctx.game.id);
                if (data.last_move) {
                    ctx.setLastMove(data.last_move);
                    if (data.last_move.is_check && data.result === 'playing') {
                        if (ctx.myColor && ctx.myColor === data.current_turn) {
                            ctx.showStatusModal('체크입니다. 왕을 보호하세요.');
                            ctx.showGuideMessage('체크 상태입니다. 왕을 지키는 수만 가능합니다.', 'warning');
                        }
                    }
                    if (data.last_move.is_checkmate) {
                        ctx.showStatusModal('체크메이트입니다.');
                    }
                }

                ctx.renderBoard({ animatePieceChanges: false });
                ctx.renderMoveList();
                ctx.updateCapturedFromMove(data);
                ctx.renderCapturedPieces();
                ctx.updateTurn();
                ctx.clearSelection();

                if (data.last_move?.is_checkmate && data.result !== 'playing') {
                    ctx.showStatusModal('체크메이트입니다!', 1200);
                    setTimeout(() => ctx.showGameEndModal(data.result), 1200);
                } else if (data.result !== 'playing') {
                    ctx.showGameEndModal(data.result);
                }

                if (data.commentary && data.commentary_color === ctx.myColor) {
                    ctx.showGuideMessage(data.commentary, data.commentary_level || 'info');
                }
                return;

            case 'game_end':
                ctx.game.result = data.result;
                ctx.showGameEndModal(data.result);
                return;

            case 'draw_offer':
                if (data.from !== ctx.myColor) {
                    ctx.showDrawOfferModal();
                }
                return;

            case 'draw_declined':
                ctx.toastInfo('상대가 무승부를 거절했습니다.');
                return;

            case 'rematch_offer':
                if (data.from !== ctx.myColor) {
                    ctx.showRematchOfferModal();
                }
                return;

            case 'rematch_declined':
                ctx.toastInfo('상대가 리매치를 거절했습니다.');
                return;

            case 'rematch_created':
                await ctx.handleRematchCreated(data);
                return;

            case 'chat':
                ctx.addChatMessage(data);
                return;

            case 'reaction_update':
                ctx.applyReactionUpdate(data.message_id, data.reactions || {}, data.my_reactions);
                return;

            case 'recent_messages':
                (data.messages || []).forEach((msg) => ctx.addChatMessage(msg));
                return;

            case 'spectator_event': {
                const nickname = data.user?.nickname || '관전자';
                const isSelf = ctx.currentUser && data.user?.id === ctx.currentUser.id;
                if (!isSelf) {
                    const actionText = data.action === 'leave' ? '퇴장' : '입장';
                    ctx.toastInfo(`${nickname}님이 관전에 ${actionText}했습니다.`);
                    ctx.addChatNotice(`${nickname}님이 관전에 ${actionText}했습니다.`);
                }
                ctx.applySpectatorDelta(data.action, data.user, data.spectator_count);
                return;
            }

            case 'room_update':
                if (typeof data.room?.spectator_count === 'number' && ctx.spectatorCount) {
                    ctx.spectatorCount.textContent = `${data.room.spectator_count}명`;
                }
                return;

            case 'error':
                ctx.toastError(data.message);
                if (data.message && data.message.includes('허용되지 않는 수')) {
                    ctx.showStatusModal('허용되지 않는 수입니다. 체크 상태라면 체크를 해제하는 수만 가능합니다.', 2000);
                }
                return;

            case 'heartbeat_ack':
                return;
        }
    }

    window.GameSocketHandlers = {
        handle,
    };
})();
