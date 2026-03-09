/**
 * Chess Game Page Logic
 * - 체스보드 렌더링
 * - 기물 이동 (클릭/드래그)
 * - 타이머
 * - WebSocket 통신
 * - 게임 종료 처리
 */

(function() {
    'use strict';

    // Constants
    const isTouchDevice = 'ontouchstart' in window || navigator.maxTouchPoints > 0;

    const PIECE_SPRITE = {
        K: '♔',
        Q: '♕',
        R: '♖',
        B: '♗',
        N: '♘',
        P: '♙',
        k: '♚',
        q: '♛',
        r: '♜',
        b: '♝',
        n: '♞',
        p: '♟',
    };
    const PIECE_VALUE = {
        p: 1,
        n: 3,
        b: 3,
        r: 5,
        q: 9,
        k: 0,
    };

    // 접근성용 기물 이름
    const PIECE_NAMES = {
        'K': '백 킹', 'Q': '백 퀸', 'R': '백 룩', 'B': '백 비숍', 'N': '백 나이트', 'P': '백 폰',
        'k': '흑 킹', 'q': '흑 퀸', 'r': '흑 룩', 'b': '흑 비숍', 'n': '흑 나이트', 'p': '흑 폰'
    };

    const FILES = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'];
    const RANKS = ['8', '7', '6', '5', '4', '3', '2', '1'];
    const NOTIFICATION_TYPES = Object.freeze({
        CHAT_MUTE: 'chat_mute',
        CHAT_UNMUTE: 'chat_unmute',
        ACCOUNT_SUSPENDED: 'account_suspended',
        ACCOUNT_UNSUSPENDED: 'account_unsuspended',
    });

    // DOM Elements
    const chessBoard = document.getElementById('chess-board');
    const chessBoardWrapper = document.querySelector('.chess-board-wrapper');
    const opponentBar = document.getElementById('opponent-bar');
    const myBar = document.getElementById('my-bar');
    const opponentTimer = document.getElementById('opponent-timer');
    const myTimer = document.getElementById('my-timer');
    const moveList = document.getElementById('move-list');
    const movePrevBtn = document.getElementById('move-prev');
    const moveNextBtn = document.getElementById('move-next');
    const movePageLabel = document.getElementById('move-page');
    const turnIndicator = document.getElementById('turn-indicator');
    const moveSection = document.getElementById('game-moves-section');
    const guideToggle = document.getElementById('guide-toggle');
    const capturedWhite = document.getElementById('captured-white');
    const capturedBlack = document.getElementById('captured-black');
    const spectatorSection = document.getElementById('spectator-section');
    const spectatorList = document.getElementById('spectator-list');
    const spectatorCount = document.getElementById('spectator-count');
    const chatMessages = document.getElementById('chat-messages');
    const chatForm = document.getElementById('chat-form');
    const chatInput = document.getElementById('chat-input');
    const chatSection = document.getElementById('game-chat-section');
    const chatCloseBtn = document.getElementById('chat-close-btn');
    const sidePanel = document.querySelector('.game-side-panel');
    const mobileTabbar = document.getElementById('mobile-tabbar');
    const chatBadge = document.getElementById('chat-badge');
    const chatFabBadge = document.getElementById('chat-fab-badge');
    const gameActions = document.getElementById('game-actions');
    const drawBtn = document.getElementById('draw-btn');
    const resignBtn = document.getElementById('resign-btn');
    const leaveBtn = document.getElementById('leave-btn');
    const replayBtn = document.getElementById('replay-btn');
    const rematchBtn = document.getElementById('rematch-btn');

    // Modals
    const gameEndModal = document.getElementById('game-end-modal');
    const drawModal = document.getElementById('draw-modal');
    const rematchModal = document.getElementById('rematch-modal');
    const promotionModal = document.getElementById('promotion-modal');
    const statusModal = document.getElementById('status-modal');
    const statusModalMessage = document.getElementById('status-modal-message');
    const statusModalOk = document.getElementById('status-modal-ok');
    const replayModal = document.getElementById('replay-modal');
    const replayStatus = document.getElementById('replay-status');
    const replayPrev = document.getElementById('replay-prev');
    const replayNext = document.getElementById('replay-next');
    const replayPlay = document.getElementById('replay-play');
    const replayClose = document.getElementById('replay-close');
    const replayDock = document.getElementById('replay-dock');
    const replayStatusDock = document.getElementById('replay-status-dock');
    const replayPrevDock = document.getElementById('replay-prev-dock');
    const replayNextDock = document.getElementById('replay-next-dock');
    const replayPlayDock = document.getElementById('replay-play-dock');
    const replayCloseDock = document.getElementById('replay-close-dock');
    const reportOpenBtn = document.getElementById('report-btn');
    const chatFab = document.getElementById('chat-fab');
    const shareBtn = document.getElementById('share-btn');
    const gameEndStats = document.getElementById('game-end-stats');
    const analysisCanvas = document.getElementById('analysis-canvas');
    const analysisSummary = document.getElementById('analysis-summary');
    let pendingEnd = false;

    // State
    const roomId = Utils.getPathParam(/\/games\/(\d+)/);
    const urlParams = Utils.getUrlParams();
    const replayParam = urlParams.replay_game_id || urlParams.replay;
    const replayGameParamId = replayParam ? parseInt(replayParam, 10) : null;
    const replayOnly = Boolean(replayGameParamId);
    let game = null;
    let currentUser = null;
    let socket = null;
    let isSuspended = false;
    let myColor = null; // 'white' or 'black'
    let isMyTurn = false;
    let selectedSquare = null;
    let selectedDisplaySquare = null;
    let validMoves = [];
    let pendingPromotion = null;
    let pendingConfirmedMove = null;
    let moveConfirmEnabled = false;
    const arrowLayer = document.getElementById('arrow-layer');
    let premove = null;
    let drawings = { arrows: [], circles: [] };
    let rightClickStartSq = null;
    let timerInterval = null;
    let heartbeatInterval = null;
    let hasShownStartGuide = false;
    let lastTurnColor = null;
    let lastMove = null;
    let replayMoves = [];
    let replayIndex = 0;
    let replayTimer = null;
    let replayActive = false;
    let liveFen = null;
    let liveLastMove = null;
    let replayGameId = null;
    let replayMode = 'modal';
    let captured = { white: [], black: [] };
    let squareCache = null; // Map<squareName, element> for DOM caching
    let isChatOpen = false;
    let chatUnread = 0;
    let opponentUserId = null;
    let guideEnabled = true;
    let dragPiece = null;
    let dragStartSquare = null;
    let touchHandled = false; // 터치 이벤트 처리 플래그
    let isAiRoom = false;
    let isSpectator = false;
    let movePage = 1;
    const movePageSize = 6;
    let aiExitTriggered = false;
    let wsReconnectAttempts = 0;
    const WS_MAX_RECONNECT_ATTEMPTS = 10;
    const WS_BASE_RECONNECT_DELAY = 1000;
    let ratingPollAttempts = 0;
    const RATING_POLL_MAX_ATTEMPTS = 30;
    let notificationEventBound = false;
    let notificationEventHandler = null;
    let selectedBoardSkinClass = 'skin-board-classic';
    let selectedPieceSkinClass = 'skin-piece-classic';

    function showStatus(message, type = 'info', duration = 1800) {
        if (window.StatusBadge) {
            window.StatusBadge.show(message, { type, duration });
            return;
        }
        if (type === 'error') {
            Toast.error(message);
            return;
        }
        if (type === 'success') {
            Toast.success(message);
            return;
        }
        Toast.info(message);
    }
    // Init
    init();

    async function init() {
        if (!roomId) {
            Toast.error('잘못된 접근입니다.');
            window.location.href = '/';
            return;
        }

        const globalDmFab = document.getElementById('global-dm-fab');
        const globalDmPanel = document.getElementById('global-dm-panel');
        globalDmFab?.classList.add('hidden');
        if (globalDmFab) {
            globalDmFab.style.display = 'none';
        }
        globalDmPanel?.classList.add('hidden');

        guideEnabled = Utils.Storage.get('guide_enabled', true);
        setupGuideToggle();
        mountReplayDock();

        const savedMoveConfirm = localStorage.getItem('move_confirm_enabled');
        if (savedMoveConfirm === null) {
            moveConfirmEnabled = isTouchDevice;
            Utils.Storage.set('move_confirm_enabled', moveConfirmEnabled);
        } else {
            moveConfirmEnabled = Utils.Storage.get('move_confirm_enabled', false);
        }
        const confirmToggle = document.getElementById('move-confirm-toggle');
        if (confirmToggle) {
            confirmToggle.checked = moveConfirmEnabled;
            confirmToggle.addEventListener('change', (e) => {
                moveConfirmEnabled = e.target.checked;
                Utils.Storage.set('move_confirm_enabled', moveConfirmEnabled);
            });
        }
        injectPieceSpriteStyles();

        try {
            currentUser = await API.get('/accounts/me/');
            selectedBoardSkinClass = currentUser?.stats?.selected_board_skin_class || 'skin-board-classic';
            selectedPieceSkinClass = currentUser?.stats?.selected_piece_skin_class || 'skin-piece-classic';
            if (currentUser?.is_muted) {
                setChatMutedState(true, currentUser.mute_reason || '');
            }
            if (currentUser?.is_suspended) {
                setSuspendedState(true, currentUser.suspension_reason || '');
            }
            setupNotificationEvents();
        } catch {
            // 관전자로 처리
            currentUser = null;
        }

        setupBoard();
        await loadGame();
        setupChat();
        setupMobileTabs();
        setupActions();
        setupModals();
        setupMovePagination();
        setupStatusModal();
        setupReplayControls();
        setupShareButton();
        setupReport();
        setupChatToggle();
        setupSidePanelAccordion();
        setupExitGuard();
        setupKeyboardShortcuts();
        setupGuestExpiryHandler();
        ensureReactionUIForExistingMessages();
        if (!replayOnly) {
            connectWebSocket();
        }
    }

    function mountReplayDock() {
        if (!replayDock || !sidePanel || !capturedWhite) return;
        if (replayDock.parentElement === sidePanel) return;
        const anchor = spectatorSection || chatSection || null;
        sidePanel.insertBefore(replayDock, anchor);
    }

    /**
     * 게스트 세션 만료 처리
     */
    function setupGuestExpiryHandler() {
        window.addEventListener('guest:expired', () => {
            // 게임 중이면 자동 기권
            if (game?.result === 'playing' && myColor && socket?.readyState === WebSocket.OPEN) {
                socket.send(JSON.stringify({ action: 'resign', game_id: game.id }));
            }
        });
    }

    /**
     * 키보드 단축키 설정
     */
    function setupKeyboardShortcuts() {
        const shortcutHelpBtn = document.getElementById('shortcut-help-btn');
        const shortcutModal = document.getElementById('shortcut-modal');
        const shortcutClose = document.getElementById('shortcut-close');

        // 단축키 모달 열기
        shortcutHelpBtn?.addEventListener('click', () => {
            shortcutModal?.classList.remove('hidden');
        });

        // 단축키 모달 닫기
        shortcutClose?.addEventListener('click', () => {
            shortcutModal?.classList.add('hidden');
        });

        shortcutModal?.addEventListener('click', (e) => {
            if (e.target === shortcutModal) {
                shortcutModal.classList.add('hidden');
            }
        });

        // 전역 키보드 단축키
        document.addEventListener('keydown', (e) => {
            // 입력 필드에서는 무시
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
            // 모달이 열려있을 때 ESC로 닫기
            if (e.key === 'Escape') {
                if (shortcutModal && !shortcutModal.classList.contains('hidden')) {
                    shortcutModal.classList.add('hidden');
                    return;
                }
            }

            // 게임 중 단축키 (리플레이 모드가 아닐 때)
            const isPlaying = game?.result === 'playing';
            const isWatching = !myColor; // 관전자
            if (!replayActive && isPlaying) {
                if (e.key === 'd' || e.key === 'D') {
                    drawBtn?.click();
                } else if (e.key === 'r' || e.key === 'R') {
                    resignBtn?.click();
                } else if (e.key === 'g' || e.key === 'G') {
                    guideToggle?.click();
                }
            }

            // 기보 이동 (게임 종료 후 또는 관전)
            if (!isPlaying || isWatching) {
                if (e.key === 'ArrowLeft') {
                    e.preventDefault();
                    movePrevBtn?.click();
                } else if (e.key === 'ArrowRight') {
                    e.preventDefault();
                    moveNextBtn?.click();
                }
            }
        });
    }

    /**
     * 게임 정보 로드
     */
    async function loadGame() {
        try {
            let roomTypeHint = null;
            if (replayOnly && replayGameParamId) {
                game = await API.get(`/chess/games/${replayGameParamId}/`);
            } else {
                // 방에서 현재 게임 가져오기
                let room = null;
                try {
                    room = await API.get(`/chess/rooms/${roomId}/`);
                } catch (roomError) {
                    try {
                        const active = await API.get('/chess/rooms/active/');
                        if (active?.room?.id) {
                            window.location.href = `/games/${active.room.id}/`;
                            return;
                        }
                    } catch {
                        // noop
                    }
                    throw roomError;
                }
                roomTypeHint = room?.room_type || null;

                if (room.status !== 'playing') {
                    Toast.error('진행 중인 게임이 없습니다.');
                    window.location.href = `/rooms/${roomId}/`;
                    return;
                }

                let gameId = room.current_game_id;
                if (!gameId) {
                    const history = await API.get(`/chess/games/history/`, { result: 'playing', limit: 20, no_count: 1 });
                    const matches = history.results || [];
                    const found = matches.find(item => item.room_id === roomId);
                    gameId = found?.id;
                }
                if (!gameId) {
                    Toast.error('게임을 찾을 수 없습니다.');
                    window.location.href = `/rooms/${roomId}/`;
                    return;
                }
                game = await API.get(`/chess/games/${gameId}/`);
                if (roomTypeHint && !game.room_type) {
                    game.room_type = roomTypeHint;
                }
            }

            // 내 색상 결정
            if (currentUser) {
                if (game.white_player?.id === currentUser.id) {
                    myColor = 'white';
                } else if (game.black_player?.id === currentUser.id) {
                    myColor = 'black';
                }
            }
            if (currentUser && myColor === 'white') {
                opponentUserId = game.black_player?.id || null;
            } else if (currentUser && myColor === 'black') {
                opponentUserId = game.white_player?.id || null;
            }

            isSpectator = !myColor;

            if (!myColor || replayOnly) {
                gameActions?.classList.add('hidden');
            }
            isAiRoom = Boolean(game.room_type && game.room_type.startsWith('ai_'));
            const roomType = game.room_type || game.room?.room_type || roomTypeHint;
            isAiRoom = Boolean(roomType && roomType.startsWith('ai_'));
            if (roomType === 'quick' || roomType === 'competitive') {
                document.body.classList.add('competitive-room');
                guideEnabled = false;
                guideToggle?.classList.add('hidden');
                document.getElementById('guide-toggle-wrap')?.classList.add('hidden');
                rematchBtn?.remove();
                rematchModal?.remove();
                document.getElementById('accept-rematch-btn')?.remove();
                document.getElementById('decline-rematch-btn')?.remove();
            }
            if (isAiRoom) {
                document.body.classList.add('ai-room');
                drawBtn?.remove();
                resignBtn?.remove();
                drawModal?.remove();
                reportOpenBtn?.remove();
                chatSection?.classList.add('is-hidden');
                spectatorSection?.classList.add('hidden');
                document.querySelector('.mobile-tab[data-tab="chat"]')?.classList.add('hidden');
            }
            if (!currentUser) {
                const fallbackBoard = game.white_player?.selected_board_skin_class || 'skin-board-classic';
                const fallbackPieces = game.white_player?.selected_piece_skin_class || 'skin-piece-classic';
                selectedBoardSkinClass = fallbackBoard;
                selectedPieceSkinClass = fallbackPieces;
            }
            applySkinClasses();

            renderPlayerBars();
            renderBoard();
            renderMoveList();
            await loadCapturedPieces();
            renderCapturedPieces();
            await refreshSpectatorList();
            updateTurn();
            startTimer();
            if (game.move_count > 0) {
                await loadLastMove();
                renderBoard();
            }
            if (replayOnly && replayGameParamId) {
                await openReplay(replayGameParamId);
            }
        } catch (error) {
            console.error('Failed to load game:', error);
            Toast.error('게임 정보를 불러올 수 없습니다.');
        }
    }

    function applySkinClasses() {
        if (!chessBoard) return;
        const boardClasses = [
            'skin-board-classic',
            'skin-board-wood',
            'skin-board-dark',
            'skin-board-neon',
            'skin-board-marble',
            'skin-board-obsidian',
            'skin-board-sakura',
        ];
        chessBoard.classList.remove(...boardClasses);
        chessBoard.classList.add(selectedBoardSkinClass || 'skin-board-classic');

        if (chessBoardWrapper) {
            const pieceClasses = [
                'skin-piece-classic',
                'skin-piece-pixel',
                'skin-piece-modern',
                'skin-piece-3d',
                'skin-piece-glass',
                'skin-piece-rune',
            ];
            chessBoardWrapper.classList.remove(...pieceClasses);
            chessBoardWrapper.classList.add(selectedPieceSkinClass || 'skin-piece-classic');
        }
    }

    async function handleRematchCreated(data) {
        Toast.success('리매치가 생성되었습니다!');
        gameEndModal?.classList.add('hidden');
        rematchModal?.classList.add('hidden');
        await startRematch(data.game_id || data.rematch_game_id, data.room_id);
    }

    async function startRematch(rematchGameId, rematchRoomId) {
        const targetRoomId = rematchRoomId || roomId;
        if (!rematchGameId) {
            window.location.href = `/games/${targetRoomId}/`;
            return;
        }

        if (socket) {
            socket.close();
            socket = null;
        }
        stopHeartbeat();
        if (timerInterval) {
            clearInterval(timerInterval);
            timerInterval = null;
        }

        pendingEnd = false;
        selectedSquare = null;
        selectedDisplaySquare = null;
        validMoves = [];
        pendingPromotion = null;
        lastMove = null;
        replayMoves = [];
        replayIndex = 0;
        replayActive = false;
        captured = { white: [], black: [] };
        hasShownStartGuide = false;
        lastTurnColor = null;
        wsReconnectAttempts = 0;
        ratingPollAttempts = 0;

        let fetched = null;
        for (let attempt = 0; attempt < 3; attempt += 1) {
            try {
                fetched = await API.get(`/chess/games/${rematchGameId}/`);
                break;
            } catch (error) {
                if (attempt === 2) {
                    break;
                }
                await new Promise((resolve) => setTimeout(resolve, 500));
            }
        }
        if (!fetched) {
            try {
                const room = await API.get(`/chess/rooms/${targetRoomId}/`);
                if (room?.current_game_id) {
                    fetched = await API.get(`/chess/games/${room.current_game_id}/`);
                }
            } catch (error) {
                // fallback handled below
            }
        }
        if (!fetched) {
            Toast.error('리매치 정보를 불러오지 못했습니다.');
            window.location.href = `/games/${targetRoomId}/`;
            return;
        }
        game = fetched;

        if (currentUser) {
            if (game.white_player?.id === currentUser.id) {
                myColor = 'white';
            } else if (game.black_player?.id === currentUser.id) {
                myColor = 'black';
            } else {
                myColor = null;
            }
        }
        opponentUserId = null;
        if (currentUser && myColor === 'white') {
            opponentUserId = game.black_player?.id || null;
        } else if (currentUser && myColor === 'black') {
            opponentUserId = game.white_player?.id || null;
        }

        renderPlayerBars();
        renderBoard();
        renderMoveList();
        renderCapturedPieces();
        updateTurn();
        startTimer();
        connectWebSocket();
    }

    function setupReport() {
        if (isAiRoom) return;
        if (!reportOpenBtn) return;
        if (!currentUser || !myColor) {
            reportOpenBtn.disabled = true;
            return;
        }
        reportOpenBtn.addEventListener('click', () => {
            if (!opponentUserId) {
                Toast.error('상대 정보를 찾을 수 없습니다.');
                return;
            }
            Utils.ReportModal.open(opponentUserId);
        });
    }

    function setupChatToggle() {
        if (!chatFab || !chatSection) return;
        chatSection.classList.add('is-collapsed');
        syncGameChatFabVisibility();
        chatFab.addEventListener('click', () => {
            Utils?.Sounds?.unlock?.();
            const willOpen = chatSection.classList.contains('is-collapsed');
            chatSection.classList.toggle('is-collapsed');
            chatSection.classList.toggle('is-floating', willOpen);
            chatFab.classList.toggle('is-active', willOpen);
            syncGameChatFabVisibility();
            // 채팅 열 때 배지 리셋
            if (willOpen) {
                resetChatBadge();
            }
        });
        chatCloseBtn?.addEventListener('click', () => {
            chatSection.classList.add('is-collapsed');
            chatSection.classList.remove('is-floating');
            chatFab.classList.remove('is-active');
            syncGameChatFabVisibility();
        });
    }

    function syncGameChatFabVisibility() {
        if (!chatFab || !chatSection) return;
        const isMobile = window.innerWidth <= 768;
        if (!isMobile) {
            chatFab.classList.remove('hidden');
            return;
        }
        const chatVisible = !chatSection.classList.contains('is-collapsed') && !chatSection.classList.contains('is-hidden');
        chatFab.classList.toggle('hidden', chatVisible);
    }

    function setupSidePanelAccordion() {
        if (!sidePanel) return;
        const sections = Array.from(sidePanel.querySelectorAll('.panel-section'));
        if (!sections.length) return;

        const isNarrow = () => window.innerWidth <= 1280;

        const applyLayout = () => {
            const narrow = isNarrow();
            sidePanel.classList.toggle('is-accordion', narrow);
            sections.forEach((section, idx) => {
                const header = section.querySelector('.panel-header');
                if (!header) return;
                header.classList.toggle('is-clickable', narrow);
                if (!narrow) {
                    section.classList.remove('is-collapsed');
                    return;
                }
                const shouldOpen = section.id === 'game-actions' || section.id === 'game-chat-section' || idx === 0;
                section.classList.toggle('is-collapsed', !shouldOpen);
            });
        };

        sections.forEach((section) => {
            const header = section.querySelector('.panel-header');
            if (!header || header.dataset.accordionBound === '1') return;
            header.dataset.accordionBound = '1';
            header.addEventListener('click', () => {
                if (!isNarrow()) return;
                if (section.id === 'game-actions') return;
                section.classList.toggle('is-collapsed');
            });
        });

        applyLayout();
        window.addEventListener('resize', Utils.debounce(applyLayout, 120));
    }

    /**
     * 보드 초기 설정
     */
    function setupBoard() {
        // 스켈레톤 로딩 제거 및 빈 보드 생성
        chessBoard.classList.remove('chess-board--loading');
        chessBoard.innerHTML = '';
        for (let rank = 0; rank < 8; rank++) {
            for (let file = 0; file < 8; file++) {
                const square = document.createElement('div');
                const isLight = (rank + file) % 2 === 0;
                const squareName = FILES[file] + RANKS[rank];

                square.className = `square ${isLight ? 'light' : 'dark'}`;
                square.dataset.square = squareName;
                square.tabIndex = 0;
                square.setAttribute('role', 'button');
                square.setAttribute('aria-label', squareName);

                square.addEventListener('click', () => {
                    clearDrawings();
                    handleSquareClick(squareName);
                });
                square.addEventListener('keydown', (e) => handleSquareKeydown(e, squareName));

                // 우클릭 이벤트 (시각적 보조)
                square.addEventListener('contextmenu', (e) => e.preventDefault());
                square.addEventListener('mousedown', (e) => {
                    if (e.button === 2) { // 우클릭
                        rightClickStartSq = squareName;
                    } else if (e.button === 0) { // 좌클릭 시 지우기
                        clearDrawings();
                    }
                });
                square.addEventListener('mouseup', (e) => {
                    if (e.button === 2 && rightClickStartSq) {
                        const endSq = squareName;
                        if (rightClickStartSq === endSq) {
                            toggleCircle(rightClickStartSq);
                        } else {
                            toggleArrow(rightClickStartSq, endSq);
                        }
                        rightClickStartSq = null;
                        renderDrawings();
                    }
                });
                square.addEventListener('mouseleave', (e) => {
                    // 드래그 중 밖으로 나갈 때의 처리는 복잡하므로, 일단 mouseup 기반으로 구현
                });

                // 터치 드래그 지원
                square.addEventListener('touchstart', (e) => handleTouchStart(e, squareName), { passive: false });

                chessBoard.appendChild(square);
            }
        }

        // 터치 이벤트 (보드 레벨)
        chessBoard.addEventListener('touchmove', handleTouchMove, { passive: false });
        chessBoard.addEventListener('touchend', handleTouchEnd, { passive: false });
    }

    async function handleTouchStart(e, squareName) {
        if (!isMyTurn || !myColor) return;

        // 실제 좌표로 변환 (흑색일 때 반전)
        const actualSquare = toActualSquare(squareName);
        const piece = getPieceAtSquare(actualSquare);

        // 이미 기물이 선택된 상태에서 다른 칸 터치
        if (selectedSquare) {
            // 유효한 이동 위치인 경우 이동 실행
            if (validMoves.includes(actualSquare)) {
                e.preventDefault();
                touchHandled = true;
                makeMove(selectedSquare, actualSquare);
                clearSelection();
                return;
            }

            // 내 다른 기물 선택
            if (piece) {
                const pieceColor = piece === piece.toUpperCase() ? 'white' : 'black';
                if (pieceColor === myColor) {
                    e.preventDefault();
                    touchHandled = true;
                    clearSelection();
                    // 새 기물 선택 (아래 로직 계속)
                } else {
                    // 상대 기물 - 선택 해제
                    clearSelection();
                    return;
                }
            } else {
                // 빈 칸 (유효하지 않은 이동) - 선택 해제
                clearSelection();
                return;
            }
        }

        // 기물이 없으면 리턴
        if (!piece) return;

        const pieceColor = piece === piece.toUpperCase() ? 'white' : 'black';
        if (pieceColor !== myColor) return;

        e.preventDefault();
        touchHandled = true; // 터치 처리됨 플래그
        dragStartSquare = squareName;

        // 드래그 중인 기물 표시 생성
        const touch = e.touches[0];
        createDragPiece(piece, touch.clientX, touch.clientY);

        // 유효한 이동 표시 (selectSquare와 동일한 로직)
        clearSelection();
        selectedSquare = actualSquare;
        selectedDisplaySquare = squareName;

        const squareEl = getSquare(squareName);
        squareEl?.classList.add('selected');

        validMoves = await fetchLegalMoves(actualSquare);

        // 유효한 이동 위치 표시
        validMoves.forEach(sq => {
            const displaySquare = toDisplaySquare(sq);
            const el = getSquare(displaySquare);
            if (el && sq !== actualSquare) {
                const hasPiece = el.querySelector('.piece');
                el.classList.add(hasPiece ? 'valid-capture' : 'valid-move');
            }
        });
    }

    function getPieceAtSquare(squareName) {
        if (!game || !game.fen) return null;
        const fen = game.fen.split(' ')[0];
        const ranks = fen.split('/');
        const file = squareName.charCodeAt(0) - 97; // a=0, h=7
        const rank = 8 - parseInt(squareName[1]); // 8=0, 1=7

        if (rank < 0 || rank > 7 || file < 0 || file > 7) return null;

        const rankStr = ranks[rank];
        let currentFile = 0;
        for (const char of rankStr) {
            if (/\d/.test(char)) {
                currentFile += parseInt(char);
            } else {
                if (currentFile === file) return char;
                currentFile++;
            }
        }
        return null;
    }

    function handleTouchMove(e) {
        if (!dragPiece || !dragStartSquare) return;
        e.preventDefault();

        const touch = e.touches[0];
        dragPiece.style.left = (touch.clientX - 25) + 'px';
        dragPiece.style.top = (touch.clientY - 25) + 'px';

        // 현재 위치의 칸 하이라이트
        const targetSquare = getSquareFromPoint(touch.clientX, touch.clientY);
        highlightDropTarget(targetSquare);
    }

    function handleTouchEnd(e) {
        const startSquare = dragStartSquare;
        dragStartSquare = null;

        // 드래그 기물 제거
        removeDragPiece();
        clearDropHighlight();

        if (!startSquare) {
            // 드래그 시작이 없었던 경우 - 이미 선택된 기물이 있으면 이동 시도
            if (selectedSquare && e.changedTouches && e.changedTouches[0]) {
                const touch = e.changedTouches[0];
                const targetDisplaySquare = getSquareFromPoint(touch.clientX, touch.clientY);
                if (targetDisplaySquare) {
                    const targetActualSquare = toActualSquare(targetDisplaySquare);
                    if (validMoves.includes(targetActualSquare)) {
                        e.preventDefault();
                        touchHandled = true;
                        makeMove(selectedSquare, targetActualSquare);
                        clearSelection();
                        return;
                    }
                }
            }
            return;
        }

        e.preventDefault();

        const touch = e.changedTouches[0];
        const targetDisplaySquare = getSquareFromPoint(touch.clientX, touch.clientY);

        if (targetDisplaySquare && targetDisplaySquare !== startSquare) {
            // 드래그 이동 시도 - 실제 좌표로 변환
            const targetActualSquare = toActualSquare(targetDisplaySquare);
            if (validMoves.includes(targetActualSquare)) {
                // 이동 실행
                makeMove(selectedSquare, targetActualSquare);
                clearSelection();
            } else {
                // 잘못된 위치 - 선택 해제하지 않고 유지 (다른 칸 탭 가능)
            }
        }
        // 같은 위치 탭 - 선택 상태 유지 (이미 handleTouchStart에서 선택됨)
    }

    function createDragPiece(piece, x, y) {
        removeDragPiece();
        dragPiece = document.createElement('div');
        dragPiece.className = 'drag-piece';
        dragPiece.textContent = PIECE_SPRITE[piece] || '';
        dragPiece.classList.add(piece === piece.toUpperCase() ? 'white' : 'black');
        dragPiece.style.left = (x - 32) + 'px';
        dragPiece.style.top = (y - 32) + 'px';
        document.body.appendChild(dragPiece);
    }

    function removeDragPiece() {
        if (dragPiece) {
            dragPiece.remove();
            dragPiece = null;
        }
    }

    function getSquareFromPoint(x, y) {
        const element = document.elementFromPoint(x, y);
        if (element && element.classList.contains('square')) {
            return element.dataset.square;
        }
        return null;
    }

    function highlightDropTarget(squareName) {
        clearDropHighlight();
        if (squareName) {
            // 디스플레이 좌표를 실제 좌표로 변환 후 비교
            const actualSquare = toActualSquare(squareName);
            if (validMoves.includes(actualSquare)) {
                const square = getSquare(squareName);
                if (square) square.classList.add('drop-target');
            }
        }
    }

    function clearDropHighlight() {
        chessBoard.querySelectorAll('.drop-target').forEach(el => el.classList.remove('drop-target'));
    }

    function handleSquareKeydown(e, squareName) {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            handleSquareClick(squareName);
        } else if (['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight'].includes(e.key)) {
            e.preventDefault();
            navigateSquare(squareName, e.key);
        }
    }

    function navigateSquare(currentSquare, direction) {
        const file = currentSquare.charCodeAt(0) - 97; // a=0
        const rank = parseInt(currentSquare[1]) - 1; // 1=0

        let newFile = file;
        let newRank = rank;

        // 보드가 뒤집혔을 때 방향 조정
        const isFlipped = myColor === 'black';

        switch (direction) {
            case 'ArrowUp':
                newRank += isFlipped ? -1 : 1;
                break;
            case 'ArrowDown':
                newRank += isFlipped ? 1 : -1;
                break;
            case 'ArrowLeft':
                newFile += isFlipped ? 1 : -1;
                break;
            case 'ArrowRight':
                newFile += isFlipped ? -1 : 1;
                break;
        }

        if (newFile >= 0 && newFile <= 7 && newRank >= 0 && newRank <= 7) {
            const newSquare = String.fromCharCode(97 + newFile) + (newRank + 1);
            const el = getSquare(toDisplaySquare(newSquare));
            if (el) el.focus();
        }
    }

    /**
     * 플레이어 바 렌더링
     */
    function renderPlayerBars() {
        if (!game) return;

        const whitePlayer = game.white_player;
        const blackPlayer = game.black_player;

        // 내가 흑이면 보드를 뒤집어야 함 (상대가 위에)
        const isFlipped = myColor === 'black';
        const topPlayer = isFlipped ? whitePlayer : blackPlayer;
        const bottomPlayer = isFlipped ? blackPlayer : whitePlayer;

        // 상대 (위)
        const topTier = topPlayer?.rank_tier || 'Junior';
        const bottomTier = bottomPlayer?.rank_tier || 'Junior';
        const topNicknameColor = Utils.getNicknameColorValue(topPlayer?.nickname_color || '');
        const bottomNicknameColor = Utils.getNicknameColorValue(bottomPlayer?.nickname_color || '');
        const topProfileRing = Utils.getProfileBorderValue(topPlayer?.profile_border || '');
        const bottomProfileRing = Utils.getProfileBorderValue(bottomPlayer?.profile_border || '');
        opponentBar.innerHTML = `
            <div class="player-bar-info">
                <div class="avatar avatar-sm" style="box-shadow:${topProfileRing}">
                    ${topPlayer?.avatar_url
                        ? `<img src="${Utils.escapeHtml(topPlayer.avatar_url)}" alt="${Utils.escapeHtml(topPlayer?.nickname || '상대')}">`
                        : '<span class="avatar-placeholder">?</span>'}
                </div>
                <div class="player-bar-details">
                    <span class="player-bar-name" style="color:${topNicknameColor}">${Utils.escapeHtml(topPlayer?.nickname || '상대')} <span class="tier-badge" title="${Utils.escapeHtml(topTier)}">${Utils.getTierIcon(topTier)}</span></span>
                    <span class="player-bar-rating">${topPlayer?.rating || '--'}</span>
                </div>
            </div>
            <div class="player-bar-timer" id="opponent-timer">--:--</div>
        `;

        // 나 (아래)
        myBar.innerHTML = `
            <div class="player-bar-info">
                <div class="avatar avatar-sm" style="box-shadow:${bottomProfileRing}">
                    ${bottomPlayer?.avatar_url
                        ? `<img src="${Utils.escapeHtml(bottomPlayer.avatar_url)}" alt="${Utils.escapeHtml(bottomPlayer?.nickname || '나')}">`
                        : '<span class="avatar-placeholder">?</span>'}
                </div>
                <div class="player-bar-details">
                    <span class="player-bar-name" style="color:${bottomNicknameColor}">${Utils.escapeHtml(bottomPlayer?.nickname || '나')} <span class="tier-badge" title="${Utils.escapeHtml(bottomTier)}">${Utils.getTierIcon(bottomTier)}</span></span>
                    <span class="player-bar-rating">${bottomPlayer?.rating || '--'}</span>
                </div>
            </div>
            <div class="player-bar-timer" id="my-timer">--:--</div>
        `;
    }

    /**
     * 보드 칸 요소 캐시 초기화
     */
    function initSquareCache() {
        if (squareCache) return;
        squareCache = new Map();
        document.querySelectorAll('.square').forEach(sq => {
            const name = sq.dataset.square;
            if (name) squareCache.set(name, sq);
        });
    }

    function getSquare(name) {
        if (!squareCache) initSquareCache();
        return squareCache.get(name);
    }

    function getAllSquareElements() {
        if (!squareCache) initSquareCache();
        return squareCache.values();
    }

    /**
     * 보드 렌더링
     */
    function renderBoard() {
        if (!game || !game.fen) return;

        const fen = game.fen;
        const position = parseFEN(fen);
        const isFlipped = myColor === 'black';

        // 모든 칸의 하이라이트 클래스만 제거 (기물 제거 방지)
        for (const sq of getAllSquareElements()) {
            sq.classList.remove(
                'selected',
                'valid-move',
                'valid-capture',
                'last-move',
                'check',
                'check-king',
                'checkmate-king'
            );
        }

        // 기물 배치 및 aria-label 업데이트
        for (let rank = 0; rank < 8; rank++) {
            for (let file = 0; file < 8; file++) {
                const actualFile = isFlipped ? 7 - file : file;
                const actualRank = isFlipped ? 7 - rank : rank;
                const actualSquareName = FILES[actualFile] + RANKS[actualRank];
                const piece = position[rank][file];
                const displayRank = isFlipped ? 7 - rank : rank;
                const displayFile = isFlipped ? 7 - file : file;
                const squareName = FILES[displayFile] + RANKS[displayRank];
                const squareEl = getSquare(squareName);

                if (squareEl) {
                    const existingPieceEl = squareEl.querySelector('.piece');
                    const existingPiece = existingPieceEl?.dataset.piece;

                    if (piece) {
                        const pieceName = PIECE_NAMES[piece] || piece;
                        squareEl.setAttribute('aria-label', `${actualSquareName} ${pieceName}`);

                        if (existingPiece !== piece) {
                            // 기물이 바뀌었거나 새로 생성됨
                            if (existingPieceEl) existingPieceEl.remove();
                            
                            const pieceEl = createPieceElement(piece);
                            
                            // 등장 애니메이션 준비
                            pieceEl.style.opacity = '0';
                            pieceEl.style.transform = 'scale(0.6)';
                            squareEl.appendChild(pieceEl);
                            
                            // 애니메이션 실행
                            requestAnimationFrame(() => {
                                pieceEl.style.opacity = '1';
                                pieceEl.style.transform = 'scale(1)';
                            });

                            pieceEl.addEventListener('dragstart', (e) => handleDragStart(e, squareName));
                        }
                    } else {
                        // 빈 칸인데 기물이 남아있는 경우 부드럽게 제거
                        if (existingPieceEl) {
                            existingPieceEl.style.opacity = '0';
                            existingPieceEl.style.transform = 'scale(0.6)';
                            setTimeout(() => {
                                if (existingPieceEl.parentNode === squareEl) {
                                    existingPieceEl.remove();
                                }
                            }, 200);
                        }
                        squareEl.setAttribute('aria-label', `${actualSquareName} 빈 칸`);
                    }
                }
            }
        }

        applyLastMoveHighlight();
        applyKingDangerHighlight(position);
    }

    /**
     * FEN 파싱
     */
    function parseFEN(fen) {
        const position = [];
        const rows = fen.split(' ')[0].split('/');

        for (const row of rows) {
            const rank = [];
            for (const char of row) {
                if (isNaN(char)) {
                    rank.push(char);
                } else {
                    for (let i = 0; i < parseInt(char); i++) {
                        rank.push(null);
                    }
                }
            }
            position.push(rank);
        }

        return position;
    }

    /**
     * 기보 렌더링
     */
    function renderMoveList() {
        if (!game || !game.pgn || game.pgn.trim() === '') {
            moveList.innerHTML = '<div class="move-list-empty">아직 착수가 없습니다.</div>';
            if (movePageLabel) movePageLabel.textContent = '1';
            movePrevBtn && (movePrevBtn.disabled = true);
            moveNextBtn && (moveNextBtn.disabled = true);
            return;
        }

        // PGN 파싱 (간단한 구현)
        const moves = game.pgn.trim().split(/\d+\.\s*/).filter(m => m.trim());
        const totalPages = Math.max(1, Math.ceil(moves.length / movePageSize));
        movePage = Math.min(movePage, totalPages);
        const startIndex = (movePage - 1) * movePageSize;
        const pageMoves = moves.slice(startIndex, startIndex + movePageSize);
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
            moveNum++;
        }

        moveList.innerHTML = html || '<div class="move-list-empty">아직 착수가 없습니다.</div>';
        if (movePageLabel) movePageLabel.textContent = `${movePage} / ${totalPages}`;
        movePrevBtn && (movePrevBtn.disabled = movePage <= 1);
        moveNextBtn && (moveNextBtn.disabled = movePage >= totalPages);
    }

    /**
     * 턴 업데이트
     */
    function updateTurn() {
        if (!game) return;

        isMyTurn = myColor === game.current_turn;

        const isFlipped = myColor === 'black';
        const isWhiteTurn = game.current_turn === 'white';
        const isTopPlayerTurn = isFlipped ? isWhiteTurn : !isWhiteTurn;

        opponentBar.classList.toggle('active', isTopPlayerTurn);
        myBar.classList.toggle('active', !isTopPlayerTurn);

        // 관전자면 액션 버튼 숨기기
        if (!myColor) {
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
            showStatusModal(`${currentName}님부터 시작합니다. 번갈아가며 한 번씩 수를 둡니다.`, 2500);
            hasShownStartGuide = true;
        }

        if (!lastTurnColor) {
            lastTurnColor = game.current_turn;
        }
    }

    /**
     * 타이머 시작
     */
    let timeoutHandled = false;

    function startTimer() {
        if (timerInterval) {
            clearInterval(timerInterval);
        }
        timeoutHandled = false;

        updateTimerDisplay();

        timerInterval = setInterval(() => {
            if (!game || game.result !== 'playing') {
                clearInterval(timerInterval);
                return;
            }

            // 현재 턴의 시간 감소 (서버 기준 계산)
            if (game.turn_started_at) {
                const elapsed = (Date.now() - new Date(game.turn_started_at).getTime()) / 1000;
                if (game.current_turn === 'white') {
                    game.white_time_remaining = Math.max(0, game.white_time_remaining - elapsed);
                } else {
                    game.black_time_remaining = Math.max(0, game.black_time_remaining - elapsed);
                }
                game.turn_started_at = new Date().toISOString();
            }

            updateTimerDisplay();
            checkTimeout();
        }, 1000);
    }

    function checkTimeout() {
        if (timeoutHandled || !game || game.result !== 'playing') return;

        const myTime = myColor === 'white' ? game.white_time_remaining : game.black_time_remaining;
        const opponentTime = myColor === 'white' ? game.black_time_remaining : game.white_time_remaining;

        if (myTime <= 0 && game.current_turn === myColor) {
            timeoutHandled = true;
            showPendingEnd('시간 초과 처리 중...');
            // 서버에 timeout 알림 (빈 move 시도로 서버가 timeout 처리)
            if (socket && socket.readyState === WebSocket.OPEN) {
                socket.send(JSON.stringify({ action: 'timeout', game_id: game.id }));
            }
        } else if (opponentTime <= 0 && game.current_turn !== myColor) {
            timeoutHandled = true;
            showPendingEnd('상대 시간 초과 처리 중...');
            if (socket && socket.readyState === WebSocket.OPEN) {
                socket.send(JSON.stringify({ action: 'timeout', game_id: game.id }));
            }
        }
    }

    /**
     * 타이머 표시 업데이트
     */
    function updateTimerDisplay() {
        if (!game) return;

        const isFlipped = myColor === 'black';
        const topTime = isFlipped ? game.white_time_remaining : game.black_time_remaining;
        const bottomTime = isFlipped ? game.black_time_remaining : game.white_time_remaining;

        const opponentTimerEl = opponentBar.querySelector('.player-bar-timer');
        const myTimerEl = myBar.querySelector('.player-bar-timer');

        if (opponentTimerEl) {
            opponentTimerEl.textContent = Utils.formatTime(topTime);
            opponentTimerEl.classList.toggle('low', topTime < 30);
        }
        if (myTimerEl) {
            myTimerEl.textContent = Utils.formatTime(bottomTime);
            myTimerEl.classList.toggle('low', bottomTime < 30);
        }
    }

    /**
     * 칸 클릭 핸들러
     */
    async function handleSquareClick(squareName) {
        // 터치 이벤트로 이미 처리된 경우 클릭 무시
        if (touchHandled) {
            touchHandled = false;
            return;
        }
        if (!isMyTurn || !myColor) return;

        if (selectedSquare) {
            // 이동 시도
            const targetSquare = toActualSquare(squareName);
            const targetEl = getSquare(squareName);
            const targetPiece = targetEl?.querySelector('.piece');
            if (targetPiece) {
                const isWhitePiece = targetPiece.classList.contains('white');
                const isMyPiece = (myColor === 'white' && isWhitePiece) || (myColor === 'black' && !isWhitePiece);
                if (isMyPiece) {
                    clearSelection();
                    await selectSquare(squareName);
                    return;
                }
            }
            if (validMoves.includes(targetSquare)) {
                makeMove(selectedSquare, targetSquare);
            }
            clearSelection();
        } else {
            // 기물 선택
            const squareEl = getSquare(squareName);
            const piece = squareEl?.querySelector('.piece');

            if (piece) {
                const isWhitePiece = piece.classList.contains('white');
                const isMyPiece = (myColor === 'white' && isWhitePiece) || (myColor === 'black' && !isWhitePiece);

                if (isMyPiece) {
                    await selectSquare(squareName);
                }
            }
        }
    }

    /**
     * 드래그 시작
     */
    function handleDragStart(e, squareName) {
        if (!isMyTurn || !myColor) {
            e.preventDefault();
            return;
        }

        selectSquare(squareName);
        e.dataTransfer.setData('text/plain', squareName);
    }

    /**
     * 칸 선택
     */
    async function selectSquare(squareName) {
        clearSelection();
        selectedDisplaySquare = squareName;
        selectedSquare = toActualSquare(squareName);

        const squareEl = getSquare(squareName);
        squareEl?.classList.add('selected');

        validMoves = await fetchLegalMoves(selectedSquare);

        validMoves.forEach(sq => {
            const displaySquare = toDisplaySquare(sq);
            const el = getSquare(displaySquare);
            if (el && sq !== selectedSquare) {
                const hasPiece = el.querySelector('.piece');
                el.classList.add(hasPiece ? 'valid-capture' : 'valid-move');
            }
        });
    }

    /**
     * 시각적 수 읽기 보조 (우클릭 화살표/하이라이트)
     */
    function clearDrawings() {
        drawings = { arrows: [], circles: [] };
        renderDrawings();
    }

    function toggleCircle(sq) {
        const idx = drawings.circles.indexOf(sq);
        if (idx === -1) drawings.circles.push(sq);
        else drawings.circles.splice(idx, 1);
    }

    function toggleArrow(fromSq, toSq) {
        const idx = drawings.arrows.findIndex(a => a.from === fromSq && a.to === toSq);
        if (idx === -1) drawings.arrows.push({ from: fromSq, to: toSq });
        else drawings.arrows.splice(idx, 1);
    }

    function getSquareCoords(sq) {
        if (!sq || sq.length < 2) return { x: 0, y: 0 };
        let fileIdx = FILES.indexOf(sq[0]);
        let rankIdx = RANKS.indexOf(sq[1]);
        if (myColor === 'black') {
            fileIdx = 7 - fileIdx;
            rankIdx = 7 - rankIdx;
        }
        return {
            x: (fileIdx + 0.5) * 12.5,
            y: (rankIdx + 0.5) * 12.5
        };
    }

    function renderDrawings() {
        if (!arrowLayer) return;
        
        let html = `
            <defs>
                <marker id="arrowhead" markerWidth="4" markerHeight="4" refX="2.5" refY="2" orient="auto">
                    <polygon points="0 0, 4 2, 0 4" fill="rgba(235, 97, 80, 0.85)" />
                </marker>
            </defs>
        `;

        drawings.circles.forEach(sq => {
            const { x, y } = getSquareCoords(sq);
            html += `<circle cx="${x}%" cy="${y}%" r="5.5%" fill="none" stroke="rgba(235, 97, 80, 0.85)" stroke-width="1%" />`;
        });

        drawings.arrows.forEach(arrow => {
            const from = getSquareCoords(arrow.from);
            const to = getSquareCoords(arrow.to);
            // 화살표가 렌더링될 때 중심에서 중심까지 선을 그림
            html += `<line x1="${from.x}%" y1="${from.y}%" x2="${to.x}%" y2="${to.y}%" stroke="rgba(235, 97, 80, 0.85)" stroke-width="1.8%" marker-end="url(#arrowhead)" opacity="0.9" stroke-linecap="round" />`;
        });

        arrowLayer.innerHTML = html;
    }

    /**
     * 선택 해제
     */
    function clearSelection() {
        selectedSquare = null;
        selectedDisplaySquare = null;
        validMoves = [];

        for (const sq of getAllSquareElements()) {
            sq.classList.remove('selected', 'valid-move', 'valid-capture');
        }
    }

    /**
     * 모든 칸 이름 가져오기
     */
    function getAllSquares() {
        const squares = [];
        for (const file of FILES) {
            for (const rank of RANKS) {
                squares.push(file + rank);
            }
        }
        return squares;
    }

    function toActualSquare(square) {
        if (myColor !== 'black') return square;
        return flipSquare(square);
    }

    function toDisplaySquare(square) {
        if (myColor !== 'black') return square;
        return flipSquare(square);
    }

    function flipSquare(square) {
        if (!square || square.length < 2) return square;
        const file = square[0];
        const rank = square[1];
        const fileIdx = FILES.indexOf(file);
        const rankIdx = RANKS.indexOf(rank);
        if (fileIdx < 0 || rankIdx < 0) return square;
        return FILES[7 - fileIdx] + RANKS[7 - rankIdx];
    }

    async function fetchLegalMoves(fromSquare) {
        if (!game || !fromSquare) return [];
        try {
            const data = await API.get(`/chess/games/${game.id}/legal-moves/`, { from: fromSquare });
            const moves = data.moves || [];
            return moves.map(move => move.slice(2, 4));
        } catch (error) {
            console.error('Failed to load legal moves:', error);
            return [];
        }
    }

    function applyLastMoveHighlight() {
        for (const sq of getAllSquareElements()) {
            sq.classList.remove('last-move');
        }
        if (!lastMove) return;
        const fromSquare = toDisplaySquare(lastMove.from);
        const toSquare = toDisplaySquare(lastMove.to);
        const fromEl = getSquare(fromSquare);
        const toEl = getSquare(toSquare);
        fromEl?.classList.add('last-move');
        toEl?.classList.add('last-move');
    }

    function getDangerTargetColor() {
        if (!game) return null;
        if (lastMove?.is_checkmate) return game.current_turn;
        if (lastMove?.is_check) return game.current_turn;
        if (typeof game.result === 'string') {
            if (game.result === 'checkmate_white') return 'black';
            if (game.result === 'checkmate_black') return 'white';
        }
        return null;
    }

    function applyKingDangerHighlight(position) {
        const targetColor = getDangerTargetColor();
        if (!targetColor || !position) return;

        const kingChar = targetColor === 'white' ? 'K' : 'k';
        let actualKingSquare = null;

        for (let rank = 0; rank < 8 && !actualKingSquare; rank++) {
            for (let file = 0; file < 8; file++) {
                if (position[rank]?.[file] === kingChar) {
                    actualKingSquare = `${FILES[file]}${RANKS[rank]}`;
                    break;
                }
            }
        }

        if (!actualKingSquare) return;

        const displayKingSquare = toDisplaySquare(actualKingSquare);
        const kingSquareEl = getSquare(displayKingSquare);
        if (!kingSquareEl) return;

        if (lastMove?.is_checkmate || game.result === 'checkmate_white' || game.result === 'checkmate_black') {
            kingSquareEl.classList.add('checkmate-king');
        } else {
            kingSquareEl.classList.add('check-king');
        }
    }

    async function loadCapturedPieces() {
        try {
            const data = await API.get(`/chess/games/${game.id}/captured/`);
            captured = {
                white: data.white || [],
                black: data.black || [],
            };
        } catch (error) {
            console.error('Failed to load captured pieces:', error);
        }
    }

    function updateCapturedFromMove(data) {
        const capture = data?.last_move?.capture;
        if (!capture) return;
        captured[capture.color].push(capture.piece);
    }

    function renderCapturedPieces() {
        if (!capturedWhite || !capturedBlack) return;

        // 백이 잡은 기물은 흑(소문자), 흑이 잡은 기물은 백(대문자)
        capturedWhite.innerHTML = captured.white
            .map((letter) => createCapturedPieceMarkup(letter.toLowerCase()))
            .join('');

        capturedBlack.innerHTML = captured.black
            .map((letter) => createCapturedPieceMarkup(letter.toUpperCase()))
            .join('');
    }

    /**
     * 수 두기
     */
    function makeMove(from, to) {
        const uci = from + to;

        // 프로모션 체크
        const fromEl = getSquare(toDisplaySquare(from));
        const piece = fromEl?.querySelector('.piece');

        let isPromotion = false;
        if (piece) {
            const isPawn = piece.dataset.piece && piece.dataset.piece.toLowerCase() === 'p';
            isPromotion = isPawn && (to[1] === '8' || to[1] === '1');
        }

        if (moveConfirmEnabled) {
            if (isPromotion) {
                pendingPromotion = { from, to };
                showPromotionModal();
            } else {
                pendingConfirmedMove = { uci, promotion: '' };
                document.getElementById('move-confirm-overlay')?.classList.remove('hidden');
            }
            return;
        }

        if (isPromotion) {
            pendingPromotion = { from, to };
            showPromotionModal();
            return;
        }

        sendMove(uci);
    }

    /**
     * 수 전송
     */
    function sendMove(uci, promotion = '') {
        if (!socket || socket.readyState !== WebSocket.OPEN) {
            Toast.error('연결이 끊어졌습니다.');
            return;
        }

        socket.send(JSON.stringify({
            action: 'move',
            game_id: game.id,
            uci: uci,
            promotion: promotion
        }));
    }

    /**
     * 프로모션 모달 표시
     */
    function showPromotionModal() {
        promotionModal.classList.remove('hidden');

        document.querySelectorAll('.promotion-piece').forEach(btn => {
            const piece = btn.dataset.piece;
            const pieceChar = myColor === 'white' ? piece.toUpperCase() : piece.toLowerCase();
            btn.textContent = PIECE_SPRITE[pieceChar] || '';
            
            btn.onclick = () => {
                const uci = pendingPromotion.from + pendingPromotion.to;
                if (moveConfirmEnabled) {
                    pendingConfirmedMove = { uci, promotion: piece };
                    document.getElementById('move-confirm-overlay')?.classList.remove('hidden');
                } else {
                    sendMove(uci, piece);
                }
                promotionModal.classList.add('hidden');
                pendingPromotion = null;
            };
        });
    }

    /**
     * WebSocket 연결
     */
    function connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        let wsUrl = `${protocol}//${window.location.host}/ws/chess/${roomId}/`;

        // 게스트 토큰이 있으면 쿼리 파라미터로 추가
        const guestToken = localStorage.getItem('guest_token');
        if (guestToken) {
            wsUrl += `?guest_token=${encodeURIComponent(guestToken)}`;
        }

        socket = new WebSocket(wsUrl);

        socket.onopen = () => {
            addChatNotice('연결되었습니다.');
            wsReconnectAttempts = 0;
            startHeartbeat();
            refreshSpectatorList();
            showStatus('게임 실시간 연결 완료', 'success', 1200);
        };

        socket.onmessage = (e) => {
            const data = JSON.parse(e.data);
            handleSocketMessage(data);
        };

        socket.onclose = () => {
            addChatNotice('연결이 끊어졌습니다.');
            stopHeartbeat();
            if (wsReconnectAttempts >= WS_MAX_RECONNECT_ATTEMPTS) {
                addChatNotice('재연결 시도 횟수를 초과했습니다. 페이지를 새로고침해 주세요.');
                showStatus('연결 복구 실패. 새로고침해주세요.', 'error', 2600);
                return;
            }
            wsReconnectAttempts += 1;
            const delay = Math.min(WS_BASE_RECONNECT_DELAY * Math.pow(2, wsReconnectAttempts - 1), 30000);
            addChatNotice(`${Math.round(delay / 1000)}초 후 재연결 시도 (${wsReconnectAttempts}/${WS_MAX_RECONNECT_ATTEMPTS})...`);
            showStatus(`${Math.round(delay / 1000)}초 후 게임 연결 재시도`, 'pending', 1500);
            setTimeout(connectWebSocket, delay);
        };

        socket.onerror = () => {
            addChatNotice('연결 오류');
        };
    }

    /**
     * WebSocket 메시지 처리
     */
    async function handleSocketMessage(data) {
        switch (data.type) {
            case 'move':
                if (data.last_move && !replayActive) {
                    await animateIncomingMove(data.last_move);
                }
                // 게임 상태 업데이트
                game.fen = data.fen;
                game.pgn = data.pgn;
                game.current_turn = data.current_turn;
                game.result = data.result;
                game.white_time_remaining = data.white_time_remaining;
                game.black_time_remaining = data.black_time_remaining;
                game.turn_started_at = data.turn_started_at;
                if (data.last_move) {
                    Utils?.Sounds?.move?.();
                }
                if (data.last_move) {
                    lastMove = data.last_move;
                    if (data.last_move.is_check && data.result === 'playing') {
                        if (myColor && myColor === data.current_turn) {
                            showStatusModal('체크입니다. 왕을 보호하세요.');
                            showGuideMessage('체크 상태입니다. 왕을 지키는 수만 가능합니다.', 'warning');
                        }
                    }
                    if (data.last_move.is_checkmate) {
                        showStatusModal('체크메이트입니다.');
                    }
                }

                renderBoard();
                renderMoveList();
                updateCapturedFromMove(data);
                renderCapturedPieces();
                updateTurn();
                clearSelection();

                if (data.last_move?.is_checkmate && data.result !== 'playing') {
                    showStatusModal('체크메이트입니다!', 1200);
                    setTimeout(() => showGameEndModal(data.result), 1200);
                } else if (data.result !== 'playing') {
                    showGameEndModal(data.result);
                }

                if (data.commentary && data.commentary_color === myColor) {
                    showGuideMessage(data.commentary, data.commentary_level || 'info');
                }
                break;

            case 'game_end':
                game.result = data.result;
                showGameEndModal(data.result);
                break;

            case 'draw_offer':
                if (data.from !== myColor) {
                    showDrawOfferModal();
                }
                break;

            case 'draw_declined':
                Toast.info('상대가 무승부를 거절했습니다.');
                break;

            case 'rematch_offer':
                if (data.from !== myColor) {
                    showRematchOfferModal();
                }
                break;

            case 'rematch_declined':
                Toast.info('상대가 리매치를 거절했습니다.');
                break;

            case 'rematch_created':
                await handleRematchCreated(data);
                break;

            case 'chat':
                addChatMessage(data);
                break;

            case 'reaction_update':
                applyReactionUpdate(data.message_id, data.reactions || {}, data.my_reactions);
                break;

            case 'recent_messages':
                (data.messages || []).forEach((msg) => addChatMessage(msg));
                break;

            case 'spectator_event': {
                const nickname = data.user?.nickname || '관전자';
                const isSelf = currentUser && data.user?.id === currentUser.id;
                if (!isSelf) {
                    const actionText = data.action === 'leave' ? '퇴장' : '입장';
                    Toast.info(`${nickname}님이 관전에 ${actionText}했습니다.`);
                    addChatNotice(`${nickname}님이 관전에 ${actionText}했습니다.`);
                }
                await refreshSpectatorList();
                break;
            }

            case 'room_update':
                await refreshSpectatorList();
                break;

            case 'error':
                Toast.error(data.message);
                if (data.message && data.message.includes('허용되지 않는 수')) {
                    showStatusModal('허용되지 않는 수입니다. 체크 상태라면 체크를 해제하는 수만 가능합니다.', 2000);
                }
                break;

            case 'heartbeat_ack':
                break;
        }
    }

    async function animateIncomingMove(lastMove) {
        if (!lastMove || !lastMove.from || !lastMove.to) return;
        const fromSquare = toDisplaySquare(lastMove.from);
        const toSquare = toDisplaySquare(lastMove.to);
        const fromEl = getSquare(fromSquare);
        const toEl = getSquare(toSquare);
        const movingPiece = fromEl?.querySelector('.piece');
        if (!fromEl || !toEl || !movingPiece) return;

        const fromRect = fromEl.getBoundingClientRect();
        const toRect = toEl.getBoundingClientRect();
        const clone = movingPiece.cloneNode(true);

        clone.style.position = 'fixed';
        clone.style.left = `${fromRect.left}px`;
        clone.style.top = `${fromRect.top}px`;
        clone.style.width = `${fromRect.width}px`;
        clone.style.height = `${fromRect.height}px`;
        clone.style.margin = '0';
        clone.style.pointerEvents = 'none';
        clone.style.zIndex = '2000';
        clone.style.transition = 'transform 180ms cubic-bezier(0.25, 0.8, 0.25, 1)';
        clone.style.willChange = 'transform';

        const capturedPiece = toEl.querySelector('.piece');
        if (capturedPiece) {
            capturedPiece.style.transition = 'opacity 120ms ease';
            capturedPiece.style.opacity = '0.2';
        }

        document.body.appendChild(clone);
        movingPiece.style.visibility = 'hidden';

        await new Promise((resolve) => {
            requestAnimationFrame(() => {
                const dx = toRect.left - fromRect.left;
                const dy = toRect.top - fromRect.top;
                clone.style.transform = `translate(${dx}px, ${dy}px)`;
            });
            setTimeout(resolve, 190);
        });

        clone.remove();
        movingPiece.style.visibility = '';
        if (capturedPiece) {
            capturedPiece.style.opacity = '';
            capturedPiece.style.transition = '';
        }
    }

    /**
     * 채팅 설정
     */
    function setupChat() {
        if (isAiRoom) {
            chatSection?.classList.add('is-hidden');
            return;
        }
        const titleEl = chatSection?.querySelector('.panel-title');
        if (titleEl) {
            titleEl.textContent = myColor ? '채팅' : '관전자 채팅';
        }
        injectChatEmojiBar();
        chatForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const message = chatInput.value.trim();
            if (!message || !socket) return;
            Utils?.Sounds?.unlock?.();

            const action = myColor ? 'chat' : 'spectator_chat';
            socket.send(JSON.stringify({ action, message }));
            chatInput.value = '';
        });
        if (!myColor) {
            addChatNotice('관전자는 관전자끼리만 채팅할 수 있습니다.');
        }
    }

    function injectChatEmojiBar() {
        if (!chatForm || !chatInput) return;
        if (chatForm.previousElementSibling?.classList?.contains('chat-emoji-bar')) return;
        const bar = document.createElement('div');
        bar.className = 'chat-emoji-bar';
        const emojis = ['😊', '😂', '👍', '🔥', '👏', '🙏'];
        bar.innerHTML = emojis
            .map((emoji) => `<button type="button" class="emoji-btn" data-emoji="${emoji}">${emoji}</button>`)
            .join('');
        bar.addEventListener('click', (e) => {
            const btn = e.target.closest('.emoji-btn');
            if (!btn) return;
            chatInput.value += btn.dataset.emoji || '';
            chatInput.focus();
        });
        chatForm.parentNode.insertBefore(bar, chatForm);
    }

    function setupNotificationEvents() {
        if (!currentUser || notificationEventBound) return;
        notificationEventHandler = (event) => {
            const data = event.detail || {};
            const reason = data.payload?.reason || '';
            const handlers = {
                [NOTIFICATION_TYPES.CHAT_MUTE]: () => {
                    setChatMutedState(true, reason);
                    Toast.error(data.message || '채팅이 제한되었습니다.');
                },
                [NOTIFICATION_TYPES.ACCOUNT_SUSPENDED]: () => {
                    setSuspendedState(true, reason);
                    Toast.error(data.message || '계정이 정지되었습니다.');
                },
                [NOTIFICATION_TYPES.CHAT_UNMUTE]: () => {
                    setChatMutedState(false);
                    Toast.success(data.message || '채팅 제한이 해제되었습니다.');
                },
                [NOTIFICATION_TYPES.ACCOUNT_UNSUSPENDED]: () => {
                    setSuspendedState(false);
                    Toast.success(data.message || '계정 정지가 해제되었습니다.');
                },
            };
            handlers[data.type]?.();
        };
        window.addEventListener('chessok:notification', notificationEventHandler);
        notificationEventBound = true;
    }

    function setChatMutedState(muted, reason = '') {
        if (!chatInput || !chatForm) return;
        if (muted) {
            chatInput.disabled = true;
            chatForm.querySelector('button').disabled = true;
            if (reason) {
                addChatNotice(`채팅 제한됨: ${reason}`);
            } else {
                addChatNotice('채팅이 제한되었습니다.');
            }
        } else {
            chatInput.disabled = false;
            chatForm.querySelector('button').disabled = false;
        }
    }

    function setSuspendedState(suspended, reason = '') {
        isSuspended = suspended;
        setGameActionButtonsDisabled(Boolean(suspended));
        if (suspended) {
            if (reason) {
                addChatNotice(`계정 정지됨: ${reason}`);
            } else {
                addChatNotice('계정이 정지되었습니다.');
            }
        }
    }

    function setGameActionButtonsDisabled(disabled) {
        [drawBtn, resignBtn, leaveBtn, rematchBtn].forEach((btn) => {
            if (btn) {
                btn.disabled = disabled;
            }
        });
    }

    /**
     * 채팅 메시지 추가
     */
    function addChatMessage(data) {
        const isMine = currentUser && data.user_id === currentUser.id;
        const avatar = !isMine
            ? (data.avatar_url
                ? `<img src="${Utils.escapeHtml(data.avatar_url)}" alt="${Utils.escapeHtml(data.nickname || '')}">`
                : '<span class="avatar-placeholder">?</span>')
            : '';
        const messageEl = document.createElement('div');
        messageEl.className = `chat-message ${isMine ? 'mine' : 'others'}`;
        if (data.message_id) {
            messageEl.dataset.messageId = String(data.message_id);
        }
        const reactions = data.reactions || {};
        const myReactions = data.my_reactions || [];
        const thumbCount = Number(reactions['👍'] || 0);
        const clapCount = Number(reactions['👏'] || 0);
        messageEl.innerHTML = `
            ${!isMine ? `<div class="chat-avatar">${avatar}</div>` : ''}
            <div class="chat-content">
                <span class="chat-nickname">${Utils.escapeHtml(data.nickname)}</span>
                <div class="chat-bubble">${Utils.escapeHtml(data.message)}</div>
                <div class="chat-reactions">
                    <button type="button" class="reaction-btn ${myReactions.includes('👍') ? 'active' : ''}" data-reaction="👍">👍 <span>${thumbCount}</span></button>
                    <button type="button" class="reaction-btn ${myReactions.includes('👏') ? 'active' : ''}" data-reaction="👏">👏 <span>${clapCount}</span></button>
                </div>
            </div>
        `;
        chatMessages.appendChild(messageEl);
        chatMessages.scrollTop = chatMessages.scrollHeight;
        if (!isMine) Utils?.Sounds?.chat?.();
        handleChatBadge(data);
        bindReactionButtons(messageEl);
    }

    async function refreshSpectatorList() {
        if (!spectatorSection || !spectatorList || !spectatorCount || isAiRoom) return;
        try {
            const data = await API.get(`/chess/rooms/${roomId}/spectators/`);
            const spectators = data?.spectators || [];
            spectatorCount.textContent = `${spectators.length}명`;
            renderSpectatorList(spectators);
        } catch (error) {
            if (error?.status === 403 || error?.status === 404) {
                spectatorSection.classList.add('hidden');
                return;
            }
            spectatorCount.textContent = '--';
            spectatorList.innerHTML = '<div class="spectator-empty">목록을 불러오지 못했습니다.</div>';
        }
    }

    function renderSpectatorList(users) {
        if (!spectatorList) return;
        if (!users.length) {
            spectatorList.innerHTML = '<div class="spectator-empty">관전자가 없습니다.</div>';
            return;
        }
        spectatorList.innerHTML = users
            .map((user) => `
                <div class="spectator-item">
                    <div class="avatar avatar-xs" style="box-shadow:${Utils.getProfileBorderValue(user.profile_border || '')}">
                        ${user.avatar_url
                            ? `<img src="${Utils.escapeHtml(user.avatar_url)}" alt="${Utils.escapeHtml(user.nickname || '관전자')}">`
                            : '<span class="avatar-placeholder">?</span>'}
                    </div>
                    <span style="color:${Utils.getNicknameColorValue(user.nickname_color || '')}">${Utils.escapeHtml(user.nickname || '관전자')}</span>
                </div>
            `)
            .join('');
    }

    function setupMobileTabs() {
        if (!mobileTabbar) return;
        document.body.classList.add('has-mobile-tabbar');
        const tabs = mobileTabbar.querySelectorAll('.mobile-tab');
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const target = tab.dataset.tab;
                tabs.forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                if (target === 'chat') {
                    isChatOpen = true;
                    if (chatSection) chatSection.classList.remove('is-hidden');
                    if (moveSection) moveSection.classList.add('is-hidden');
                    resetChatBadge();
                } else {
                    isChatOpen = false;
                    if (chatSection) chatSection.classList.add('is-hidden');
                    if (moveSection) moveSection.classList.remove('is-hidden');
                }
                syncGameChatFabVisibility();
            });
        });
        isChatOpen = false;
        if (chatSection) chatSection.classList.add('is-hidden');
        if (moveSection) moveSection.classList.remove('is-hidden');
        syncGameChatFabVisibility();
    }

    function handleChatBadge(data) {
        // 채팅이 열려있으면(FAB 토글 또는 모바일 탭) 배지 리셋
        const isChatVisible = isChatOpen ||
            (chatSection && !chatSection.classList.contains('is-collapsed') && !chatSection.classList.contains('is-hidden'));
        if (isChatVisible) {
            resetChatBadge();
            return;
        }
        if (currentUser && data.user_id === currentUser.id) return;
        chatUnread += 1;
        // 모바일 탭 배지
        if (chatBadge) {
            chatBadge.textContent = chatUnread;
            chatBadge.classList.remove('hidden');
        }
        // FAB 배지
        if (chatFabBadge) {
            chatFabBadge.textContent = chatUnread;
            chatFabBadge.classList.remove('hidden');
        }
    }

    function resetChatBadge() {
        chatUnread = 0;
        if (chatBadge) {
            chatBadge.textContent = '0';
            chatBadge.classList.add('hidden');
        }
        if (chatFabBadge) {
            chatFabBadge.textContent = '0';
            chatFabBadge.classList.add('hidden');
        }
    }

    /**
     * 채팅 알림 추가
     */
    function addChatNotice(text) {
        const noticeEl = document.createElement('div');
        noticeEl.className = 'chat-notice';
        noticeEl.textContent = text;
        chatMessages.appendChild(noticeEl);
    }

    /**
     * 액션 버튼 설정
     */
    function setupActions() {
        if (!myColor || replayOnly) {
            gameActions?.classList.add('hidden');
            return;
        }

        // Move confirmation buttons
        const confirmOverlay = document.getElementById('move-confirm-overlay');
        const confirmYes = document.getElementById('move-confirm-yes');
        const confirmNo = document.getElementById('move-confirm-no');

        confirmYes?.addEventListener('click', () => {
            if (pendingConfirmedMove) {
                sendMove(pendingConfirmedMove.uci, pendingConfirmedMove.promotion);
                pendingConfirmedMove = null;
                confirmOverlay?.classList.add('hidden');
            }
        });

        confirmNo?.addEventListener('click', () => {
            pendingConfirmedMove = null;
            confirmOverlay?.classList.add('hidden');
            renderBoard();
        });

        if (isAiRoom) {
            gameActions?.classList.remove('hidden');
            drawBtn?.remove();
            resignBtn?.remove();
            if (leaveBtn) {
                leaveBtn.addEventListener('click', () => {
                    sendAiResign();
                    window.location.href = '/';
                });
            }
            return;
        }
        drawBtn.addEventListener('click', async () => {
            const confirmed = await Modal.confirm('무승부를 제안하시겠습니까?', {
                title: '무승부 제안',
                confirmText: '제안하기'
            });
            if (!confirmed) return;
            socket.send(JSON.stringify({ action: 'draw', game_id: game.id }));
            Toast.info('무승부를 제안했습니다.');
        });

        resignBtn.addEventListener('click', async () => {
            const confirmed = await Modal.confirm('정말 기권하시겠습니까?', {
                title: '기권',
                confirmText: '기권하기',
                danger: true
            });
            if (!confirmed) return;
            socket.send(JSON.stringify({ action: 'resign', game_id: game.id }));
            showPendingEnd('기권 처리 중...');
        });

        if (leaveBtn) {
            leaveBtn.addEventListener('click', async () => {
                if (myColor) {
                    const confirmed = await Modal.confirm('나가면 기권 처리됩니다. 나가시겠습니까?', {
                        title: '게임 나가기',
                        confirmText: '나가기',
                        danger: true
                    });
                    if (!confirmed) return;
                    socket.send(JSON.stringify({ action: 'resign', game_id: game.id }));
                    showPendingEnd('나가기 처리 중...');
                } else {
                    window.location.href = '/';
                }
            });
        }
    }

    function setupGuideToggle() {
        if (!guideToggle) return;
        const updateToggle = () => {
            guideToggle.textContent = guideEnabled ? 'ON' : 'OFF';
            guideToggle.setAttribute('aria-pressed', guideEnabled ? 'true' : 'false');
            guideToggle.classList.toggle('is-off', !guideEnabled);
        };
        updateToggle();
        guideToggle.addEventListener('click', () => {
            guideEnabled = !guideEnabled;
            Utils.Storage.set('guide_enabled', guideEnabled);
            updateToggle();
        });
    }

    function showGuideMessage(message, level = 'info') {
        if (!guideEnabled || !message) return;
        if (level === 'warning' || level === 'major') {
            showStatusModal(message);
            return;
        }
        Toast.info(message);
    }

    function setupExitGuard() {
        const logo = document.querySelector('.navbar-logo');

        // 게임 중인지 확인하는 헬퍼 함수
        const isGameInProgress = () => {
            // game.result가 'playing'이고, 내가 참여자이며, 소켓 연결 상태
            return game?.result === 'playing' && myColor && socket?.readyState === WebSocket.OPEN;
        };

        // 기권 후 이동 처리
        const resignAndLeave = (targetUrl = '/') => {
            if (isGameInProgress()) {
                socket.send(JSON.stringify({ action: 'resign', game_id: game.id }));
            }
            // 약간의 딜레이 후 이동 (서버에 기권 전송 보장)
            setTimeout(() => {
                window.location.href = targetUrl;
            }, 100);
        };

        // 나가기 확인 다이얼로그
        const confirmExit = async (targetUrl = '/') => {
            if (isGameInProgress()) {
                const confirmed = await Modal.confirm('나가면 기권 처리됩니다. 나가시겠습니까?', {
                    title: '기권 확인',
                    confirmText: '기권하고 나가기',
                    danger: true
                });
                if (confirmed) {
                    resignAndLeave(targetUrl);
                }
                return confirmed;
            } else {
                // 게임 종료 상태면 바로 이동
                window.location.href = targetUrl;
                return true;
            }
        };

        // 로고 클릭 시
        if (logo) {
            logo.addEventListener('click', async (e) => {
                e.preventDefault();
                await confirmExit('/');
            });
        }

        // 브라우저 뒤로가기 처리
        // 게임 로드 후 히스토리 상태 추가
        const pushGuardState = () => {
            if (!history.state?.gameGuard) {
                history.pushState({ gameGuard: true }, '');
            }
        };

        // 초기 히스토리 상태 추가 (게임 로드 후)
        setTimeout(pushGuardState, 500);

        window.addEventListener('popstate', async () => {
            if (isGameInProgress()) {
                // 뒤로가기 방지를 위해 다시 히스토리 추가
                pushGuardState();
                await confirmExit('/');
            }
        });

        // 페이지 나가기 전 경고 (새로고침, 탭 닫기 등)
        window.addEventListener('beforeunload', (e) => {
            if (isGameInProgress()) {
                e.preventDefault();
                // 브라우저 호환성을 위해 returnValue 설정
                return (e.returnValue = '게임이 진행 중입니다. 나가면 기권 처리됩니다.');
            }
        });
    }

    /**
     * 모달 설정
     */
    function setupModals() {
        const roomType = game?.room_type || game?.room?.room_type;
        const isCompetitive = roomType === 'quick' || roomType === 'competitive';
        const isAiRoom = roomType?.startsWith('ai_');
        if (replayOnly) {
            rematchBtn?.classList.add('hidden');
            const lobbyBtn = document.getElementById('lobby-btn');
            if (lobbyBtn) lobbyBtn.textContent = '전적 보기';
        }
        if (isCompetitive || isAiRoom) {
            rematchBtn?.remove();
            rematchModal?.remove();
            document.getElementById('accept-rematch-btn')?.remove();
            document.getElementById('decline-rematch-btn')?.remove();
        }
        const historyBtn = document.getElementById('history-btn');
        historyBtn?.addEventListener('click', () => {
            window.location.href = '/history/';
        });
        // 리매치 버튼
        if (!replayOnly && !isCompetitive && rematchBtn) {
            rematchBtn.addEventListener('click', () => {
                socket.send(JSON.stringify({ action: 'rematch', game_id: game.id }));
                Toast.info('리매치를 요청했습니다.');
            });
        }

        // 로비 버튼
        document.getElementById('lobby-btn')?.addEventListener('click', () => {
            window.location.href = replayOnly ? '/history/' : '/';
        });

        // 무승부 수락/거절
        const acceptDrawBtn = document.getElementById('accept-draw-btn');
        const declineDrawBtn = document.getElementById('decline-draw-btn');
        if (drawModal && acceptDrawBtn && declineDrawBtn) {
            acceptDrawBtn.addEventListener('click', () => {
                socket.send(JSON.stringify({ action: 'draw', game_id: game.id }));
                drawModal.classList.add('hidden');
            });

            declineDrawBtn.addEventListener('click', () => {
                socket.send(JSON.stringify({ action: 'decline_draw', game_id: game.id }));
                drawModal.classList.add('hidden');
                Toast.info('무승부를 거절했습니다.');
            });
        }

        // 리매치 수락/거절
        if (!replayOnly && !isCompetitive) {
            const acceptRematchBtn = document.getElementById('accept-rematch-btn');
            const declineRematchBtn = document.getElementById('decline-rematch-btn');
            acceptRematchBtn?.addEventListener('click', () => {
                socket.send(JSON.stringify({ action: 'rematch', game_id: game.id }));
                rematchModal?.classList.add('hidden');
            });

            declineRematchBtn?.addEventListener('click', () => {
                socket.send(JSON.stringify({ action: 'decline_rematch', game_id: game.id }));
                rematchModal?.classList.add('hidden');
            });
        }
    }

    function setupMovePagination() {
        if (!movePrevBtn || !moveNextBtn) return;
        movePrevBtn.addEventListener('click', () => {
            if (movePage > 1) {
                movePage -= 1;
                renderMoveList();
            }
        });
        moveNextBtn.addEventListener('click', () => {
            movePage += 1;
            renderMoveList();
        });
    }

    function setupStatusModal() {
        if (!statusModalOk) return;
        statusModalOk.addEventListener('click', () => {
            statusModal.classList.add('hidden');
        });
    }

    function showStatusModal(message, autoCloseMs = null) {
        if (!statusModal || !statusModalMessage) return;
        statusModalMessage.textContent = message;
        statusModal.classList.remove('hidden');
        if (autoCloseMs) {
            setTimeout(() => {
                statusModal.classList.add('hidden');
            }, autoCloseMs);
        }
    }

    async function loadLastMove() {
        try {
            const offset = Math.max(0, (game.move_count || 0) - 1);
            const data = await API.get(`/chess/games/${game.id}/moves/`, { limit: 1, offset });
            const last = data.results?.[0];
            if (last) {
                lastMove = { from: last.from_square, to: last.to_square };
            }
        } catch (error) {
            console.error('Failed to load last move:', error);
        }
    }

    function setupReplayControls() {
        if (!replayBtn) return;
        replayBtn.addEventListener('click', async () => {
            await openReplay();
        });
        replayPrev?.addEventListener('click', () => stepReplay(-1));
        replayNext?.addEventListener('click', () => stepReplay(1));
        replayPlay?.addEventListener('click', () => toggleReplay());
        replayClose?.addEventListener('click', () => closeReplay());
        replayPrevDock?.addEventListener('click', () => stepReplay(-1));
        replayNextDock?.addEventListener('click', () => stepReplay(1));
        replayPlayDock?.addEventListener('click', () => toggleReplay());
        replayCloseDock?.addEventListener('click', () => closeReplay());

        // 키보드 단축키 (좌/우 화살표)
        document.addEventListener('keydown', (e) => {
            if (!replayActive) return;
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
            if (e.key === 'ArrowLeft') {
                e.preventDefault();
                stepReplay(-1);
            } else if (e.key === 'ArrowRight') {
                e.preventDefault();
                stepReplay(1);
            } else if (e.key === ' ') {
                e.preventDefault();
                toggleReplay();
            }
        });
    }

    function setupShareButton() {
        if (!shareBtn) return;
        shareBtn.addEventListener('click', async () => {
            const targetGameId = replayGameId || game?.id;
            if (!targetGameId) {
                Toast.error('공유할 게임 정보가 없습니다.');
                return;
            }
            const shareUrl = `${window.location.origin}/games/${roomId}/?replay_game_id=${targetGameId}`;
            try {
                await navigator.clipboard.writeText(shareUrl);
                Toast.success('기보 링크가 복사되었습니다!');
            } catch {
                // 복사 실패 시 prompt로 표시
                Modal.alert(`링크를 직접 복사해주세요:\n${shareUrl}`, { title: '기보 공유 링크' });
            }
        });
    }

    async function openReplay(targetGameId = null) {
        if (!replayModal && !replayDock) return;
        if (gameEndModal) {
            gameEndModal.classList.add('hidden');
        }
        replayMoves = [];
        replayGameId = targetGameId || game?.id || null;
        try {
            const data = await API.get(`/chess/games/${replayGameId}/moves/`, { limit: 200, offset: 0 });
            replayMoves = data.results || [];
        } catch (error) {
            try {
                const history = await API.get('/chess/games/history/', { limit: 20, no_count: 1 });
                const matches = history.results || [];
                const fallback = matches.find(item => item.room_id === roomId);
                if (fallback?.id) {
                    const data = await API.get(`/chess/games/${fallback.id}/moves/`, { limit: 200, offset: 0 });
                    replayMoves = data.results || [];
                    replayGameId = fallback.id;
                } else {
                    throw error;
                }
            } catch (innerError) {
                console.error('Failed to load replay moves:', innerError);
                replayMoves = [];
                if (replayStatus) replayStatus.textContent = '기보를 불러오지 못했습니다.';
                if (replayStatusDock) replayStatusDock.textContent = '기보를 불러오지 못했습니다.';
            }
        }
        liveFen = game.fen;
        liveLastMove = lastMove;
        replayIndex = 0;
        replayActive = true;
        updateReplayBoard();
        if (replayOnly) {
            if (replayClose) replayClose.textContent = '전적 보기';
            if (replayCloseDock) replayCloseDock.textContent = '전적 보기';
        } else {
            if (replayClose) replayClose.textContent = '닫기';
            if (replayCloseDock) replayCloseDock.textContent = '닫기';
        }
        replayMode = replayDock ? 'dock' : 'modal';
        if (replayMode === 'dock') {
            replayDock?.classList.remove('hidden');
            replayModal?.classList.add('hidden');
        } else {
            replayModal?.classList.remove('hidden');
            replayDock?.classList.add('hidden');
        }
    }

    function closeReplay() {
        if (!replayModal && !replayDock) return;
        if (replayTimer) {
            clearInterval(replayTimer);
            replayTimer = null;
        }
        replayActive = false;
        replayModal.classList.add('hidden');
        replayDock?.classList.add('hidden');
        if (replayOnly) {
            window.location.href = '/history/';
            return;
        }
        if (gameEndModal) {
            gameEndModal.classList.remove('hidden');
        }
        if (liveFen) {
            game.fen = liveFen;
            lastMove = liveLastMove;
            renderBoard();
        }
    }

    function toggleReplay() {
        if (!replayActive) return;
        if (replayTimer) {
            clearInterval(replayTimer);
            replayTimer = null;
            if (replayPlay) replayPlay.textContent = '재생';
            if (replayPlayDock) replayPlayDock.textContent = '재생';
            return;
        }
        if (replayPlay) replayPlay.textContent = '일시정지';
        if (replayPlayDock) replayPlayDock.textContent = '일시정지';
        replayTimer = setInterval(() => {
            if (replayIndex >= replayMoves.length) {
                clearInterval(replayTimer);
                replayTimer = null;
                if (replayPlay) replayPlay.textContent = '재생';
                if (replayPlayDock) replayPlayDock.textContent = '재생';
                return;
            }
            replayIndex += 1;
            updateReplayBoard();
        }, 900);
    }

    function stepReplay(direction) {
        if (!replayActive) return;
        replayIndex = Math.max(0, Math.min(replayMoves.length, replayIndex + direction));
        updateReplayBoard();
    }

    function updateReplayBoard() {
        if (!replayMoves.length) {
            if (replayStatus) replayStatus.textContent = '기보가 없습니다.';
            replayPrev && (replayPrev.disabled = true);
            replayNext && (replayNext.disabled = true);
            replayPlay && (replayPlay.disabled = true);
            replayPrevDock && (replayPrevDock.disabled = true);
            replayNextDock && (replayNextDock.disabled = true);
            replayPlayDock && (replayPlayDock.disabled = true);
            return;
        }
        replayPrev && (replayPrev.disabled = false);
        replayNext && (replayNext.disabled = false);
        replayPlay && (replayPlay.disabled = false);
        replayPrevDock && (replayPrevDock.disabled = false);
        replayNextDock && (replayNextDock.disabled = false);
        replayPlayDock && (replayPlayDock.disabled = false);

        const total = replayMoves.length;
        const statusText = replayIndex === 0
            ? '시작 위치'
            : `${replayIndex}/${total} 수`;
        if (replayStatus) replayStatus.textContent = statusText;
        if (replayStatusDock) replayStatusDock.textContent = statusText;

        const fen = replayIndex === 0
            ? 'rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1'
            : replayMoves[replayIndex - 1]?.fen_after_move;
        if (fen) {
            game.fen = fen;
            lastMove = replayIndex === 0
                ? null
                : { from: replayMoves[replayIndex - 1].from_square, to: replayMoves[replayIndex - 1].to_square };
            renderBoard();
        }
    }

    /**
     * 게임 종료 모달 표시
     */
    function showGameEndModal(result) {
        if (timerInterval) {
            clearInterval(timerInterval);
        }
        pendingEnd = false;

        const iconEl = document.getElementById('game-end-icon');
        const titleEl = document.getElementById('game-end-title');
        const resultEl = document.getElementById('game-end-result');

        // 분석 UI 초기화
        const analysisLoading = document.getElementById('analysis-loading');
        const analysisContent = document.getElementById('analysis-content');
        if (analysisLoading) analysisLoading.classList.remove('hidden');
        if (analysisContent) analysisContent.classList.add('hidden');
        if (analysisSummary) analysisSummary.textContent = '';

        let icon = '🎮';
        let title = '게임 종료';
        let resultText = result;

        // 결과에 따른 표시
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

        iconEl.textContent = icon;
        titleEl.textContent = title;
        resultEl.textContent = resultText;

        ratingPollAttempts = 0;
        loadRatingChange();
        loadMoveTimeStats();

        gameEndModal.classList.remove('hidden');
        gameEndModal.style.display = 'flex';
        loadGameAnalysis();
    }

    async function loadGameAnalysis() {
        if (!analysisCanvas) return;
        const analysisLoading = document.getElementById('analysis-loading');
        const analysisContent = document.getElementById('analysis-content');
        try {
            const data = await API.get(`/chess/games/${game.id}/moves/`, { limit: 300, offset: 0 });
            const moves = data.results || [];
            const series = buildEvalSeries(moves);
            drawAnalysisGraph(series);
            if (analysisSummary) {
                const maxSwing = series.length > 1
                    ? Math.max(...series.map((v, i) => i === 0 ? 0 : Math.abs(v - series[i - 1])))
                    : 0;
                analysisSummary.textContent = `평균 평가값: ${avg(series).toFixed(2)} · 최대 변동: ${maxSwing.toFixed(2)}`;
            }
            analysisLoading?.classList.add('hidden');
            analysisContent?.classList.remove('hidden');
        } catch (error) {
            if (analysisLoading) {
                analysisLoading.textContent = '분석을 불러오지 못했습니다.';
            }
        }
    }

    function buildEvalSeries(moves) {
        const series = [0];
        for (const move of moves) {
            const fen = move.fen_after_move;
            if (!fen) {
                series.push(series[series.length - 1]);
                continue;
            }
            series.push(scoreFenMaterial(fen));
        }
        return series;
    }

    function scoreFenMaterial(fen) {
        const board = fen.split(' ')[0];
        let score = 0;
        for (const ch of board) {
            if (ch === '/' || /\d/.test(ch)) continue;
            const value = PIECE_VALUE[ch.toLowerCase()] || 0;
            score += ch === ch.toUpperCase() ? value : -value;
        }
        return score;
    }

    function drawAnalysisGraph(series) {
        const ctx = analysisCanvas.getContext('2d');
        const w = analysisCanvas.width;
        const h = analysisCanvas.height;
        ctx.clearRect(0, 0, w, h);
        if (!series.length) return;
        const maxAbs = Math.max(1, ...series.map((v) => Math.abs(v)));
        const pad = 12;
        const graphW = w - pad * 2;
        const graphH = h - pad * 2;
        const yMid = pad + graphH / 2;

        ctx.strokeStyle = '#64748b';
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(pad, yMid);
        ctx.lineTo(w - pad, yMid);
        ctx.stroke();

        ctx.strokeStyle = '#22c55e';
        ctx.lineWidth = 2;
        ctx.beginPath();
        series.forEach((val, i) => {
            const x = pad + (series.length === 1 ? 0 : (i / (series.length - 1)) * graphW);
            const y = yMid - (val / maxAbs) * (graphH / 2 - 4);
            if (i === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        });
        ctx.stroke();
    }

    function avg(arr) {
        if (!arr.length) return 0;
        return arr.reduce((sum, x) => sum + x, 0) / arr.length;
    }

    function createPieceElement(piece) {
        const pieceEl = document.createElement('div');
        const isWhite = piece === piece.toUpperCase();
        pieceEl.className = `piece ${isWhite ? 'white' : 'black'}`;
        pieceEl.dataset.piece = piece;
        pieceEl.draggable = true;
        pieceEl.textContent = PIECE_SPRITE[piece] || '';
        return pieceEl;
    }

    function createCapturedPieceMarkup(piece) {
        const isWhite = piece === piece.toUpperCase();
        const glyph = PIECE_SPRITE[piece] || '';
        return `<span class="captured-piece ${isWhite ? 'white' : 'black'}">${glyph}</span>`;
    }

    function bindReactionButtons(messageEl) {
        messageEl.querySelectorAll('.reaction-btn').forEach((btn) => {
            btn.addEventListener('click', () => {
                if (!socket || socket.readyState !== WebSocket.OPEN) return;
                const root = btn.closest('.chat-message');
                const key = root?.dataset.messageId;
                const reaction = btn.dataset.reaction;
                if (!key || !reaction) return;
                btn.classList.toggle('active');
                socket.send(
                    JSON.stringify({
                        action: 'reaction',
                        message_id: key,
                        reaction,
                    })
                );
            });
        });
    }

    function ensureReactionUIForExistingMessages() {
        if (!chatMessages) return;
        const messageEls = chatMessages.querySelectorAll('.chat-message .chat-content');
        messageEls.forEach((contentEl) => {
            if (contentEl.querySelector('.chat-reactions')) return;
            const reactions = document.createElement('div');
            reactions.className = 'chat-reactions';
            reactions.innerHTML = `
                <button type="button" class="reaction-btn" data-reaction="👍">👍 <span>0</span></button>
                <button type="button" class="reaction-btn" data-reaction="👏">👏 <span>0</span></button>
            `;
            contentEl.appendChild(reactions);
            bindReactionButtons(contentEl.closest('.chat-message'));
        });
    }

    function applyReactionUpdate(messageId, reactions, myReactions) {
        if (!chatMessages || !messageId) return;
        const target = chatMessages.querySelector(`.chat-message[data-message-id="${String(messageId)}"]`);
        if (!target) return;
        target.querySelectorAll('.reaction-btn').forEach((btn) => {
            const emoji = btn.dataset.reaction;
            if (!emoji) return;
            const countEl = btn.querySelector('span');
            if (!countEl) return;
            const next = Number(reactions?.[emoji] || 0);
            countEl.textContent = String(next);
            if (Array.isArray(myReactions)) {
                btn.classList.toggle('active', myReactions.includes(emoji));
            }
        });
    }

    function injectPieceSpriteStyles() {
        if (document.getElementById('piece-sprite-font-style')) return;
        const style = document.createElement('style');
        style.id = 'piece-sprite-font-style';
        style.textContent = `
            .piece, .captured-piece, .promotion-piece, .drag-piece {
                font-family: "Noto Sans Symbols 2", "Noto Sans KR", sans-serif;
                line-height: 1;
                text-align: center;
                user-select: none;
            }
        `;
        document.head.appendChild(style);
    }

    async function loadMoveTimeStats() {
        if (!gameEndStats || !game) return;
        gameEndStats.innerHTML = '';

        try {
            const data = await API.get(`/chess/games/${game.id}/moves/`, { limit: 200, offset: 0 });
            const moves = data.results || [];
            if (!moves.length) return;

            // 내 착수 시간 계산
            const myMoves = moves.filter(m => m.color === myColor);
            const opMoves = moves.filter(m => m.color !== myColor);

            if (!myMoves.length) return;

            const myTimes = myMoves.map(m => m.time_spent || 0).filter(t => t > 0);
            const opTimes = opMoves.map(m => m.time_spent || 0).filter(t => t > 0);

            if (!myTimes.length && !opTimes.length) return;

            const avgTime = myTimes.length ? (myTimes.reduce((a, b) => a + b, 0) / myTimes.length).toFixed(1) : '--';
            const maxTime = myTimes.length ? Math.max(...myTimes).toFixed(1) : '--';
            const opAvgTime = opTimes.length ? (opTimes.reduce((a, b) => a + b, 0) / opTimes.length).toFixed(1) : '--';

            gameEndStats.innerHTML = `
                <div class="stats-row">
                    <span class="stats-label">평균 착수 시간</span>
                    <span class="stats-value">${avgTime}초</span>
                </div>
                <div class="stats-row">
                    <span class="stats-label">최장 고민 시간</span>
                    <span class="stats-value">${maxTime}초</span>
                </div>
                <div class="stats-row">
                    <span class="stats-label">상대 평균 착수</span>
                    <span class="stats-value">${opAvgTime}초</span>
                </div>
            `;
        } catch {
            // 통계 로드 실패 시 무시
        }
    }

    function showPendingEnd(message) {
        if (pendingEnd) return;
        pendingEnd = true;

        const iconEl = document.getElementById('game-end-icon');
        const titleEl = document.getElementById('game-end-title');
        const resultEl = document.getElementById('game-end-result');
        const ratingEl = document.getElementById('game-end-rating');

        iconEl.textContent = '⏳';
        titleEl.textContent = '처리 중...';
        resultEl.textContent = message;
        if (ratingEl) ratingEl.textContent = '';

        gameEndModal.classList.remove('hidden');
        gameEndModal.style.display = 'flex';
    }

    function getOutcome(result, color) {
        if (!color) return null;
        const whiteWin = ['white_win', 'checkmate_white', 'timeout_black', 'resignation_black'];
        const blackWin = ['black_win', 'checkmate_black', 'timeout_white', 'resignation_white'];
        const draws = [
            'draw',
            'draw_agreement',
            'draw_repetition',
            'draw_fifty_move',
            'draw_insufficient',
            'stalemate'
        ];

        if (draws.includes(result)) return 'draw';
        if (whiteWin.includes(result)) return color === 'white' ? 'win' : 'loss';
        if (blackWin.includes(result)) return color === 'black' ? 'win' : 'loss';
        return null;
    }

    /**
     * 무승부 제안 모달
     */
    function showDrawOfferModal() {
        drawModal.classList.remove('hidden');
    }

    /**
     * 리매치 제안 모달
     */
    function showRematchOfferModal() {
        rematchModal.classList.remove('hidden');
    }

    async function loadRatingChange() {
        const ratingEl = document.getElementById('game-end-rating');
        if (!ratingEl || !currentUser || !game) return;

        // 빠른 대전/AI 대전은 레이팅 변화 없음
        const roomType = game.room_type || game.room?.room_type;
        if (roomType === 'random' || roomType?.startsWith('ai_')) {
            ratingEl.textContent = '';
            return;
        }

        try {
            const data = await API.get('/notifications/', { limit: 10, offset: 0, no_count: 1 });
            const items = data.results || [];
            const target = items.find(
                (item) =>
                    item.type === 'rating_change' &&
                    item.payload &&
                    item.payload.game_id === game.id
            );

            if (!target) {
                ratingPollAttempts += 1;
                if (ratingPollAttempts >= RATING_POLL_MAX_ATTEMPTS) {
                    ratingEl.textContent = '레이팅 정보를 불러오지 못했습니다.';
                    return;
                }
                setTimeout(loadRatingChange, 1000);
                return;
            }

            ratingPollAttempts = 0;
            const before = target.payload.before;
            const after = target.payload.after;
            const delta = target.payload.delta ?? (after - before);
            const deltaClass = delta >= 0 ? 'positive' : 'negative';
            ratingEl.innerHTML = `
                <span>${before} → ${after}</span>
                <span class="${deltaClass}">(${delta >= 0 ? '+' : ''}${delta})</span>
            `;
        } catch {
            // ignore fetch errors
        }
    }

    /**
     * Heartbeat
     */
    function startHeartbeat() {
        heartbeatInterval = setInterval(() => {
            if (socket && socket.readyState === WebSocket.OPEN) {
                socket.send(JSON.stringify({ action: 'heartbeat' }));
            }
        }, 30000);
    }

    function stopHeartbeat() {
        if (heartbeatInterval) {
            clearInterval(heartbeatInterval);
            heartbeatInterval = null;
        }
    }

    // 페이지 떠날 때 정리
    window.addEventListener('beforeunload', () => {
        stopHeartbeat();
        if (timerInterval) clearInterval(timerInterval);
        if (isAiRoom) {
            sendAiResign();
        }
        if (socket) socket.close();
    });

    window.addEventListener('pagehide', () => {
        if (isAiRoom) {
            sendAiResign();
        }
    });

    // 화면 회전 시 보드 크기 재계산
    window.addEventListener('orientationchange', () => {
        setTimeout(() => {
            renderBoard();
            syncGameChatFabVisibility();
        }, 100);
    });

    window.addEventListener('resize', Utils.debounce(() => {
        renderBoard();
        syncGameChatFabVisibility();
    }, 200));

    function sendAiResign() {
        if (aiExitTriggered) return;
        if (!socket || !game || !myColor) return;
        if (socket.readyState !== WebSocket.OPEN) return;
        aiExitTriggered = true;
        socket.send(JSON.stringify({ action: 'resign', game_id: game.id }));
    }
})();
