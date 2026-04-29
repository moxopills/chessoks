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
    const boardUI = window.GameBoardUI;
    const socketClient = window.GameSocketClient;
    const statusUI = window.GameStatusUI;

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
    const gameModeBadge = document.getElementById('game-mode-badge');
    const gameTurnBadge = document.getElementById('game-turn-badge');
    const gameAlertBadge = document.getElementById('game-alert-badge');
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
    const sidePanelTabs = Array.from(document.querySelectorAll('.side-panel-tab'));
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
    let currentSpectators = [];
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
    let wsReconnectTimer = null;
    let resumeSyncInFlight = false;
    let lastResumeSyncAt = 0;
    let notificationEventBound = false;
    let notificationEventHandler = null;
    let selectedBoardSkinClass = 'skin-board-classic';
    let selectedPieceSkinClass = 'skin-piece-classic';
    let lastMoveListSignature = null;
    let activeSidePanelSectionId = window.innerWidth <= 900 ? 'game-actions' : 'game-moves-section';
    const pieceSvgMarkupCache = new Map();
    let currentUserReadyPromise = null;

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

        setupBoard();
        currentUserReadyPromise = hydrateCurrentUser();
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
        setupSidePanelNav();
        setupExitGuard();
        setupKeyboardShortcuts();
        setupGuestExpiryHandler();
        ensureReactionUIForExistingMessages();
        if (!replayOnly) {
            connectWebSocket();
        }
    }

    async function hydrateCurrentUser() {
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
            currentUser = null;
        }
        return currentUser;
    }

    function mountReplayDock() {
        if (!replayDock || !sidePanel || !capturedWhite) return;
        if (replayDock.parentElement === sidePanel) return;
        const anchor = spectatorSection || chatSection || null;
        sidePanel.insertBefore(replayDock, anchor);
    }

    function clearReconnectTimer() {
        if (!wsReconnectTimer) return;
        clearTimeout(wsReconnectTimer);
        wsReconnectTimer = null;
    }

    function teardownSocket({ silent = false } = {}) {
        if (!socket) return;
        if (silent) {
            socket.onopen = null;
            socket.onmessage = null;
            socket.onclose = null;
            socket.onerror = null;
        }
        try {
            socket.close();
        } catch {
            // noop
        }
        socket = null;
    }

    function syncPerspectiveFromGame() {
        myColor = null;
        opponentUserId = null;

        if (currentUser) {
            if (game?.white_player?.id === currentUser.id) {
                myColor = 'white';
            } else if (game?.black_player?.id === currentUser.id) {
                myColor = 'black';
            }
        }

        if (currentUser && myColor === 'white') {
            opponentUserId = game?.black_player?.id || null;
        } else if (currentUser && myColor === 'black') {
            opponentUserId = game?.white_player?.id || null;
        }

        isSpectator = !myColor;
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

            await currentUserReadyPromise;

            syncPerspectiveFromGame();

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
            renderBoard({ animatePieceChanges: false });
            renderMoveList();
            updateTurn();
            startTimer();
            schedulePostLoadHydration();
            if (replayOnly && replayGameParamId) {
                await openReplay(replayGameParamId);
            }
        } catch (error) {
            console.error('Failed to load game:', error);
            Toast.error('게임 정보를 불러올 수 없습니다.');
        }
    }

    function scheduleDeferredTask(task, { timeout = 300 } = {}) {
        const run = () => Promise.resolve().then(task).catch(() => {});
        requestAnimationFrame(() => {
            if (typeof window.requestIdleCallback === 'function') {
                window.requestIdleCallback(run, { timeout });
            } else {
                setTimeout(run, 0);
            }
        });
    }

    function schedulePostLoadHydration() {
        if (!game) return;

        if (game.move_count > 0) {
            scheduleDeferredTask(async () => {
                await loadCapturedPieces();
                renderCapturedPieces();
            }, { timeout: 350 });

            scheduleDeferredTask(async () => {
                await loadLastMove();
                renderBoard({ animatePieceChanges: false });
                updateTurn();
                scheduleMoveCacheWarmup();
            }, { timeout: 500 });
        } else {
            renderCapturedPieces();
        }

        if (!isAiRoom) {
            scheduleDeferredTask(() => refreshSpectatorList(), { timeout: 900 });
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
            document.body.classList.remove(...pieceClasses);
            document.body.classList.add(selectedPieceSkinClass || 'skin-piece-classic');
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
        wsReconnectAttempts = 0;

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

        syncPerspectiveFromGame();

        renderPlayerBars();
        renderBoard({ animatePieceChanges: false });
        renderMoveList();
        updateTurn();
        startTimer();
        schedulePostLoadHydration();
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
                setActiveSidePanelTab('game-chat-section');
                resetChatBadge();
            }
        });
        chatCloseBtn?.addEventListener('click', () => {
            chatSection.classList.add('is-collapsed');
            chatSection.classList.remove('is-floating');
            chatFab.classList.remove('is-active');
            setActiveSidePanelTab('game-moves-section');
            syncGameChatFabVisibility();
        });
    }

    function setActiveSidePanelTab(sectionId) {
        activeSidePanelSectionId = sectionId || activeSidePanelSectionId;
        sidePanelTabs.forEach((button) => {
            const isActive = button.dataset.panelTarget === activeSidePanelSectionId;
            button.classList.toggle('is-active', isActive);
            button.setAttribute('aria-pressed', isActive ? 'true' : 'false');
        });
    }

    function focusSidePanelSection(sectionId) {
        if (!sidePanel || !sectionId) return;
        const section = document.getElementById(sectionId);
        if (!section) return;
        const header = section.querySelector('.panel-header');
        if (header && section.classList.contains('is-collapsed')) {
            header.click();
        } else {
            setActiveSidePanelTab(sectionId);
        }
        requestAnimationFrame(() => {
            section.scrollIntoView({
                behavior: 'smooth',
                block: window.innerWidth <= 1360 ? 'start' : 'nearest',
            });
        });
    }

    function setupSidePanelNav() {
        if (!sidePanelTabs.length) return;
        setActiveSidePanelTab(activeSidePanelSectionId);
        sidePanelTabs.forEach((button) => {
            button.addEventListener('click', () => {
                focusSidePanelSection(button.dataset.panelTarget);
            });
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
        const storageKey = 'game_side_panel_sections_v3';
        const defaultStates = {
            'game-actions': false,
            'game-moves-section': window.innerWidth <= 900,
            'captured-section': true,
            'spectator-section': true,
            'game-chat-section': window.innerWidth <= 900,
        };
        const isNarrow = () => window.innerWidth <= 1360;

        const getSavedStates = () => Utils.Storage.get(storageKey, { ...defaultStates }) || { ...defaultStates };
        const saveStates = (states) => Utils.Storage.set(storageKey, states);

        const setCollapsed = (section, collapsed) => {
            const header = section.querySelector('.panel-header');
            section.classList.toggle('is-collapsed', collapsed);
            section.dataset.collapsed = collapsed ? 'true' : 'false';
            if (header) {
                header.dataset.accordionLabel = collapsed ? '닫힘' : '열림';
                header.classList.add('is-clickable');
            }
        };

        const applyLayout = () => {
            const narrow = isNarrow();
            const states = getSavedStates();
            sidePanel.classList.add('is-accordion');
            sections.forEach((section) => {
                const header = section.querySelector('.panel-header');
                if (!header) return;
                const collapsed = Boolean(states[section.id]);
                setCollapsed(section, collapsed);
                header.dataset.accordionMode = narrow ? 'single' : 'multi';
            });
            if (states[activeSidePanelSectionId]) {
                activeSidePanelSectionId = narrow ? 'game-actions' : 'game-moves-section';
            }
            setActiveSidePanelTab(activeSidePanelSectionId);
            syncGameChatFabVisibility();
        };

        sections.forEach((section) => {
            const header = section.querySelector('.panel-header');
            if (!header || header.dataset.accordionBound === '1') return;
            header.dataset.accordionBound = '1';
            header.addEventListener('click', () => {
                const states = getSavedStates();
                const nextCollapsed = !section.classList.contains('is-collapsed');
                if (isNarrow() && !nextCollapsed) {
                    sections.forEach((target) => {
                        if (target.id === section.id) return;
                        states[target.id] = true;
                        setCollapsed(target, true);
                    });
                }
                states[section.id] = nextCollapsed;
                setCollapsed(section, nextCollapsed);
                saveStates(states);
                if (!nextCollapsed) {
                    setActiveSidePanelTab(section.id);
                }
                syncGameChatFabVisibility();
            });
        });

        applyLayout();
        window.addEventListener('resize', Utils.debounce(applyLayout, 120));
    }

    /**
     * 보드 초기 설정
     */
    function setupBoard() {
        boardUI?.setupBoard({
            chessBoard,
            files: FILES,
            ranks: RANKS,
            onSquareClick: (squareName) => {
                clearDrawings();
                handleSquareClick(squareName);
            },
            onSquareKeydown: handleSquareKeydown,
            onRightMouseDown: (event, squareName) => {
                if (event.button === 2) {
                    rightClickStartSq = squareName;
                } else if (event.button === 0) {
                    clearDrawings();
                }
            },
            onRightMouseUp: (event, squareName) => {
                if (event.button === 2 && rightClickStartSq) {
                    const endSq = squareName;
                    if (rightClickStartSq === endSq) {
                        toggleCircle(rightClickStartSq);
                    } else {
                        toggleArrow(rightClickStartSq, endSq);
                    }
                    rightClickStartSq = null;
                    renderDrawings();
                }
            },
            onTouchStart: handleTouchStart,
            onTouchMove: handleTouchMove,
            onTouchEnd: handleTouchEnd,
        });
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
        return boardUI?.getPieceAtSquare({ game, squareName }) || null;
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
        dragPiece = boardUI?.createDragPiece({
            piece,
            x,
            y,
            getPieceSvgMarkup,
            getPieceTypeClass,
        }) || null;
    }

    function removeDragPiece() {
        dragPiece = boardUI?.removeDragPiece(dragPiece) || null;
    }

    function getSquareFromPoint(x, y) {
        return boardUI?.getSquareFromPoint(x, y) || null;
    }

    function highlightDropTarget(squareName) {
        boardUI?.highlightDropTarget({
            chessBoard,
            squareName,
            validMoves,
            toActualSquare,
            getSquare,
        });
    }

    function clearDropHighlight() {
        boardUI?.clearDropHighlight(chessBoard);
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
        statusUI?.renderPlayerBars({
            game,
            myColor,
            opponentBar,
            myBar,
        });
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
    function renderBoard(options = {}) {
        boardUI?.renderBoard({
            game,
            myColor,
            lastMove,
            animatePieceChanges: options.animatePieceChanges === true,
            files: FILES,
            ranks: RANKS,
            getAllSquareElements,
            getSquare,
            createPieceElement,
            onPieceDragStart: handleDragStart,
            updateBoardBrandState,
        });
    }

    /**
     * 기보 렌더링
     */
    function renderMoveList() {
        if (!moveList) return;
        const emptySignature = `empty:${movePage}`;
        if (!game || !game.pgn || game.pgn.trim() === '') {
            if (lastMoveListSignature !== emptySignature) {
                moveList.innerHTML = '<div class="move-list-empty">아직 착수가 없습니다.</div>';
                lastMoveListSignature = emptySignature;
            }
            if (movePageLabel) movePageLabel.textContent = '1';
            movePrevBtn && (movePrevBtn.disabled = true);
            moveNextBtn && (moveNextBtn.disabled = true);
            return;
        }

        const moves = game.pgn.trim().split(/\d+\.\s*/).filter(m => m.trim());
        const totalPages = Math.max(1, Math.ceil(moves.length / movePageSize));
        movePage = Math.min(movePage, totalPages);
        const startIndex = (movePage - 1) * movePageSize;
        const pageMoves = moves.slice(startIndex, startIndex + movePageSize);
        const signature = `${game.pgn}|${movePage}|${startIndex}|${totalPages}`;
        if (lastMoveListSignature !== signature) {
            moveList.innerHTML = GameReplayUI.buildMovePage({
                pageMoves,
                startIndex,
                emptyMessage: '아직 착수가 없습니다.',
            });
            lastMoveListSignature = signature;
        }
        GameReplayUI.bindPager({
            labelEl: movePageLabel,
            prevBtn: movePrevBtn,
            nextBtn: moveNextBtn,
            page: movePage,
            totalPages,
        });
    }

    function updateBoardBrandState() {
        if (!chessBoard || !game) return;
        chessBoard.classList.remove('is-check', 'is-checkmate');

        if (lastMove?.is_checkmate || game.result === 'checkmate_white' || game.result === 'checkmate_black') {
            chessBoard.classList.add('is-checkmate');
            return;
        }

        if (lastMove?.is_check && game.result === 'playing') {
            chessBoard.classList.add('is-check');
        }
    }

    function updateGameStatusStrip() {
        statusUI?.updateStatusStrip({
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
        });
    }

    /**
     * 턴 업데이트
     */
    function updateTurn() {
        if (!game) return;

        isMyTurn = myColor === game.current_turn;
        const turnState = statusUI?.updateTurnPresentation({
            game,
            myColor,
            isMyTurn,
            opponentBar,
            myBar,
            gameActions,
            turnIndicator,
            hasShownStartGuide,
            showStatusModal,
        });
        hasShownStartGuide = turnState?.hasShownStartGuide ?? hasShownStartGuide;

        updateGameStatusStrip();
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
            updateTimerDisplay();
            checkTimeout();
        }, 1000);
    }

    function checkTimeout() {
        if (timeoutHandled || !game || game.result !== 'playing') return;

        const liveTimes = statusUI?.getLiveTimeSnapshot({ game }) || { white: 0, black: 0 };
        const myTime = myColor === 'white' ? liveTimes.white : liveTimes.black;
        const opponentTime = myColor === 'white' ? liveTimes.black : liveTimes.white;

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
        statusUI?.updateTimerDisplay({
            game,
            myColor,
            opponentBar,
            myBar,
        });
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

    function renderDrawings() {
        boardUI?.renderDrawings({
            arrowLayer,
            drawings,
            files: FILES,
            ranks: RANKS,
            isFlipped: myColor === 'black',
        });
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
        window.GameSidePanelsUI?.renderCapturedPieces({
            capturedWhite,
            capturedBlack,
            captured,
            createCapturedPieceMarkup,
        });
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
    function connectWebSocket({ force = false, suppressStatus = false } = {}) {
        if (replayOnly) return;
        clearReconnectTimer();
        if (socket && !force) {
            if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
                return;
            }
        }
        if (socket && force) {
            teardownSocket({ silent: true });
        }
        socket = socketClient?.connect({
            roomId,
            onOpen: () => {
                if (!suppressStatus) {
                    addChatNotice('연결되었습니다.');
                }
                wsReconnectAttempts = 0;
                startHeartbeat();
                refreshSpectatorList();
                if (!suppressStatus) {
                    showStatus('게임 실시간 연결 완료', 'success', 1200);
                }
            },
            onMessage: (data) => {
                handleSocketMessage(data);
            },
            onClose: () => {
                socket = null;
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
                wsReconnectTimer = setTimeout(() => {
                    wsReconnectTimer = null;
                    connectWebSocket({ suppressStatus: true });
                }, delay);
            },
            onError: () => {
                addChatNotice('연결 오류');
            },
        }) || null;
    }

    async function syncLiveGameStateOnResume({ forceReconnect = false } = {}) {
        if (replayOnly || !game?.id) return;
        const now = Date.now();
        if (resumeSyncInFlight || now - lastResumeSyncAt < 900) return;
        lastResumeSyncAt = now;
        resumeSyncInFlight = true;

        try {
            if (forceReconnect || !socket || socket.readyState === WebSocket.CLOSED || socket.readyState === WebSocket.CLOSING) {
                connectWebSocket({ force: forceReconnect, suppressStatus: true });
            } else if (socket.readyState === WebSocket.OPEN) {
                socketClient?.sendJson?.(socket, { action: 'heartbeat' });
            }

            const previousResult = game.result;
            const latestGame = await API.get(`/chess/games/${game.id}/`);
            if (game?.room_type && !latestGame.room_type) {
                latestGame.room_type = game.room_type;
            }
            game = latestGame;

            syncPerspectiveFromGame();

            renderPlayerBars();
            renderBoard({ animatePieceChanges: false });
            renderMoveList();
            updateTurn();

            const syncTasks = [loadCapturedPieces(), refreshSpectatorList()];
            if (game.move_count > 0) {
                syncTasks.push(loadLastMove());
            } else {
                lastMove = null;
            }
            await Promise.allSettled(syncTasks);
            renderCapturedPieces();
            renderBoard({ animatePieceChanges: false });
            updateTurn();

            if (game.result !== 'playing' && previousResult === 'playing') {
                showGameEndModal(game.result);
            }
        } catch (error) {
            console.error('Failed to sync game after resume:', error);
        } finally {
            resumeSyncInFlight = false;
        }
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
                if (data.pgn_append) {
                    game.pgn = appendPgnMove(game.pgn, data.pgn_append);
                } else if (typeof data.pgn === 'string') {
                    game.pgn = data.pgn;
                }
                game.current_turn = data.current_turn;
                game.result = data.result;
                game.white_time_remaining = data.white_time_remaining;
                game.black_time_remaining = data.black_time_remaining;
                game.turn_started_at = data.turn_started_at;
                if (data.last_move) {
                    Utils?.Sounds?.move?.();
                }
                window.GameMovesCache?.invalidate(game.id);
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

                renderBoard({ animatePieceChanges: false });
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
                applySpectatorDelta(data.action, data.user, data.spectator_count);
                break;
            }

            case 'room_update':
                if (typeof data.room?.spectator_count === 'number' && spectatorCount) {
                    spectatorCount.textContent = `${data.room.spectator_count}명`;
                }
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
        ChatUI?.ensureEmojiBar(chatForm, chatInput);
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
        window.GameChatUI?.addMessage({
            chatMessages,
            data,
            currentUserId: currentUser?.id,
            onBadge: handleChatBadge,
            onSound: () => Utils?.Sounds?.chat?.(),
            onReact: ({ messageId, reaction }) => {
                if (!socket || socket.readyState !== WebSocket.OPEN) return;
                socket.send(JSON.stringify({
                    action: 'reaction',
                    message_id: messageId,
                    reaction,
                }));
            },
        });
    }

    async function refreshSpectatorList() {
        if (!spectatorSection || !spectatorList || !spectatorCount || isAiRoom) return;
        try {
            const data = await API.get(`/chess/rooms/${roomId}/spectators/`);
            updateSpectatorState(data?.spectators || []);
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
        window.GameSidePanelsUI?.renderSpectatorList({
            spectatorList,
            users,
        });
    }

    function updateSpectatorState(users) {
        currentSpectators = window.GameSidePanelsUI?.updateSpectatorState({
            spectatorCount,
            spectatorList,
            users,
        }) || [];
    }

    function applySpectatorDelta(action, user, spectatorCountValue) {
        currentSpectators = window.GameSidePanelsUI?.applySpectatorDelta({
            currentSpectators,
            action,
            user,
            spectatorCountValue,
            spectatorCount,
            spectatorList,
        }) || currentSpectators;
    }

    function appendPgnMove(pgn, patch) {
        if (!patch?.san) return pgn || '';
        const base = (pgn || '').trim();
        if (patch.player_color === 'white') {
            return `${base}${base ? ' ' : ''}${patch.move_number}. ${patch.san}`.trim();
        }
        return `${base} ${patch.san}`.trim();
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
        window.GameChatUI?.resetBadge(chatBadge, chatFabBadge);
    }

    /**
     * 채팅 알림 추가
     */
    function addChatNotice(text) {
        window.GameChatUI?.addNotice(chatMessages, text);
    }

    /**
     * 액션 버튼 설정
     */
    function setupActions() {
        const confirmOverlay = document.getElementById('move-confirm-overlay');
        const confirmYes = document.getElementById('move-confirm-yes');
        const confirmNo = document.getElementById('move-confirm-no');

        window.GameActionUI?.bindPrimaryActions({
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
            onConfirmMove: () => {
                if (!pendingConfirmedMove) return;
                sendMove(pendingConfirmedMove.uci, pendingConfirmedMove.promotion);
                pendingConfirmedMove = null;
            },
            onCancelMove: () => {
                pendingConfirmedMove = null;
                renderBoard({ animatePieceChanges: false });
            },
            onAiLeave: () => {
                sendAiResign();
                window.location.href = '/';
            },
            onOfferDraw: () => {
                socket.send(JSON.stringify({ action: 'draw', game_id: game.id }));
                Toast.info('무승부를 제안했습니다.');
            },
            onResign: () => {
                socket.send(JSON.stringify({ action: 'resign', game_id: game.id }));
                showPendingEnd('기권 처리 중...');
            },
            onLeave: () => {
                socket.send(JSON.stringify({ action: 'resign', game_id: game.id }));
                showPendingEnd('나가기 처리 중...');
            },
        });
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
        const historyBtn = document.getElementById('history-btn');
        const lobbyBtn = document.getElementById('lobby-btn');
        window.GameActionUI?.bindModalActions({
            replayOnly,
            isCompetitive,
            isAiRoom,
            rematchBtn,
            rematchModal,
            drawModal,
            historyBtn,
            lobbyBtn,
            onHistory: () => {
                window.location.href = '/history/';
            },
            onLobby: () => {
                window.location.href = replayOnly ? '/history/' : '/';
            },
            onRematch: () => {
                socket.send(JSON.stringify({ action: 'rematch', game_id: game.id }));
                Toast.info('리매치를 요청했습니다.');
            },
            onAcceptDraw: () => {
                socket.send(JSON.stringify({ action: 'draw', game_id: game.id }));
                drawModal.classList.add('hidden');
            },
            onDeclineDraw: () => {
                socket.send(JSON.stringify({ action: 'decline_draw', game_id: game.id }));
                drawModal.classList.add('hidden');
                Toast.info('무승부를 거절했습니다.');
            },
            onAcceptRematch: () => {
                socket.send(JSON.stringify({ action: 'rematch', game_id: game.id }));
                rematchModal?.classList.add('hidden');
            },
            onDeclineRematch: () => {
                socket.send(JSON.stringify({ action: 'decline_rematch', game_id: game.id }));
                rematchModal?.classList.add('hidden');
            },
        });
    }

    function setupMovePagination() {
        GameReplayUI.bindPager({
            prevBtn: movePrevBtn,
            nextBtn: moveNextBtn,
            onPrev: () => {
                if (movePage > 1) {
                    movePage -= 1;
                    renderMoveList();
                }
            },
            onNext: () => {
                movePage += 1;
                renderMoveList();
            },
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
            const last = await window.GameMovesCache?.loadLast(game.id, game.move_count);
            if (last) {
                lastMove = { from: last.from_square, to: last.to_square };
            }
        } catch (error) {
            console.error('Failed to load last move:', error);
        }
    }

    function scheduleMoveCacheWarmup() {
        if (!game?.id || !game?.move_count) return;
        if (!replayOnly && game.result === 'playing') return;
        const run = () => {
            const promise = window.GameMovesCache?.loadPage(game.id, { limit: 300, offset: 0 });
            promise?.catch(() => {});
        };
        if (typeof window.requestIdleCallback === 'function') {
            window.requestIdleCallback(run, { timeout: 1500 });
        } else {
            setTimeout(run, 250);
        }
    }

    function setupReplayControls() {
        GameReplayUI.bindReplayControls({
            replayBtn,
            replayPrev,
            replayNext,
            replayPlay,
            replayClose,
            replayPrevDock,
            replayNextDock,
            replayPlayDock,
            replayCloseDock,
            onOpen: () => openReplay(),
            onPrev: () => stepReplay(-1),
            onNext: () => stepReplay(1),
            onPlayPause: () => toggleReplay(),
            onClose: () => closeReplay(),
        });

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
            replayMoves = await window.GameMovesCache?.loadPage(replayGameId, { limit: 200, offset: 0 }) || [];
        } catch (error) {
            try {
                const history = await API.get('/chess/games/history/', { limit: 20, no_count: 1 });
                const matches = history.results || [];
                const fallback = matches.find(item => item.room_id === roomId);
                if (fallback?.id) {
                    replayMoves = await window.GameMovesCache?.loadPage(fallback.id, { limit: 200, offset: 0 }) || [];
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
            renderBoard({ animatePieceChanges: false });
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
        window.GameReplayUI?.applyReplayPosition({
            replayMoves,
            replayIndex,
            replayStatus,
            replayStatusDock,
            replayPrev,
            replayNext,
            replayPlay,
            replayPrevDock,
            replayNextDock,
            replayPlayDock,
            onApplyFen: ({ fen, lastMove: nextLastMove }) => {
                game.fen = fen;
                lastMove = nextLastMove;
                renderBoard({ animatePieceChanges: false });
            },
        });
    }

    /**
     * 게임 종료 모달 표시
     */
    function showGameEndModal(result) {
        if (timerInterval) {
            clearInterval(timerInterval);
        }
        pendingEnd = false;
        gameEndModal.classList.remove('outcome-win', 'outcome-loss', 'outcome-draw');

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

        if (outcome === 'win') {
            gameEndModal.classList.add('outcome-win');
        } else if (outcome === 'loss') {
            gameEndModal.classList.add('outcome-loss');
        } else if (outcome === 'draw') {
            gameEndModal.classList.add('outcome-draw');
        }

        iconEl.textContent = icon;
        titleEl.textContent = title;
        resultEl.textContent = resultText;

        loadGameSummary();

        gameEndModal.classList.remove('hidden');
        gameEndModal.style.display = 'flex';
        updateGameStatusStrip();
        loadGameAnalysis();
    }

    async function loadGameAnalysis() {
        if (!analysisCanvas) return;
        const analysisLoading = document.getElementById('analysis-loading');
        const analysisContent = document.getElementById('analysis-content');
        try {
            const moves = await window.GameMovesCache?.loadPage(game.id, { limit: 300, offset: 0 }) || [];
            window.GameAnalysisUI?.render({
                canvas: analysisCanvas,
                summaryEl: analysisSummary,
                moves,
            });
            analysisLoading?.classList.add('hidden');
            analysisContent?.classList.remove('hidden');
        } catch (error) {
            if (analysisLoading) {
                analysisLoading.textContent = '분석을 불러오지 못했습니다.';
            }
        }
    }

    function createPieceElement(piece) {
        const pieceEl = document.createElement('div');
        const isWhite = piece === piece.toUpperCase();
        pieceEl.className = `piece ${isWhite ? 'white' : 'black'}`;
        pieceEl.classList.add(getPieceTypeClass(piece));
        pieceEl.dataset.piece = piece;
        pieceEl.draggable = true;
        pieceEl.innerHTML = getPieceSvgMarkup(piece);
        return pieceEl;
    }

    function createCapturedPieceMarkup(piece) {
        const isWhite = piece === piece.toUpperCase();
        const glyph = getPieceSvgMarkup(piece);
        return `<span class="captured-piece ${isWhite ? 'white' : 'black'} ${getPieceTypeClass(piece)}">${glyph}</span>`;
    }

    function getPieceTypeClass(piece) {
        const type = String(piece || '').toLowerCase();
        if (!['p', 'r', 'n', 'b', 'q', 'k'].includes(type)) {
            return 'piece-type-p';
        }
        return `piece-type-${type}`;
    }

    function getPieceSkinVariant() {
        const cls = String(selectedPieceSkinClass || 'skin-piece-classic');
        if (cls.includes('pixel')) return 'pixel';
        if (cls.includes('modern')) return 'modern';
        if (cls.includes('3d')) return '3d';
        if (cls.includes('glass')) return 'glass';
        if (cls.includes('rune')) return 'rune';
        return 'classic';
    }

    function getPieceShapeSet(variant) {
        const classic = {
            p: `
                <circle cx="32" cy="14.6" r="5.2"></circle>
                <rect x="29.8" y="19.8" width="4.4" height="4.5" rx="1.6"></rect>
                <path d="M25.4 34.2c0-5.9 3-9.8 6.6-9.8s6.6 3.9 6.6 9.8v2.6H25.4z"></path>
                <rect x="22.4" y="36.4" width="19.2" height="8.4" rx="3.9"></rect>
                <rect x="18.7" y="46.8" width="26.6" height="2.7" rx="1.3"></rect>
                <rect x="17.1" y="49.8" width="29.8" height="3.3" rx="1.6"></rect>
            `,
            r: `
                <rect x="17.2" y="12.8" width="5.8" height="8" rx="1"></rect>
                <rect x="29.1" y="12.8" width="5.8" height="8" rx="1"></rect>
                <rect x="41" y="12.8" width="5.8" height="8" rx="1"></rect>
                <rect x="17.2" y="21.1" width="29.6" height="4.9" rx="1.7"></rect>
                <rect x="21.7" y="27.1" width="20.6" height="17.3" rx="2.3"></rect>
                <rect x="18.7" y="46.8" width="26.6" height="2.7" rx="1.3"></rect>
                <rect x="17.1" y="49.8" width="29.8" height="3.3" rx="1.6"></rect>
            `,
            n: `
                <path d="M17.1 49.8h29.8v3.3H17.1z"></path>
                <path d="M18.7 46.8h26.6v2.7H18.7z"></path>
                <path d="M21.6 44.1c7.1-.8 11.7-3.9 13.7-9.4 1.1-3.2 1-6.4-.2-9.8
                -2.2.7-4.2.5-5.9-.8.2-4.3 2.8-7.8 7.7-10.4l7.5 4.8-1.7 6.7c3 2 4.8 5 5.3 9-1.1 6.1-6.2 9.3-15.1 9.9z"></path>
                <circle cx="35.9" cy="22.6" r="1.7" class="piece-eye"></circle>
            `,
            b: `
                <ellipse cx="32" cy="16.2" rx="5.8" ry="7.6"></ellipse>
                <path d="M30.8 12.7h2.4l-1.2 7h-1z"></path>
                <rect x="30.9" y="22.4" width="2.2" height="4.3" rx="1"></rect>
                <path d="M25.4 34c0-6.6 3-10.7 6.6-10.7s6.6 4.1 6.6 10.7v2.7H25.4z"></path>
                <rect x="22.4" y="36.3" width="19.2" height="8.6" rx="4"></rect>
                <rect x="18.7" y="46.8" width="26.6" height="2.7" rx="1.3"></rect>
                <rect x="17.1" y="49.8" width="29.8" height="3.3" rx="1.6"></rect>
            `,
            q: `
                <circle cx="20.1" cy="16.1" r="2.3"></circle>
                <circle cx="27.8" cy="13.1" r="2.3"></circle>
                <circle cx="36.2" cy="13.1" r="2.3"></circle>
                <circle cx="43.9" cy="16.1" r="2.3"></circle>
                <path d="M20.3 22.1l4.7 13.3h14l4.7-13.3-5.8 4.4-5.9-6-5.9 6z"></path>
                <rect x="22.4" y="36.2" width="19.2" height="8.5" rx="3.9"></rect>
                <rect x="18.7" y="46.8" width="26.6" height="2.7" rx="1.3"></rect>
                <rect x="17.1" y="49.8" width="29.8" height="3.3" rx="1.6"></rect>
            `,
            k: `
                <rect x="31" y="8.1" width="2" height="8.8" rx="1"></rect>
                <rect x="26.8" y="11.3" width="10.4" height="2.8" rx="1.2"></rect>
                <path d="M25.4 33.8c0-7.2 3-11.2 6.6-11.2s6.6 4 6.6 11.2v2.6H25.4z"></path>
                <rect x="22.4" y="36.3" width="19.2" height="8.6" rx="4"></rect>
                <rect x="18.7" y="46.8" width="26.6" height="2.7" rx="1.3"></rect>
                <rect x="17.1" y="49.8" width="29.8" height="3.3" rx="1.6"></rect>
            `,
        };
        const pixel = {
            p: `<rect x="28" y="12" width="8" height="8"></rect><rect x="28" y="20" width="8" height="4"></rect><rect x="25" y="24" width="14" height="10"></rect><rect x="22" y="35" width="20" height="10"></rect><rect x="19" y="47" width="26" height="3"></rect><rect x="17" y="50" width="30" height="3"></rect>`,
            r: `<rect x="17" y="13" width="6" height="8"></rect><rect x="29" y="13" width="6" height="8"></rect><rect x="41" y="13" width="6" height="8"></rect><rect x="17" y="21" width="30" height="5"></rect><rect x="22" y="27" width="20" height="17"></rect><rect x="19" y="47" width="26" height="3"></rect><rect x="17" y="50" width="30" height="3"></rect>`,
            n: `<path d="M17 50h30v3H17zM19 47h26v3H19zM22 44h13l9-9-2-7 2-6-4-4-7 3-4 6 2 3-6 5z"></path><rect x="36" y="23" width="3" height="3" class="piece-eye"></rect>`,
            b: `<rect x="28" y="10" width="8" height="8"></rect><rect x="31" y="18" width="2" height="5"></rect><rect x="25" y="23" width="14" height="11"></rect><rect x="22" y="35" width="20" height="10"></rect><rect x="19" y="47" width="26" height="3"></rect><rect x="17" y="50" width="30" height="3"></rect>`,
            q: `<rect x="20" y="15" width="4" height="4"></rect><rect x="27" y="12" width="4" height="4"></rect><rect x="33" y="12" width="4" height="4"></rect><rect x="40" y="15" width="4" height="4"></rect><path d="M20 21h24l-4 14H24z"></path><rect x="22" y="36" width="20" height="9"></rect><rect x="19" y="47" width="26" height="3"></rect><rect x="17" y="50" width="30" height="3"></rect>`,
            k: `<rect x="31" y="8" width="2" height="8"></rect><rect x="27" y="11" width="10" height="3"></rect><rect x="25" y="23" width="14" height="11"></rect><rect x="22" y="35" width="20" height="10"></rect><rect x="19" y="47" width="26" height="3"></rect><rect x="17" y="50" width="30" height="3"></rect>`,
        };
        const modern = classic;
        const rune = classic;
        const map = { classic, pixel, modern, rune };
        return map[variant] || classic;
    }

    function getPieceSvgMarkup(piece) {
        const variant = getPieceSkinVariant();
        const cacheKey = `${variant}:${piece}`;
        const cachedMarkup = pieceSvgMarkupCache.get(cacheKey);
        if (cachedMarkup) {
            return cachedMarkup;
        }
        const type = String(piece || '').toLowerCase();
        const isWhite = piece === piece.toUpperCase();
        const whiteGlyphMap = { p: '♙', r: '♖', n: '♘', b: '♗', q: '♕', k: '♔' };
        const blackGlyphMap = { p: '♟', r: '♜', n: '♞', b: '♝', q: '♛', k: '♚' };
        const glyph = (isWhite ? whiteGlyphMap : blackGlyphMap)[type] || (isWhite ? '♙' : '♟');
        const shadowLayer = variant === '3d'
            ? `<text class="piece-shadow-glyph" x="33.2" y="47.2">${glyph}</text>`
            : '';
        const accentLayer = variant === 'glass'
            ? `<g class="piece-accent"><ellipse cx="32" cy="23" rx="11" ry="5.8"></ellipse><path d="M20 34h24"></path></g>`
            : '';
        const markup = `
            <svg class="piece-svg variant-${variant}" viewBox="0 0 64 64" aria-hidden="true" focusable="false">
                ${shadowLayer}
                <text class="piece-glyph" x="32" y="45.5">${glyph}</text>
                ${accentLayer}
            </svg>
        `;
        pieceSvgMarkupCache.set(cacheKey, markup);
        return markup;
    }

    function ensureReactionUIForExistingMessages() {
        if (!chatMessages) return;
        const messageEls = chatMessages.querySelectorAll('.chat-message .chat-content');
        messageEls.forEach((contentEl) => {
            ChatReactions?.ensureReactionBar(contentEl);
            ChatReactions?.bindReactionButtons(contentEl.closest('.chat-message'), {
                onReact: ({ messageId, reaction, button }) => {
                    if (!socket || socket.readyState !== WebSocket.OPEN || !messageId || !reaction) return;
                    button?.classList.toggle('active');
                    socket.send(JSON.stringify({
                        action: 'reaction',
                        message_id: messageId,
                        reaction,
                    }));
                },
            });
        });
    }

    function applyReactionUpdate(messageId, reactions, myReactions) {
        if (!chatMessages || !messageId) return;
        const target = chatMessages.querySelector(`.chat-message[data-message-id="${String(messageId)}"]`);
        if (!target) return;
        ChatReactions?.applyReactionUpdate(target, reactions, myReactions);
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

    async function loadGameSummary() {
        if (!game) return;
        const ratingEl = document.getElementById('game-end-rating');
        if (gameEndStats) {
            gameEndStats.innerHTML = '';
        }
        if (ratingEl) {
            ratingEl.textContent = '';
        }
        try {
            const summary = await API.get(`/chess/games/${game.id}/summary/`);
            window.GameEndSummary?.render(summary, {
                statsRoot: gameEndStats,
                ratingRoot: ratingEl,
            });
        } catch {
            // 요약 로드 실패 시 무시
        }
    }

    function showPendingEnd(message) {
        if (pendingEnd) return;
        pendingEnd = true;
        gameEndModal.classList.remove('outcome-win', 'outcome-loss', 'outcome-draw');

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
        window.GameActionUI?.showDrawOfferModal(drawModal);
    }

    /**
     * 리매치 제안 모달
     */
    function showRematchOfferModal() {
        window.GameActionUI?.showRematchOfferModal(rematchModal);
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
        clearReconnectTimer();
        stopHeartbeat();
        if (timerInterval) clearInterval(timerInterval);
        if (isAiRoom) {
            sendAiResign();
        }
        teardownSocket({ silent: true });
    });

    window.addEventListener('pagehide', (event) => {
        clearReconnectTimer();
        stopHeartbeat();
        if (event.persisted) {
            teardownSocket({ silent: true });
        }
        if (isAiRoom) {
            sendAiResign();
        }
    });

    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            stopHeartbeat();
            return;
        }
        syncLiveGameStateOnResume({ forceReconnect: true });
    });

    window.addEventListener('pageshow', () => {
        syncLiveGameStateOnResume({ forceReconnect: true });
    });

    window.addEventListener('focus', () => {
        syncLiveGameStateOnResume();
    });

    // 화면 회전 시 보드 크기 재계산
    window.addEventListener('orientationchange', () => {
        setTimeout(() => {
            syncGameChatFabVisibility();
        }, 100);
    });

    window.addEventListener('resize', Utils.debounce(() => {
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
