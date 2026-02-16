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
    const PIECES = {
        'K': '♔', 'Q': '♕', 'R': '♖', 'B': '♗', 'N': '♘', 'P': '♙',
        'k': '♚', 'q': '♛', 'r': '♜', 'b': '♝', 'n': '♞', 'p': '♟'
    };

    const FILES = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'];
    const RANKS = ['8', '7', '6', '5', '4', '3', '2', '1'];

    // DOM Elements
    const chessBoard = document.getElementById('chess-board');
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
    const chatMessages = document.getElementById('chat-messages');
    const chatForm = document.getElementById('chat-form');
    const chatInput = document.getElementById('chat-input');
    const chatSection = document.getElementById('game-chat-section');
    const mobileTabbar = document.getElementById('mobile-tabbar');
    const chatBadge = document.getElementById('chat-badge');
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
    let notificationSocket = null;
    let isSuspended = false;
    let myColor = null; // 'white' or 'black'
    let isMyTurn = false;
    let selectedSquare = null;
    let selectedDisplaySquare = null;
    let validMoves = [];
    let pendingPromotion = null;
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
    let isAiRoom = false;
    let movePage = 1;
    const movePageSize = 6;
    let aiExitTriggered = false;
    let wsReconnectAttempts = 0;
    const WS_MAX_RECONNECT_ATTEMPTS = 10;
    const WS_BASE_RECONNECT_DELAY = 1000;
    let ratingPollAttempts = 0;
    const RATING_POLL_MAX_ATTEMPTS = 30;

    // Init
    init();

    async function init() {
        if (!roomId) {
            Toast.error('잘못된 접근입니다.');
            window.location.href = '/';
            return;
        }

        guideEnabled = Utils.Storage.get('guide_enabled', true);
        setupGuideToggle();

        try {
            currentUser = await API.get('/accounts/me/');
            if (currentUser?.is_muted) {
                setChatMutedState(true, currentUser.mute_reason || '');
            }
            if (currentUser?.is_suspended) {
                setSuspendedState(true, currentUser.suspension_reason || '');
            }
            connectNotificationSocket();
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
        setupReport();
        setupChatToggle();
        setupExitGuard();
        if (!replayOnly) {
            connectWebSocket();
        }
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
                document.querySelector('.mobile-tab[data-tab="chat"]')?.classList.add('hidden');
            }

            renderPlayerBars();
            renderBoard();
            renderMoveList();
            await loadCapturedPieces();
            renderCapturedPieces();
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
        chatFab.addEventListener('click', () => {
            const willOpen = chatSection.classList.contains('is-collapsed');
            chatSection.classList.toggle('is-collapsed');
            chatSection.classList.toggle('is-floating', willOpen);
            chatFab.classList.toggle('is-active', willOpen);
        });
    }

    /**
     * 보드 초기 설정
     */
    function setupBoard() {
        // 빈 보드 생성
        chessBoard.innerHTML = '';
        for (let rank = 0; rank < 8; rank++) {
            for (let file = 0; file < 8; file++) {
                const square = document.createElement('div');
                const isLight = (rank + file) % 2 === 0;
                const squareName = FILES[file] + RANKS[rank];

                square.className = `square ${isLight ? 'light' : 'dark'}`;
                square.dataset.square = squareName;

                square.addEventListener('click', () => handleSquareClick(squareName));

                chessBoard.appendChild(square);
            }
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
        opponentBar.innerHTML = `
            <div class="player-bar-info">
                <div class="avatar avatar-sm">
                    ${topPlayer?.avatar_url
                        ? `<img src="${Utils.escapeHtml(topPlayer.avatar_url)}" alt="">`
                        : '<span class="avatar-placeholder">?</span>'}
                    <span class="tier-badge" title="${Utils.escapeHtml(topTier)}">${Utils.getTierIcon(topTier)}</span>
                </div>
                <div class="player-bar-details">
                    <span class="player-bar-name">${Utils.escapeHtml(topPlayer?.nickname || '상대')}</span>
                    <span class="player-bar-rating">${topPlayer?.rating || '--'}</span>
                </div>
            </div>
            <div class="player-bar-timer" id="opponent-timer">--:--</div>
        `;

        // 나 (아래)
        myBar.innerHTML = `
            <div class="player-bar-info">
                <div class="avatar avatar-sm">
                    ${bottomPlayer?.avatar_url
                        ? `<img src="${Utils.escapeHtml(bottomPlayer.avatar_url)}" alt="">`
                        : '<span class="avatar-placeholder">?</span>'}
                    <span class="tier-badge" title="${Utils.escapeHtml(bottomTier)}">${Utils.getTierIcon(bottomTier)}</span>
                </div>
                <div class="player-bar-details">
                    <span class="player-bar-name">${Utils.escapeHtml(bottomPlayer?.nickname || '나')}</span>
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

        // 모든 칸 초기화 (캐시 사용)
        for (const sq of getAllSquareElements()) {
            sq.innerHTML = '';
            sq.classList.remove('selected', 'valid-move', 'valid-capture', 'last-move', 'check');
        }

        // 기물 배치
        for (let rank = 0; rank < 8; rank++) {
            for (let file = 0; file < 8; file++) {
                const piece = position[rank][file];
                if (piece) {
                    const displayRank = isFlipped ? 7 - rank : rank;
                    const displayFile = isFlipped ? 7 - file : file;
                    const squareName = FILES[displayFile] + RANKS[displayRank];
                    const squareEl = getSquare(squareName);

                    if (squareEl) {
                        const pieceEl = document.createElement('span');
                        const isWhite = piece === piece.toUpperCase();
                        pieceEl.className = `piece ${isWhite ? 'white' : 'black'}`;
                        pieceEl.textContent = PIECES[piece];
                        pieceEl.draggable = true;
                        pieceEl.addEventListener('dragstart', (e) => handleDragStart(e, squareName));
                        squareEl.appendChild(pieceEl);
                    }
                }
            }
        }

        applyLastMoveHighlight();

        // 마지막 수 하이라이트
        if (game.pgn) {
            // PGN에서 마지막 수 추출 (간단한 구현)
            // 실제로는 서버에서 last_move 정보를 받아야 함
        }
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
    function startTimer() {
        if (timerInterval) {
            clearInterval(timerInterval);
        }

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
        }, 1000);
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

    async function loadCapturedPieces() {
        try {
            const data = await API.get(`/chess/games/${game.id}/captured/`);
            captured = {
                white: (data.white || []).map(letter => pieceSymbolFromLetter(letter, 'white')).filter(Boolean),
                black: (data.black || []).map(letter => pieceSymbolFromLetter(letter, 'black')).filter(Boolean),
            };
        } catch (error) {
            console.error('Failed to load captured pieces:', error);
        }
    }

    function updateCapturedFromMove(data) {
        const capture = data?.last_move?.capture;
        if (!capture) return;
        const symbol = pieceSymbolFromLetter(capture.piece, capture.color);
        if (!symbol) return;
        captured[capture.color].push(symbol);
    }

    function renderCapturedPieces() {
        if (!capturedWhite || !capturedBlack) return;
        capturedWhite.innerHTML = captured.white
            .map(symbol => `<span class="captured-piece white">${symbol}</span>`)
            .join('');
        capturedBlack.innerHTML = captured.black
            .map(symbol => `<span class="captured-piece black">${symbol}</span>`)
            .join('');
    }

    function pieceSymbolFromLetter(letter, color) {
        const map = {
            K: color === 'white' ? '♔' : '♚',
            Q: color === 'white' ? '♕' : '♛',
            R: color === 'white' ? '♖' : '♜',
            B: color === 'white' ? '♗' : '♝',
            N: color === 'white' ? '♘' : '♞',
            P: color === 'white' ? '♙' : '♟',
        };
        return map[letter] || null;
    }

    /**
     * 수 두기
     */
    function makeMove(from, to) {
        const uci = from + to;

        // 프로모션 체크
        const fromEl = getSquare(toDisplaySquare(from));
        const piece = fromEl?.querySelector('.piece');

        if (piece) {
            const isPawn = piece.textContent === '♙' || piece.textContent === '♟';
            const isPromotion = isPawn && (to[1] === '8' || to[1] === '1');

            if (isPromotion) {
                pendingPromotion = { from, to };
                showPromotionModal();
                return;
            }
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
            btn.onclick = () => {
                const piece = btn.dataset.piece;
                const uci = pendingPromotion.from + pendingPromotion.to;
                sendMove(uci, piece);
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
        const wsUrl = `${protocol}//${window.location.host}/ws/chess/${roomId}/`;

        socket = new WebSocket(wsUrl);

        socket.onopen = () => {
            addChatNotice('연결되었습니다.');
            wsReconnectAttempts = 0;
            startHeartbeat();
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
                return;
            }
            wsReconnectAttempts += 1;
            const delay = Math.min(WS_BASE_RECONNECT_DELAY * Math.pow(2, wsReconnectAttempts - 1), 30000);
            addChatNotice(`${Math.round(delay / 1000)}초 후 재연결 시도 (${wsReconnectAttempts}/${WS_MAX_RECONNECT_ATTEMPTS})...`);
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

            case 'spectator_event': {
                const nickname = data.user?.nickname || '관전자';
                const isSelf = currentUser && data.user?.id === currentUser.id;
                if (!isSelf) {
                    const actionText = data.action === 'leave' ? '퇴장' : '입장';
                    Toast.info(`${nickname}님이 관전에 ${actionText}했습니다.`);
                    addChatNotice(`${nickname}님이 관전에 ${actionText}했습니다.`);
                }
                break;
            }

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

    /**
     * 채팅 설정
     */
    function setupChat() {
        if (isAiRoom) {
            chatSection?.classList.add('is-hidden');
            return;
        }
        chatForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const message = chatInput.value.trim();
            if (!message || !socket) return;

            const action = myColor ? 'chat' : 'spectator_chat';
            socket.send(JSON.stringify({ action, message }));
            chatInput.value = '';
        });
    }

    function connectNotificationSocket() {
        if (notificationSocket || !currentUser) return;
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/notifications/`;
        notificationSocket = new WebSocket(wsUrl);
        notificationSocket.onmessage = function(e) {
            const data = JSON.parse(e.data);
            if (data.type === 'chat_mute') {
                setChatMutedState(true, data.payload?.reason || '');
                Toast.error(data.message || '채팅이 제한되었습니다.');
            } else if (data.type === 'account_suspended') {
                setSuspendedState(true, data.payload?.reason || '');
                Toast.error(data.message || '계정이 정지되었습니다.');
            } else if (data.type === 'chat_unmute') {
                setChatMutedState(false);
                Toast.success(data.message || '채팅 제한이 해제되었습니다.');
            } else if (data.type === 'account_unsuspended') {
                setSuspendedState(false);
                Toast.success(data.message || '계정 정지가 해제되었습니다.');
            }
        };
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
        if (suspended) {
            drawBtn && (drawBtn.disabled = true);
            resignBtn && (resignBtn.disabled = true);
            leaveBtn && (leaveBtn.disabled = true);
            rematchBtn && (rematchBtn.disabled = true);
            if (reason) {
                addChatNotice(`계정 정지됨: ${reason}`);
            } else {
                addChatNotice('계정이 정지되었습니다.');
            }
        } else {
            drawBtn && (drawBtn.disabled = false);
            resignBtn && (resignBtn.disabled = false);
            leaveBtn && (leaveBtn.disabled = false);
            rematchBtn && (rematchBtn.disabled = false);
        }
    }

    /**
     * 채팅 메시지 추가
     */
    function addChatMessage(data) {
        const isMine = currentUser && data.user_id === currentUser.id;
        const avatar = !isMine
            ? (data.avatar_url
                ? `<img src="${Utils.escapeHtml(data.avatar_url)}" alt="">`
                : '<span class="avatar-placeholder">?</span>')
            : '';
        const messageEl = document.createElement('div');
        messageEl.className = `chat-message ${isMine ? 'mine' : 'others'}`;
        messageEl.innerHTML = `
            ${!isMine ? `<div class="chat-avatar">${avatar}</div>` : ''}
            <div class="chat-content">
                <span class="chat-nickname">${Utils.escapeHtml(data.nickname)}</span>
                <div class="chat-bubble">${Utils.escapeHtml(data.message)}</div>
            </div>
        `;
        chatMessages.appendChild(messageEl);
        chatMessages.scrollTop = chatMessages.scrollHeight;
        if (!isMine) Utils?.Sounds?.chat?.();
        handleChatBadge(data);
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
            });
        });
        isChatOpen = false;
        if (chatSection) chatSection.classList.add('is-hidden');
        if (moveSection) moveSection.classList.remove('is-hidden');
    }

    function handleChatBadge(data) {
        if (isChatOpen || !chatSection?.classList.contains('is-hidden')) {
            resetChatBadge();
            return;
        }
        if (currentUser && data.user_id === currentUser.id) return;
        chatUnread += 1;
        if (chatBadge) {
            chatBadge.textContent = chatUnread;
            chatBadge.classList.remove('hidden');
        }
    }

    function resetChatBadge() {
        chatUnread = 0;
        if (chatBadge) {
            chatBadge.textContent = '0';
            chatBadge.classList.add('hidden');
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
        if (!logo) return;
        logo.addEventListener('click', async (e) => {
            e.preventDefault();
            const leave = await Modal.confirm('게임을 나가시겠습니까?', {
                title: '게임 나가기',
                confirmText: '나가기',
                danger: true
            });
            if (leave) {
                window.location.href = '/';
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
        replayMode = window.innerWidth <= 768 && replayDock ? 'dock' : 'modal';
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

        gameEndModal.classList.remove('hidden');
        gameEndModal.style.display = 'flex';
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

    function sendAiResign() {
        if (aiExitTriggered) return;
        if (!socket || !game || !myColor) return;
        if (socket.readyState !== WebSocket.OPEN) return;
        aiExitTriggered = true;
        socket.send(JSON.stringify({ action: 'resign', game_id: game.id }));
    }
})();
