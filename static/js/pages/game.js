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
    const chatMessages = document.getElementById('chat-messages');
    const chatForm = document.getElementById('chat-form');
    const chatInput = document.getElementById('chat-input');
    const gameActions = document.getElementById('game-actions');
    const drawBtn = document.getElementById('draw-btn');
    const resignBtn = document.getElementById('resign-btn');
    const leaveBtn = document.getElementById('leave-btn');

    // Modals
    const gameEndModal = document.getElementById('game-end-modal');
    const drawModal = document.getElementById('draw-modal');
    const rematchModal = document.getElementById('rematch-modal');
    const promotionModal = document.getElementById('promotion-modal');

    // State
    const roomId = Utils.getPathParam(/\/games\/(\d+)/);
    let game = null;
    let currentUser = null;
    let socket = null;
    let myColor = null; // 'white' or 'black'
    let isMyTurn = false;
    let selectedSquare = null;
    let validMoves = [];
    let pendingPromotion = null;
    let timerInterval = null;
    let heartbeatInterval = null;

    // Init
    init();

    async function init() {
        if (!roomId) {
            Toast.error('잘못된 접근입니다.');
            window.location.href = '/';
            return;
        }

        try {
            currentUser = await API.get('/accounts/me/');
        } catch {
            // 관전자로 처리
            currentUser = null;
        }

        await loadGame();
        setupBoard();
        setupChat();
        setupActions();
        setupModals();
        setupExitGuard();
        connectWebSocket();
    }

    /**
     * 게임 정보 로드
     */
    async function loadGame() {
        try {
            // 방에서 현재 게임 가져오기
            const room = await API.get(`/chess/rooms/${roomId}/`);

            if (room.status !== 'playing') {
                Toast.error('진행 중인 게임이 없습니다.');
                window.location.href = `/rooms/${roomId}/`;
                return;
            }

            let gameId = room.current_game_id;
            if (!gameId) {
                const history = await API.get(`/chess/games/history/`, { result: 'playing', limit: 20 });
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

            // 내 색상 결정
            if (currentUser) {
                if (game.white_player?.id === currentUser.id) {
                    myColor = 'white';
                } else if (game.black_player?.id === currentUser.id) {
                    myColor = 'black';
                }
            }

            renderPlayerBars();
            renderBoard();
            renderMoveList();
            updateTurn();
            startTimer();
        } catch (error) {
            console.error('Failed to load game:', error);
            Toast.error('게임 정보를 불러올 수 없습니다.');
        }
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
        opponentBar.innerHTML = `
            <div class="player-bar-info">
                <div class="avatar avatar-sm">
                    ${topPlayer?.avatar_url
                        ? `<img src="${Utils.escapeHtml(topPlayer.avatar_url)}" alt="">`
                        : '<span class="avatar-placeholder">?</span>'}
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
     * 보드 렌더링
     */
    function renderBoard() {
        if (!game || !game.fen) return;

        const fen = game.fen;
        const position = parseFEN(fen);
        const isFlipped = myColor === 'black';

        // 모든 칸 초기화
        document.querySelectorAll('.square').forEach(sq => {
            sq.innerHTML = '';
            sq.classList.remove('selected', 'valid-move', 'valid-capture', 'last-move', 'check');
        });

        // 기물 배치
        for (let rank = 0; rank < 8; rank++) {
            for (let file = 0; file < 8; file++) {
                const piece = position[rank][file];
                if (piece) {
                    const displayRank = isFlipped ? 7 - rank : rank;
                    const displayFile = isFlipped ? 7 - file : file;
                    const squareName = FILES[displayFile] + RANKS[displayRank];
                    const squareEl = document.querySelector(`[data-square="${squareName}"]`);

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
            return;
        }

        // PGN 파싱 (간단한 구현)
        const moves = game.pgn.trim().split(/\d+\.\s*/).filter(m => m.trim());
        let html = '';
        let moveNum = 1;

        for (const movePair of moves) {
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
        moveList.scrollTop = moveList.scrollHeight;
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
    function handleSquareClick(squareName) {
        if (!isMyTurn || !myColor) return;

        if (selectedSquare) {
            // 이동 시도
            if (validMoves.includes(squareName)) {
                makeMove(selectedSquare, squareName);
            }
            clearSelection();
        } else {
            // 기물 선택
            const squareEl = document.querySelector(`[data-square="${squareName}"]`);
            const piece = squareEl?.querySelector('.piece');

            if (piece) {
                const isWhitePiece = piece.classList.contains('white');
                const isMyPiece = (myColor === 'white' && isWhitePiece) || (myColor === 'black' && !isWhitePiece);

                if (isMyPiece) {
                    selectSquare(squareName);
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
    function selectSquare(squareName) {
        clearSelection();
        selectedSquare = squareName;

        const squareEl = document.querySelector(`[data-square="${squareName}"]`);
        squareEl?.classList.add('selected');

        // 유효한 수 계산 (간단한 구현 - 실제로는 서버에서 받아야 함)
        // 여기서는 모든 칸을 유효한 이동으로 표시 (서버에서 검증)
        validMoves = getAllSquares();

        validMoves.forEach(sq => {
            const el = document.querySelector(`[data-square="${sq}"]`);
            if (el && sq !== squareName) {
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
        validMoves = [];

        document.querySelectorAll('.square').forEach(sq => {
            sq.classList.remove('selected', 'valid-move', 'valid-capture');
        });
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

    /**
     * 수 두기
     */
    function makeMove(from, to) {
        const uci = from + to;

        // 프로모션 체크
        const fromEl = document.querySelector(`[data-square="${from}"]`);
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
            startHeartbeat();
        };

        socket.onmessage = (e) => {
            const data = JSON.parse(e.data);
            handleSocketMessage(data);
        };

        socket.onclose = () => {
            addChatNotice('연결이 끊어졌습니다.');
            stopHeartbeat();
            setTimeout(connectWebSocket, 3000);
        };

        socket.onerror = () => {
            addChatNotice('연결 오류');
        };
    }

    /**
     * WebSocket 메시지 처리
     */
    function handleSocketMessage(data) {
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

                renderBoard();
                renderMoveList();
                updateTurn();
                clearSelection();

                if (data.result !== 'playing') {
                    showGameEndModal(data.result);
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
                Toast.success('리매치가 생성되었습니다!');
                window.location.href = `/games/${data.room_id}/`;
                break;

            case 'chat':
                addChatMessage(data);
                break;

            case 'error':
                Toast.error(data.message);
                break;

            case 'heartbeat_ack':
                break;
        }
    }

    /**
     * 채팅 설정
     */
    function setupChat() {
        chatForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const message = chatInput.value.trim();
            if (!message || !socket) return;

            const action = myColor ? 'chat' : 'spectator_chat';
            socket.send(JSON.stringify({ action, message }));
            chatInput.value = '';
        });
    }

    /**
     * 채팅 메시지 추가
     */
    function addChatMessage(data) {
        const isMine = currentUser && data.user_id === currentUser.id;
        const messageEl = document.createElement('div');
        messageEl.className = `chat-message ${isMine ? 'mine' : 'others'}`;
        messageEl.innerHTML = `
            <span class="chat-nickname">${Utils.escapeHtml(data.nickname)}</span>
            <div class="chat-bubble">${Utils.escapeHtml(data.message)}</div>
        `;
        chatMessages.appendChild(messageEl);
        chatMessages.scrollTop = chatMessages.scrollHeight;
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
        drawBtn.addEventListener('click', () => {
            if (!confirm('무승부를 제안하시겠습니까?')) return;
            socket.send(JSON.stringify({ action: 'draw', game_id: game.id }));
            Toast.info('무승부를 제안했습니다.');
        });

        resignBtn.addEventListener('click', () => {
            if (!confirm('정말 기권하시겠습니까?')) return;
            socket.send(JSON.stringify({ action: 'resign', game_id: game.id }));
        });

        if (leaveBtn) {
            leaveBtn.addEventListener('click', () => {
                if (myColor) {
                    if (!confirm('나가면 기권 처리됩니다. 나가시겠습니까?')) return;
                    socket.send(JSON.stringify({ action: 'resign', game_id: game.id }));
                } else {
                    window.location.href = '/';
                }
            });
        }
    }

    function setupExitGuard() {
        const logo = document.querySelector('.navbar-logo');
        if (!logo) return;
        logo.addEventListener('click', (e) => {
            const leave = confirm('게임을 나가시겠습니까?');
            if (!leave) {
                e.preventDefault();
            }
        });
    }

    /**
     * 모달 설정
     */
    function setupModals() {
        // 리매치 버튼
        document.getElementById('rematch-btn').addEventListener('click', () => {
            socket.send(JSON.stringify({ action: 'rematch', game_id: game.id }));
            Toast.info('리매치를 요청했습니다.');
        });

        // 로비 버튼
        document.getElementById('lobby-btn').addEventListener('click', () => {
            window.location.href = '/';
        });

        // 무승부 수락/거절
        document.getElementById('accept-draw-btn').addEventListener('click', () => {
            socket.send(JSON.stringify({ action: 'draw', game_id: game.id }));
            drawModal.classList.add('hidden');
        });

        document.getElementById('decline-draw-btn').addEventListener('click', () => {
            drawModal.classList.add('hidden');
            Toast.info('무승부를 거절했습니다.');
        });

        // 리매치 수락/거절
        document.getElementById('accept-rematch-btn').addEventListener('click', () => {
            socket.send(JSON.stringify({ action: 'rematch', game_id: game.id }));
            rematchModal.classList.add('hidden');
        });

        document.getElementById('decline-rematch-btn').addEventListener('click', () => {
            socket.send(JSON.stringify({ action: 'decline_rematch', game_id: game.id }));
            rematchModal.classList.add('hidden');
        });
    }

    /**
     * 게임 종료 모달 표시
     */
    function showGameEndModal(result) {
        if (timerInterval) {
            clearInterval(timerInterval);
        }

        const iconEl = document.getElementById('game-end-icon');
        const titleEl = document.getElementById('game-end-title');
        const resultEl = document.getElementById('game-end-result');

        let icon = '🎮';
        let title = '게임 종료';
        let resultText = result;

        // 결과에 따른 표시
        const outcome = getOutcome(result, myColor);
        const isWin = outcome === 'win';
        const isLoss = outcome === 'loss';

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

        loadRatingChange();

        gameEndModal.classList.remove('hidden');
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
            const data = await API.get('/notifications/', { limit: 10, offset: 0 });
            const items = data.results || [];
            const target = items.find(
                (item) =>
                    item.type === 'rating_change' &&
                    item.payload &&
                    item.payload.game_id === game.id
            );

            if (!target) {
                setTimeout(loadRatingChange, 1000);
                return;
            }

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
        if (socket) socket.close();
    });
})();
