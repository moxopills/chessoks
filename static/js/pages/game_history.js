(function() {
    'use strict';

    const listEl = document.getElementById('history-list');
    const resultSelect = document.getElementById('filter-result');
    const startInput = document.getElementById('filter-start');
    const endInput = document.getElementById('filter-end');
    const applyBtn = document.getElementById('filter-apply');
    const resetBtn = document.getElementById('filter-reset');
    const prevBtn = document.getElementById('page-prev');
    const nextBtn = document.getElementById('page-next');
    const indicator = document.getElementById('page-indicator');

    const PAGE_SIZE = 10;
    let currentUser = null;
    let totalCount = 0;
    let currentPage = 1;

    init();

    async function init() {
        try {
            currentUser = await API.get('/accounts/me/');
        } catch (error) {
            Toast.error('로그인 시 가능합니다.');
            window.location.href = '/login/';
            return;
        }

        loadFromUrl();
        bindEvents();
        await fetchHistory();
    }

    function bindEvents() {
        applyBtn.addEventListener('click', () => {
            currentPage = 1;
            pushFiltersToUrl();
            fetchHistory();
        });
        resetBtn.addEventListener('click', () => {
            resultSelect.value = '';
            startInput.value = '';
            endInput.value = '';
            currentPage = 1;
            pushFiltersToUrl();
            fetchHistory();
        });
        prevBtn.addEventListener('click', () => {
            if (currentPage > 1) {
                currentPage -= 1;
                fetchHistory();
            }
        });
        nextBtn.addEventListener('click', () => {
            const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));
            if (currentPage < totalPages) {
                currentPage += 1;
                fetchHistory();
            }
        });
    }

    function loadFromUrl() {
        const params = Utils.getUrlParams();
        if (params.result) resultSelect.value = params.result;
        if (params.start_date) startInput.value = params.start_date;
        if (params.end_date) endInput.value = params.end_date;
        if (params.page) currentPage = Math.max(1, parseInt(params.page, 10) || 1);
    }

    function pushFiltersToUrl() {
        const params = new URLSearchParams();
        if (resultSelect.value) params.set('result', resultSelect.value);
        if (startInput.value) params.set('start_date', startInput.value);
        if (endInput.value) params.set('end_date', endInput.value);
        if (currentPage > 1) params.set('page', String(currentPage));
        const newUrl = params.toString() ? `${window.location.pathname}?${params.toString()}` : window.location.pathname;
        window.history.replaceState({}, '', newUrl);
    }

    async function fetchHistory() {
        listEl.innerHTML = '<div class="history-empty">불러오는 중...</div>';
        try {
            const offset = (currentPage - 1) * PAGE_SIZE;
            const params = {
                limit: PAGE_SIZE,
                offset,
            };
            if (resultSelect.value) params.result = resultSelect.value;
            if (startInput.value) params.start_date = startInput.value;
            if (endInput.value) params.end_date = endInput.value;
            const data = await API.get('/chess/games/history/', params);
            totalCount = data.count || 0;
            renderHistory(data.results || []);
            updatePagination();
            pushFiltersToUrl();
        } catch (error) {
            listEl.innerHTML = '<div class="history-empty">불러오기 실패</div>';
        }
    }

    function renderHistory(items) {
        if (!items.length) {
            listEl.innerHTML = '<div class="history-empty">표시할 기록이 없습니다.</div>';
            return;
        }

        listEl.innerHTML = items.map((game) => {
            const opponent = getOpponent(game);
            const outcome = getOutcome(game);
            const resultLabel = outcome.label;
            const resultClass = outcome.className;
            const dateText = formatDate(game.finished_at || game.created_at);
            const roomLabel = game.room_type === 'quick' ? '빠른 대전' : '사용자 방';
            const moveCount = game.move_count ?? 0;
            const opponentName = opponent?.nickname || '알 수 없음';
            const myName = currentUser?.nickname || '나';
            const resultText = resultLabel || '-';
            return `
                <div class="history-card">
                    <div class="history-actions">
                        <div class="history-result ${resultClass}">${resultText}</div>
                        <button class="btn btn-secondary btn-xs" data-action="replay" data-game-id="${game.id}" data-room-id="${game.room_id}">기보 다시보기</button>
                    </div>
                    <div class="history-info">
                        <div class="history-title">${Utils.escapeHtml(myName)} vs ${Utils.escapeHtml(opponentName)}</div>
                        <div class="history-sub text-muted">${[dateText, roomLabel, `${moveCount}수`].join(' · ')}</div>
                    </div>
                </div>
            `;
        }).join('');

        listEl.querySelectorAll('[data-action="replay"]').forEach((btn) => {
            btn.addEventListener('click', () => {
                const gameId = btn.dataset.gameId;
                const roomId = btn.dataset.roomId;
                if (!gameId || !roomId) return;
                window.location.href = `/games/${roomId}/?replay_game_id=${gameId}`;
            });
        });
    }

    function updatePagination() {
        const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));
        indicator.textContent = `${currentPage} / ${totalPages}`;
        prevBtn.disabled = currentPage <= 1;
        nextBtn.disabled = currentPage >= totalPages;
    }

    function getOpponent(game) {
        if (!currentUser) return null;
        const meId = Number(currentUser.id);
        const whiteId = Number(game.white_player?.id);
        const blackId = Number(game.black_player?.id);
        if (whiteId === meId) return game.black_player;
        if (blackId === meId) return game.white_player;
        return game.white_player || game.black_player;
    }

    function getOutcome(game) {
        const result = game.result;
        if (!currentUser) return { className: '', label: result };
        const meId = Number(currentUser.id);
        const isWhite = Number(game.white_player?.id) === meId;
        const isBlack = Number(game.black_player?.id) === meId;
        const drawResults = new Set([
            'draw',
            'draw_agreement',
            'draw_insufficient',
            'draw_repetition',
            'draw_fifty_move',
            'stalemate',
        ]);
        const whiteWin = new Set([
            'white_win',
            'checkmate_white',
            'timeout_black',
            'resignation_black',
        ]);
        const blackWin = new Set([
            'black_win',
            'checkmate_black',
            'timeout_white',
            'resignation_white',
        ]);
        if (drawResults.has(result)) {
            return { className: 'draw', label: '무' };
        }
        if (whiteWin.has(result)) {
            return { className: isWhite ? 'win' : 'lose', label: isWhite ? '승' : '패' };
        }
        if (blackWin.has(result)) {
            return { className: isBlack ? 'win' : 'lose', label: isBlack ? '승' : '패' };
        }
        return { className: '', label: result };
    }

    function formatDate(value) {
        if (!value) return '-';
        const d = new Date(value);
        const y = d.getFullYear();
        const m = String(d.getMonth() + 1).padStart(2, '0');
        const day = String(d.getDate()).padStart(2, '0');
        const hh = String(d.getHours()).padStart(2, '0');
        const mm = String(d.getMinutes()).padStart(2, '0');
        return `${y}-${m}-${day} ${hh}:${mm}`;
    }
})();
