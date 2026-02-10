/**
 * Rooms List Page Logic
 * - 방 목록 조회/필터링/페이지네이션
 * - 방 생성 모달
 * - 방 입장
 */

(function() {
    'use strict';

    // DOM Elements
    const roomsList = document.getElementById('rooms-list');
    const pagination = document.getElementById('pagination');
    const filterStatus = document.getElementById('filter-status');
    const filterSort = document.getElementById('filter-sort');
    const createRoomBtn = document.getElementById('create-room-btn');
    const createModal = document.getElementById('create-modal');
    const modalClose = document.getElementById('modal-close');
    const modalCancel = document.getElementById('modal-cancel');
    const createRoomForm = document.getElementById('create-room-form');
    const roomsTabs = document.getElementById('rooms-tabs');

    // State
    let currentPage = 1;
    const pageSize = 10;
    let totalCount = 0;
    let refreshInterval = null;
    let currentView = 'game'; // game | spectate

    // Init
    init();

    async function init() {
        await loadRooms();
        setupFilters();
        setupTabs();
        setupModal();
        setupCreateForm();
        startAutoRefresh();
    }

    /**
     * 방 목록 로드
     */
    async function loadRooms() {
        try {
            roomsList.innerHTML = `
                <div class="loading-placeholder">
                    <span class="spinner"></span>
                    <span>로딩 중...</span>
                </div>
            `;

            const params = {
                limit: pageSize,
                offset: (currentPage - 1) * pageSize
            };

            const status = currentView === 'spectate' ? 'playing' : filterStatus.value;
            if (status) params.status = status;

            const data = await API.get('/chess/rooms/', params);
            let rooms = data.results || [];
            if (currentView === 'spectate') {
                rooms = rooms.filter(room => room.allow_spectators && room.status === 'playing');
            } else {
                rooms = rooms.filter(room => room.status !== 'playing');
            }
            totalCount = currentView === 'spectate' ? rooms.length : (data.count || 0);
            renderRooms(rooms);
            renderPagination();
        } catch (error) {
            roomsList.innerHTML = '<div class="rooms-empty">방 목록을 불러올 수 없습니다.</div>';
            console.error('Failed to load rooms:', error);
        }
    }

    /**
     * 방 목록 렌더링
     */
    function renderRooms(rooms) {
        if (!rooms || rooms.length === 0) {
            roomsList.innerHTML = currentView === 'spectate'
                ? '<div class="rooms-empty">현재 관전 가능한 방이 없습니다.</div>'
                : '<div class="rooms-empty">생성된 방이 없습니다. 새로운 방을 만들어보세요!</div>';
            return;
        }

        roomsList.innerHTML = rooms.map(room => {
            const isPlaying = room.status === 'playing';
            const hasGame = !!room.current_game_id;
            const isFull = room.guest !== null;
            const statusText = {
                'waiting': '대기 중',
                'ready': '준비 완료',
                'playing': '게임 중',
                'finished': '종료'
            }[room.status] || room.status;
            const safeStatusText = isPlaying && !hasGame ? '게임 준비 중' : statusText;

            return `
                <div class="room-card ${isPlaying ? 'is-playing' : ''} ${isFull ? 'is-full' : ''}"
                     data-room-id="${room.id}"
                     data-game-id="${room.current_game_id || ''}">
                    <div class="room-host">
                        <div class="avatar">
                            ${room.host?.avatar_url
                                ? `<img src="${Utils.escapeHtml(room.host.avatar_url)}" alt="">`
                                : '<span class="avatar-placeholder">?</span>'}
                        </div>
                        <div class="room-host-name">${Utils.escapeHtml(room.host?.nickname || '호스트')}</div>
                        <div class="room-host-rating">${room.host?.rating || 1500}</div>
                    </div>
                    <div class="room-info">
                        <div class="room-title">
                            ${room.is_private ? '<span class="icon-private">🔒</span>' : ''}
                            ${Utils.escapeHtml(room.title || '빠른 대전')}
                        </div>
                        <div class="room-meta">
                            <span class="room-meta-item">
                                ⏱ ${room.time_limit ? room.time_limit + '분' : '무제한'}
                            </span>
                            <span class="room-meta-item">
                                👥 ${room.player_count || 1}/2
                            </span>
                            ${room.allow_spectators ? '<span class="room-meta-item">👁 관전 가능</span>' : ''}
                        </div>
                    </div>
                    <span class="room-status ${room.status}">${safeStatusText}</span>
                </div>
            `;
        }).join('');

        // 방 클릭 이벤트
        roomsList.querySelectorAll('.room-card').forEach(card => {
            card.addEventListener('click', () => handleRoomClick(card));
        });
    }

    /**
     * 페이지네이션 렌더링
     */
    function renderPagination() {
        const totalPages = Math.ceil(totalCount / pageSize);
        if (totalPages <= 1) {
            pagination.innerHTML = '';
            return;
        }

        let html = '';

        // 이전 버튼
        html += `<button class="pagination-btn" ${currentPage === 1 ? 'disabled' : ''} data-page="${currentPage - 1}">&lt;</button>`;

        // 페이지 번호
        const startPage = Math.max(1, currentPage - 2);
        const endPage = Math.min(totalPages, currentPage + 2);

        if (startPage > 1) {
            html += `<button class="pagination-btn" data-page="1">1</button>`;
            if (startPage > 2) {
                html += `<span class="pagination-dots">...</span>`;
            }
        }

        for (let i = startPage; i <= endPage; i++) {
            html += `<button class="pagination-btn ${i === currentPage ? 'active' : ''}" data-page="${i}">${i}</button>`;
        }

        if (endPage < totalPages) {
            if (endPage < totalPages - 1) {
                html += `<span class="pagination-dots">...</span>`;
            }
            html += `<button class="pagination-btn" data-page="${totalPages}">${totalPages}</button>`;
        }

        // 다음 버튼
        html += `<button class="pagination-btn" ${currentPage === totalPages ? 'disabled' : ''} data-page="${currentPage + 1}">&gt;</button>`;

        pagination.innerHTML = html;

        // 페이지 클릭 이벤트
        pagination.querySelectorAll('.pagination-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const page = parseInt(btn.dataset.page);
                if (page && page !== currentPage && !btn.disabled) {
                    currentPage = page;
                    loadRooms();
                }
            });
        });
    }

    /**
     * 필터 설정
     */
    function setupFilters() {
        filterStatus.addEventListener('change', () => {
            currentPage = 1;
            loadRooms();
        });

        filterSort.addEventListener('change', () => {
            currentPage = 1;
            loadRooms();
        });
    }

    function setupTabs() {
        if (!roomsTabs) return;
        roomsTabs.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const view = btn.dataset.view;
                if (!view || view === currentView) return;
                currentView = view;
                roomsTabs.querySelectorAll('.tab-btn').forEach(tab => {
                    tab.classList.toggle('active', tab === btn);
                });
                if (currentView === 'spectate') {
                    filterStatus.value = 'playing';
                    filterStatus.disabled = true;
                } else {
                    filterStatus.disabled = false;
                }
                currentPage = 1;
                loadRooms();
            });
        });
    }

    function startAutoRefresh() {
        refreshInterval = setInterval(() => {
            loadRooms();
        }, 5000);

        window.addEventListener('beforeunload', () => {
            if (refreshInterval) clearInterval(refreshInterval);
        });
    }

    /**
     * 모달 설정
     */
    function setupModal() {
        createRoomBtn.addEventListener('click', openModal);
        modalClose.addEventListener('click', closeModal);
        modalCancel.addEventListener('click', closeModal);

        createModal.addEventListener('click', (e) => {
            if (e.target === createModal) {
                closeModal();
            }
        });

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && !createModal.classList.contains('hidden')) {
                closeModal();
            }
        });
    }

    function openModal() {
        createRoomForm.reset();
        document.getElementById('room-title').value = '';
        document.getElementById('room-password').value = '';
        createModal.classList.remove('hidden');
        document.getElementById('room-title').focus();
    }

    function closeModal() {
        createModal.classList.add('hidden');
        createRoomForm.reset();
    }

    /**
     * 방 생성 폼 설정
     */
    function setupCreateForm() {
        createRoomForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            await createRoom();
        });
    }

    /**
     * 방 생성
     */
    async function createRoom() {
        const title = document.getElementById('room-title').value.trim();
        const timeLimit = parseInt(document.querySelector('input[name="time_limit"]:checked').value);
        const password = document.getElementById('room-password').value;
        const allowSpectators = document.getElementById('allow-spectators').checked;

        try {
            const data = {
                room_type: 'custom',
                time_limit: timeLimit,
                allow_spectators: allowSpectators
            };

            if (title) data.title = title;
            if (password) data.password = password;

            const room = await API.post('/chess/rooms/', data);
            Toast.success('방이 생성되었습니다!');
            closeModal();

            // 생성된 방으로 이동
            window.location.href = `/rooms/${room.id}/`;
        } catch (error) {
            Toast.error(error.data?.message || '방 생성에 실패했습니다.');
        }
    }

    /**
     * 방 클릭 핸들러
     */
    async function handleRoomClick(card) {
        const roomId = card.dataset.roomId;
        const gameId = card.dataset.gameId;
        const isPlaying = card.classList.contains('is-playing');
        const isFull = card.classList.contains('is-full');
        const isPrivate = card.querySelector('.icon-private') !== null;

        if (isFull && !isPlaying) {
            Toast.error('이미 인원이 가득 찼습니다.');
            return;
        }

        if (isPlaying) {
            // 게임 중인 방은 관전 페이지로
            if (gameId) {
                window.location.href = `/games/${gameId}/`;
            } else {
                Toast.error('관전 가능한 게임 정보를 찾을 수 없습니다.');
            }
            return;
        }

        if (isPrivate && !isFull) {
            // 비공개 방 - 비밀번호 입력
            const password = prompt('비밀번호를 입력하세요:');
            if (!password) return;

            try {
            const joined = await API.post(`/chess/rooms/${roomId}/join/`, { password });
            if (joined.room_type === 'quick' || joined.status === 'playing') {
                const joinedGameId = joined.current_game_id;
                if (joinedGameId) {
                    window.location.href = `/games/${joinedGameId}/`;
                } else {
                    Toast.error('게임 정보를 찾을 수 없습니다.');
                }
            } else {
                window.location.href = `/rooms/${roomId}/`;
            }
        } catch (error) {
            Toast.error(error.data?.message || '입장에 실패했습니다.');
        }
        return;
        }

        // 일반 입장
        try {
            const joined = await API.post(`/chess/rooms/${roomId}/join/`);
            if (joined.room_type === 'quick' || joined.status === 'playing') {
                const joinedGameId = joined.current_game_id;
                if (joinedGameId) {
                    window.location.href = `/games/${joinedGameId}/`;
                } else {
                    Toast.error('게임 정보를 찾을 수 없습니다.');
                }
            } else {
                window.location.href = `/rooms/${roomId}/`;
            }
        } catch (error) {
            Toast.error(error.data?.message || '입장에 실패했습니다.');
        }
    }
})();
