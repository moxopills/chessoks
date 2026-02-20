/**
 * ContextMenu Component
 * 공통 컨텍스트 메뉴 (friends, leaderboard, lobby에서 사용)
 */
const ContextMenu = (function() {
    let menuEl = null;
    let currentCallback = null;
    let currentTargetId = null;

    function init() {
        if (menuEl) return;
        menuEl = document.createElement('div');
        menuEl.className = 'context-menu hidden';
        document.body.appendChild(menuEl);

        menuEl.addEventListener('click', (e) => {
            const action = e.target.closest('.context-menu-item')?.dataset.action;
            if (action && currentCallback && currentTargetId) {
                currentCallback(action, currentTargetId);
            }
            hide();
        });

        document.addEventListener('click', (e) => {
            if (!menuEl.contains(e.target)) hide();
        });

        // 스크롤 시 메뉴 숨기기 (모든 스크롤 이벤트 캡처)
        document.addEventListener('scroll', hide, true);
        window.addEventListener('scroll', hide, { passive: true });

        // 모바일 터치 스크롤 시 메뉴 숨기기
        document.addEventListener('touchmove', hide, { passive: true });

        // 화면 크기 변경 시 메뉴 숨기기 (iOS 주소창 변화 대응)
        window.addEventListener('resize', hide);

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') hide();
        });
    }

    /**
     * 컨텍스트 메뉴 표시
     * @param {MouseEvent|TouchEvent} event - 위치 기준 이벤트
     * @param {number} targetId - 대상 유저 ID
     * @param {Array<{action: string, label: string}>} items - 메뉴 항목
     * @param {Function} callback - 액션 콜백 (action, targetId) => void
     */
    function show(event, targetId, items, callback) {
        init();
        currentTargetId = targetId;
        currentCallback = callback;

        menuEl.innerHTML = items.map(item => (
            `<div class="context-menu-item" data-action="${item.action}">${item.label}</div>`
        )).join('');

        menuEl.classList.remove('hidden');
        position(event);
    }

    function position(event) {
        if (!menuEl) return;
        const padding = 8;
        const rect = menuEl.getBoundingClientRect();
        const maxX = window.innerWidth - rect.width - padding;
        const maxY = window.innerHeight - rect.height - padding;
        // touchend 이벤트는 changedTouches 사용, touchstart/touchmove는 touches 사용
        const touch = event.changedTouches?.[0] || event.touches?.[0];
        const clientX = event.clientX ?? touch?.clientX ?? 0;
        const clientY = event.clientY ?? touch?.clientY ?? 0;
        menuEl.style.left = `${Math.min(clientX, maxX)}px`;
        menuEl.style.top = `${Math.min(clientY, maxY)}px`;
    }

    function hide() {
        if (menuEl) menuEl.classList.add('hidden');
        currentTargetId = null;
        currentCallback = null;
    }

    /**
     * 유저 컨텍스트 메뉴 항목 생성 헬퍼
     * @param {Object} options
     * @param {number} options.currentUserId - 현재 로그인 유저 ID
     * @param {number} options.targetUserId - 대상 유저 ID
     * @param {boolean} options.isFriend - 친구 여부
     * @param {boolean} options.isPending - 요청 대기 중 여부
     * @param {boolean} options.showRemove - 친구 삭제 옵션 표시 여부
     * @returns {Array<{action: string, label: string}>}
     */
    function buildUserMenuItems({ currentUserId, targetUserId, isFriend = false, isPending = false, showRemove = false }) {
        const items = [{ action: 'profile', label: '프로필 보기' }];
        if (!currentUserId || targetUserId === currentUserId) return items;

        items.push({ action: 'invite', label: '게임 초대' });
        if (!isFriend && !isPending) {
            items.push({ action: 'friend', label: '친구 추가' });
        }
        if (isFriend && showRemove) {
            items.push({ action: 'remove', label: '친구 삭제' });
        }
        items.push({ action: 'chat', label: '1:1 채팅' });
        items.push({ action: 'report', label: '신고하기' });
        return items;
    }

    return { show, hide, buildUserMenuItems };
})();
