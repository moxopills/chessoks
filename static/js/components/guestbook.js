/**
 * Guestbook Component
 * 방명록 공통 로직 (friends, leaderboard에서 사용)
 */
const Guestbook = (function() {
    let listEl = null;
    let inputEl = null;
    let getCurrentUserId = null;
    let getTargetUserId = null;

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

    /**
     * 방명록 초기화
     * @param {Object} options
     * @param {HTMLElement} options.listEl - 방명록 목록 컨테이너
     * @param {HTMLElement} options.inputEl - 입력 필드
     * @param {Function} options.getCurrentUserId - 현재 유저 ID 반환 함수
     * @param {Function} options.getTargetUserId - 대상 유저 ID 반환 함수
     */
    function init(options) {
        listEl = options.listEl;
        inputEl = options.inputEl;
        getCurrentUserId = options.getCurrentUserId;
        getTargetUserId = options.getTargetUserId;
    }

    async function load(userId) {
        if (!listEl) return;
        listEl.innerHTML = '<div class="text-muted">불러오는 중...</div>';
        try {
            const data = await API.get(`/accounts/users/${userId}/guestbook/`);
            render(data || []);
        } catch (error) {
            listEl.innerHTML = '<div class="text-muted">방명록을 불러오지 못했습니다.</div>';
        }
    }

    function render(entries) {
        if (!listEl) return;
        const currentUserId = getCurrentUserId?.();
        const targetUserId = getTargetUserId?.();

        if (!entries.length) {
            listEl.innerHTML = '<div class="text-muted">방명록이 없습니다.</div>';
            return;
        }

        listEl.innerHTML = entries.map((entry) => {
            const canDelete = entry.author?.id === currentUserId || targetUserId === currentUserId;
            const time = formatDate(entry.created_at);
            return `
                <div class="guestbook-item" data-entry-id="${entry.id}">
                    <div>${Utils.escapeHtml(entry.message)}</div>
                    <div class="guestbook-meta">
                        <span>${Utils.escapeHtml(entry.author?.nickname || '알 수 없음')}</span>
                        <span>${time}</span>
                    </div>
                    ${canDelete ? '<button class="btn btn-secondary btn-sm" data-action="delete">삭제</button>' : ''}
                </div>
            `;
        }).join('');

        listEl.querySelectorAll('[data-action="delete"]').forEach((btn) => {
            btn.addEventListener('click', async () => {
                const entryId = btn.closest('.guestbook-item')?.dataset.entryId;
                if (!entryId) return;
                await deleteEntry(entryId);
            });
        });
    }

    async function submit() {
        const targetUserId = getTargetUserId?.();
        if (!inputEl || !targetUserId) return;
        const message = inputEl.value.trim();
        if (!message) return;
        try {
            await API.post(`/accounts/users/${targetUserId}/guestbook/`, { message });
            inputEl.value = '';
            await load(targetUserId);
        } catch (error) {
            Toast.error(error.data?.detail || error.data?.message || '방명록 등록에 실패했습니다.');
        }
    }

    async function deleteEntry(entryId) {
        const targetUserId = getTargetUserId?.();
        try {
            await API.delete(`/accounts/guestbook/${entryId}/`);
            if (targetUserId) await load(targetUserId);
        } catch (error) {
            Toast.error(error.data?.message || '삭제에 실패했습니다.');
        }
    }

    return { init, load, submit };
})();
