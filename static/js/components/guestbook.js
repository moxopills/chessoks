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
        renderStatus('불러오는 중...');
        try {
            const data = await API.get(`/accounts/users/${userId}/guestbook/`);
            render(data || []);
        } catch (error) {
            renderStatus('방명록을 불러오지 못했습니다.');
        }
    }

    function renderStatus(message) {
        const el = document.createElement('div');
        el.className = 'text-muted';
        el.textContent = message;
        listEl.replaceChildren(el);
    }

    function render(entries) {
        if (!listEl) return;
        const currentUserId = getCurrentUserId?.();
        const targetUserId = getTargetUserId?.();

        if (!entries.length) {
            renderStatus('방명록이 없습니다.');
            return;
        }

        const fragment = document.createDocumentFragment();
        entries.forEach((entry) => {
            const canDelete = entry.author?.id === currentUserId || targetUserId === currentUserId;
            const time = formatDate(entry.created_at);
            const item = document.createElement('div');
            item.className = 'guestbook-item';
            item.dataset.entryId = String(entry.id);

            const message = document.createElement('div');
            message.textContent = entry.message || '';

            const meta = document.createElement('div');
            meta.className = 'guestbook-meta';

            const author = document.createElement('span');
            author.textContent = entry.author?.nickname || '알 수 없음';
            const timeEl = document.createElement('span');
            timeEl.textContent = time;
            meta.append(author, timeEl);

            item.append(message, meta);

            if (canDelete) {
                const deleteBtn = document.createElement('button');
                deleteBtn.className = 'btn btn-secondary btn-sm';
                deleteBtn.dataset.action = 'delete';
                deleteBtn.textContent = '삭제';
                deleteBtn.addEventListener('click', async () => {
                    await deleteEntry(entry.id);
                });
                item.appendChild(deleteBtn);
            }

            fragment.appendChild(item);
        });
        listEl.replaceChildren(fragment);
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
