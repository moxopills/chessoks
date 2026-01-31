(function() {
    'use strict';

    const listEl = document.getElementById('thread-list');

    init();

    async function init() {
        try {
            await API.get('/accounts/me/');
        } catch {
            Toast.error('로그인이 필요합니다.');
            window.location.href = '/login/';
            return;
        }
        fetchThreads();
    }

    async function fetchThreads() {
        listEl.innerHTML = '<div class="history-empty">불러오는 중...</div>';
        try {
            const data = await API.get('/accounts/messages/threads/', { limit: 50, offset: 0 });
            const threads = data.results || [];
            if (!threads.length) {
                listEl.innerHTML = '<div class="history-empty">대화가 없습니다.</div>';
                return;
            }
            listEl.innerHTML = threads.map(renderThread).join('');
            listEl.querySelectorAll('[data-action="open-thread"]').forEach((btn) => {
                btn.addEventListener('click', () => {
                    const targetId = btn.dataset.userId;
                    if (targetId) window.location.href = `/messages/${targetId}/`;
                });
            });
        } catch (error) {
            listEl.innerHTML = '<div class="history-empty">불러오지 못했습니다.</div>';
        }
    }

    function renderThread(thread) {
        const user = thread.other_user || {};
        const nickname = user.nickname || '알 수 없음';
        const avatar = user.avatar_url
            ? `<img src="${Utils.escapeHtml(user.avatar_url)}" alt="">`
            : '<span>👤</span>';
        const time = thread.last_message_at ? formatTime(thread.last_message_at) : '';
        const message = thread.last_message || '대화를 시작해보세요.';
        return `
            <div class="thread-card">
                <div class="thread-info">
                    <div class="thread-avatar">${avatar}</div>
                    <div class="thread-text">
                        <div class="thread-title">${Utils.escapeHtml(nickname)}</div>
                        <div class="thread-message">${Utils.escapeHtml(message)}</div>
                    </div>
                </div>
                <div class="thread-action">
                    <span class="thread-time">${time}</span>
                    <button class="btn btn-secondary btn-xs" data-action="open-thread" data-user-id="${user.id}">열기</button>
                </div>
            </div>
        `;
    }

    function formatTime(value) {
        const date = new Date(value);
        const yy = String(date.getFullYear()).slice(-2);
        const mm = String(date.getMonth() + 1).padStart(2, '0');
        const dd = String(date.getDate()).padStart(2, '0');
        const hh = String(date.getHours()).padStart(2, '0');
        const mi = String(date.getMinutes()).padStart(2, '0');
        return `${yy}.${mm}.${dd} ${hh}:${mi}`;
    }
})();
