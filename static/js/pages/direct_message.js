(function() {
    'use strict';

    const messagesEl = document.getElementById('dm-messages');
    const formEl = document.getElementById('dm-form');
    const inputEl = document.getElementById('dm-input');
    const titleEl = document.getElementById('dm-title');
    const subtitleEl = document.getElementById('dm-subtitle');
    const backBtn = document.getElementById('dm-back');

    const targetUserId = parseInt(Utils.getPathParam(/\/messages\/(\d+)/), 10);
    let currentUser = null;
    let pollTimer = null;
    let lastCount = 0;

    init();

    async function init() {
        if (!targetUserId) {
            Toast.error('잘못된 접근입니다.');
            window.location.href = '/friends/';
            return;
        }
        try {
            currentUser = await API.get('/accounts/me/');
        } catch {
            Toast.error('로그인이 필요합니다.');
            window.location.href = '/login/';
            return;
        }
        await loadTargetInfo();
        await loadMessages(true);
        bindEvents();
        startPolling();
    }

    function bindEvents() {
        backBtn?.addEventListener('click', () => window.history.back());
        inputEl.addEventListener('focus', () => {
            inputEl.value = '';
        });
        formEl.addEventListener('submit', async (e) => {
            e.preventDefault();
            const message = inputEl.value.trim();
            if (!message) return;
            try {
                await API.post(`/accounts/messages/${targetUserId}/`, { message });
                inputEl.value = '';
                await loadMessages(true);
            } catch (error) {
                Toast.error(error.data?.message || '전송에 실패했습니다.');
            }
        });
    }

    async function loadTargetInfo() {
        try {
            const data = await API.get(`/accounts/users/${targetUserId}/profile/`);
            titleEl.textContent = `${data.nickname}님과의 채팅`;
            subtitleEl.textContent = `레이팅 ${data.stats?.rating ?? '-'} · ${data.stats?.rank_tier ?? '-'}`;
        } catch {
            // ignore
        }
    }

    async function loadMessages(forceScroll = false) {
        try {
            const data = await API.get(`/accounts/messages/${targetUserId}/`, { limit: 200, offset: 0 });
            const items = (data.results || []).slice().reverse();
            renderMessages(items);
            if (forceScroll || data.count !== lastCount) {
                messagesEl.scrollTop = 0;
            }
            lastCount = data.count || 0;
        } catch (error) {
            messagesEl.innerHTML = '<div class="history-empty">메시지를 불러오지 못했습니다.</div>';
        }
    }

    function renderMessages(items) {
        if (!items.length) {
            messagesEl.innerHTML = '<div class="history-empty">아직 메시지가 없습니다.</div>';
            return;
        }
        messagesEl.innerHTML = items.map((item) => {
            const isMe = item.sender?.id === currentUser.id;
            const time = formatTime(item.created_at);
            return `
                <div class="dm-message ${isMe ? 'me' : 'other'}">
                    <div class="dm-message-text">${Utils.escapeHtml(item.message)}</div>
                    <div class="dm-message-time">${time}</div>
                </div>
            `;
        }).join('');
    }

    function startPolling() {
        if (pollTimer) clearInterval(pollTimer);
        pollTimer = setInterval(() => {
            loadMessages();
        }, 4000);
        window.addEventListener('beforeunload', () => pollTimer && clearInterval(pollTimer));
    }

    function formatTime(value) {
        if (!value) return '';
        const d = new Date(value);
        const hh = String(d.getHours()).padStart(2, '0');
        const mm = String(d.getMinutes()).padStart(2, '0');
        return `${hh}:${mm}`;
    }
})();
