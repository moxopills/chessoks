(function() {
    'use strict';

    const listEl = document.getElementById('thread-list');

    init();

    async function init() {
        try {
            await API.get('/accounts/me/');
        } catch {
            Toast.error('로그인 시 가능합니다.');
            window.location.href = '/login/';
            return;
        }
        fetchThreads();
    }

    async function fetchThreads() {
        renderThreadSkeletons();
        try {
            const [data, notifications] = await Promise.all([
                API.get('/accounts/messages/threads/', { limit: 50, offset: 0, no_count: 1 }),
                API.get('/notifications/', { limit: 200, offset: 0, no_count: 1 }),
            ]);
            const threads = data.results || [];
            if (!threads.length) {
                renderEmpty('대화가 없습니다.');
                return;
            }
            const unreadMap = buildUnreadMap(notifications.results || []);
            const fragment = document.createDocumentFragment();
            threads.forEach((thread) => {
                fragment.appendChild(renderThread(thread, unreadMap));
            });
            listEl.replaceChildren(fragment);
        } catch (error) {
            renderEmpty('불러오지 못했습니다.');
        }
    }

    function renderEmpty(message) {
        const el = document.createElement('div');
        el.className = 'history-empty';
        el.textContent = message;
        listEl.replaceChildren(el);
    }

    function renderThreadSkeletons() {
        const fragment = document.createDocumentFragment();
        Array.from({ length: 5 }).forEach(() => {
            const card = document.createElement('div');
            card.className = 'thread-card';
            const info = document.createElement('div');
            info.className = 'thread-info';
            const avatar = document.createElement('div');
            avatar.className = 'thread-avatar';
            const avatarSkel = document.createElement('div');
            avatarSkel.className = 'skeleton skeleton-avatar';
            avatarSkel.style.width = '40px';
            avatarSkel.style.height = '40px';
            avatar.appendChild(avatarSkel);
            const text = document.createElement('div');
            text.className = 'thread-text';
            const line1 = document.createElement('div');
            line1.className = 'skeleton';
            line1.style.width = '120px';
            line1.style.height = '12px';
            line1.style.marginBottom = '8px';
            const line2 = document.createElement('div');
            line2.className = 'skeleton';
            line2.style.width = '180px';
            line2.style.height = '11px';
            text.append(line1, line2);
            info.append(avatar, text);

            const action = document.createElement('div');
            action.className = 'thread-action';
            const actionLine = document.createElement('div');
            actionLine.className = 'skeleton';
            actionLine.style.width = '70px';
            actionLine.style.height = '10px';
            actionLine.style.marginBottom = '8px';
            const actionBtn = document.createElement('div');
            actionBtn.className = 'skeleton';
            actionBtn.style.width = '62px';
            actionBtn.style.height = '26px';
            actionBtn.style.borderRadius = '8px';
            action.append(actionLine, actionBtn);

            card.append(info, action);
            fragment.appendChild(card);
        });
        listEl.replaceChildren(fragment);
    }

    function renderThread(thread, unreadMap) {
        const user = thread.other_user || {};
        const nickname = user.nickname || '알 수 없음';
        const time = thread.last_message_at ? formatTime(thread.last_message_at) : '';
        const message = thread.last_message || '대화를 시작해보세요.';
        const unreadCount = unreadMap[user.id] || 0;
        const card = document.createElement('div');
        card.className = 'thread-card';
        const info = document.createElement('div');
        info.className = 'thread-info';

        const avatarWrap = document.createElement('div');
        avatarWrap.className = 'thread-avatar';
        Utils.setAvatar(avatarWrap, {
            url: user.avatar_url || '',
            alt: nickname,
            placeholder: '👤',
        });

        const textWrap = document.createElement('div');
        textWrap.className = 'thread-text';
        const title = document.createElement('div');
        title.className = 'thread-title';
        title.textContent = nickname;
        const msg = document.createElement('div');
        msg.className = 'thread-message';
        msg.textContent = message;
        textWrap.append(title, msg);
        info.append(avatarWrap, textWrap);

        const action = document.createElement('div');
        action.className = 'thread-action';
        const timeEl = document.createElement('span');
        timeEl.className = 'thread-time';
        timeEl.textContent = time;
        const button = document.createElement('button');
        button.className = 'btn btn-secondary btn-xs';
        button.dataset.action = 'open-thread';
        button.dataset.userId = String(user.id || '');
        button.textContent = '열기';
        button.addEventListener('click', () => {
            if (user.id) window.location.href = `/messages/${user.id}/`;
        });
        if (unreadCount) {
            const badge = document.createElement('span');
            badge.className = 'thread-badge';
            badge.textContent = String(unreadCount);
            button.appendChild(badge);
        }
        action.append(timeEl, button);

        card.append(info, action);
        return card;
    }

    function buildUnreadMap(items) {
        return items
            .filter((item) => item.type === 'direct_message' && !item.is_read)
            .reduce((acc, item) => {
                const senderId = item.payload?.sender_id;
                if (!senderId) return acc;
                acc[senderId] = (acc[senderId] || 0) + 1;
                return acc;
            }, {});
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
