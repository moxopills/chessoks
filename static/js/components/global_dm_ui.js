(function() {
    'use strict';

    function createEmpty(message) {
        const empty = document.createElement('div');
        empty.className = 'global-dm-empty';
        empty.textContent = message;
        return empty;
    }

    function setThreadListEmpty(root, message) {
        if (!root) return;
        root.replaceChildren(createEmpty(message));
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

    function updateGlobalBadge(fabBadge, unreadMap) {
        if (!fabBadge) return;
        const totalUnread = Object.values(unreadMap).reduce((a, b) => a + b, 0);
        if (totalUnread > 0) {
            fabBadge.textContent = totalUnread;
            fabBadge.classList.remove('hidden');
        } else {
            fabBadge.textContent = '0';
            fabBadge.classList.add('hidden');
        }
    }

    function setChannelEmpty(messagesRoot, titleRoot, subtitleRoot, inputRoot, text, title) {
        if (titleRoot) titleRoot.textContent = title;
        if (subtitleRoot) subtitleRoot.textContent = text;
        if (messagesRoot) {
            messagesRoot.replaceChildren(createEmpty(text));
        }
        if (inputRoot) {
            inputRoot.value = '';
            inputRoot.disabled = true;
            inputRoot.placeholder = text;
            inputRoot.closest('form')?.querySelector('button[type="submit"]')?.toggleAttribute('disabled', true);
        }
    }

    function setChannelReady(inputRoot, placeholder) {
        if (!inputRoot) return;
        inputRoot.disabled = false;
        inputRoot.placeholder = placeholder;
        inputRoot.closest('form')?.querySelector('button[type="submit"]')?.toggleAttribute('disabled', false);
    }

    function buildMessageSignature(items) {
        return items.map((item) => `${item.id}:${item.created_at || ''}`).join('|');
    }

    function syncMessageList(root, items, renderItem, forceScroll, emptyText, state) {
        if (!root) return false;
        const orderedItems = items.slice().reverse();

        if (!orderedItems.length) {
            if (state.signature !== 'empty') {
                root.replaceChildren(createEmpty(emptyText));
                state.signature = 'empty';
                state.ids = [];
            }
            return false;
        }

        const nextIds = orderedItems.map((item) => String(item.id ?? ''));
        const nextSignature = buildMessageSignature(orderedItems);
        const shouldScroll = forceScroll || (root.scrollTop + root.clientHeight >= root.scrollHeight - 50);

        if (nextSignature === state.signature) {
            if (shouldScroll) {
                ChatUI?.scrollToBottom(root);
            }
            return false;
        }

        const canAppendOnly =
            state.ids.length > 0 &&
            nextIds.length > state.ids.length &&
            state.ids.every((id, index) => id === nextIds[index]);

        if (canAppendOnly) {
            const fragment = document.createDocumentFragment();
            orderedItems.slice(state.ids.length).forEach((item) => {
                fragment.appendChild(renderItem(item));
            });
            root.appendChild(fragment);
        } else {
            const fragment = document.createDocumentFragment();
            orderedItems.forEach((item) => {
                fragment.appendChild(renderItem(item));
            });
            root.replaceChildren(fragment);
        }

        state.signature = nextSignature;
        state.ids = nextIds;

        if (shouldScroll) {
            ChatUI?.scrollToBottom(root);
        }

        return true;
    }

    function isEmojiOnly(text) {
        if (!text || typeof text !== 'string') return false;
        try {
            const compact = text.replace(/\s+/g, '');
            return compact.length > 0 && /^[\p{Extended_Pictographic}\uFE0F\u200D]+$/u.test(compact);
        } catch {
            return false;
        }
    }

    function formatTimeOnly(value) {
        if (!value) return '';
        const d = new Date(value);
        const hh = String(d.getHours()).padStart(2, '0');
        const mm = String(d.getMinutes()).padStart(2, '0');
        return `${hh}:${mm}`;
    }

    function formatRelativeTimeShort(dateString) {
        const date = new Date(dateString);
        const now = new Date();
        const diffMs = now - date;
        const diffSec = Math.floor(diffMs / 1000);
        const diffMin = Math.floor(diffSec / 60);
        const diffHour = Math.floor(diffMin / 60);

        if (diffSec < 60) return '방금';
        if (diffMin < 60) return `${diffMin}분`;
        if (diffHour < 24) return `${diffHour}시간`;

        const mm = String(date.getMonth() + 1).padStart(2, '0');
        const dd = String(date.getDate()).padStart(2, '0');
        return `${mm}/${dd}`;
    }

    function renderGroupMessageItem(item, currentUser) {
        const isMe = currentUser && item.user?.id === currentUser.id;
        const time = formatTimeOnly(item.created_at);
        const messageText = item.content || '';
        const emojiOnlyClass = isEmojiOnly(messageText) ? ' emoji-only' : '';
        const row = document.createElement('div');
        row.className = `global-dm-message ${isMe ? 'me' : 'other'}`;

        if (!isMe) {
            const avatarWrap = document.createElement('div');
            avatarWrap.className = 'global-dm-message-avatar';
            Utils.setAvatar(avatarWrap, {
                url: item.user?.avatar_url || '',
                alt: item.user?.nickname || '',
                placeholder: '?',
                placeholderClass: 'avatar-placeholder',
            });
            row.appendChild(avatarWrap);
        }

        const content = document.createElement('div');
        content.className = 'global-dm-message-content';
        const text = document.createElement('div');
        text.className = `global-dm-message-text${emojiOnlyClass}`;
        text.textContent = messageText;
        const timeEl = document.createElement('div');
        timeEl.className = 'global-dm-message-time';
        timeEl.textContent = `${item.user?.nickname || ''} · ${time}`.trim();
        content.append(text, timeEl);
        row.appendChild(content);
        return row;
    }

    function renderThreadItem(thread, unreadMap, onOpen) {
        const user = thread.other_user || {};
        const nickname = user.nickname || '알 수 없음';
        const time = thread.last_message_at ? formatRelativeTimeShort(thread.last_message_at) : '';
        const message = thread.last_message || '대화를 시작해보세요.';
        const unreadCount = unreadMap[user.id] || 0;
        const row = document.createElement('div');
        row.className = 'global-dm-thread';
        row.dataset.userId = String(user.id || '');
        row.dataset.nickname = nickname;
        row.addEventListener('click', () => onOpen?.(user.id, nickname));

        const avatarWrap = document.createElement('div');
        avatarWrap.className = 'global-dm-thread-avatar';
        Utils.setAvatar(avatarWrap, {
            url: user.avatar_url || '',
            alt: nickname,
            placeholder: '?',
            placeholderClass: 'avatar-placeholder',
        });

        const info = document.createElement('div');
        info.className = 'global-dm-thread-info';
        const nameEl = document.createElement('div');
        nameEl.className = 'global-dm-thread-name';
        nameEl.textContent = nickname;
        const msgEl = document.createElement('div');
        msgEl.className = 'global-dm-thread-msg';
        msgEl.textContent = message;
        info.append(nameEl, msgEl);

        const meta = document.createElement('div');
        meta.className = 'global-dm-thread-meta';
        const timeEl = document.createElement('div');
        timeEl.className = 'global-dm-thread-time';
        timeEl.textContent = time;
        meta.appendChild(timeEl);
        if (unreadCount) {
            const badge = document.createElement('div');
            badge.className = 'global-dm-thread-badge';
            badge.textContent = String(unreadCount);
            meta.appendChild(badge);
        }

        row.append(avatarWrap, info, meta);
        return row;
    }

    function setMessagesEmpty(root, state, message) {
        if (!root) return;
        root.replaceChildren(createEmpty(message));
        if (state) {
            state.signature = 'empty';
            state.ids = [];
        }
    }

    function renderDirectMessageItem(item, currentUser) {
        const isMe = currentUser && item.sender?.id === currentUser.id;
        const time = formatTimeOnly(item.created_at);
        const messageText = item.message || '';
        const emojiOnlyClass = isEmojiOnly(messageText) ? ' emoji-only' : '';
        const row = document.createElement('div');
        row.className = `global-dm-message ${isMe ? 'me' : 'other'}`;

        if (!isMe) {
            const avatarWrap = document.createElement('div');
            avatarWrap.className = 'global-dm-message-avatar';
            Utils.setAvatar(avatarWrap, {
                url: item.sender?.avatar_url || '',
                alt: item.sender?.nickname || '',
                placeholder: '?',
                placeholderClass: 'avatar-placeholder',
            });
            row.appendChild(avatarWrap);
        }

        const content = document.createElement('div');
        content.className = 'global-dm-message-content';
        const text = document.createElement('div');
        text.className = `global-dm-message-text${emojiOnlyClass}`;
        text.textContent = messageText;
        const timeEl = document.createElement('div');
        timeEl.className = 'global-dm-message-time';
        timeEl.textContent = time;
        content.append(text, timeEl);
        row.appendChild(content);
        return row;
    }

    window.GlobalDMUI = {
        buildUnreadMap,
        formatRelativeTimeShort,
        formatTimeOnly,
        renderDirectMessageItem,
        renderGroupMessageItem,
        renderThreadItem,
        setChannelEmpty,
        setChannelReady,
        setMessagesEmpty,
        setThreadListEmpty,
        syncMessageList,
        updateGlobalBadge,
    };
})();
