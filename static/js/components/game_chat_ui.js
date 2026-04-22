(function() {
    'use strict';

    function addNotice(chatMessages, text) {
        if (!chatMessages) return;
        const noticeEl = document.createElement('div');
        noticeEl.className = 'chat-notice';
        noticeEl.textContent = text;
        chatMessages.appendChild(noticeEl);
        ChatUI?.scrollToBottom(chatMessages);
    }

    function addMessage({
        chatMessages,
        data,
        currentUserId,
        onBadge,
        onSound,
        onReact,
    }) {
        if (!chatMessages) return;
        const isMine = currentUserId && data.user_id === currentUserId;
        const messageEl = document.createElement('div');
        messageEl.className = `chat-message ${isMine ? 'mine' : 'others'}`;
        if (data.message_id) {
            messageEl.dataset.messageId = String(data.message_id);
        }
        if (!isMine) {
            const avatarWrap = document.createElement('div');
            avatarWrap.className = 'chat-avatar';
            Utils.setAvatar(avatarWrap, {
                url: data.avatar_url,
                alt: data.nickname || '',
                placeholder: '?',
                placeholderClass: 'avatar-placeholder',
            });
            messageEl.appendChild(avatarWrap);
        }

        const contentEl = document.createElement('div');
        contentEl.className = 'chat-content';

        const nicknameEl = document.createElement('span');
        nicknameEl.className = 'chat-nickname';
        nicknameEl.textContent = data.nickname || '';
        contentEl.appendChild(nicknameEl);

        const bubbleEl = document.createElement('div');
        bubbleEl.className = 'chat-bubble';
        bubbleEl.textContent = data.message || '';
        contentEl.appendChild(bubbleEl);

        ChatReactions?.ensureReactionBar(contentEl, {
            reactions: data.reactions || {},
            myReactions: data.my_reactions || [],
        });
        messageEl.appendChild(contentEl);

        chatMessages.appendChild(messageEl);
        ChatUI?.scrollToBottom(chatMessages);
        if (!isMine) onSound?.();
        onBadge?.(data);

        ChatReactions?.bindReactionButtons(messageEl, {
            onReact: ({ messageId, reaction, button }) => {
                if (!messageId || !reaction) return;
                button?.classList.toggle('active');
                onReact?.({ messageId, reaction });
            },
        });
    }

    function resetBadge(chatBadge, chatFabBadge) {
        if (chatBadge) {
            chatBadge.textContent = '0';
            chatBadge.classList.add('hidden');
        }
        if (chatFabBadge) {
            chatFabBadge.textContent = '0';
            chatFabBadge.classList.add('hidden');
        }
    }

    window.GameChatUI = {
        addNotice,
        addMessage,
        resetBadge,
    };
})();
