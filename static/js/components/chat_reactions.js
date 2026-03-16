(function() {
    'use strict';

    const DEFAULT_REACTIONS = ['👍', '👏'];

    function createReactionBar({
        reactions = {},
        myReactions = [],
        emojis = DEFAULT_REACTIONS,
    } = {}) {
        const wrapper = document.createElement('div');
        wrapper.className = 'chat-reactions';

        emojis.forEach((emoji) => {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = `reaction-btn ${myReactions.includes(emoji) ? 'active' : ''}`.trim();
            btn.dataset.reaction = emoji;
            btn.appendChild(document.createTextNode(`${emoji} `));
            const count = document.createElement('span');
            count.textContent = String(Number(reactions?.[emoji] ?? 0));
            btn.appendChild(count);
            wrapper.appendChild(btn);
        });

        return wrapper;
    }

    function bindReactionButtons(rootEl, { getMessageId, onReact } = {}) {
        if (!rootEl) return;
        rootEl.querySelectorAll('.reaction-btn').forEach((btn) => {
            if (btn.dataset.reactionBound === 'true') return;
            btn.dataset.reactionBound = 'true';
            btn.addEventListener('click', () => {
                const reaction = btn.dataset.reaction;
                const messageId = getMessageId?.(btn) || btn.closest('.chat-message')?.dataset.messageId;
                if (!reaction || !messageId) return;
                onReact?.({ reaction, messageId, button: btn });
            });
        });
    }

    function applyReactionUpdate(rootEl, reactions = {}, myReactions = []) {
        if (!rootEl) return;
        rootEl.querySelectorAll('.reaction-btn').forEach((btn) => {
            const emoji = btn.dataset.reaction;
            const countEl = btn.querySelector('span');
            if (!emoji || !countEl) return;
            countEl.textContent = String(Number(reactions?.[emoji] ?? 0));
            btn.classList.toggle('active', Array.isArray(myReactions) && myReactions.includes(emoji));
        });
    }

    function ensureReactionBar(containerEl, options = {}) {
        if (!containerEl) return null;
        let bar = containerEl.querySelector('.chat-reactions');
        if (!bar) {
            bar = createReactionBar(options);
            containerEl.appendChild(bar);
        } else {
            applyReactionUpdate(bar, options.reactions, options.myReactions);
        }
        return bar;
    }

    window.ChatReactions = {
        createReactionBar,
        bindReactionButtons,
        applyReactionUpdate,
        ensureReactionBar,
    };
})();
