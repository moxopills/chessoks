(function() {
    'use strict';

    function getDefaultEmojis() {
        if (window.Utils?.getDefaultEmojiList) {
            return window.Utils.getDefaultEmojiList();
        }
        return ['😀', '😂', '👍', '🔥', '👏', '🙏'];
    }

    function appendEmoji(inputEl, emoji) {
        if (!inputEl || !emoji) return;
        inputEl.value += emoji;
        inputEl.focus();
    }

    function bindEmojiButtons(scopeEl, inputEl, selector = '.emoji-btn') {
        if (!scopeEl || !inputEl) return;
        scopeEl.querySelectorAll(selector).forEach((button) => {
            if (button.dataset.chatUiBound === 'true') return;
            button.dataset.chatUiBound = 'true';
            button.addEventListener('click', () => {
                appendEmoji(inputEl, button.dataset.emoji || button.textContent || '');
                window.Utils?.Sounds?.unlock?.();
            });
        });
    }

    function ensureEmojiBar(formEl, inputEl, options = {}) {
        if (!formEl || !inputEl) return null;

        const {
            barClassName = 'chat-emoji-bar',
            buttonClassName = 'emoji-btn',
            buttonSelector = '.emoji-btn',
            emojis = getDefaultEmojis(),
        } = options;

        const anchorClass = barClassName.split(' ')[0];
        const previous = formEl.previousElementSibling;
        if (previous?.classList?.contains(anchorClass)) {
            bindEmojiButtons(previous, inputEl, buttonSelector);
            return previous;
        }

        const bar = document.createElement('div');
        bar.className = barClassName;
        emojis.forEach((emoji) => {
            const button = document.createElement('button');
            button.type = 'button';
            button.className = buttonClassName;
            button.dataset.emoji = emoji;
            button.textContent = emoji;
            bar.appendChild(button);
        });
        formEl.parentNode.insertBefore(bar, formEl);
        bindEmojiButtons(bar, inputEl, buttonSelector);
        return bar;
    }

    function scrollToBottom(containerEl) {
        if (!containerEl) return;
        containerEl.scrollTop = containerEl.scrollHeight;
    }

    window.ChatUI = {
        appendEmoji,
        bindEmojiButtons,
        ensureEmojiBar,
        scrollToBottom,
    };
})();
