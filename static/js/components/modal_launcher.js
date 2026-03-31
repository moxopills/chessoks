(function() {
    'use strict';

    function bind({
        openButton,
        modal,
        closeButton,
        closeOnOverlay = true,
        closeOnEscape = true,
    } = {}) {
        if (!openButton || !modal) {
            return { open() {}, close() {}, destroy() {} };
        }

        const close = () => modal.classList.add('hidden');
        const open = () => modal.classList.remove('hidden');

        const overlayHandler = (event) => {
            if (closeOnOverlay && event.target === modal) {
                close();
            }
        };
        const escapeHandler = (event) => {
            if (closeOnEscape && event.key === 'Escape' && !modal.classList.contains('hidden')) {
                close();
            }
        };

        openButton.addEventListener('click', open);
        closeButton?.addEventListener('click', close);
        modal.addEventListener('click', overlayHandler);
        document.addEventListener('keydown', escapeHandler);

        return {
            open,
            close,
            destroy() {
                openButton.removeEventListener('click', open);
                closeButton?.removeEventListener('click', close);
                modal.removeEventListener('click', overlayHandler);
                document.removeEventListener('keydown', escapeHandler);
            },
        };
    }

    window.ModalLauncher = { bind };
})();
