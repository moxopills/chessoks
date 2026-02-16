/**
 * Modal Component
 * - prompt(), confirm() 대체 커스텀 모달
 * - 일관된 UX 제공
 */

const Modal = (function() {
    'use strict';

    let modalContainer = null;

    function init() {
        if (modalContainer) return;
        modalContainer = document.createElement('div');
        modalContainer.id = 'modal-container';
        modalContainer.innerHTML = `
            <div class="modal-overlay hidden" id="custom-modal">
                <div class="modal-dialog">
                    <div class="modal-header">
                        <h3 class="modal-title" id="modal-title"></h3>
                    </div>
                    <div class="modal-body">
                        <p class="modal-message" id="modal-message"></p>
                        <input type="text" class="form-input modal-input hidden" id="modal-input" />
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-secondary" id="modal-cancel">취소</button>
                        <button class="btn btn-primary" id="modal-confirm">확인</button>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modalContainer);

        // 오버레이 클릭으로 닫기
        const overlay = document.getElementById('custom-modal');
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) {
                closeModal(null);
            }
        });

        // ESC 키로 닫기
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && !overlay.classList.contains('hidden')) {
                closeModal(null);
            }
        });
    }

    let currentResolve = null;

    function closeModal(result) {
        const overlay = document.getElementById('custom-modal');
        const input = document.getElementById('modal-input');
        overlay.classList.add('hidden');
        input.value = '';
        input.classList.add('hidden');
        if (currentResolve) {
            currentResolve(result);
            currentResolve = null;
        }
    }

    /**
     * 확인 모달 (confirm 대체)
     * @param {string} message - 메시지
     * @param {Object} options - 옵션 { title, confirmText, cancelText, danger }
     * @returns {Promise<boolean>}
     */
    function confirm(message, options = {}) {
        init();
        return new Promise((resolve) => {
            currentResolve = resolve;

            const overlay = document.getElementById('custom-modal');
            const titleEl = document.getElementById('modal-title');
            const messageEl = document.getElementById('modal-message');
            const inputEl = document.getElementById('modal-input');
            const cancelBtn = document.getElementById('modal-cancel');
            const confirmBtn = document.getElementById('modal-confirm');

            titleEl.textContent = options.title || '확인';
            messageEl.textContent = message;
            inputEl.classList.add('hidden');

            cancelBtn.textContent = options.cancelText || '취소';
            confirmBtn.textContent = options.confirmText || '확인';

            confirmBtn.className = options.danger
                ? 'btn btn-danger'
                : 'btn btn-primary';

            const onConfirm = () => {
                cleanup();
                closeModal(true);
            };
            const onCancel = () => {
                cleanup();
                closeModal(false);
            };

            function cleanup() {
                confirmBtn.removeEventListener('click', onConfirm);
                cancelBtn.removeEventListener('click', onCancel);
            }

            confirmBtn.addEventListener('click', onConfirm);
            cancelBtn.addEventListener('click', onCancel);

            overlay.classList.remove('hidden');
            confirmBtn.focus();
        });
    }

    /**
     * 입력 모달 (prompt 대체)
     * @param {string} message - 메시지
     * @param {Object} options - 옵션 { title, placeholder, inputType, confirmText, cancelText }
     * @returns {Promise<string|null>}
     */
    function prompt(message, options = {}) {
        init();
        return new Promise((resolve) => {
            currentResolve = resolve;

            const overlay = document.getElementById('custom-modal');
            const titleEl = document.getElementById('modal-title');
            const messageEl = document.getElementById('modal-message');
            const inputEl = document.getElementById('modal-input');
            const cancelBtn = document.getElementById('modal-cancel');
            const confirmBtn = document.getElementById('modal-confirm');

            titleEl.textContent = options.title || '입력';
            messageEl.textContent = message;
            inputEl.classList.remove('hidden');
            inputEl.type = options.inputType || 'text';
            inputEl.placeholder = options.placeholder || '';
            inputEl.value = options.defaultValue || '';

            cancelBtn.textContent = options.cancelText || '취소';
            confirmBtn.textContent = options.confirmText || '확인';
            confirmBtn.className = 'btn btn-primary';

            const onConfirm = () => {
                const value = inputEl.value.trim();
                cleanup();
                closeModal(value || null);
            };
            const onCancel = () => {
                cleanup();
                closeModal(null);
            };
            const onKeydown = (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    onConfirm();
                }
            };

            function cleanup() {
                confirmBtn.removeEventListener('click', onConfirm);
                cancelBtn.removeEventListener('click', onCancel);
                inputEl.removeEventListener('keydown', onKeydown);
            }

            confirmBtn.addEventListener('click', onConfirm);
            cancelBtn.addEventListener('click', onCancel);
            inputEl.addEventListener('keydown', onKeydown);

            overlay.classList.remove('hidden');
            inputEl.focus();
        });
    }

    /**
     * 알림 모달 (alert 대체)
     * @param {string} message - 메시지
     * @param {Object} options - 옵션 { title, confirmText }
     * @returns {Promise<void>}
     */
    function alert(message, options = {}) {
        init();
        return new Promise((resolve) => {
            currentResolve = resolve;

            const overlay = document.getElementById('custom-modal');
            const titleEl = document.getElementById('modal-title');
            const messageEl = document.getElementById('modal-message');
            const inputEl = document.getElementById('modal-input');
            const cancelBtn = document.getElementById('modal-cancel');
            const confirmBtn = document.getElementById('modal-confirm');

            titleEl.textContent = options.title || '알림';
            messageEl.textContent = message;
            inputEl.classList.add('hidden');

            cancelBtn.classList.add('hidden');
            confirmBtn.textContent = options.confirmText || '확인';
            confirmBtn.className = 'btn btn-primary';

            const onConfirm = () => {
                cleanup();
                cancelBtn.classList.remove('hidden');
                closeModal(undefined);
            };

            function cleanup() {
                confirmBtn.removeEventListener('click', onConfirm);
            }

            confirmBtn.addEventListener('click', onConfirm);

            overlay.classList.remove('hidden');
            confirmBtn.focus();
        });
    }

    return {
        confirm,
        prompt,
        alert
    };
})();

// 전역 사용
if (typeof window !== 'undefined') {
    window.Modal = Modal;
}
