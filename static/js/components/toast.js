/**
 * Toast Notification Component
 */

const Toast = (function() {
    const DURATION = 4000;
    const container = document.getElementById('toast-container');

    // 타입별 아이콘
    const ICONS = {
        success: '✓',
        error: '✕',
        warning: '⚠',
        info: 'ℹ'
    };

    /**
     * 토스트 생성
     */
    function show(message, type = 'info') {
        if (!container) return;

        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;

        const icon = ICONS[type] || ICONS.info;
        toast.innerHTML = `<span class="toast-icon">${icon}</span><span class="toast-message">${Utils.escapeHtml(message)}</span>`;

        container.appendChild(toast);

        // 자동 제거
        setTimeout(() => {
            remove(toast);
        }, DURATION);

        // 클릭으로 제거
        toast.addEventListener('click', () => {
            remove(toast);
        });

        return toast;
    }

    /**
     * 토스트 제거
     */
    function remove(toast) {
        toast.style.animation = 'slideOut 0.3s ease forwards';
        setTimeout(() => {
            toast.remove();
        }, 300);
    }

    /**
     * 성공 토스트
     */
    function success(message) {
        return show(message, 'success');
    }

    /**
     * 에러 토스트
     */
    function error(message) {
        return show(message, 'error');
    }

    /**
     * 경고 토스트
     */
    function warning(message) {
        return show(message, 'warning');
    }

    /**
     * 정보 토스트
     */
    function info(message) {
        return show(message, 'info');
    }

    // Public API
    return {
        show,
        success,
        error,
        warning,
        info,
    };
})();
