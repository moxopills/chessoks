/**
 * Utility Functions
 */

const Utils = (function() {
    /**
     * DOM 요소 선택
     */
    function $(selector) {
        return document.querySelector(selector);
    }

    function $$(selector) {
        return document.querySelectorAll(selector);
    }

    /**
     * 시간 포맷팅 (mm:ss)
     */
    function formatTime(seconds) {
        if (seconds < 0) seconds = 0;
        const mins = Math.floor(seconds / 60);
        const secs = Math.floor(seconds % 60);
        return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    }

    /**
     * 상대 시간 포맷팅 (몇 분 전, 몇 시간 전 등)
     */
    function formatRelativeTime(dateString) {
        const date = new Date(dateString);
        const now = new Date();
        const diffMs = now - date;
        const diffSec = Math.floor(diffMs / 1000);
        const diffMin = Math.floor(diffSec / 60);
        const diffHour = Math.floor(diffMin / 60);
        const diffDay = Math.floor(diffHour / 24);

        if (diffSec < 60) return '방금 전';
        if (diffMin < 60) return `${diffMin}분 전`;
        if (diffHour < 24) return `${diffHour}시간 전`;
        if (diffDay < 7) return `${diffDay}일 전`;

        return date.toLocaleDateString('ko-KR');
    }

    /**
     * 날짜 포맷팅
     */
    function formatDate(dateString, options = {}) {
        const date = new Date(dateString);
        const defaultOptions = {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            ...options
        };
        return date.toLocaleDateString('ko-KR', defaultOptions);
    }

    /**
     * 디바운스
     */
    function debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    /**
     * 쓰로틀
     */
    function throttle(func, limit) {
        let inThrottle;
        return function executedFunction(...args) {
            if (!inThrottle) {
                func(...args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    }

    /**
     * HTML 이스케이프
     */
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * 클래스 토글 헬퍼
     */
    function toggleClass(element, className, condition) {
        if (condition) {
            element.classList.add(className);
        } else {
            element.classList.remove(className);
        }
    }

    /**
     * 로컬 스토리지 헬퍼
     */
    const Storage = {
        get(key, defaultValue = null) {
            try {
                const item = localStorage.getItem(key);
                return item ? JSON.parse(item) : defaultValue;
            } catch {
                return defaultValue;
            }
        },

        set(key, value) {
            try {
                localStorage.setItem(key, JSON.stringify(value));
                return true;
            } catch {
                return false;
            }
        },

        remove(key) {
            localStorage.removeItem(key);
        }
    };

    /**
     * URL 파라미터 파싱
     */
    function getUrlParams() {
        const params = new URLSearchParams(window.location.search);
        const result = {};
        for (const [key, value] of params) {
            result[key] = value;
        }
        return result;
    }

    /**
     * URL에서 경로 파라미터 추출 (예: /rooms/123/ -> 123)
     */
    function getPathParam(pattern, path = window.location.pathname) {
        const regex = new RegExp(pattern);
        const match = path.match(regex);
        return match ? match[1] : null;
    }

    /**
     * 숫자 포맷팅 (천 단위 콤마)
     */
    function formatNumber(num) {
        return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    }

    /**
     * 승률 계산
     */
    function calculateWinRate(wins, total) {
        if (total === 0) return 0;
        return Math.round((wins / total) * 100);
    }

    /**
     * 랭크 티어 색상
     */
    function getTierColor(tier) {
        return '#a0a0a0';
    }

    /**
     * 랭크 티어 아이콘
     */
    function getTierIcon(tier) {
        const icons = {
            'Unranked': '❔',
            'Beginner': '🥉',
            'Junior': '🥈',
            'Intermediate': '🥇',
            'Advanced': '🔷',
            'Expert': '💎',
            'Master': '👑',
        };
        return icons[tier] || '♟️';
    }

    /**
     * 더블 탭 바인딩 (모바일용)
     */
    function bindDoubleTap(element, { single, double, threshold = 260 } = {}) {
        if (!element) return () => {};
        let lastTap = 0;
        let timer = null;
        const handler = (event) => {
            const now = Date.now();
            if (now - lastTap < threshold) {
                lastTap = 0;
                if (timer) {
                    clearTimeout(timer);
                    timer = null;
                }
                if (double) double(event);
                return;
            }
            lastTap = now;
            if (timer) clearTimeout(timer);
            timer = setTimeout(() => {
                lastTap = 0;
                timer = null;
                if (single) single(event);
            }, threshold);
        };
        element.addEventListener('touchend', handler);
        element.addEventListener('touchcancel', () => {
            lastTap = 0;
            if (timer) {
                clearTimeout(timer);
                timer = null;
            }
        });
        return () => {
            element.removeEventListener('touchend', handler);
        };
    }

    const Sounds = (() => {
        let ctx = null;

        function getContext() {
            if (!ctx) {
                const AudioContext = window.AudioContext || window.webkitAudioContext;
                if (!AudioContext) return null;
                ctx = new AudioContext();
            }
            return ctx;
        }

        function playTone(freq, duration = 0.12, volume = 0.12) {
            try {
                const context = getContext();
                if (!context) return;
                if (context.state === 'suspended') context.resume();
                const osc = context.createOscillator();
                const gain = context.createGain();
                osc.type = 'sine';
                osc.frequency.value = freq;
                gain.gain.value = 0.0001;
                osc.connect(gain);
                gain.connect(context.destination);
                osc.start();
                gain.gain.exponentialRampToValueAtTime(volume, context.currentTime + 0.01);
                gain.gain.exponentialRampToValueAtTime(0.0001, context.currentTime + duration);
                osc.stop(context.currentTime + duration + 0.02);
            } catch {
                // ignore
            }
        }

        function notice() {
            playTone(880, 0.16, 0.1);
            setTimeout(() => playTone(1320, 0.12, 0.08), 90);
        }

        function chat() {
            playTone(880, 0.12, 0.06);
        }

        function move() {
            playTone(440, 0.08, 0.05);
        }

        return { notice, chat, move };
    })();

    const ReportModal = (() => {
        let modal;
        let categoryEl;
        let messageEl;
        let cancelBtn;
        let submitBtn;
        let targetId = null;
        let initialized = false;

        function init() {
            if (initialized) return;
            modal = document.getElementById('report-modal');
            if (!modal) {
                initialized = true;
                return;
            }
            categoryEl = document.getElementById('report-category');
            messageEl = document.getElementById('report-message');
            cancelBtn = document.getElementById('report-cancel');
            submitBtn = document.getElementById('report-submit');

            cancelBtn?.addEventListener('click', () => {
                close();
            });

            modal.addEventListener('click', (event) => {
                if (event.target === modal) close();
            });

            submitBtn?.addEventListener('click', async () => {
                if (!targetId || !submitBtn) return;
                submitBtn.disabled = true;
                try {
                    await API.post('/reports/', {
                        target_id: targetId,
                        category: categoryEl?.value || 'other',
                        description: (messageEl?.value || '').trim(),
                    });
                    Toast.success('신고가 접수되었습니다.');
                    close();
                } catch (error) {
                    Toast.error(error.data?.message || '신고에 실패했습니다.');
                } finally {
                    submitBtn.disabled = false;
                }
            });

            initialized = true;
        }

        function open(target) {
            init();
            if (!modal) return;
            targetId = target;
            if (categoryEl) categoryEl.value = 'other';
            if (messageEl) messageEl.value = '';
            modal.classList.remove('hidden');
        }

        function close() {
            if (!modal) return;
            modal.classList.add('hidden');
            targetId = null;
            if (messageEl) messageEl.value = '';
        }

        return { open };
    })();

    // Public API
    return {
        $,
        $$,
        formatTime,
        formatRelativeTime,
        formatDate,
        debounce,
        throttle,
        escapeHtml,
        toggleClass,
        Storage,
        getUrlParams,
        getPathParam,
        formatNumber,
        calculateWinRate,
        getTierColor,
        getTierIcon,
        bindDoubleTap,
        ReportModal,
        Sounds,
    };
})();
