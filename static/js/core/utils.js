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
     * 안전한 URL만 허용 (http/https 또는 현재 origin 상대경로)
     */
    function sanitizeUrl(url, fallback = '') {
        const raw = String(url || '').trim();
        if (!raw) return fallback;
        try {
            const parsed = new URL(raw, window.location.origin);
            if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
                return parsed.href;
            }
            return fallback;
        } catch {
            return fallback;
        }
    }

    /**
     * 아바타 공통 렌더링
     */
    function setAvatar(el, {
        url = '',
        alt = 'avatar',
        placeholder = '?',
        placeholderClass = 'avatar-placeholder',
    } = {}) {
        if (!el) return;
        el.textContent = '';

        const safeUrl = sanitizeUrl(url, '');
        if (safeUrl) {
            const img = document.createElement('img');
            const fallbackSize = Math.max(el.clientWidth || 0, el.clientHeight || 0, 32);
            img.src = safeUrl;
            img.alt = String(alt || 'avatar');
            img.loading = 'lazy';
            img.decoding = 'async';
            img.referrerPolicy = 'no-referrer';
            img.width = fallbackSize;
            img.height = fallbackSize;
            el.appendChild(img);
            return;
        }

        const span = document.createElement('span');
        span.className = placeholderClass;
        span.textContent = String(placeholder || '?');
        el.appendChild(span);
    }

    /**
     * HTML 문자열 최소 안전화 (script/on* 제거, javascript: URL 차단)
     */
    function sanitizeHtml(html) {
        const template = document.createElement('template');
        template.innerHTML = String(html || '');

        const blockedTags = ['script', 'iframe', 'object', 'embed'];
        blockedTags.forEach((tag) => {
            template.content.querySelectorAll(tag).forEach((el) => el.remove());
        });

        template.content.querySelectorAll('*').forEach((el) => {
            [...el.attributes].forEach((attr) => {
                const name = attr.name.toLowerCase();
                const value = String(attr.value || '').trim();
                if (name.startsWith('on')) {
                    el.removeAttribute(attr.name);
                    return;
                }
                if ((name === 'href' || name === 'src' || name === 'xlink:href') && /^javascript:/i.test(value)) {
                    el.removeAttribute(attr.name);
                    return;
                }
                if (name === 'srcdoc') {
                    el.removeAttribute(attr.name);
                    return;
                }
            });
        });
        return template.innerHTML;
    }

    /**
     * sanitize 후 innerHTML 반영
     */
    function setSafeHtml(el, html) {
        if (!el) return;
        el.innerHTML = sanitizeHtml(html);
    }

    function appendSafeHtml(el, html) {
        if (!el) return;
        const template = document.createElement('template');
        template.innerHTML = sanitizeHtml(html);
        el.appendChild(template.content);
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
     * 게임 결과 라벨 (승/패/무)
     */
    const DRAW_RESULTS = new Set([
        'draw', 'draw_agreement', 'draw_insufficient',
        'draw_repetition', 'draw_fifty_move', 'stalemate',
    ]);
    const WHITE_WIN_RESULTS = new Set([
        'white_win', 'checkmate_white', 'timeout_black', 'resignation_black',
    ]);
    const BLACK_WIN_RESULTS = new Set([
        'black_win', 'checkmate_black', 'timeout_white', 'resignation_white',
    ]);

    function getGameResultLabel(result, isWhite) {
        if (!result) return '-';
        if (result === 'playing') return '진행';
        if (DRAW_RESULTS.has(result)) return '무';
        if (WHITE_WIN_RESULTS.has(result)) return isWhite ? '승' : '패';
        if (BLACK_WIN_RESULTS.has(result)) return isWhite ? '패' : '승';
        return '종료';
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

    function getNicknameColorValue(key) {
        const colorMap = {
            mint: '#2dd4bf',
            sunset: '#fb7185',
            gold: '#f59e0b',
        };
        return colorMap[key] || '';
    }

    function getProfileBorderValue(key) {
        const borderMap = {
            mint_ring: '0 0 0 3px rgba(45, 212, 191, 0.45)',
            royal_ring: '0 0 0 3px rgba(99, 102, 241, 0.45)',
            champion_ring: '0 0 0 3px rgba(245, 158, 11, 0.45)',
        };
        return borderMap[key] || '';
    }

    function getProfileCardFrameClass(key) {
        const classMap = {
            season_champion_frame: 'season-frame-champion',
            season_runnerup_frame: 'season-frame-runnerup',
            season_third_frame: 'season-frame-third',
            season_top10_frame: 'season-frame-top10',
        };
        return classMap[key] || '';
    }

    function getDefaultEmojiList() {
        return ['😊', '😂', '👍', '🔥', '👏', '🤔', '😮', '🙏'];
    }

    let statusBadgeTimer = null;
    function showStatusBadge(message, type = 'waiting', duration = 1600) {
        if (!message) return;
        let badge = document.getElementById('global-status-badge');
        if (!badge) {
            badge = document.createElement('div');
            badge.id = 'global-status-badge';
            badge.className = 'global-status-badge';
            badge.setAttribute('role', 'status');
            badge.setAttribute('aria-live', 'polite');
            document.body.appendChild(badge);
        }
        badge.className = `global-status-badge global-status-badge--${type}`;
        badge.textContent = String(message);
        badge.classList.remove('hidden');

        if (statusBadgeTimer) clearTimeout(statusBadgeTimer);
        statusBadgeTimer = setTimeout(() => {
            badge.classList.add('hidden');
        }, Math.max(600, duration));
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

    function createAdaptivePoller({
        callback,
        activeInterval = 5000,
        hiddenInterval = 15000,
        enabled = () => true,
        immediate = true,
    } = {}) {
        let timer = null;
        let running = false;
        let started = false;

        async function tick() {
            if (!started) return;
            if (!enabled()) {
                schedule();
                return;
            }
            if (running) {
                schedule();
                return;
            }
            running = true;
            try {
                await callback?.();
            } finally {
                running = false;
                schedule();
            }
        }

        function getDelay() {
            return document.hidden ? hiddenInterval : activeInterval;
        }

        function schedule() {
            if (!started) return;
            clearTimeout(timer);
            timer = setTimeout(tick, getDelay());
        }

        function start() {
            if (started) return;
            started = true;
            if (immediate) {
                tick();
            } else {
                schedule();
            }
        }

        function stop() {
            started = false;
            clearTimeout(timer);
            timer = null;
        }

        function trigger() {
            if (!started) return;
            clearTimeout(timer);
            tick();
        }

        return { start, stop, trigger };
    }

    const Sounds = (() => {
        let ctx = null;
        let bgmAudio = null;
        let bgmTimer = null;
        let bgmStep = 0;
        let bgmVolume = normalizeVolume(Storage.get('chessok-bgm-vol', 30));
        let isMuted = (bgmVolume === 0);

        function normalizeVolume(value) {
            const num = parseInt(value, 10);
            return isNaN(num) ? 30 : Math.max(0, Math.min(100, num));
        }

        function getContext() {
            try {
                if (!ctx) {
                    const AudioContext = window.AudioContext || window.webkitAudioContext;
                    if (!AudioContext) return null;
                    ctx = new AudioContext();
                }
                return ctx;
            } catch (e) {
                return null;
            }
        }

        function ensureContextRunning() {
            const context = getContext();
            if (!context) return Promise.resolve(null);
            if (context.state === 'running') return Promise.resolve(context);
            return context.resume().then(() => context).catch(() => context);
        }

        const BGM_URL = null;

        function initBGM() {
            if (!BGM_URL) return;
            if (!bgmAudio) {
                bgmAudio = new Audio(BGM_URL);
                bgmAudio.crossOrigin = "anonymous";
                bgmAudio.loop = true;
                bgmAudio.preload = 'auto';
                bgmAudio.addEventListener('playing', () => {
                    stopSynthBGM();
                });
                bgmAudio.addEventListener('error', () => {
                    if (!isMuted && bgmVolume > 0) startSynthBGM();
                });
                bgmAudio.addEventListener('stalled', () => {
                    if (!isMuted && bgmVolume > 0) startSynthBGM();
                });
            }
            bgmAudio.volume = bgmVolume / 100;
        }

        function startSynthBGM() {
            if (bgmTimer) return;
            // 업템포 칩튠 아케이드 패턴
            const seq = [523, 659, 784, 988, 784, 659, 523, 392];
            bgmTimer = setInterval(() => {
                if (isMuted || bgmVolume === 0) return;
                const freq = seq[bgmStep % seq.length];
                bgmStep += 1;
                playTone(freq, 0.16, Math.max(0.02, (bgmVolume / 100) * 0.09), 'square');
                if (bgmStep % 2 === 0) {
                    playTone(freq / 2, 0.12, Math.max(0.01, (bgmVolume / 100) * 0.045), 'triangle');
                }
            }, 260);
        }

        function stopSynthBGM() {
            if (bgmTimer) {
                clearInterval(bgmTimer);
                bgmTimer = null;
            }
        }

        function unlock() {
            try {
                ensureContextRunning();
                if (!isMuted && bgmVolume > 0) {
                    playBGM();
                }
            } catch (e) {}
        }

        function playTone(freq, duration = 0.12, volume = 0.12, wave = 'sine') {
            if (isMuted || bgmVolume === 0) return;
            try {
                ensureContextRunning().then((context) => {
                    if (!context || isMuted || bgmVolume === 0) return;
                    const osc = context.createOscillator();
                    const gain = context.createGain();
                    osc.type = wave;
                    osc.frequency.value = freq;
                    gain.gain.value = 0.0001;
                    osc.connect(gain);
                    gain.connect(context.destination);
                    osc.start();
                    gain.gain.exponentialRampToValueAtTime(volume, context.currentTime + 0.01);
                    gain.gain.exponentialRampToValueAtTime(0.0001, context.currentTime + duration);
                    osc.stop(context.currentTime + duration + 0.02);
                });
            } catch (e) {}
        }

        function vibrate(pattern) {
            if (isMuted || !navigator.vibrate) return;
            try { navigator.vibrate(pattern); } catch (e) {}
        }

        function notice() {
            playTone(880, 0.16, 0.1);
            setTimeout(() => playTone(1320, 0.12, 0.08), 90);
            vibrate([50, 50, 50]);
        }

        function chat() {
            playTone(880, 0.12, 0.06);
            vibrate([30, 50, 30]);
        }

        function move() {
            playTone(440, 0.08, 0.05);
            vibrate(15);
        }

        function setVolume(val) {
            bgmVolume = normalizeVolume(val);
            Storage.set('chessok-bgm-vol', bgmVolume);
            isMuted = (bgmVolume === 0);
            
            if (bgmAudio) {
                bgmAudio.volume = bgmVolume / 100;
                if (bgmVolume > 0 && bgmAudio.paused) {
                    bgmAudio.play().catch(() => startSynthBGM());
                } else if (bgmVolume === 0) {
                    bgmAudio.pause();
                }
            } else if (bgmVolume > 0) {
                playBGM();
            }
            if (bgmVolume === 0) {
                stopSynthBGM();
            }
            return isMuted;
        }

        function getVolume() {
            return bgmVolume;
        }

        function toggleMute() {
            if (bgmVolume > 0) {
                Storage.set('chessok-prev-vol', bgmVolume);
                setVolume(0);
            } else {
                let prev = normalizeVolume(Storage.get('chessok-prev-vol', 30));
                setVolume(prev || 30);
            }
            return isMuted;
        }

        function playBGM() {
            if (isMuted || bgmVolume === 0) return;
            // 즉시 배경음 보장(외부 음원 지연/실패 대비)
            startSynthBGM();
            initBGM();
            if (bgmAudio) {
                const playPromise = bgmAudio.play()
                    .then(() => stopSynthBGM())
                    .catch(() => startSynthBGM());
                // 일부 브라우저에서 play Promise가 resolve/reject 없이 지연될 수 있어 타임아웃 백업
                setTimeout(() => {
                    if (playPromise && bgmAudio && bgmAudio.paused && !isMuted && bgmVolume > 0) {
                        startSynthBGM();
                    }
                }, 1200);
            } else {
                startSynthBGM();
            }
        }

        // 페이지 어디서든 첫 사용자 제스처 시 오디오 언락
        if (typeof document !== 'undefined') {
            const onceUnlock = () => unlock();
            document.addEventListener('pointerdown', onceUnlock, { once: true });
            document.addEventListener('keydown', onceUnlock, { once: true });
        }

        return {
            notice, chat, move, vibrate, unlock,
            toggleMute, playBGM, setVolume, 
            getVolume: () => bgmVolume,
            isMuted: () => isMuted 
        };
    })();

    /**
     * 친구 요청 전송 (공통)
     * @returns {Promise<{success: boolean, accepted?: boolean}>}
     */
    async function sendFriendRequest(userId, currentUserId) {
        if (!currentUserId) {
            Toast.error('로그인 시 가능합니다.');
            return { success: false };
        }
        if (userId === currentUserId) {
            Toast.error('자기 자신에게 요청할 수 없습니다.');
            return { success: false };
        }
        try {
            const result = await API.post('/accounts/friends/requests/', { user_id: userId });
            if (result.status === 'accepted') {
                Toast.success('친구 요청이 자동 수락되었습니다.');
                return { success: true, accepted: true };
            }
            Toast.success('친구 요청을 보냈습니다.');
            return { success: true, accepted: false };
        } catch (error) {
            Toast.error(error.data?.message || '친구 요청에 실패했습니다.');
            return { success: false };
        }
    }

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
        sanitizeUrl,
        setAvatar,
        sanitizeHtml,
        setSafeHtml,
        appendSafeHtml,
        toggleClass,
        Storage,
        getUrlParams,
        getPathParam,
        formatNumber,
        calculateWinRate,
        getGameResultLabel,
        sendFriendRequest,
        getTierColor,
        getTierIcon,
        getNicknameColorValue,
        getProfileBorderValue,
        getProfileCardFrameClass,
        getDefaultEmojiList,
        showStatusBadge,
        bindDoubleTap,
        createAdaptivePoller,
        ReportModal,
        Sounds,
    };
})();
