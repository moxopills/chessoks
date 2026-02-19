/**
 * Guest Session Module
 * 비회원 게스트 세션 관리
 */

const Guest = (function() {
    'use strict';

    const STORAGE_KEY = 'guest_token';
    const GUEST_INFO_KEY = 'guest_info';

    let sessionInfo = null;
    let expiryTimer = null;
    let warningShown = false;

    /**
     * 게스트 세션 정보 가져오기
     */
    function getSession() {
        const token = localStorage.getItem(STORAGE_KEY);
        if (!token) return null;

        const infoStr = localStorage.getItem(GUEST_INFO_KEY);
        if (!infoStr) return null;

        try {
            const info = JSON.parse(infoStr);
            // 만료 확인
            if (new Date(info.expires_at) <= new Date()) {
                clearSession();
                return null;
            }
            return info;
        } catch {
            clearSession();
            return null;
        }
    }

    /**
     * 게스트 세션 저장
     */
    function saveSession(data) {
        localStorage.setItem(STORAGE_KEY, data.token);
        localStorage.setItem(GUEST_INFO_KEY, JSON.stringify({
            nickname: data.nickname,
            display_name: data.display_name,
            expires_at: data.expires_at,
        }));
        sessionInfo = data;
        startExpiryTimer();
    }

    /**
     * 게스트 세션 삭제
     */
    function clearSession() {
        localStorage.removeItem(STORAGE_KEY);
        localStorage.removeItem(GUEST_INFO_KEY);
        sessionInfo = null;
        stopExpiryTimer();
    }

    /**
     * 게스트 세션 생성
     */
    async function createSession(nickname) {
        try {
            const response = await API.post('/accounts/guest/', { nickname });
            saveSession(response);
            return { success: true, data: response };
        } catch (error) {
            return {
                success: false,
                message: error.data?.message || '게스트 세션 생성에 실패했습니다.'
            };
        }
    }

    /**
     * 게스트 세션 종료
     */
    async function endSession() {
        try {
            await API.delete('/accounts/guest/me/');
        } catch {
            // 서버 에러 무시
        }
        clearSession();
    }

    /**
     * 게스트 여부 확인
     */
    function isGuest() {
        return getSession() !== null;
    }

    /**
     * 남은 시간 계산 (분 단위)
     */
    function getRemainingMinutes() {
        const session = getSession();
        if (!session) return 0;

        const expiresAt = new Date(session.expires_at);
        const now = new Date();
        const diff = expiresAt - now;

        return Math.max(0, Math.ceil(diff / (1000 * 60)));
    }

    /**
     * 남은 시간 텍스트
     */
    function getRemainingText() {
        const minutes = getRemainingMinutes();
        if (minutes <= 0) return '만료됨';

        const hours = Math.floor(minutes / 60);
        const mins = minutes % 60;

        if (hours > 0) {
            return `${hours}시간 ${mins}분`;
        }
        return `${mins}분`;
    }

    /**
     * 만료 타이머 시작
     */
    function startExpiryTimer() {
        stopExpiryTimer();
        warningShown = false;

        expiryTimer = setInterval(() => {
            const minutes = getRemainingMinutes();

            // 10분 전 경고
            if (minutes <= 10 && minutes > 0 && !warningShown) {
                warningShown = true;
                if (typeof Toast !== 'undefined') {
                    Toast.warning(`게스트 세션이 ${minutes}분 후 만료됩니다.`);
                }
            }

            // 만료 시 세션 정리
            if (minutes <= 0) {
                clearSession();
                if (typeof Toast !== 'undefined') {
                    Toast.error('게스트 세션이 만료되었습니다.');
                }
                // 페이지 새로고침으로 상태 초기화
                setTimeout(() => window.location.reload(), 1500);
            }

            // UI 업데이트 이벤트
            window.dispatchEvent(new CustomEvent('guest:timer-update', {
                detail: { remaining: getRemainingText() }
            }));
        }, 60000); // 1분마다 체크
    }

    /**
     * 만료 타이머 중지
     */
    function stopExpiryTimer() {
        if (expiryTimer) {
            clearInterval(expiryTimer);
            expiryTimer = null;
        }
    }

    /**
     * 게스트 로그인 모달 표시
     */
    function showLoginModal() {
        return new Promise((resolve) => {
            const modal = document.getElementById('guest-login-modal');
            const form = document.getElementById('guest-login-form');
            const input = document.getElementById('guest-nickname-input');
            const cancelBtn = document.getElementById('guest-login-cancel');
            const errorEl = document.getElementById('guest-login-error');

            if (!modal || !form || !input) {
                resolve(null);
                return;
            }

            modal.classList.remove('hidden');
            input.value = '';
            input.focus();
            if (errorEl) errorEl.textContent = '';

            const cleanup = () => {
                modal.classList.add('hidden');
                form.removeEventListener('submit', handleSubmit);
                cancelBtn?.removeEventListener('click', handleCancel);
            };

            const handleSubmit = async (e) => {
                e.preventDefault();
                const nickname = input.value.trim();

                if (!nickname || nickname.length < 2 || nickname.length > 10) {
                    if (errorEl) errorEl.textContent = '닉네임은 2~10자여야 합니다.';
                    return;
                }

                const result = await createSession(nickname);
                if (result.success) {
                    cleanup();
                    resolve(result.data);
                } else {
                    if (errorEl) errorEl.textContent = result.message;
                }
            };

            const handleCancel = () => {
                cleanup();
                resolve(null);
            };

            form.addEventListener('submit', handleSubmit);
            cancelBtn?.addEventListener('click', handleCancel);
        });
    }

    /**
     * 초기화
     */
    function init() {
        const session = getSession();
        if (session) {
            sessionInfo = session;
            startExpiryTimer();
        }
    }

    // 페이지 로드 시 초기화
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    return {
        getSession,
        createSession,
        endSession,
        isGuest,
        getRemainingMinutes,
        getRemainingText,
        showLoginModal,
        clearSession,
    };
})();
