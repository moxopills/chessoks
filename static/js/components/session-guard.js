/**
 * Session Guard Component
 * - 사용자 활동 감지
 * - 세션 만료 전 경고 표시
 * - 세션 연장 기능
 */

const SessionGuard = (function() {
    'use strict';

    const WARNING_TIMEOUT_SECONDS = 5 * 60; // 경고 후 5분 내 연장 안 하면 로그아웃
    const SESSION_TIMEOUT_SECONDS = 25 * 60; // 25분 비활동 시 경고
    const CHECK_INTERVAL_SECONDS = 60; // 1분마다 체크

    let lastActivity = Date.now();
    let warningShown = false;
    let checkInterval = null;
    let warningModal = null;
    let countdownInterval = null;

    function init() {
        // 활동 이벤트 감지
        const events = ['mousedown', 'keydown', 'scroll', 'touchstart'];
        events.forEach(event => {
            document.addEventListener(event, recordActivity, { passive: true });
        });

        // 주기적 체크
        checkInterval = setInterval(checkSession, CHECK_INTERVAL_SECONDS * 1000);
    }

    function recordActivity() {
        lastActivity = Date.now();
        // 경고 모달이 떠있을 때는 활동해도 자동으로 닫지 않음 (연장 버튼 눌러야 함)
    }

    function checkSession() {
        if (warningShown) return; // 이미 경고 중이면 체크 안 함

        const elapsed = (Date.now() - lastActivity) / 1000;

        if (elapsed >= SESSION_TIMEOUT_SECONDS) {
            // 경고 표시
            showWarning(WARNING_TIMEOUT_SECONDS);
        }
    }

    function showWarning(remainingSeconds) {
        warningShown = true;
        createWarningModal(remainingSeconds);
    }

    function hideWarning() {
        warningShown = false;
        if (warningModal) {
            warningModal.classList.add('hidden');
        }
        if (countdownInterval) {
            clearInterval(countdownInterval);
            countdownInterval = null;
        }
    }

    function createWarningModal(remainingSeconds) {
        if (!warningModal) {
            warningModal = document.createElement('div');
            warningModal.id = 'session-warning-modal';
            warningModal.className = 'modal-overlay';
            warningModal.innerHTML = `
                <div class="modal-dialog session-warning-dialog">
                    <div class="modal-header">
                        <h3 class="modal-title">⚠️ 세션 만료 경고</h3>
                    </div>
                    <div class="modal-body">
                        <p class="modal-message">
                            오랜 시간 활동이 없어 <strong id="session-remaining">5분</strong> 후 자동 로그아웃됩니다.
                        </p>
                        <p class="session-warning-hint">계속 사용하시려면 "연장" 버튼을 클릭해주세요.</p>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-secondary" id="session-logout-btn">로그아웃</button>
                        <button class="btn btn-primary" id="session-extend-btn">연장</button>
                    </div>
                </div>
            `;
            document.body.appendChild(warningModal);

            document.getElementById('session-extend-btn').addEventListener('click', extendSession);
            document.getElementById('session-logout-btn').addEventListener('click', logout);
        }

        updateRemainingTime(remainingSeconds);
        warningModal.classList.remove('hidden');

        // 카운트다운 시작
        startCountdown(remainingSeconds);
    }

    function startCountdown(seconds) {
        if (countdownInterval) clearInterval(countdownInterval);

        let remaining = seconds;
        countdownInterval = setInterval(() => {
            remaining -= 1;
            if (remaining <= 0) {
                clearInterval(countdownInterval);
                countdownInterval = null;
                forceLogout();
            } else {
                updateRemainingTime(remaining);
            }
        }, 1000);
    }

    function updateRemainingTime(seconds) {
        const el = document.getElementById('session-remaining');
        if (!el) return;

        const minutes = Math.floor(seconds / 60);
        const secs = seconds % 60;
        if (minutes > 0) {
            el.textContent = `${minutes}분 ${secs}초`;
        } else {
            el.textContent = `${secs}초`;
        }
    }

    async function extendSession() {
        try {
            // API 호출로 세션 연장
            await API.get('/accounts/me/');
            lastActivity = Date.now();
            hideWarning();
            Toast.success('세션이 연장되었습니다.');
        } catch {
            // 이미 만료됨
            forceLogout();
        }
    }

    async function logout() {
        try {
            await API.post('/accounts/logout/');
        } catch {
            // 이미 로그아웃 상태일 수 있음
        }
        window.location.href = '/login/';
    }

    async function forceLogout() {
        if (checkInterval) {
            clearInterval(checkInterval);
            checkInterval = null;
        }
        // 실제 로그아웃 수행
        try {
            await API.post('/accounts/logout/');
        } catch {
            // 이미 로그아웃 상태
        }
        window.location.href = '/login/';
    }

    return {
        init
    };
})();

// 자동 초기화 (로그인 상태에서만)
document.addEventListener('DOMContentLoaded', () => {
    // 로그인 상태인지 확인 (간단하게 API 호출)
    API.get('/accounts/me/').then(() => {
        SessionGuard.init();
    }).catch(() => {
        // 비로그인 상태 - 무시
    });
});
