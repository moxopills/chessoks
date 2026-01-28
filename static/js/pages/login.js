/**
 * Login Page Logic
 */

(function() {
    'use strict';

    const form = document.getElementById('login-form');
    const emailInput = document.getElementById('email');
    const passwordInput = document.getElementById('password');
    const submitBtn = document.getElementById('login-btn');
    const formError = document.getElementById('form-error');

    // 폼 제출 핸들러
    form.addEventListener('submit', async function(e) {
        e.preventDefault();
        clearErrors();

        const email = emailInput.value.trim();
        const password = passwordInput.value;

        // 클라이언트 유효성 검사
        if (!validateForm(email, password)) {
            return;
        }

        // 로딩 상태
        setLoading(true);

        try {
            await API.post('/accounts/login/', { email, password });

            // 성공 시 메인 페이지로 이동
            window.location.href = '/';
        } catch (error) {
            handleError(error);
        } finally {
            setLoading(false);
        }
    });

    // 입력 시 에러 클리어
    emailInput.addEventListener('input', () => clearFieldError('email'));
    passwordInput.addEventListener('input', () => clearFieldError('password'));

    /**
     * 클라이언트 유효성 검사
     */
    function validateForm(email, password) {
        let isValid = true;

        if (!email) {
            showFieldError('email', '이메일을 입력해주세요.');
            isValid = false;
        } else if (!isValidEmail(email)) {
            showFieldError('email', '올바른 이메일 형식을 입력해주세요.');
            isValid = false;
        }

        if (!password) {
            showFieldError('password', '비밀번호를 입력해주세요.');
            isValid = false;
        }

        return isValid;
    }

    /**
     * 이메일 유효성 검사
     */
    function isValidEmail(email) {
        const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return regex.test(email);
    }

    /**
     * 에러 처리
     */
    function handleError(error) {
        if (error.status === 400) {
            // 필드별 에러
            if (error.data && error.data.details) {
                const details = error.data.details;
                if (details.email) showFieldError('email', details.email[0]);
                if (details.password) showFieldError('password', details.password[0]);
            }
            // 일반 에러 메시지
            if (error.data && error.data.message) {
                formError.textContent = error.data.message;
            }
        } else if (error.status === 401) {
            formError.textContent = '이메일 또는 비밀번호가 올바르지 않습니다.';
        } else if (error.status === 403) {
            formError.textContent = error.data?.message || '계정이 잠겨 있습니다. 잠시 후 다시 시도해주세요.';
        } else {
            formError.textContent = '로그인 중 오류가 발생했습니다. 다시 시도해주세요.';
        }
    }

    /**
     * 필드 에러 표시
     */
    function showFieldError(field, message) {
        const input = document.getElementById(field);
        const error = document.getElementById(`${field}-error`);

        input.classList.add('is-error');
        error.textContent = message;
    }

    /**
     * 필드 에러 클리어
     */
    function clearFieldError(field) {
        const input = document.getElementById(field);
        const error = document.getElementById(`${field}-error`);

        input.classList.remove('is-error');
        error.textContent = '';
    }

    /**
     * 모든 에러 클리어
     */
    function clearErrors() {
        clearFieldError('email');
        clearFieldError('password');
        formError.textContent = '';
    }

    /**
     * 로딩 상태 설정
     */
    function setLoading(isLoading) {
        submitBtn.disabled = isLoading;
        submitBtn.querySelector('.btn-text').classList.toggle('hidden', isLoading);
        submitBtn.querySelector('.btn-loading').classList.toggle('hidden', !isLoading);
    }
})();
