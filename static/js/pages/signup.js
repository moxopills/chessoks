/**
 * Signup Page Logic
 * 백엔드:
 *  - POST /api/accounts/signup/email/request/
 *  - POST /api/accounts/signup/email/confirm/
 *  - POST /api/accounts/signup/
 * 필드: email, nickname, password, password2
 */

(function() {
    'use strict';

    const form = document.getElementById('signup-form');
    const emailInput = document.getElementById('email');
    const tokenInput = document.getElementById('signup-code');
    const nicknameInput = document.getElementById('nickname');
    const passwordInput = document.getElementById('password');
    const password2Input = document.getElementById('password2');
    const submitBtn = document.getElementById('signup-btn');
    const formError = document.getElementById('form-error');
    const strengthFill = document.getElementById('strength-fill');
    const strengthText = document.getElementById('strength-text');
    const sendEmailBtn = document.getElementById('send-email-btn');
    const confirmEmailBtn = document.getElementById('confirm-email-btn');
    const emailStatus = document.getElementById('email-status');

    let emailVerified = false;

    // 비밀번호 강도 체크
    passwordInput.addEventListener('input', function() {
        const strength = checkPasswordStrength(this.value);
        updateStrengthUI(strength);
        clearFieldError('password');
    });

    // 입력 시 에러 클리어
    emailInput.addEventListener('input', () => {
        clearFieldError('email');
        if (!emailInput.readOnly) {
            emailVerified = false;
            tokenInput.value = '';
            emailStatus.textContent = '';
            enableSignupFields(false);
        }
    });
    tokenInput.addEventListener('input', () => clearFieldError('signup-code'));
    nicknameInput.addEventListener('input', () => clearFieldError('nickname'));
    password2Input.addEventListener('input', () => clearFieldError('password2'));

    // 이메일 중복 체크 (디바운스)
    let emailCheckTimeout;
    emailInput.addEventListener('blur', function() {
        clearTimeout(emailCheckTimeout);
        const email = this.value.trim();
        if (email && isValidEmail(email)) {
            emailCheckTimeout = setTimeout(() => checkEmailAvailable(email), 300);
        }
    });

    // 닉네임 중복 체크 (디바운스)
    let nicknameCheckTimeout;
    nicknameInput.addEventListener('blur', function() {
        clearTimeout(nicknameCheckTimeout);
        const nickname = this.value.trim();
        if (nickname && nickname.length >= 2) {
            nicknameCheckTimeout = setTimeout(() => checkNicknameAvailable(nickname), 300);
        }
    });

    // 이메일 인증 요청
    sendEmailBtn.addEventListener('click', async function() {
        clearErrors();
        const email = emailInput.value.trim();

        if (!email) {
            showFieldError('email', '이메일을 입력해주세요.');
            return;
        }
        if (!isValidEmail(email)) {
            showFieldError('email', '올바른 이메일 형식을 입력해주세요.');
            return;
        }

        setEmailLoading(true);
        try {
            await API.post('/accounts/signup/email/request/', { email });
            emailStatus.textContent = '인증번호를 보냈습니다. 메일을 확인해주세요.';
        } catch (error) {
            handleError(error);
        } finally {
            setEmailLoading(false);
        }
    });

    // 이메일 인증 확인
    confirmEmailBtn.addEventListener('click', async function() {
        clearErrors();
        const code = tokenInput.value.trim();
        const email = emailInput.value.trim();
        if (!email) {
            showFieldError('email', '이메일을 입력해주세요.');
            return;
        }
        if (!code) {
            showFieldError('signup-code', '인증 코드를 입력해주세요.');
            return;
        }

        setEmailLoading(true);
        try {
            const result = await API.post('/accounts/signup/email/confirm/', {
                email,
                code
            });
            emailVerified = true;
            emailInput.value = result.email || emailInput.value;
            emailInput.readOnly = true;
            tokenInput.readOnly = true;
            emailStatus.textContent = '이메일 인증이 완료되었습니다.';
            enableSignupFields(true);
        } catch (error) {
            handleError(error);
        } finally {
            setEmailLoading(false);
        }
    });

    // 폼 제출 핸들러
    form.addEventListener('submit', async function(e) {
        e.preventDefault();
        clearErrors();

        const email = emailInput.value.trim();
        const nickname = nicknameInput.value.trim();
        const password = passwordInput.value;
        const password2 = password2Input.value;
        // 클라이언트 유효성 검사
        if (!emailVerified) {
            formError.textContent = '이메일 인증을 먼저 완료해주세요.';
            return;
        }

        if (!validateForm(email, nickname, password, password2)) {
            return;
        }

        setLoading(true);

        try {
            await API.post('/accounts/signup/', {
                email,
                nickname,
                password,
                password2
            });

            // 성공 시 자동 로그인 후 로비로 이동
            await API.post('/accounts/login/', { email, password });
            Toast.success('회원가입이 완료되었습니다.');
            setTimeout(() => {
                window.location.href = '/';
            }, 800);
        } catch (error) {
            handleError(error);
        } finally {
            setLoading(false);
        }
    });

    /**
     * 클라이언트 유효성 검사
     */
    function validateForm(email, nickname, password, password2) {
        let isValid = true;

        // 이메일
        if (!email) {
            showFieldError('email', '이메일을 입력해주세요.');
            isValid = false;
        } else if (!isValidEmail(email)) {
            showFieldError('email', '올바른 이메일 형식을 입력해주세요.');
            isValid = false;
        }

        // 닉네임
        if (!nickname) {
            showFieldError('nickname', '닉네임을 입력해주세요.');
            isValid = false;
        } else if (nickname.length < 2) {
            showFieldError('nickname', '닉네임은 최소 2자 이상이어야 합니다.');
            isValid = false;
        }

        // 비밀번호
        if (!password) {
            showFieldError('password', '비밀번호를 입력해주세요.');
            isValid = false;
        } else {
            const strength = checkPasswordStrength(password);
            if (strength.score < 3) {
                showFieldError('password', '비밀번호가 너무 약합니다. 대소문자, 숫자, 특수문자를 포함해주세요.');
                isValid = false;
            }
        }

        // 비밀번호 확인
        if (!password2) {
            showFieldError('password2', '비밀번호 확인을 입력해주세요.');
            isValid = false;
        } else if (password !== password2) {
            showFieldError('password2', '비밀번호가 일치하지 않습니다.');
            isValid = false;
        }

        return isValid;
    }

    /**
     * 비밀번호 강도 체크
     */
    function checkPasswordStrength(password) {
        let score = 0;
        const checks = {
            length: password.length >= 8,
            lowercase: /[a-z]/.test(password),
            uppercase: /[A-Z]/.test(password),
            number: /[0-9]/.test(password),
            special: /[!@#$%^&*(),.?":{}|<>]/.test(password)
        };

        Object.values(checks).forEach(passed => {
            if (passed) score++;
        });

        let level = 'weak';
        let text = '약함';

        if (score >= 4) {
            level = 'strong';
            text = '강함';
        } else if (score >= 3) {
            level = 'medium';
            text = '보통';
        }

        return { score, level, text, checks };
    }

    /**
     * 비밀번호 강도 UI 업데이트
     */
    function updateStrengthUI(strength) {
        strengthFill.className = 'strength-fill';
        if (strength.score > 0) {
            strengthFill.classList.add(strength.level);
        }
        strengthText.textContent = strength.score > 0 ? strength.text : '';
    }

    /**
     * 이메일 중복 체크
     */
    async function checkEmailAvailable(email) {
        try {
            const result = await API.post('/accounts/check-email/', { email });
            if (!result.available) {
                showFieldError('email', '이미 사용 중인 이메일입니다.');
            }
        } catch (error) {
            // 무시 (서버 에러)
        }
    }

    /**
     * 닉네임 중복 체크
     */
    async function checkNicknameAvailable(nickname) {
        try {
            const result = await API.post('/accounts/check-nickname/', { nickname });
            if (!result.available) {
                showFieldError('nickname', '이미 사용 중인 닉네임입니다.');
            }
        } catch (error) {
            // 무시 (서버 에러)
        }
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
        if (error.status === 400 && error.data) {
            // 필드별 에러
            if (error.data.details) {
                const details = error.data.details;
                if (details.email) showFieldError('email', details.email[0]);
                if (details.nickname) showFieldError('nickname', details.nickname[0]);
                if (details.password) showFieldError('password', details.password[0]);
                if (details.password2) showFieldError('password2', details.password2[0]);
                if (details.code) showFieldError('signup-code', details.code[0]);
            }
            // 일반 에러 메시지
            if (error.data.message) {
                formError.textContent = error.data.message;
            }
        } else {
            formError.textContent = '회원가입 중 오류가 발생했습니다. 다시 시도해주세요.';
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
        ['email', 'signup-code', 'nickname', 'password', 'password2'].forEach(clearFieldError);
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

    function setEmailLoading(isLoading) {
        sendEmailBtn.disabled = isLoading;
        confirmEmailBtn.disabled = isLoading;
    }

    function enableSignupFields(enabled) {
        nicknameInput.disabled = !enabled;
        passwordInput.disabled = !enabled;
        password2Input.disabled = !enabled;
        submitBtn.disabled = !enabled;
    }

    enableSignupFields(false);
})();
