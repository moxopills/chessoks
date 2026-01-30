/* Password Reset Page */
(function() {
    'use strict';

    const requestForm = document.getElementById('password-reset-request-form');
    const confirmForm = document.getElementById('password-reset-confirm-form');
    const resetEmail = document.getElementById('reset-email');
    const resetToken = document.getElementById('reset-token');
    const resetPassword = document.getElementById('reset-password');
    const resetPassword2 = document.getElementById('reset-password2');
    const formError = document.getElementById('reset-form-error');

    requestForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        try {
            const result = await API.post('/accounts/password-reset/request/', { email: resetEmail.value.trim() });
            Toast.success(result.message || '재설정 인증번호를 발송했습니다.');
        } catch (error) {
            Toast.error(error.data?.message || '요청에 실패했습니다.');
        }
    });

    confirmForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        formError.textContent = '';
        try {
            const payload = {
                code: resetToken.value.trim(),
                new_password: resetPassword.value,
                new_password2: resetPassword2.value,
            };
            const result = await API.post('/accounts/password-reset/confirm/', payload);
            Toast.success(result.message || '비밀번호가 변경되었습니다.');
            confirmForm.reset();
        } catch (error) {
            formError.textContent = error.data?.message || '변경에 실패했습니다.';
        }
    });
})();
