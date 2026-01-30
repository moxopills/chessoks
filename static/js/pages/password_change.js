/* Password Change Page */
(function() {
    'use strict';

    const form = document.getElementById('password-change-form');
    const currentPassword = document.getElementById('current-password');
    const newPassword = document.getElementById('new-password');
    const newPassword2 = document.getElementById('new-password2');
    const formError = document.getElementById('form-error');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        formError.textContent = '';
        try {
            const payload = {
                current_password: currentPassword.value,
                new_password: newPassword.value,
                new_password2: newPassword2.value,
            };
            const result = await API.post('/accounts/password/change/', payload);
            Toast.success(result.message || '비밀번호가 변경되었습니다.');
            form.reset();
        } catch (error) {
            formError.textContent = error.data?.message || '변경에 실패했습니다.';
        }
    });
})();
