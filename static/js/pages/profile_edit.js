/* Profile Edit Page Logic */
(function() {
    'use strict';

    const avatarPreview = document.getElementById('avatar-preview');
    const avatarInput = document.getElementById('avatar-input');
    const avatarUploadBtn = document.getElementById('avatar-upload-btn');
    const avatarDeleteBtn = document.getElementById('avatar-delete-btn');

    const profileForm = document.getElementById('profile-edit-form');
    const nicknameInput = document.getElementById('nickname');
    const bioInput = document.getElementById('bio');
    const nicknameError = document.getElementById('nickname-error');

    const emailChangeBtn = document.getElementById('email-change-btn');
    const emailConfirmBtn = document.getElementById('email-confirm-btn');
    const newEmailInput = document.getElementById('new-email');
    const emailPasswordInput = document.getElementById('email-password');
    const emailTokenInput = document.getElementById('email-token');

    const deleteBtn = document.getElementById('delete-account-btn');
    const deletePasswordInput = document.getElementById('delete-password');

    init();

    async function init() {
        await loadProfile();
        setupAvatarActions();
        setupProfileForm();
        setupEmailChange();
        setupDelete();
    }

    function notifyUserUpdated(user) {
        window.dispatchEvent(new CustomEvent('user:updated', { detail: { user } }));
    }

    async function refreshAuthUser() {
        try {
            const me = await API.get('/accounts/me/');
            notifyUserUpdated(me);
        } catch (error) {
            // Ignore refresh failure; navbar will update on next page load.
        }
    }

    async function loadProfile() {
        try {
            const me = await API.get('/accounts/me/');
            nicknameInput.value = me.nickname || '';
            bioInput.value = me.bio || '';
            renderAvatar(me.avatar_url, me.nickname);
            renderCustomization(me.stats || {});
        } catch (error) {
            Toast.error('프로필 정보를 불러올 수 없습니다.');
        }
    }

    function renderCustomization(stats) {
        void stats;
    }

    function renderAvatar(url, nickname) {
        avatarPreview.innerHTML = '';
        if (url) {
            const img = document.createElement('img');
            img.src = url;
            img.alt = nickname || 'avatar';
            avatarPreview.appendChild(img);
        } else {
            const span = document.createElement('span');
            span.className = 'profile-avatar-placeholder';
            span.textContent = nickname?.[0] || '?';
            avatarPreview.appendChild(span);
        }
    }

    function setupAvatarActions() {
        avatarUploadBtn.addEventListener('click', async () => {
            const file = avatarInput.files[0];
            if (!file) {
                Toast.error('이미지를 선택해주세요.');
                return;
            }
            const formData = new FormData();
            formData.append('avatar', file);
            try {
                const result = await API.patch('/accounts/profile/avatar/', formData, true);
                Toast.success(result.message || '아바타가 업데이트되었습니다.');
                renderAvatar(result.avatar_url, nicknameInput.value);
                await refreshAuthUser();
            } catch (error) {
                Toast.error(error.data?.message || '업로드에 실패했습니다.');
            }
        });

        avatarDeleteBtn.addEventListener('click', async () => {
            if (!confirm('아바타를 삭제할까요?')) return;
            try {
                const result = await API.delete('/accounts/profile/avatar/');
                Toast.success(result.message || '아바타가 삭제되었습니다.');
                renderAvatar('', nicknameInput.value);
                await refreshAuthUser();
            } catch (error) {
                Toast.error(error.data?.message || '삭제에 실패했습니다.');
            }
        });
    }

    function setupProfileForm() {
        profileForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            nicknameError.textContent = '';
            const payload = {
                nickname: nicknameInput.value.trim(),
                bio: bioInput.value.trim(),
            };
            try {
                const updated = await API.patch('/accounts/profile/', payload);
                Toast.success('프로필이 업데이트되었습니다.');
                renderAvatar(updated.avatar_url, updated.nickname);
                renderCustomization(updated.stats || {});
                await refreshAuthUser();
            } catch (error) {
                const fieldError = error.data?.nickname?.[0];
                if (fieldError) nicknameError.textContent = fieldError;
                Toast.error(error.data?.message || '저장에 실패했습니다.');
            }
        });
    }

    function setupEmailChange() {
        emailChangeBtn.addEventListener('click', async () => {
            const newEmail = newEmailInput.value.trim();
            const password = emailPasswordInput.value;
            if (!newEmail || !password) {
                Toast.error('새 이메일과 비밀번호를 입력해주세요.');
                return;
            }
            try {
                const result = await API.post('/accounts/email/change/', { new_email: newEmail, password });
                Toast.success(result.message || '인증 메일을 발송했습니다.');
            } catch (error) {
                Toast.error(error.data?.message || '요청에 실패했습니다.');
            }
        });

        emailConfirmBtn.addEventListener('click', async () => {
            const code = emailTokenInput.value.trim();
            if (!code) {
                Toast.error('인증번호를 입력해주세요.');
                return;
            }
            try {
                const result = await API.post('/accounts/email/change/confirm/', { code });
                Toast.success(result.message || '이메일이 변경되었습니다.');
                emailTokenInput.value = '';
            } catch (error) {
                Toast.error(error.data?.message || '확인에 실패했습니다.');
            }
        });
    }

    function setupDelete() {
        deleteBtn.addEventListener('click', async () => {
            const password = deletePasswordInput.value;
            if (!password) {
                Toast.error('비밀번호를 입력해주세요.');
                return;
            }
            if (!confirm('정말 탈퇴하시겠습니까?')) return;
            try {
                const result = await API.post('/accounts/account/delete/', { password });
                Toast.success(result.message || '탈퇴가 예약되었습니다.');
                setTimeout(() => {
                    window.location.href = '/';
                }, 1000);
            } catch (error) {
                Toast.error(error.data?.message || '탈퇴에 실패했습니다.');
            }
        });
    }
})();
