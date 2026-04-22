(function() {
    'use strict';

    function renderCapturedPieces({
        capturedWhite,
        capturedBlack,
        captured,
        createCapturedPieceMarkup,
    }) {
        if (!capturedWhite || !capturedBlack) return;

        capturedWhite.innerHTML = (captured?.white || [])
            .map((letter) => createCapturedPieceMarkup(letter.toLowerCase()))
            .join('');

        capturedBlack.innerHTML = (captured?.black || [])
            .map((letter) => createCapturedPieceMarkup(letter.toUpperCase()))
            .join('');
    }

    function createSpectatorItem(user) {
        const item = document.createElement('div');
        item.className = 'spectator-item';

        const avatar = document.createElement('div');
        avatar.className = 'avatar avatar-xs';
        const ring = Utils.getProfileBorderValue(user.profile_border || '');
        if (ring) avatar.style.boxShadow = ring;
        Utils.setAvatar(avatar, {
            url: user.avatar_url,
            alt: user.nickname || '관전자',
            placeholder: '?',
            placeholderClass: 'avatar-placeholder',
        });

        const name = document.createElement('span');
        const color = Utils.getNicknameColorValue(user.nickname_color || '');
        if (color) name.style.color = color;
        name.textContent = user.nickname || '관전자';

        item.appendChild(avatar);
        item.appendChild(name);
        return item;
    }

    function renderSpectatorList({ spectatorList, users }) {
        if (!spectatorList) return;
        if (!users.length) {
            spectatorList.innerHTML = '<div class="spectator-empty">관전자가 없습니다.</div>';
            return;
        }

        spectatorList.textContent = '';
        const fragment = document.createDocumentFragment();
        users.forEach((user) => {
            fragment.appendChild(createSpectatorItem(user));
        });
        spectatorList.appendChild(fragment);
    }

    function updateSpectatorState({ spectatorCount, spectatorList, users }) {
        const nextUsers = Array.isArray(users) ? users : [];
        if (spectatorCount) {
            spectatorCount.textContent = `${nextUsers.length}명`;
        }
        renderSpectatorList({ spectatorList, users: nextUsers });
        return nextUsers;
    }

    function applySpectatorDelta({
        currentSpectators,
        action,
        user,
        spectatorCountValue,
        spectatorCount,
        spectatorList,
    }) {
        if (!user?.id) {
            if (typeof spectatorCountValue === 'number' && spectatorCount) {
                spectatorCount.textContent = `${spectatorCountValue}명`;
            }
            return Array.isArray(currentSpectators) ? currentSpectators : [];
        }

        const nextUsers = Array.isArray(currentSpectators) ? [...currentSpectators] : [];
        const existingIndex = nextUsers.findIndex((item) => item.id === user.id);
        if (action === 'leave') {
            if (existingIndex >= 0) {
                nextUsers.splice(existingIndex, 1);
            }
        } else if (existingIndex >= 0) {
            nextUsers.splice(existingIndex, 1, user);
        } else {
            nextUsers.push(user);
        }

        if (spectatorCount) {
            spectatorCount.textContent = `${typeof spectatorCountValue === 'number' ? spectatorCountValue : nextUsers.length}명`;
        }
        renderSpectatorList({ spectatorList, users: nextUsers });
        return nextUsers;
    }

    window.GameSidePanelsUI = {
        renderCapturedPieces,
        renderSpectatorList,
        updateSpectatorState,
        applySpectatorDelta,
    };
})();
