(function() {
    'use strict';

    function getPresenceViewModel(source, onlineFallback = true) {
        const isOnline = typeof source?.online === 'boolean' ? source.online : onlineFallback;
        return {
            online: isOnline,
            status: source?.status || (isOnline ? 'online' : 'offline'),
            label: source?.status_label || (isOnline ? '온라인' : '오프라인'),
        };
    }

    function getPresenceCssClass(status, online) {
        if (!online) return 'offline';
        const normalized = String(status || 'online');
        const supported = new Set([
            'online',
            'lobby',
            'room_waiting',
            'playing',
            'competitive',
            'quick',
            'ai_playing',
            'spectating',
            'puzzle',
        ]);
        return supported.has(normalized) ? normalized : 'online';
    }

    function createAchievementLabel(achievement) {
        if (!achievement?.title) return null;
        const badge = document.createElement('div');
        badge.className = `user-achievement user-achievement--${achievement.tone || 'info'}`;
        badge.textContent = `${achievement.icon || '🏅'} ${achievement.title}`;
        return badge;
    }

    function createUserRowElement(user, presenceSource = null) {
        const presence = getPresenceViewModel(presenceSource || user, true);
        const statusText = presence.label;
        const statusClass = getPresenceCssClass(presence.status, presence.online);
        const tier = user.rank_tier || user.stats?.rank_tier || 'Junior';
        const tierIcon = Utils.getTierIcon(tier);
        const nicknameColor = Utils.getNicknameColorValue(
            user.nickname_color || user.stats?.nickname_color || ''
        );
        const profileRing = Utils.getProfileBorderValue(
            user.profile_border || user.stats?.profile_border || ''
        );
        const row = document.createElement('div');
        row.className = 'user-item';
        row.dataset.userId = String(user.id);

        const avatar = document.createElement('div');
        avatar.className = 'user-avatar';
        if (profileRing) avatar.style.boxShadow = profileRing;
        Utils.setAvatar(avatar, {
            url: user.avatar_url,
            alt: user.nickname || '',
            placeholder: '👤',
            placeholderClass: 'avatar-placeholder',
        });
        row.appendChild(avatar);

        const info = document.createElement('div');
        info.className = 'user-info';

        const nick = document.createElement('div');
        nick.className = 'user-nickname';
        if (nicknameColor) nick.style.color = nicknameColor;
        nick.appendChild(document.createTextNode(user.nickname || ''));
        nick.appendChild(document.createTextNode(' '));
        const badge = document.createElement('span');
        badge.className = 'user-tier-icon';
        badge.title = tier;
        badge.textContent = tierIcon;
        nick.appendChild(badge);
        info.appendChild(nick);

        const achievement = createAchievementLabel(user.featured_achievement);
        if (achievement) {
            info.appendChild(achievement);
        }

        const status = document.createElement('div');
        status.className = `user-status ${statusClass}`;
        status.textContent = statusText;
        info.appendChild(status);
        row.appendChild(info);
        return row;
    }

    window.LobbyPresenceUI = {
        createUserRowElement,
        createAchievementLabel,
        getPresenceCssClass,
        getPresenceViewModel,
    };
})();
