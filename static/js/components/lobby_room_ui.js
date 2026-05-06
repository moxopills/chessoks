(function() {
    'use strict';

    function styledUserInline(user, fallback = '플레이어') {
        const nickname = user?.nickname || fallback;
        const color = Utils.getNicknameColorValue(user?.nickname_color || user?.stats?.nickname_color || '');
        const ring = Utils.getProfileBorderValue(user?.profile_border || user?.stats?.profile_border || '');
        const wrapper = document.createElement('span');
        wrapper.style.display = 'inline-flex';
        wrapper.style.alignItems = 'center';
        wrapper.style.gap = '6px';

        const avatar = document.createElement('span');
        avatar.style.width = '20px';
        avatar.style.height = '20px';
        avatar.style.borderRadius = '50%';
        avatar.style.display = 'inline-flex';
        avatar.style.alignItems = 'center';
        avatar.style.justifyContent = 'center';
        avatar.style.overflow = 'hidden';
        avatar.style.background = 'rgba(255,255,255,.08)';
        if (ring) avatar.style.boxShadow = ring;
        Utils.setAvatar(avatar, {
            url: user?.avatar_url,
            alt: nickname,
            placeholder: '👤',
            placeholderClass: 'avatar-placeholder',
        });

        const name = document.createElement('span');
        name.style.fontWeight = '600';
        if (color) name.style.color = color;
        name.textContent = nickname;

        wrapper.appendChild(avatar);
        wrapper.appendChild(name);
        return wrapper;
    }

    function renderWaitingRoomCard({ card, infoEl, enterEl, room, onEnter }) {
        if (!card || !infoEl || !enterEl || !room) return;
        card.classList.remove('hidden');
        const title = room.title || '빠른 대전';
        const timeText = room.time_limit ? `${room.time_limit}분` : '무제한';
        infoEl.textContent = '';

        const titleRow = document.createElement('div');
        titleRow.style.fontWeight = '700';
        titleRow.style.marginBottom = '4px';
        titleRow.textContent = `${title} · ${timeText}`;
        infoEl.appendChild(titleRow);

        const hostRow = document.createElement('div');
        hostRow.style.opacity = '0.95';
        hostRow.appendChild(styledUserInline(room.host));
        infoEl.appendChild(hostRow);

        enterEl.onclick = onEnter;
        card.onclick = onEnter;
    }

    function renderActiveGameCard({ card, infoEl, enterEl, room, onEnter }) {
        if (!card || !infoEl || !enterEl || !room) return;
        card.classList.remove('hidden');
        infoEl.textContent = '';

        const row = document.createElement('div');
        row.style.display = 'flex';
        row.style.alignItems = 'center';
        row.style.gap = '8px';
        row.style.flexWrap = 'wrap';
        row.appendChild(styledUserInline(room.host, '화이트'));

        const vs = document.createElement('span');
        vs.style.opacity = '0.7';
        vs.textContent = 'vs';
        row.appendChild(vs);

        row.appendChild(styledUserInline(room.guest, '블랙'));
        infoEl.appendChild(row);

        enterEl.onclick = onEnter;
        card.onclick = onEnter;
    }

    function renderBoardPreview({ container, posts, formatRelativeTime }) {
        if (!container) return;
        if (!posts.length) {
            container.innerHTML = '<div class="board-preview-empty">표시할 게시글이 없습니다.</div>';
            return;
        }
        container.innerHTML = posts.map((post) => {
            const categoryCode = post.category?.code || '';
            const categoryTitle = post.category?.title || '게시글';
            const author = post.author?.nickname || '익명';
            const previewText = (post.content || '').trim().slice(0, 72);
            const isRecruit = categoryCode === 'recruit';
            const recruitMeta = isRecruit
                ? [
                    post.guild_name ? `<span class="board-preview-pill is-emphasis">${Utils.escapeHtml(post.guild_name)}</span>` : '',
                    post.recruitment_slots ? `<span class="board-preview-pill">모집 ${Number(post.recruitment_slots)}명</span>` : '',
                ].filter(Boolean).join('')
                : '';
            return `
                <a class="board-preview-item" href="/board/?post=${post.id}">
                    <div class="board-preview-meta">
                        <span class="board-category-badge" data-board-category="${Utils.escapeHtml(categoryCode)}">${Utils.escapeHtml(categoryTitle)}</span>
                        <span class="board-preview-scope">${Utils.escapeHtml(author)}</span>
                    </div>
                    <div class="board-preview-title">${Utils.escapeHtml(post.title || '제목 없음')}</div>
                    <div class="board-preview-stats">
                        <span class="board-preview-pill">💬 ${Number(post.comment_count || 0)}</span>
                        <span class="board-preview-pill">👁 ${Number(post.view_count || 0)}</span>
                        <span class="board-preview-pill">${Utils.escapeHtml(formatRelativeTime(post.created_at))}</span>
                    </div>
                    ${recruitMeta ? `<div class="board-preview-stats">${recruitMeta}</div>` : ''}
                    <div class="board-preview-copy">${Utils.escapeHtml(previewText || '본문 미리보기가 없습니다.')}</div>
                </a>
            `;
        }).join('');
    }

    function buildRoomSignature(room) {
        return [
            room?.id || 0,
            room?.status || '',
            room?.title || '',
            room?.time_limit || 0,
            room?.host?.id || 0,
            room?.host?.nickname || '',
            room?.host?.nickname_color || '',
            room?.guest?.id || 0,
            room?.guest?.nickname || '',
            room?.player_count || 0,
            room?.spectator_count || 0,
            room?.current_game_id || 0,
        ].join(':');
    }

    function createRoomEmptyState() {
        const empty = document.createElement('div');
        empty.className = 'room-empty';
        empty.textContent = '대기 중인 방이 없습니다.';
        return empty;
    }

    function bindRoomItemEvents(item, onRoomClick) {
        if (!item || item.dataset.bound === '1') return;
        item.dataset.bound = '1';
        item.addEventListener('click', () => {
            onRoomClick?.(item);
        });
    }

    function createRoomElement({ room, onRoomClick }) {
        const item = document.createElement('div');
        item.className = 'room-item';
        item.dataset.roomId = String(room.id);
        item.dataset.signature = buildRoomSignature(room);

        const info = document.createElement('div');
        info.className = 'room-info';

        const title = document.createElement('div');
        title.className = 'room-title';
        title.textContent = room.title || '빠른 대전';

        const meta = document.createElement('div');
        meta.className = 'room-meta';

        const host = document.createElement('span');
        const hostColor = Utils.getNicknameColorValue(room.host?.nickname_color || '');
        if (hostColor) host.style.color = hostColor;
        host.textContent = room.host?.nickname || '호스트';

        meta.appendChild(host);
        meta.append(` · ${room.time_limit ? `${room.time_limit}분` : '무제한'}`);
        if (room.spectator_count > 0) {
            meta.append(` · 👁 ${room.spectator_count}`);
        }

        info.appendChild(title);
        info.appendChild(meta);

        const status = document.createElement('span');
        status.className = `room-status ${room.status}`;
        status.textContent = room.status === 'waiting' ? '대기 중' : '게임 중';

        item.appendChild(info);
        item.appendChild(status);
        bindRoomItemEvents(item, onRoomClick);
        return item;
    }

    function renderRooms({ roomList, rooms, isHiddenRoomType, onRoomClick }) {
        if (!roomList) return;
        const visibleRooms = (rooms || []).filter((room) => !isHiddenRoomType(room));
        if (!visibleRooms.length) {
            roomList.replaceChildren(createRoomEmptyState());
            return;
        }

        const existingMap = new Map(
            Array.from(roomList.querySelectorAll('.room-item')).map((item) => [item.dataset.roomId, item])
        );
        const fragment = document.createDocumentFragment();
        visibleRooms.forEach((room) => {
            const key = String(room.id);
            const signature = buildRoomSignature(room);
            const existing = existingMap.get(key);
            if (existing && existing.dataset.signature === signature) {
                fragment.appendChild(existing);
                return;
            }
            fragment.appendChild(createRoomElement({ room, onRoomClick }));
        });
        roomList.replaceChildren(fragment);
    }

    window.LobbyRoomUI = {
        styledUserInline,
        renderWaitingRoomCard,
        renderActiveGameCard,
        renderBoardPreview,
        buildRoomSignature,
        createRoomElement,
        renderRooms,
    };
})();
