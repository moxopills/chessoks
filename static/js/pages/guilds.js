(function () {
    let me = null;
    let selectedGuildId = null;
    let selectedGuild = null;
    let selectedMemberId = null;
    let lastGuildListSignature = '';
    let lastGuildMembersSignature = '';
    let lastGuildChatSignature = '';
    let lastGuildRequestsSignature = '';
    let lastGuildNoticeSignature = '';
    const pageEl = document.getElementById('guild-page');
    const pageMode = pageEl?.dataset.view || 'browse';

    const guildListEl = document.getElementById('guild-list');
    const detailEmptyEl = document.getElementById('guild-detail-empty');
    const detailPanelEl = document.getElementById('guild-detail-panel');
    const guildSummaryEl = document.getElementById('guild-summary');
    const guildMembersEl = document.getElementById('guild-members');
    const guildChatLogEl = document.getElementById('guild-chat-log');
    const guildChatPanelEl = document.getElementById('guild-chat-panel');
    const guildChatToggleBtn = document.getElementById('guild-chat-toggle');
    const guildRequestsEl = document.getElementById('guild-requests');
    const guildNoticeHistoryEl = document.getElementById('guild-notice-history');
    const guildJoinBtn = document.getElementById('guild-join-btn');
    const guildLeaveBtn = document.getElementById('guild-leave-btn');
    const guildBattleBtn = document.getElementById('guild-battle-btn');
    const guildNoticeInput = document.getElementById('guild-notice-input');
    const memberSelectionEl = document.getElementById('guild-member-selection');
    const guildAvatarInput = document.getElementById('guild-avatar-input');

    const ACHIEVEMENT_LABELS = {
        first_win: '첫 승',
        regular_player: '단골',
        win_streak: '연승',
        ranked_rookie: '배치 완료',
        puzzle_starter: '퍼즐 입문',
        puzzle_focus: '퍼즐 집중',
        social_knight: '친구 기사',
        style_collector: '수집가',
        season_reward: '시즌 수상',
    };

    function myMembership() {
        if (!selectedGuild || !me) return null;
        return (selectedGuild.members || []).find((member) => member.user.id === me.id) || null;
    }

    function isManager() {
        const membership = myMembership();
        return Boolean(membership && ['leader', 'vice', 'manager'].includes(membership.role));
    }

    function isLeader() {
        const membership = myMembership();
        return Boolean(membership && membership.role === 'leader');
    }

    function getSelectedMember() {
        return (selectedGuild?.members || []).find((member) => member.user.id === selectedMemberId) || null;
    }

    function achievementLabel(key) {
        return ACHIEVEMENT_LABELS[key] || '';
    }

    function formatNoticeTimestamp(value) {
        if (!value) return '';
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return '';
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        const hours = String(date.getHours()).padStart(2, '0');
        const minutes = String(date.getMinutes()).padStart(2, '0');
        return `${year}/${month}/${day} ${hours}:${minutes}`;
    }

    function setChatPanelExpanded(expanded) {
        if (!guildChatPanelEl || !guildChatToggleBtn) return;
        guildChatPanelEl.classList.toggle('hidden', !expanded);
        guildChatToggleBtn.setAttribute('aria-expanded', expanded ? 'true' : 'false');
        guildChatToggleBtn.textContent = expanded ? '채팅 접기' : '채팅 펼치기';
    }

    function setupManageTabs() {
        const tabs = Array.from(document.querySelectorAll('[data-manage-target]'));
        const panes = Array.from(document.querySelectorAll('[data-manage-pane]'));
        if (pageMode !== 'manage' || !tabs.length || !panes.length) return;

        const activate = (target) => {
            tabs.forEach((tab) => {
                tab.classList.toggle('is-active', tab.dataset.manageTarget === target);
            });
            panes.forEach((pane) => {
                pane.classList.toggle('is-active', pane.dataset.managePane === target);
            });
        };

        tabs.forEach((tab) => {
            tab.addEventListener('click', () => activate(tab.dataset.manageTarget));
        });

        activate(tabs[0].dataset.manageTarget);
    }

    function renderMemberSelection() {
        if (!memberSelectionEl) return;
        const member = getSelectedMember();
        if (!member) {
            memberSelectionEl.classList.remove('is-selected');
            memberSelectionEl.textContent = '멤버 카드에서 관리 대상을 선택하세요.';
            return;
        }
        memberSelectionEl.classList.add('is-selected');
        memberSelectionEl.textContent = `${member.user.nickname} · ${member.role} · ID ${member.user.id}`;
        const roleSelect = document.getElementById('guild-member-role');
        if (roleSelect) {
            roleSelect.value = member.role === 'leader' ? 'vice' : member.role;
        }
    }

    function renderAvatar(url, nickname) {
        const safeUrl = Utils.sanitizeUrl ? Utils.sanitizeUrl(url || '', '') : '';
        if (safeUrl) {
            return `<div class="community-member-avatar"><img src="${Utils.escapeHtml(safeUrl)}" alt="${Utils.escapeHtml(nickname)}"></div>`;
        }
        return `<div class="community-member-avatar">${Utils.escapeHtml((nickname || '?').trim().slice(0, 1) || '?')}</div>`;
    }

    function renderGuildAvatar(url, name, compact = false) {
        const safeUrl = Utils.sanitizeUrl ? Utils.sanitizeUrl(url || '', '') : '';
        const className = compact ? 'community-guild-avatar is-compact' : 'community-guild-avatar';
        if (safeUrl) {
            return `<div class="${className}"><img src="${Utils.escapeHtml(safeUrl)}" alt="${Utils.escapeHtml(name)}"></div>`;
        }
        const fallback = Utils.escapeHtml((name || '?').trim().slice(0, 1) || '?');
        return `<div class="${className}">${fallback}</div>`;
    }

    async function loadMe() {
        try {
            me = await API.get('/accounts/me/');
        } catch {
            me = null;
        }
    }

    function renderGuildList(items) {
        if (!guildListEl) return;
        const nextSignature = `${selectedGuildId || 0}|${items.map((guild) => [
            guild.id,
            guild.name || '',
            guild.team_rating || 0,
            guild.pending_requests || 0,
            guild.member_count || 0,
        ].join(':')).join('|')}`;
        if (nextSignature === lastGuildListSignature) return;
        guildListEl.innerHTML = '';
        if (!items.length) {
            guildListEl.innerHTML = '<div class="community-empty">아직 생성된 길드가 없습니다.</div>';
            lastGuildListSignature = 'empty';
            return;
        }
        items.forEach((guild) => {
            const item = document.createElement('button');
            item.type = 'button';
            item.className = `community-item community-item--guild-list${guild.id === selectedGuildId ? ' is-active' : ''}`;
            item.innerHTML = `
                <div class="community-guild-row community-guild-row--list">
                    ${renderGuildAvatar(guild.avatar_url, guild.name, true)}
                    <div class="community-block community-block--tight">
                        <div class="community-row community-row--start">
                            <span class="community-item-title">${Utils.escapeHtml(guild.name)}</span>
                            <span class="community-badge">${Utils.escapeHtml(guild.join_policy === 'open' ? '자유 가입' : '승인제')}</span>
                        </div>
                        <div class="community-guild-list-meta">
                            <span>팀 레이팅 ${guild.team_rating}</span>
                            <span>요청 ${guild.pending_requests || 0}</span>
                        </div>
                        <span class="community-item-copy community-item-copy--clamp2">${Utils.escapeHtml(guild.description || '길드 설명이 아직 없습니다.')}</span>
                    </div>
                </div>
            `;
            item.addEventListener('click', () => loadGuildDetail(guild.id));
            guildListEl.appendChild(item);
        });
        lastGuildListSignature = nextSignature;
    }

    function renderGuildSummary(guild) {
        selectedGuild = guild;
        if (selectedMemberId && !(guild.members || []).some((member) => member.user.id === selectedMemberId)) {
            selectedMemberId = null;
        }
        const membership = myMembership();
        guildSummaryEl.innerHTML = `
            <div class="community-item">
                <div class="community-guild-row community-guild-row--summary">
                    ${renderGuildAvatar(guild.avatar_url, guild.name)}
                    <div class="community-block">
                        <span class="community-item-title">${Utils.escapeHtml(guild.name)}</span>
                        <span class="community-item-meta">길드장 ${Utils.escapeHtml(guild.owner.nickname)} · 팀 레이팅 ${guild.team_rating} · 멤버 ${guild.member_count}명</span>
                        <span class="community-item-copy">${Utils.escapeHtml(guild.description || '길드 설명이 아직 없습니다.')}</span>
                        <span class="community-item-copy">공지: ${Utils.escapeHtml(guild.notice || '아직 공지가 없습니다.')}</span>
                    </div>
                </div>
                <div class="community-row-meta">
                    <span class="community-badge">${Utils.escapeHtml(guild.join_policy === 'open' ? '자유 가입' : '승인제')}</span>
                    ${membership ? `<span class="community-badge is-ready">내 역할 · ${Utils.escapeHtml(membership.role)}</span>` : ''}
                </div>
            </div>
        `;
        if (guildJoinBtn) {
            guildJoinBtn.disabled = Boolean(membership);
            guildJoinBtn.textContent = membership ? '가입 중' : '가입 신청';
        }
        if (guildLeaveBtn) {
            guildLeaveBtn.disabled = !membership;
        }
        if (guildBattleBtn) {
            guildBattleBtn.disabled = !isManager();
        }
        guildAvatarInput?.toggleAttribute('disabled', !isManager());
        document.querySelector('#guild-avatar-form button[type="submit"]')?.toggleAttribute('disabled', !isManager());
        document.getElementById('guild-member-role')?.toggleAttribute('disabled', !isManager());
        document.querySelector('#guild-notice-form button[type="submit"]')?.toggleAttribute('disabled', !isManager());
        document.querySelector('#guild-role-form button[type="submit"]')?.toggleAttribute('disabled', !isManager());
        document.getElementById('guild-transfer-btn')?.toggleAttribute('disabled', !isLeader());
        document.getElementById('guild-kick-btn')?.toggleAttribute('disabled', !isManager());
        guildNoticeInput?.toggleAttribute('disabled', !isManager());
        renderMemberSelection();
        setChatPanelExpanded(window.innerWidth > 768);
    }

    function renderMembers(guild) {
        if (!guildMembersEl) return;
        const members = guild.members || [];
        const nextSignature = `${selectedMemberId || 0}|${members.map((member) => [
            member.user.id,
            member.role,
            member.user.rating ?? 1200,
            member.user.featured_achievement_key || '',
        ].join(':')).join('|')}`;
        if (nextSignature === lastGuildMembersSignature) return;
        if (!(guild.members || []).length) {
            guildMembersEl.innerHTML = '<div class="community-empty">멤버가 없습니다.</div>';
            lastGuildMembersSignature = 'empty';
            return;
        }
        guildMembersEl.innerHTML = (guild.members || []).map((member) => {
            const featuredAchievement = achievementLabel(member.user.featured_achievement_key);
            const isSelf = me && member.user.id === me.id;
            const isSelected = member.user.id === selectedMemberId;
            return `
                <button class="community-item community-member-card${isSelected ? ' is-selected' : ''}" type="button" data-member-id="${member.user.id}">
                    <div class="community-member-main">
                        ${renderAvatar(member.user.avatar_url, member.user.nickname)}
                        <div class="community-block">
                            <div class="community-member-title">
                                <span class="community-item-title">${Utils.escapeHtml(member.user.nickname)}</span>
                                <span class="community-badge">${Utils.escapeHtml(member.role)}</span>
                                ${featuredAchievement ? `<span class="community-badge is-link">${Utils.escapeHtml(featuredAchievement)}</span>` : ''}
                            </div>
                            <div class="community-member-meta">
                                <span class="community-item-meta">레이팅 ${member.user.rating ?? 1200}</span>
                                <span class="community-item-meta">ID ${member.user.id}</span>
                                ${isSelf ? '<span class="community-badge is-ready">나</span>' : ''}
                            </div>
                        </div>
                    </div>
                </button>
            `;
        }).join('');
        guildMembersEl.querySelectorAll('[data-member-id]').forEach((button) => {
            button.addEventListener('click', () => {
                selectedMemberId = Number(button.dataset.memberId);
                renderMembers(selectedGuild);
                renderMemberSelection();
            });
        });
        lastGuildMembersSignature = nextSignature;
    }

    function renderChat(items) {
        if (!guildChatLogEl) return;
        const nextSignature = items.map((message) => [message.id, message.created_at || '', message.content || ''].join(':')).join('|');
        if (nextSignature === lastGuildChatSignature) return;
        guildChatLogEl.innerHTML = '';
        if (!items.length) {
            guildChatLogEl.innerHTML = '<div class="community-empty">아직 채팅이 없습니다.</div>';
            lastGuildChatSignature = 'empty';
            return;
        }
        items.slice().reverse().forEach((message) => {
            const item = document.createElement('div');
            item.className = 'community-chat-message';
            item.innerHTML = `
                <span class="community-chat-user">${Utils.escapeHtml(message.user.nickname)}</span>
                <span class="community-chat-body">${Utils.escapeHtml(message.content)}</span>
                <span class="community-chat-time">${Utils.formatDateTime ? Utils.formatDateTime(message.created_at) : message.created_at}</span>
            `;
            guildChatLogEl.appendChild(item);
        });
        lastGuildChatSignature = nextSignature;
    }

    function renderRequests(items) {
        if (!guildRequestsEl) return;
        const nextSignature = `${isManager() ? 1 : 0}|${items.map((requestItem) => [
            requestItem.id,
            requestItem.user.id,
            requestItem.user.nickname || '',
        ].join(':')).join('|')}`;
        if (nextSignature === lastGuildRequestsSignature) return;
        guildRequestsEl.innerHTML = '';
        if (!isManager()) {
            guildRequestsEl.innerHTML = '<div class="community-empty">운영진만 가입 요청을 확인할 수 있습니다.</div>';
            lastGuildRequestsSignature = 'locked';
            return;
        }
        if (!items.length) {
            guildRequestsEl.innerHTML = '<div class="community-empty">대기 중인 가입 요청이 없습니다.</div>';
            lastGuildRequestsSignature = 'empty';
            return;
        }
        items.forEach((requestItem) => {
            const item = document.createElement('div');
            item.className = 'community-item';
            item.innerHTML = `
                <div class="community-row">
                    <span class="community-item-title">${Utils.escapeHtml(requestItem.user.nickname)}</span>
                    <div class="community-row-meta">
                        <span class="community-badge">ID ${requestItem.user.id}</span>
                    </div>
                </div>
                <span class="community-item-copy">${Utils.escapeHtml(requestItem.message || '가입 메시지가 없습니다.')}</span>
                <div class="community-actions">
                    <button class="btn btn-secondary btn-sm" data-action="approve" data-id="${requestItem.id}" type="button">승인</button>
                    <button class="btn btn-danger btn-sm" data-action="reject" data-id="${requestItem.id}" type="button">거절</button>
                </div>
            `;
            guildRequestsEl.appendChild(item);
        });
        guildRequestsEl.querySelectorAll('button[data-action]').forEach((button) => {
            button.addEventListener('click', async () => {
                try {
                    await API.post(`/community/guilds/requests/${button.dataset.id}/review/`, {
                        approve: button.dataset.action === 'approve',
                    });
                    Toast.success(button.dataset.action === 'approve' ? '가입 요청을 승인했습니다.' : '가입 요청을 거절했습니다.');
                    await loadGuildDetail(selectedGuildId);
                } catch (error) {
                    Toast.error(error.data?.message || error.message);
                }
            });
        });
        lastGuildRequestsSignature = nextSignature;
    }

    function renderNoticeHistory(items) {
        if (!guildNoticeHistoryEl) return;
        const nextSignature = items.map((notice) => [notice.id, notice.created_at || '', notice.content || ''].join(':')).join('|');
        if (nextSignature === lastGuildNoticeSignature) return;
        guildNoticeHistoryEl.innerHTML = '';
        if (!items.length) {
            guildNoticeHistoryEl.innerHTML = '<div class="community-empty">아직 작성된 길드 공지가 없습니다.</div>';
            lastGuildNoticeSignature = 'empty';
            return;
        }
        items.forEach((notice) => {
            const item = document.createElement('div');
            item.className = 'community-item community-item--detail';
            item.innerHTML = `
                <div class="community-row">
                    <span class="community-item-title">${Utils.escapeHtml(notice.author?.nickname || '시스템 공지')}</span>
                    <span class="community-item-meta">${Utils.escapeHtml(formatNoticeTimestamp(notice.created_at))}</span>
                </div>
                <span class="community-item-copy community-item-copy--detail">${Utils.escapeHtml(notice.content || '')}</span>
            `;
            guildNoticeHistoryEl.appendChild(item);
        });
        lastGuildNoticeSignature = nextSignature;
    }

    async function loadGuilds() {
        if (!guildListEl) return;
        const data = await API.get('/community/guilds/');
        const items = data.results || [];
        renderGuildList(items);
        if (selectedGuildId && !items.some((guild) => guild.id === selectedGuildId)) {
            selectedGuildId = null;
        }
        if (!selectedGuildId && items.length) {
            await loadGuildDetail(items[0].id);
        }
    }

    async function loadCurrentGuildDetail() {
        const guild = await API.get('/community/guilds/me/current/');
        if (!guild?.id) {
            detailPanelEl?.classList.add('hidden');
            detailEmptyEl?.classList.remove('hidden');
            if (detailEmptyEl) {
                detailEmptyEl.innerHTML = '아직 가입한 길드가 없습니다. <a class="section-link" href="/guilds/">길드 둘러보기로 이동</a>';
            }
            return;
        }
        selectedGuildId = guild.id;
        detailEmptyEl?.classList.add('hidden');
        detailPanelEl?.classList.remove('hidden');
        renderGuildSummary(guild);
        renderMembers(guild);
        if (pageMode === 'manage') {
            const [chat, requests, noticeHistory] = await Promise.all([
                API.get(`/community/guilds/${guild.id}/chat/`).catch(() => ({ results: [] })),
                API.get(`/community/guilds/${guild.id}/join/`).catch(() => ({ results: [] })),
                API.get(`/community/guilds/${guild.id}/notice/`).catch(() => ({ results: [] })),
            ]);
            renderChat(chat.results || []);
            renderRequests(requests.results || []);
            renderNoticeHistory(noticeHistory.results || []);
        }
    }

    async function loadGuildDetail(guildId) {
        selectedGuildId = guildId;
        const [guild, guildList] = await Promise.all([
            API.get(`/community/guilds/${guildId}/`),
            API.get('/community/guilds/'),
        ]);
        detailEmptyEl.classList.add('hidden');
        detailPanelEl.classList.remove('hidden');
        renderGuildSummary(guild);
        renderMembers(guild);
        if (pageMode === 'manage') {
            const [chat, requests, noticeHistory] = await Promise.all([
                API.get(`/community/guilds/${guildId}/chat/`).catch(() => ({ results: [] })),
                API.get(`/community/guilds/${guildId}/join/`).catch(() => ({ results: [] })),
                API.get(`/community/guilds/${guildId}/notice/`).catch(() => ({ results: [] })),
            ]);
            renderChat(chat.results || []);
            renderRequests(requests.results || []);
            renderNoticeHistory(noticeHistory.results || []);
        }
        renderGuildList(guildList.results || []);
    }

    async function submitCreate(event) {
        event.preventDefault();
        const form = event.currentTarget;
        const formData = new FormData();
        formData.set('name', form.elements.name.value.trim());
        formData.set('description', form.elements.description.value.trim());
        formData.set('join_policy', form.elements.join_policy.value);
        formData.set('min_rating', String(Number(form.elements.min_rating.value || 0)));
        formData.set('active_hours', form.elements.active_hours.value.trim());
        formData.set('contact_channel', form.elements.contact_channel.value.trim());
        const avatarFile = form.elements.avatar?.files?.[0];
        if (avatarFile instanceof File && avatarFile.name) {
            formData.set('avatar', avatarFile, avatarFile.name);
        }
        const guild = await API.post('/community/guilds/', formData, true);
        selectedGuildId = guild.id;
        Toast.success('길드를 생성했습니다.');
        form.reset();
        window.location.href = '/guilds/manage/';
    }

    async function joinGuild() {
        if (!selectedGuildId) return;
        await API.post(`/community/guilds/${selectedGuildId}/join/`, { message: '함께 활동하고 싶습니다.' });
        Toast.success('길드 가입 요청을 보냈습니다.');
        await loadGuildDetail(selectedGuildId);
    }

    async function leaveGuild() {
        if (!selectedGuildId) return;
        await API.post(`/community/guilds/${selectedGuildId}/leave/`, {});
        Toast.info('길드에서 탈퇴했습니다.');
        selectedGuildId = null;
        selectedGuild = null;
        detailPanelEl.classList.add('hidden');
        detailEmptyEl.classList.remove('hidden');
        if (pageMode === 'manage') {
            window.location.href = '/guilds/';
            return;
        }
        await loadGuilds();
    }

    async function createGuildBattle() {
        if (!selectedGuildId) return;
        await API.post('/community/team-battles/', { battle_type: 'guild', guild_id: selectedGuildId });
        Toast.success('길드전 매칭 대기를 생성했습니다.');
    }

    async function saveNotice(event) {
        event.preventDefault();
        if (!selectedGuildId) return;
        const notice = guildNoticeInput.value.trim();
        if (!notice) {
            Toast.error('공지 내용을 입력하세요.');
            return;
        }
        const data = await API.post(`/community/guilds/${selectedGuildId}/notice/`, { notice });
        if (selectedGuild) {
            selectedGuild.notice = data.notice || notice;
            renderGuildSummary(selectedGuild);
        }
        renderNoticeHistory(data.results || []);
        guildNoticeInput.value = '';
        Toast.success('길드 공지를 저장했습니다.');
    }

    async function updateAvatar(event) {
        event.preventDefault();
        if (!selectedGuildId) return;
        const file = guildAvatarInput?.files?.[0];
        if (!file) {
            Toast.error('업로드할 이미지를 먼저 선택하세요.');
            return;
        }
        const formData = new FormData();
        formData.append('avatar', file);
        await API.patch(`/community/guilds/${selectedGuildId}/avatar/`, formData, true);
        guildAvatarInput.value = '';
        Toast.success('길드 프로필 사진을 업데이트했습니다.');
        await loadGuildDetail(selectedGuildId);
    }

    function selectedMemberUserId() {
        return Number(selectedMemberId || 0);
    }

    async function updateRole(event) {
        event.preventDefault();
        if (!selectedGuildId) return;
        const userId = selectedMemberUserId();
        const role = document.getElementById('guild-member-role')?.value;
        if (!userId || !role) {
            Toast.error('관리할 멤버를 먼저 선택하세요.');
            return;
        }
        await API.post(`/community/guilds/${selectedGuildId}/members/${userId}/role/`, { role });
        Toast.success('길드 멤버 역할을 변경했습니다.');
        await loadGuildDetail(selectedGuildId);
    }

    async function transferLeadership() {
        if (!selectedGuildId) return;
        const userId = selectedMemberUserId();
        if (!userId) {
            Toast.error('위임할 멤버를 먼저 선택하세요.');
            return;
        }
        await API.post(`/community/guilds/${selectedGuildId}/transfer/${userId}/`, {});
        Toast.success('길드장을 위임했습니다.');
        await loadGuildDetail(selectedGuildId);
    }

    async function kickMember() {
        if (!selectedGuildId) return;
        const userId = selectedMemberUserId();
        if (!userId) {
            Toast.error('추방할 멤버를 먼저 선택하세요.');
            return;
        }
        await API.post(`/community/guilds/${selectedGuildId}/members/${userId}/kick/`, {});
        Toast.success('길드 멤버를 추방했습니다.');
        await loadGuildDetail(selectedGuildId);
    }

    async function sendChat(event) {
        event.preventDefault();
        if (!selectedGuildId) return;
        const input = document.getElementById('guild-chat-input');
        const content = input.value.trim();
        if (!content) return;
        await API.post(`/community/guilds/${selectedGuildId}/chat/`, { content });
        input.value = '';
        await loadGuildDetail(selectedGuildId);
    }

    async function init() {
        await loadMe();
        setupManageTabs();
        if (pageMode === 'manage') {
            await loadCurrentGuildDetail();
        } else {
            await loadGuilds();
        }
        document.getElementById('guild-create-form')?.addEventListener('submit', (event) => submitCreate(event).catch((error) => Toast.error(error.data?.message || error.message)));
        guildJoinBtn?.addEventListener('click', () => joinGuild().catch((error) => Toast.error(error.data?.message || error.message)));
        guildLeaveBtn?.addEventListener('click', () => leaveGuild().catch((error) => Toast.error(error.data?.message || error.message)));
        guildBattleBtn?.addEventListener('click', () => createGuildBattle().catch((error) => Toast.error(error.data?.message || error.message)));
        document.getElementById('guild-chat-form')?.addEventListener('submit', (event) => sendChat(event).catch((error) => Toast.error(error.data?.message || error.message)));
        document.getElementById('guild-avatar-form')?.addEventListener('submit', (event) => updateAvatar(event).catch((error) => Toast.error(error.data?.message || error.message)));
        document.getElementById('guild-notice-form')?.addEventListener('submit', (event) => saveNotice(event).catch((error) => Toast.error(error.data?.message || error.message)));
        document.getElementById('guild-role-form')?.addEventListener('submit', (event) => updateRole(event).catch((error) => Toast.error(error.data?.message || error.message)));
        document.getElementById('guild-transfer-btn')?.addEventListener('click', () => transferLeadership().catch((error) => Toast.error(error.data?.message || error.message)));
        document.getElementById('guild-kick-btn')?.addEventListener('click', () => kickMember().catch((error) => Toast.error(error.data?.message || error.message)));
        guildChatToggleBtn?.addEventListener('click', () => setChatPanelExpanded(guildChatPanelEl?.classList.contains('hidden')));
    }

    document.addEventListener('DOMContentLoaded', () => {
        init().catch((error) => Toast.error(error.data?.message || error.message || '길드 화면을 불러오지 못했습니다.'));
    });
})();
