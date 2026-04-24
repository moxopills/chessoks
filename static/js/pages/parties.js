(function () {
    let me = null;
    let selectedPartyId = null;
    let selectedParty = null;
    let currentPartyReady = false;
    let selectedMemberId = null;
    let isGuestUser = false;
    let selectedInviteUserId = null;
    let onlineInviteUsers = [];
    let inviteSearchResults = [];
    let lastPartyListSignature = '';
    let lastPartyChatSignature = '';
    let lastPartyInvitesSignature = '';
    let lastInviteSuggestionSignature = '';
    let lastInviteSearchSignature = '';
    const pageEl = document.getElementById('party-page');
    const pageMode = pageEl?.dataset.view || 'browse';

    const partyListEl = document.getElementById('party-list');
    const detailEmptyEl = document.getElementById('party-detail-empty');
    const detailPanelEl = document.getElementById('party-detail-panel');
    const partySummaryEl = document.getElementById('party-summary');
    const partyMembersEl = document.getElementById('party-members');
    const partyChatLogEl = document.getElementById('party-chat-log');
    const partyInviteListEl = document.getElementById('party-invite-list');
    const readyBtn = document.getElementById('party-ready-btn');
    const lineupBtn = document.getElementById('party-lineup-btn');
    const closeBtn = document.getElementById('party-close-btn');
    const partyChatPanelEl = document.getElementById('party-chat-panel');
    const partyChatToggleBtn = document.getElementById('party-chat-toggle');
    const memberSelectionEl = document.getElementById('party-member-selection');
    const inviteSelectionEl = document.getElementById('party-invite-selection');
    const inviteResultsEl = document.getElementById('party-invite-results');
    const onlineSuggestionsEl = document.getElementById('party-online-suggestions');
    const inviteQueryInput = document.getElementById('party-invite-query');

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
        if (!selectedParty || !me) return null;
        return (selectedParty.members || []).find((member) => member.user.id === me.id) || null;
    }

    function isLeader() {
        return Boolean(selectedParty && me && selectedParty.leader.id === me.id);
    }

    function canManageParty() {
        return isLeader() && !isGuestUser;
    }

    function setChatPanelExpanded(expanded) {
        if (!partyChatPanelEl || !partyChatToggleBtn) return;
        partyChatPanelEl.classList.toggle('hidden', !expanded);
        partyChatToggleBtn.setAttribute('aria-expanded', expanded ? 'true' : 'false');
        partyChatToggleBtn.textContent = expanded ? '채팅 접기' : '채팅 펼치기';
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

    function getSelectedMember() {
        return (selectedParty?.members || []).find((member) => member.user.id === selectedMemberId) || null;
    }

    function achievementLabel(key) {
        return ACHIEVEMENT_LABELS[key] || '';
    }

    function renderAvatar(url, nickname) {
        const safeUrl = Utils.sanitizeUrl ? Utils.sanitizeUrl(url || '', '') : '';
        if (safeUrl) {
            return `<div class="community-member-avatar"><img src="${Utils.escapeHtml(safeUrl)}" alt="${Utils.escapeHtml(nickname)}"></div>`;
        }
        return `<div class="community-member-avatar">${Utils.escapeHtml((nickname || '?').trim().slice(0, 1) || '?')}</div>`;
    }

    function renderMemberSelection() {
        if (!memberSelectionEl) return;
        const member = getSelectedMember();
        if (!member) {
            memberSelectionEl.classList.remove('is-selected');
            memberSelectionEl.textContent = '멤버 카드를 선택하면 슬롯 지정과 파티장 위임/추방이 가능합니다.';
            return;
        }
        memberSelectionEl.classList.add('is-selected');
        memberSelectionEl.textContent = `${member.user.nickname} · 슬롯 ${member.slot ?? '-'} · ${member.is_ready ? '준비 완료' : '준비 전'} · ID ${member.user.id}`;
    }

    function getInviteBlockedIds() {
        const ids = new Set((selectedParty?.members || []).map((member) => member.user.id));
        if (me?.id) ids.add(me.id);
        return ids;
    }

    function getInvitePresenceClass(user) {
        if (!user?.online) return '';
        if (['playing', 'competitive', 'quick'].includes(user.status)) return 'is-live';
        if (['room_waiting', 'lobby'].includes(user.status)) return 'is-ready';
        return 'is-info';
    }

    function renderInviteSelection() {
        if (!inviteSelectionEl) return;
        const selected =
            [...onlineInviteUsers, ...inviteSearchResults].find((user) => user.id === selectedInviteUserId) || null;
        if (!selected) {
            inviteSelectionEl.classList.remove('is-selected');
            inviteSelectionEl.textContent = '초대할 유저를 검색하거나 아래 목록에서 선택하세요.';
            return;
        }
        inviteSelectionEl.classList.add('is-selected');
        const statusLabel = selected.status_label || (selected.online ? '온라인' : '오프라인');
        inviteSelectionEl.textContent = `${selected.nickname} · ${statusLabel} · 레이팅 ${selected.stats?.rating ?? selected.rating ?? '-'} · ID ${selected.id}`;
    }

    function renderInviteCandidates(container, users, emptyText) {
        if (!container) return;
        const nextSignature = `${selectedInviteUserId || 0}|${users.map((user) => [
            user.id,
            user.nickname || '',
            user.status_label || '',
            user.stats?.rating ?? user.rating ?? '',
        ].join(':')).join('|')}`;
        const isOnlineContainer = container === onlineSuggestionsEl;
        if ((isOnlineContainer ? lastInviteSuggestionSignature : lastInviteSearchSignature) === nextSignature) {
            return;
        }
        if (!users.length) {
            container.innerHTML = `<div class="community-empty">${emptyText}</div>`;
            if (isOnlineContainer) lastInviteSuggestionSignature = 'empty';
            else lastInviteSearchSignature = 'empty';
            return;
        }
        container.innerHTML = users.map((user) => {
            const featuredAchievement = achievementLabel(user.featured_achievement?.key || user.featured_achievement_key);
            const statusClass = getInvitePresenceClass(user);
            const statusLabel = user.status_label || (user.online ? '온라인' : '오프라인');
            const isSelected = user.id === selectedInviteUserId;
            return `
                <button class="community-picker-item${isSelected ? ' is-selected' : ''}" type="button" data-invite-user-id="${user.id}">
                    <div class="community-picker-main">
                        ${renderAvatar(user.avatar_url, user.nickname)}
                        <div class="community-block">
                            <span class="community-item-title">${Utils.escapeHtml(user.nickname)}</span>
                            <div class="community-picker-meta">
                                <span class="community-badge ${statusClass}">${Utils.escapeHtml(statusLabel)}</span>
                                <span class="community-item-meta">레이팅 ${user.stats?.rating ?? user.rating ?? '-'}</span>
                                ${featuredAchievement ? `<span class="community-badge is-link">${Utils.escapeHtml(featuredAchievement)}</span>` : ''}
                            </div>
                        </div>
                    </div>
                </button>
            `;
        }).join('');
        container.querySelectorAll('[data-invite-user-id]').forEach((button) => {
            button.addEventListener('click', () => {
                selectedInviteUserId = Number(button.dataset.inviteUserId);
                renderInviteSelection();
                renderInviteCandidates(onlineSuggestionsEl, onlineInviteUsers, '현재 바로 초대할 수 있는 접속자가 없습니다.');
                renderInviteCandidates(inviteResultsEl, inviteSearchResults, '검색 결과가 없습니다.');
            });
        });
        if (isOnlineContainer) lastInviteSuggestionSignature = nextSignature;
        else lastInviteSearchSignature = nextSignature;
    }

    async function loadOnlineInviteSuggestions() {
        if (!canManageParty()) {
            onlineInviteUsers = [];
            renderInviteCandidates(onlineSuggestionsEl, [], '파티장만 접속자 초대를 보낼 수 있습니다.');
            renderInviteSelection();
            return;
        }
        const blockedIds = getInviteBlockedIds();
        const data = await API.get('/accounts/online-users/');
        onlineInviteUsers = (data.results || [])
            .filter((user) => !blockedIds.has(user.id))
            .slice(0, 8);
        if (selectedInviteUserId && blockedIds.has(selectedInviteUserId)) {
            selectedInviteUserId = null;
        }
        renderInviteCandidates(onlineSuggestionsEl, onlineInviteUsers, '현재 바로 초대할 수 있는 접속자가 없습니다.');
        renderInviteSelection();
    }

    async function searchInviteUsers(event) {
        event?.preventDefault?.();
        if (!canManageParty()) {
            Toast.error('파티장만 유저를 초대할 수 있습니다.');
            return;
        }
        const query = inviteQueryInput?.value?.trim() || '';
        if (!query) {
            inviteSearchResults = [];
            renderInviteCandidates(inviteResultsEl, [], '닉네임으로 검색하면 결과가 표시됩니다.');
            renderInviteSelection();
            return;
        }
        const blockedIds = getInviteBlockedIds();
        const data = await API.get('/accounts/users/search/', { q: query });
        const onlineMap = new Map(onlineInviteUsers.map((user) => [user.id, user]));
        inviteSearchResults = (data.results || [])
            .filter((user) => !blockedIds.has(user.id))
            .map((user) => {
                const onlineEntry = onlineMap.get(user.id);
                return {
                    ...user,
                    online: Boolean(onlineEntry?.online),
                    status: onlineEntry?.status || '',
                    status_label: onlineEntry?.status_label || '오프라인',
                };
            });
        renderInviteCandidates(inviteResultsEl, inviteSearchResults, '검색 결과가 없습니다.');
        renderInviteSelection();
    }

    function resetInvitePicker() {
        selectedInviteUserId = null;
        inviteSearchResults = [];
        if (inviteQueryInput) inviteQueryInput.value = '';
        renderInviteCandidates(inviteResultsEl, [], '닉네임으로 검색하면 결과가 표시됩니다.');
        renderInviteSelection();
    }

    async function loadMe() {
        try {
            me = await API.get('/accounts/me/');
            window.__partyMeId = me.id;
            isGuestUser = Boolean(me.is_guest);
        } catch {
            me = null;
            isGuestUser = false;
        }
    }

    function renderPartyList(items) {
        if (!partyListEl) return;
        const nextSignature = `${selectedPartyId || 0}|${items.map((party) => [
            party.id,
            party.title || '',
            party.status || '',
            party.leader?.id || '',
        ].join(':')).join('|')}`;
        if (nextSignature === lastPartyListSignature) return;
        partyListEl.innerHTML = '';
        if (!items.length) {
            partyListEl.innerHTML = '<div class="community-empty">활성 파티가 없습니다.</div>';
            lastPartyListSignature = 'empty';
            return;
        }
        items.forEach((party) => {
            const item = document.createElement('button');
            item.type = 'button';
            item.className = `community-item${party.id === selectedPartyId ? ' is-active' : ''}`;
            item.innerHTML = `
                <span class="community-item-title">${Utils.escapeHtml(party.title)}</span>
                <span class="community-item-meta">${Utils.escapeHtml(party.status)} · 파티장 ${Utils.escapeHtml(party.leader.nickname)}</span>
                <span class="community-item-copy">${Utils.escapeHtml(party.description || '파티 설명이 아직 없습니다.')}</span>
            `;
            item.addEventListener('click', () => loadPartyDetail(party.id));
            partyListEl.appendChild(item);
        });
        lastPartyListSignature = nextSignature;
    }

    function renderPartyDetail(party) {
        selectedParty = party;
        if (selectedMemberId && !(party.members || []).some((member) => member.user.id === selectedMemberId)) {
            selectedMemberId = null;
        }
        detailEmptyEl.classList.add('hidden');
        detailPanelEl.classList.remove('hidden');
        currentPartyReady = Boolean((party.members || []).find((member) => member.user.id === window.__partyMeId)?.is_ready);
        readyBtn.textContent = currentPartyReady ? '준비 해제' : '준비 완료';
        lineupBtn.textContent = party.lineup_locked ? '라인업 해제' : '라인업 고정';
        readyBtn.disabled = !myMembership();
        lineupBtn.disabled = !canManageParty();
        closeBtn?.toggleAttribute('disabled', !canManageParty());
        document.querySelector('#party-invite-form button[type="submit"]')?.toggleAttribute('disabled', !canManageParty());
        document.querySelector('#party-slot-form button[type="submit"]')?.toggleAttribute('disabled', !canManageParty());
        document.getElementById('party-transfer-btn')?.toggleAttribute('disabled', !canManageParty());
        document.getElementById('party-kick-btn')?.toggleAttribute('disabled', !canManageParty());
        document.getElementById('party-battle-btn')?.toggleAttribute('disabled', !canManageParty() || !party.lineup_locked);
        document.getElementById('party-slot-value')?.toggleAttribute('disabled', !canManageParty());
        partySummaryEl.innerHTML = `
            <div class="community-item">
                <span class="community-item-title">${Utils.escapeHtml(party.title)}</span>
                <span class="community-item-meta">파티장 ${Utils.escapeHtml(party.leader.nickname)} · 상태 ${Utils.escapeHtml(party.status)} · 라인업 ${party.lineup_locked ? '고정됨' : '편집 가능'}</span>
                <span class="community-item-copy">${Utils.escapeHtml(party.description || '파티 설명이 아직 없습니다.')}</span>
                ${isGuestUser ? '<span class="community-badge is-info">게스트 참가 모드</span>' : ''}
            </div>
        `;
        if (!(party.members || []).length) {
            partyMembersEl.innerHTML = '<div class="community-empty">멤버가 없습니다.</div>';
        } else {
            partyMembersEl.innerHTML = (party.members || []).map((member) => {
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
                                    ${member.slot ? `<span class="community-badge is-info">${member.slot}번</span>` : '<span class="community-badge">대기</span>'}
                                    ${member.is_ready ? '<span class="community-badge is-ready">준비 완료</span>' : '<span class="community-badge">준비 전</span>'}
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
            partyMembersEl.querySelectorAll('[data-member-id]').forEach((button) => {
                button.addEventListener('click', () => {
                    selectedMemberId = Number(button.dataset.memberId);
                    renderPartyDetail(selectedParty);
                    renderMemberSelection();
                });
            });
        }
        renderMemberSelection();
        renderInviteSelection();
        loadOnlineInviteSuggestions().catch(() => {
            renderInviteCandidates(onlineSuggestionsEl, [], '접속자 목록을 불러오지 못했습니다.');
        });
        setChatPanelExpanded(window.innerWidth > 768);
    }

    function renderChat(items) {
        const nextSignature = items.map((message) => [message.id, message.created_at || '', message.content || ''].join(':')).join('|');
        if (nextSignature === lastPartyChatSignature) return;
        partyChatLogEl.innerHTML = '';
        if (!items.length) {
            partyChatLogEl.innerHTML = '<div class="community-empty">아직 채팅이 없습니다.</div>';
            lastPartyChatSignature = 'empty';
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
            partyChatLogEl.appendChild(item);
        });
        lastPartyChatSignature = nextSignature;
    }

    function renderInvites(items) {
        if (!partyInviteListEl) return;
        const nextSignature = items.map((invite) => [invite.id, invite.party_id || '', invite.from_user?.id || ''].join(':')).join('|');
        if (nextSignature === lastPartyInvitesSignature) return;
        partyInviteListEl.innerHTML = '';
        if (!items.length) {
            partyInviteListEl.innerHTML = '<div class="community-empty">대기 중인 파티 초대가 없습니다.</div>';
            lastPartyInvitesSignature = 'empty';
            return;
        }
        items.forEach((invite) => {
            const item = document.createElement('div');
            item.className = 'community-item';
            item.innerHTML = `
                <span class="community-item-title">${Utils.escapeHtml(invite.party_title || `파티 #${invite.party_id || invite.id}`)}</span>
                <span class="community-item-meta">초대한 사람 ${Utils.escapeHtml(invite.from_user.nickname)}</span>
                <div class="community-actions">
                    <button class="btn btn-secondary btn-sm" data-action="accept" data-id="${invite.id}" type="button">수락</button>
                    <button class="btn btn-danger btn-sm" data-action="decline" data-id="${invite.id}" type="button">거절</button>
                </div>
            `;
            partyInviteListEl.appendChild(item);
        });
        partyInviteListEl.querySelectorAll('button[data-action]').forEach((button) => {
            button.addEventListener('click', async () => {
                try {
                    await API.post(`/community/parties/invites/${button.dataset.id}/respond/`, {
                        accept: button.dataset.action === 'accept',
                    });
                    window.PartyInvites?.invalidate();
                    Toast.success(button.dataset.action === 'accept' ? '파티 초대를 수락했습니다.' : '파티 초대를 거절했습니다.');
                    await loadPendingInvites();
                    if (pageMode === 'manage') {
                        await loadCurrentPartyDetail();
                    } else {
                        await loadParties();
                    }
                } catch (error) {
                    Toast.error(error.data?.message || error.message);
                }
            });
        });
        lastPartyInvitesSignature = nextSignature;
    }

    async function loadPendingInvites() {
        if (!partyInviteListEl) return;
        if (!me) {
            renderInvites([]);
            return;
        }
        const data = await API.get('/community/parties/invites/');
        renderInvites(data.results || []);
    }

    async function loadParties() {
        if (!partyListEl) return;
        const data = await API.get('/community/parties/');
        const items = data.results || [];
        renderPartyList(items);
        if (selectedPartyId && !items.some((party) => party.id === selectedPartyId)) {
            selectedPartyId = null;
        }
        if (!selectedPartyId && items.length) {
            await loadPartyDetail(items[0].id);
        }
    }

    async function loadCurrentPartyDetail() {
        const summary = await API.get('/community/parties/me/active/');
        if (!summary?.party_id) {
            detailPanelEl?.classList.add('hidden');
            detailEmptyEl?.classList.remove('hidden');
            if (detailEmptyEl) {
                detailEmptyEl.innerHTML = '아직 참가 중인 파티가 없습니다. <a class="section-link" href="/parties/">파티 둘러보기로 이동</a>';
            }
            return;
        }
        await loadPartyDetail(summary.party_id);
    }

    async function loadPartyDetail(partyId) {
        selectedPartyId = partyId;
        const party = await API.get(`/community/parties/${partyId}/`);
        renderPartyDetail(party);
        if (partyListEl) {
            const parties = await API.get('/community/parties/');
            renderPartyList(parties.results || []);
        }
        const isMember = Boolean((party.members || []).some((member) => member.user.id === me?.id));
        if (isMember && party.status !== 'closed') {
            const chat = await API.get(`/community/parties/${partyId}/chat/`).catch(() => ({ results: [] }));
            renderChat(chat.results || []);
        } else {
            renderChat([]);
        }
    }

    async function createParty(event) {
        event.preventDefault();
        if (isGuestUser) {
            Toast.error('게스트는 파티 생성이 불가능합니다. 초대를 받아 참가만 할 수 있습니다.');
            return;
        }
        const payload = Object.fromEntries(new FormData(event.currentTarget).entries());
        await API.post('/community/parties/', payload);
        window.PartyInvites?.invalidate();
        Toast.success('파티를 생성했습니다.');
        event.currentTarget.reset();
        window.location.href = '/parties/manage/';
    }

    async function toggleReady() {
        if (!selectedPartyId) return;
        await API.post(`/community/parties/${selectedPartyId}/ready/`, { ready: !currentPartyReady });
        Toast.success('준비 상태를 갱신했습니다.');
        await loadPartyDetail(selectedPartyId);
    }

    async function toggleLineupLock() {
        if (!selectedPartyId || !selectedParty) return;
        await API.post(`/community/parties/${selectedPartyId}/lineup/`, { locked: !selectedParty.lineup_locked });
        Toast.success(selectedParty.lineup_locked ? '라인업을 해제했습니다.' : '라인업을 고정했습니다.');
        await loadPartyDetail(selectedPartyId);
    }

    async function leaveParty() {
        if (!selectedPartyId) return;
        await API.post(`/community/parties/${selectedPartyId}/leave/`, {});
        window.PartyInvites?.invalidate();
        Toast.info('파티에서 나갔습니다.');
        selectedPartyId = null;
        selectedParty = null;
        detailPanelEl.classList.add('hidden');
        detailEmptyEl.classList.remove('hidden');
        if (pageMode === 'manage') {
            window.location.href = '/parties/';
            return;
        }
        await Promise.all([loadParties(), loadPendingInvites()]);
    }

    async function closeParty() {
        if (!selectedPartyId) return;
        await API.post(`/community/parties/${selectedPartyId}/close/`, {});
        window.PartyInvites?.invalidate();
        Toast.info('파티를 삭제했습니다.');
        selectedPartyId = null;
        selectedParty = null;
        selectedMemberId = null;
        selectedInviteUserId = null;
        detailPanelEl.classList.add('hidden');
        detailEmptyEl.classList.remove('hidden');
        if (pageMode === 'manage') {
            window.location.href = '/parties/';
            return;
        }
        await Promise.all([loadParties(), loadPendingInvites()]);
    }

    async function inviteUser(event) {
        event.preventDefault();
        if (isGuestUser) {
            Toast.error('게스트는 파티에 초대만 받을 수 있습니다.');
            return;
        }
        if (!selectedPartyId) return;
        const userId = Number(selectedInviteUserId || 0);
        if (!userId) return Toast.error('초대할 유저를 먼저 선택하세요.');
        await API.post(`/community/parties/${selectedPartyId}/invite/`, { user_id: userId });
        Toast.success('파티 초대를 보냈습니다.');
        resetInvitePicker();
        await loadOnlineInviteSuggestions();
    }

    async function assignSlot(event) {
        event.preventDefault();
        if (isGuestUser) {
            Toast.error('게스트는 라인업을 관리할 수 없습니다.');
            return;
        }
        if (!selectedPartyId) return;
        const userId = Number(selectedMemberId || 0);
        const slot = Number(document.getElementById('party-slot-value').value);
        if (!userId || !slot) return Toast.error('멤버를 선택하고 슬롯을 입력하세요.');
        await API.post(`/community/parties/${selectedPartyId}/slot/`, { user_id: userId, slot });
        Toast.success('라인업을 지정했습니다.');
        await loadPartyDetail(selectedPartyId);
        event.currentTarget.reset();
    }

    function partyMemberUserId() {
        return Number(selectedMemberId || 0);
    }

    async function transferLeader() {
        if (isGuestUser) {
            Toast.error('게스트는 파티장을 맡을 수 없습니다.');
            return;
        }
        if (!selectedPartyId) return;
        const userId = partyMemberUserId();
        if (!userId) return Toast.error('위임할 멤버를 선택하세요.');
        await API.post(`/community/parties/${selectedPartyId}/transfer/${userId}/`, {});
        Toast.success('파티장을 위임했습니다.');
        await loadPartyDetail(selectedPartyId);
    }

    async function kickMember() {
        if (isGuestUser) {
            Toast.error('게스트는 멤버를 관리할 수 없습니다.');
            return;
        }
        if (!selectedPartyId) return;
        const userId = partyMemberUserId();
        if (!userId) return Toast.error('추방할 멤버를 선택하세요.');
        await API.post(`/community/parties/${selectedPartyId}/members/${userId}/kick/`, {});
        Toast.success('파티 멤버를 추방했습니다.');
        await loadPartyDetail(selectedPartyId);
    }

    async function createPartyBattle() {
        if (isGuestUser) {
            Toast.error('게스트는 단체전 매칭을 생성할 수 없습니다.');
            return;
        }
        if (!selectedPartyId) return;
        await API.post('/community/team-battles/', { battle_type: 'party', party_id: selectedPartyId });
        Toast.success('단체전 매칭 대기를 생성했습니다.');
        await loadPartyDetail(selectedPartyId);
    }

    async function sendChat(event) {
        event.preventDefault();
        if (!selectedPartyId) return;
        if (!myMembership()) return Toast.error('파티 멤버만 채팅할 수 있습니다.');
        const input = document.getElementById('party-chat-input');
        const content = input.value.trim();
        if (!content) return;
        await API.post(`/community/parties/${selectedPartyId}/chat/`, { content });
        input.value = '';
        await loadPartyDetail(selectedPartyId);
    }

    async function init() {
        await loadMe();
        setupManageTabs();
        document.getElementById('party-create-form')?.classList.toggle('hidden', isGuestUser);
        document.getElementById('party-guest-note')?.classList.toggle('hidden', !isGuestUser);
        await loadPendingInvites();
        if (pageMode === 'manage') {
            await loadCurrentPartyDetail();
        } else {
            await loadParties();
        }
        document.getElementById('party-create-form')?.addEventListener('submit', (event) => createParty(event).catch((error) => Toast.error(error.data?.message || error.message)));
        readyBtn?.addEventListener('click', () => toggleReady().catch((error) => Toast.error(error.data?.message || error.message)));
        lineupBtn?.addEventListener('click', () => toggleLineupLock().catch((error) => Toast.error(error.data?.message || error.message)));
        document.getElementById('party-leave-btn')?.addEventListener('click', () => leaveParty().catch((error) => Toast.error(error.data?.message || error.message)));
        closeBtn?.addEventListener('click', () => closeParty().catch((error) => Toast.error(error.data?.message || error.message)));
        document.getElementById('party-invite-form')?.addEventListener('submit', (event) => inviteUser(event).catch((error) => Toast.error(error.data?.message || error.message)));
        document.getElementById('party-invite-search-form')?.addEventListener('submit', (event) => searchInviteUsers(event).catch((error) => Toast.error(error.data?.message || error.message)));
        document.getElementById('party-invite-reset')?.addEventListener('click', () => resetInvitePicker());
        document.getElementById('party-slot-form')?.addEventListener('submit', (event) => assignSlot(event).catch((error) => Toast.error(error.data?.message || error.message)));
        document.getElementById('party-transfer-btn')?.addEventListener('click', () => transferLeader().catch((error) => Toast.error(error.data?.message || error.message)));
        document.getElementById('party-kick-btn')?.addEventListener('click', () => kickMember().catch((error) => Toast.error(error.data?.message || error.message)));
        document.getElementById('party-battle-btn')?.addEventListener('click', () => createPartyBattle().catch((error) => Toast.error(error.data?.message || error.message)));
        document.getElementById('party-chat-form')?.addEventListener('submit', (event) => sendChat(event).catch((error) => Toast.error(error.data?.message || error.message)));
        partyChatToggleBtn?.addEventListener('click', () => setChatPanelExpanded(partyChatPanelEl?.classList.contains('hidden')));
    }

    document.addEventListener('DOMContentLoaded', () => {
        init().catch((error) => Toast.error(error.data?.message || error.message || '파티 목록을 불러오지 못했습니다.'));
    });
})();
