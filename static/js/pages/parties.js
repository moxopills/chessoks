(function () {
    let me = null;
    let selectedPartyId = null;
    let selectedParty = null;
    let currentPartyReady = false;
    let selectedMemberId = null;
    let isGuestUser = false;

    const partyListEl = document.getElementById('party-list');
    const detailEmptyEl = document.getElementById('party-detail-empty');
    const detailPanelEl = document.getElementById('party-detail-panel');
    const partySummaryEl = document.getElementById('party-summary');
    const partyMembersEl = document.getElementById('party-members');
    const partyChatLogEl = document.getElementById('party-chat-log');
    const partyInviteListEl = document.getElementById('party-invite-list');
    const readyBtn = document.getElementById('party-ready-btn');
    const lineupBtn = document.getElementById('party-lineup-btn');
    const memberSelectionEl = document.getElementById('party-member-selection');

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
        partyListEl.innerHTML = '';
        if (!items.length) {
            partyListEl.innerHTML = '<div class="community-empty">활성 파티가 없습니다.</div>';
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
        document.querySelector('#party-invite-form button[type="submit"]')?.toggleAttribute('disabled', !canManageParty());
        document.querySelector('#party-slot-form button[type="submit"]')?.toggleAttribute('disabled', !canManageParty());
        document.getElementById('party-transfer-btn')?.toggleAttribute('disabled', !canManageParty());
        document.getElementById('party-kick-btn')?.toggleAttribute('disabled', !canManageParty());
        document.getElementById('party-battle-btn')?.toggleAttribute('disabled', !canManageParty() || !party.lineup_locked);
        document.getElementById('party-invite-user-id')?.toggleAttribute('disabled', !canManageParty());
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
    }

    function renderChat(items) {
        partyChatLogEl.innerHTML = '';
        if (!items.length) {
            partyChatLogEl.innerHTML = '<div class="community-empty">아직 채팅이 없습니다.</div>';
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
    }

    function renderInvites(items) {
        partyInviteListEl.innerHTML = '';
        if (!items.length) {
            partyInviteListEl.innerHTML = '<div class="community-empty">대기 중인 파티 초대가 없습니다.</div>';
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
                    await Promise.all([loadPendingInvites(), loadParties()]);
                } catch (error) {
                    Toast.error(error.data?.message || error.message);
                }
            });
        });
    }

    async function loadPendingInvites() {
        if (!me) {
            renderInvites([]);
            return;
        }
        const data = await API.get('/community/parties/invites/');
        renderInvites(data.results || []);
    }

    async function loadParties() {
        const data = await API.get('/community/parties/');
        renderPartyList(data.results || []);
        if (!selectedPartyId && data.results?.length) {
            await loadPartyDetail(data.results[0].id);
        }
    }

    async function loadPartyDetail(partyId) {
        selectedPartyId = partyId;
        const [party, parties, chat] = await Promise.all([
            API.get(`/community/parties/${partyId}/`),
            API.get('/community/parties/'),
            API.get(`/community/parties/${partyId}/chat/`).catch(() => ({ results: [] })),
        ]);
        renderPartyDetail(party);
        renderPartyList(parties.results || []);
        renderChat(chat.results || []);
    }

    async function createParty(event) {
        event.preventDefault();
        if (isGuestUser) {
            Toast.error('게스트는 파티 생성이 불가능합니다. 초대를 받아 참가만 할 수 있습니다.');
            return;
        }
        const payload = Object.fromEntries(new FormData(event.currentTarget).entries());
        const party = await API.post('/community/parties/', payload);
        window.PartyInvites?.invalidate();
        Toast.success('파티를 생성했습니다.');
        event.currentTarget.reset();
        await loadParties();
        await loadPartyDetail(party.id);
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
        await Promise.all([loadParties(), loadPendingInvites()]);
    }

    async function inviteUser(event) {
        event.preventDefault();
        if (isGuestUser) {
            Toast.error('게스트는 파티에 초대만 받을 수 있습니다.');
            return;
        }
        if (!selectedPartyId) return;
        const userId = Number(document.getElementById('party-invite-user-id').value);
        if (!userId) return Toast.error('초대할 유저 ID를 입력하세요.');
        await API.post(`/community/parties/${selectedPartyId}/invite/`, { user_id: userId });
        Toast.success('파티 초대를 보냈습니다.');
        event.currentTarget.reset();
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
        const input = document.getElementById('party-chat-input');
        const content = input.value.trim();
        if (!content) return;
        await API.post(`/community/parties/${selectedPartyId}/chat/`, { content });
        input.value = '';
        await loadPartyDetail(selectedPartyId);
    }

    async function init() {
        await loadMe();
        document.getElementById('party-create-form')?.classList.toggle('hidden', isGuestUser);
        document.getElementById('party-guest-note')?.classList.toggle('hidden', !isGuestUser);
        await Promise.all([loadPendingInvites(), loadParties()]);
        document.getElementById('party-create-form')?.addEventListener('submit', (event) => createParty(event).catch((error) => Toast.error(error.data?.message || error.message)));
        readyBtn?.addEventListener('click', () => toggleReady().catch((error) => Toast.error(error.data?.message || error.message)));
        lineupBtn?.addEventListener('click', () => toggleLineupLock().catch((error) => Toast.error(error.data?.message || error.message)));
        document.getElementById('party-leave-btn')?.addEventListener('click', () => leaveParty().catch((error) => Toast.error(error.data?.message || error.message)));
        document.getElementById('party-invite-form')?.addEventListener('submit', (event) => inviteUser(event).catch((error) => Toast.error(error.data?.message || error.message)));
        document.getElementById('party-slot-form')?.addEventListener('submit', (event) => assignSlot(event).catch((error) => Toast.error(error.data?.message || error.message)));
        document.getElementById('party-transfer-btn')?.addEventListener('click', () => transferLeader().catch((error) => Toast.error(error.data?.message || error.message)));
        document.getElementById('party-kick-btn')?.addEventListener('click', () => kickMember().catch((error) => Toast.error(error.data?.message || error.message)));
        document.getElementById('party-battle-btn')?.addEventListener('click', () => createPartyBattle().catch((error) => Toast.error(error.data?.message || error.message)));
        document.getElementById('party-chat-form')?.addEventListener('submit', (event) => sendChat(event).catch((error) => Toast.error(error.data?.message || error.message)));
    }

    document.addEventListener('DOMContentLoaded', () => {
        init().catch((error) => Toast.error(error.data?.message || error.message || '파티 목록을 불러오지 못했습니다.'));
    });
})();
