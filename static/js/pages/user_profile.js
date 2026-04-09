(function() {
    'use strict';

    const profileView = window.ProfileView;
    const avatarEl = document.getElementById('profile-avatar');
    const profileCardEl = document.getElementById('profile-card');
    const nameEl = document.getElementById('profile-name');
    const ratingEl = document.getElementById('profile-rating');
    const tierEl = document.getElementById('profile-tier');
    const seasonTitleEl = document.getElementById('profile-season-title');
    const statGames = document.getElementById('stat-games');
    const statWins = document.getElementById('stat-wins');
    const statLosses = document.getElementById('stat-losses');
    const statDraws = document.getElementById('stat-draws');
    const seasonSummaryContent = document.getElementById('profile-season-summary-content');
    const achievementsEl = document.getElementById('profile-achievements');
    const vsBox = document.getElementById('profile-vs');
    const vsWins = document.getElementById('vs-wins');
    const vsLosses = document.getElementById('vs-losses');
    const vsDraws = document.getElementById('vs-draws');
    const recentList = document.getElementById('recent-list');
    const friendBtn = document.getElementById('friend-request-btn');
    const partyInviteBtn = document.getElementById('party-invite-btn');
    const directMessageBtn = document.getElementById('direct-message-btn');
    const reportBtn = document.getElementById('report-btn');
    const guestbookList = document.getElementById('guestbook-list');
    const guestbookInput = document.getElementById('guestbook-input');
    const guestbookSubmit = document.getElementById('guestbook-submit');

    const userId = Utils.getPathParam('/users/(\\d+)/');
    let currentUserId = null;

    init();

    async function init() {
        setProfileLoading(true);
        await loadCurrentUser();
        await loadProfile();
        bindActions();
    }

    async function loadCurrentUser() {
        try {
            const me = await API.get('/accounts/me/');
            currentUserId = me.id;
        } catch {
            currentUserId = null;
        }
    }

    async function loadProfile() {
        if (!userId) return;
        try {
            const data = await API.get(`/accounts/users/${userId}/profile/`);
            const user = data.user;
            renderUser(user);
            renderStats(user.stats);
            renderAchievements(data.achievements || []);
            renderPreviousSeason(data.previous_season);
            renderRecent(data.recent_games || []);
            await loadGuestbook();
            updateFriendButtonState(data.friend_status);
            if (data.vs_summary) {
                vsBox.classList.remove('hidden');
                vsWins.textContent = data.vs_summary.wins;
                vsLosses.textContent = data.vs_summary.losses;
                vsDraws.textContent = data.vs_summary.draws;
            } else {
                vsBox.classList.add('hidden');
            }
        } catch (error) {
            recentList.innerHTML = '<button class="btn btn-secondary btn-sm" id="profile-retry-btn">프로필 다시 불러오기</button>';
            document.getElementById('profile-retry-btn')?.addEventListener('click', loadProfile, { once: true });
            Toast.error('프로필을 불러올 수 없습니다.');
        } finally {
            setProfileLoading(false);
        }
    }

    function setProfileLoading(isLoading) {
        [friendBtn, directMessageBtn, reportBtn, guestbookSubmit].forEach((el) => {
            if (el) el.disabled = isLoading;
        });
        if (isLoading) {
            recentList.innerHTML = '<div class="text-muted">최근 전적 불러오는 중...</div>';
            guestbookList.innerHTML = '<div class="text-muted">방명록 불러오는 중...</div>';
        }
    }

    function renderUser(user) {
        profileView.renderIdentity({
            user,
            avatarEl,
            nameEl,
            tierEl,
            ratingEl,
            seasonTitleEl,
            profileCardEl,
            placeholderClass: 'avatar-placeholder',
        });
    }

    function renderStats(stats) {
        profileView.renderStats(stats, {
            games: statGames,
            wins: statWins,
            losses: statLosses,
            draws: statDraws,
        });
    }

    function renderPreviousSeason(season) {
        profileView.renderPreviousSeason(seasonSummaryContent, season);
    }

    function renderAchievements(achievements) {
        if (!achievementsEl || !window.ProfileAchievements) return;
        window.ProfileAchievements.render(achievementsEl, achievements, {
            heading: '대표 업적',
            subheading: '이 유저의 주요 달성 기록입니다.',
        });
    }

    function renderRecent(games) {
        profileView.renderRecentGames(recentList, games, parseInt(userId, 10), {
            emptyText: '최근 전적 없음',
            compact: true,
        });
    }

    function bindActions() {
        friendBtn?.addEventListener('click', async () => {
            if (!currentUserId) {
                Toast.error('로그인 시 가능합니다.');
                return;
            }
            if (parseInt(userId, 10) === currentUserId) {
                Toast.error('자기 자신에게 요청할 수 없습니다.');
                return;
            }
            try {
                const result = await API.post('/accounts/friends/requests/', { user_id: parseInt(userId, 10) });
                if (result.status === 'accepted') {
                    Toast.success('친구 요청이 자동 수락되었습니다.');
                } else {
                    Toast.success('친구 요청을 보냈습니다.');
                }
                updateFriendButtonState({ is_friend: result.status === 'accepted', is_request_sent: result.status !== 'accepted' });
            } catch (error) {
                Toast.error(error.data?.message || '친구 요청에 실패했습니다.');
            }
        });

        directMessageBtn?.addEventListener('click', () => {
            if (!userId) return;
            window.location.href = `/messages/${userId}/`;
        });

        partyInviteBtn?.addEventListener('click', () => {
            if (!userId || !window.PartyInvites) return;
            window.PartyInvites.sendInvite(parseInt(userId, 10)).catch((error) => {
                Toast.error(error.data?.message || error.message);
            });
        });

        guestbookSubmit?.addEventListener('click', submitGuestbook);

        reportBtn?.addEventListener('click', () => {
            if (!currentUserId) {
                Toast.error('로그인 시 가능합니다.');
                return;
            }
            if (parseInt(userId, 10) === currentUserId) {
                Toast.error('자기 자신은 신고할 수 없습니다.');
                return;
            }
            Utils.ReportModal.open(parseInt(userId, 10));
        });
    }

    function updateFriendButtonState(status) {
        if (!friendBtn) return;
        const canPartyInvite = Boolean(currentUserId) && parseInt(userId, 10) !== currentUserId && document.body.dataset.guest !== 'true';
        partyInviteBtn?.classList.toggle('hidden', !canPartyInvite);
        if (partyInviteBtn) {
            partyInviteBtn.disabled = !canPartyInvite;
        }
        if (!currentUserId) {
            friendBtn.disabled = true;
            friendBtn.textContent = '로그인 시 가능합니다.';
            return;
        }
        if (parseInt(userId, 10) === currentUserId) {
            friendBtn.disabled = true;
            friendBtn.textContent = '나';
            if (directMessageBtn) {
                directMessageBtn.classList.add('hidden');
            }
            if (reportBtn) {
                reportBtn.disabled = true;
            }
            return;
        }
        if (status?.is_friend) {
            friendBtn.disabled = true;
            friendBtn.textContent = '친구';
            return;
        }
        if (status?.is_request_sent) {
            friendBtn.disabled = true;
            friendBtn.textContent = '요청 중';
            return;
        }
        if (status?.is_request_received) {
            friendBtn.disabled = true;
            friendBtn.textContent = '요청 확인';
            friendBtn.disabled = false;
            friendBtn.addEventListener('click', () => {
                window.location.href = '/friends/?tab=requests';
            }, { once: true });
            return;
        }
        friendBtn.disabled = false;
        friendBtn.textContent = '친구 요청';
    }

    async function loadGuestbook() {
        if (!guestbookList || !userId) return;
        guestbookList.innerHTML = '<div class="text-muted">불러오는 중...</div>';
        try {
            const data = await API.get(`/accounts/users/${userId}/guestbook/`);
            renderGuestbook(data || []);
        } catch {
            guestbookList.innerHTML = '<div class="text-muted">방명록을 불러오지 못했습니다.</div>';
        }
    }

    function renderGuestbook(entries) {
        if (!guestbookList) return;
        if (!entries.length) {
            guestbookList.innerHTML = '<div class="text-muted">방명록이 없습니다.</div>';
            return;
        }
        guestbookList.innerHTML = entries.map((entry) => {
            const canDelete = entry.author?.id === currentUserId || parseInt(userId, 10) === currentUserId;
            const time = formatDate(entry.created_at);
            return `
                <div class="guestbook-item" data-entry-id="${entry.id}">
                    <div>${Utils.escapeHtml(entry.message)}</div>
                    <div class="guestbook-meta">
                        <span>${Utils.escapeHtml(entry.author?.nickname || '알 수 없음')}</span>
                        <span>${time}</span>
                    </div>
                    ${canDelete ? '<button class="btn btn-secondary btn-sm" data-action="delete">삭제</button>' : ''}
                </div>
            `;
        }).join('');

        guestbookList.querySelectorAll('[data-action="delete"]').forEach((btn) => {
            btn.addEventListener('click', async () => {
                const entryId = btn.closest('.guestbook-item')?.dataset.entryId;
                if (!entryId) return;
                await deleteGuestbook(entryId);
            });
        });
    }

    async function submitGuestbook() {
        if (!guestbookInput || !userId) return;
        const message = guestbookInput.value.trim();
        if (!message) return;
        try {
            await API.post(`/accounts/users/${userId}/guestbook/`, { message });
            guestbookInput.value = '';
            await loadGuestbook();
        } catch (error) {
            Toast.error(error.data?.detail || error.data?.message || '방명록 등록에 실패했습니다.');
        }
    }

    async function deleteGuestbook(entryId) {
        try {
            await API.delete(`/accounts/guestbook/${entryId}/`);
            await loadGuestbook();
        } catch (error) {
            Toast.error(error.data?.message || '삭제에 실패했습니다.');
        }
    }

    function formatDate(value) {
        if (!value) return '-';
        const d = new Date(value);
        const y = d.getFullYear();
        const m = String(d.getMonth() + 1).padStart(2, '0');
        const day = String(d.getDate()).padStart(2, '0');
        const hh = String(d.getHours()).padStart(2, '0');
        const mm = String(d.getMinutes()).padStart(2, '0');
        return `${y}-${m}-${day} ${hh}:${mm}`;
    }
})();
