(function () {
    const listEl = document.getElementById('tournament-list');
    const teamBattleListEl = document.getElementById('team-battle-list');
    const createForm = document.getElementById('tournament-create-form');
    let refreshPoller = null;

    function battleLabel(type) {
        return type === 'guild' ? '길드전' : '단체전';
    }

    function statusClass(status) {
        if (status === 'live') return 'is-live';
        if (status === 'finished') return 'is-finished';
        if (status === 'waiting') return 'is-ready';
        return '';
    }

    function renderTournaments(items) {
        listEl.innerHTML = '';
        if (!items.length) {
            listEl.innerHTML = '<div class="community-empty">예정된 컵전이 없습니다.</div>';
            return;
        }
        items.forEach((tournament) => {
            const item = document.createElement('div');
            item.className = 'community-item';
            item.innerHTML = `
                <span class="community-item-title">${Utils.escapeHtml(tournament.title)}</span>
                <span class="community-item-meta">${Utils.escapeHtml(tournament.status)} · ${tournament.entry_count}/${tournament.max_participants}명 · ${Utils.escapeHtml(tournament.start_at)}</span>
                <span class="community-item-copy">${Utils.escapeHtml(tournament.description || '대회 설명이 아직 없습니다.')}</span>
                <div class="community-actions">
                    <button class="btn btn-secondary btn-sm community-register-btn" data-id="${tournament.id}" data-registered="${tournament.is_registered ? '1' : ''}" type="button">
                        ${tournament.is_registered ? '참가 취소' : '참가 신청'}
                    </button>
                </div>
            `;
            listEl.appendChild(item);
        });
        listEl.querySelectorAll('.community-register-btn').forEach((button) => {
            button.addEventListener('click', async () => {
                try {
                    if (button.dataset.registered) {
                        await API.post(`/community/tournaments/${button.dataset.id}/unregister/`, {});
                        Toast.success('컵전 참가를 취소했습니다.');
                    } else {
                        await API.post(`/community/tournaments/${button.dataset.id}/register/`, {});
                        Toast.success('컵전에 참가 신청했습니다.');
                    }
                    await loadPage();
                } catch (error) {
                    Toast.error(error.data?.message || error.message);
                }
            });
        });
    }

    function renderParticipants(match, side) {
        const participants = (match.participants || []).filter((item) => item.side === side);
        if (!participants.length) {
            return '<div class="community-empty">아직 라인업이 없습니다.</div>';
        }
        return participants.map((participant) => `
            <div class="community-item community-card-slim">
                <div class="community-row">
                    <span class="community-item-title">${participant.order}번 ${Utils.escapeHtml(participant.user.nickname)}</span>
                    <span class="community-badge${participant.is_eliminated ? ' is-danger' : ''}">${participant.is_eliminated ? '탈락' : `승리 ${participant.wins}`}</span>
                </div>
            </div>
        `).join('');
    }

    function renderRounds(match) {
        const rounds = match.rounds || [];
        if (!rounds.length) {
            return '<div class="community-empty">아직 시작된 라운드가 없습니다.</div>';
        }
        return rounds.map((round) => `
            <div class="community-item community-card-slim">
                <div class="community-row">
                    <span class="community-item-title">${round.round_number}라운드</span>
                    <span class="community-badge ${statusClass(round.status)}">${Utils.escapeHtml(round.status)}</span>
                </div>
                <span class="community-item-copy">${Utils.escapeHtml(round.host_participant.user.nickname)} vs ${Utils.escapeHtml(round.guest_participant.user.nickname)}</span>
                ${round.result ? `<span class="community-item-meta">결과: ${Utils.escapeHtml(round.result)}</span>` : ''}
                ${round.game_id ? `<span class="community-item-meta">연결 게임 ID: ${round.game_id}</span>` : ''}
                ${round.game_room_id && round.status === 'live' ? '<div class="community-round-note">실전 대국과 연결되어 있습니다. 결과는 게임 종료 시 자동 반영됩니다.</div>' : ''}
                <div class="community-actions community-actions--wrap">
                    ${round.game_room_id ? `<a class="btn btn-primary btn-sm" href="/games/${round.game_room_id}/">게임 입장</a>` : ''}
                    ${round.status === 'live' && !round.game_room_id ? `
                        <button class="btn btn-secondary btn-sm team-battle-result-btn" data-match-id="${match.id}" data-round-id="${round.id}" data-result="host" type="button">호스트 승</button>
                        <button class="btn btn-secondary btn-sm team-battle-result-btn" data-match-id="${match.id}" data-round-id="${round.id}" data-result="guest" type="button">게스트 승</button>
                        <button class="btn btn-secondary btn-sm team-battle-result-btn" data-match-id="${match.id}" data-round-id="${round.id}" data-result="draw" type="button">무승부</button>
                    ` : ''}
                </div>
            </div>
        `).join('');
    }

    function renderTeamBattles(items) {
        teamBattleListEl.innerHTML = '';
        if (!items.length) {
            teamBattleListEl.innerHTML = '<div class="community-empty">현재 대기 중인 팀전이 없습니다.</div>';
            return;
        }
        items.forEach((match) => {
            const item = document.createElement('div');
            item.className = 'community-item community-block';
            const joinFieldLabel = match.battle_type === 'guild' ? '길드 ID' : '파티 ID';
            item.innerHTML = `
                <div class="community-row">
                    <span class="community-item-title">${Utils.escapeHtml(battleLabel(match.battle_type))} #${match.id}</span>
                    <div class="community-row-meta">
                        <span class="community-badge ${statusClass(match.status)}">${Utils.escapeHtml(match.status)}</span>
                        <span class="community-badge">남은 인원 ${match.host_remaining} : ${match.guest_remaining}</span>
                    </div>
                </div>
                <span class="community-item-copy">호스트 ${match.host_party_id || match.host_guild_id} / 게스트 ${match.guest_party_id || match.guest_guild_id || '미참가'}</span>
                <div class="community-split">
                    <div class="community-block">
                        <h3>호스트 라인업</h3>
                        <div class="community-sublist">${renderParticipants(match, 'host')}</div>
                    </div>
                    <div class="community-block">
                        <h3>게스트 라인업</h3>
                        <div class="community-sublist">${renderParticipants(match, 'guest')}</div>
                    </div>
                </div>
                <div class="community-block">
                    <h3>라운드 진행</h3>
                    <div class="community-sublist">${renderRounds(match)}</div>
                </div>
                ${match.status === 'waiting' && !(match.guest_party_id || match.guest_guild_id) ? `
                    <form class="community-inline-form team-battle-join-form" data-match-id="${match.id}" data-type="${match.battle_type}">
                        <input class="form-input team-battle-join-id" type="number" min="1" placeholder="${joinFieldLabel}">
                        <button class="btn btn-secondary btn-sm" type="submit">${battleLabel(match.battle_type)} 참가</button>
                    </form>
                ` : ''}
                ${match.status === 'waiting' && (match.guest_party_id || match.guest_guild_id) ? `
                    <button class="btn btn-primary btn-sm team-battle-start-btn" data-match-id="${match.id}" type="button">매치 시작</button>
                ` : ''}
            `;
            teamBattleListEl.appendChild(item);
        });

        teamBattleListEl.querySelectorAll('.team-battle-join-form').forEach((form) => {
            form.addEventListener('submit', async (event) => {
                event.preventDefault();
                const idInput = form.querySelector('.team-battle-join-id');
                const joinId = Number(idInput.value || 0);
                if (!joinId) {
                    Toast.error('참가할 팀 ID를 입력하세요.');
                    return;
                }
                const payload = form.dataset.type === 'guild' ? { guild_id: joinId } : { party_id: joinId };
                try {
                    await API.post(`/community/team-battles/${form.dataset.matchId}/join/`, payload);
                    Toast.success('팀전에 참가했습니다.');
                    await loadPage();
                } catch (error) {
                    Toast.error(error.data?.message || error.message);
                }
            });
        });

        teamBattleListEl.querySelectorAll('.team-battle-start-btn').forEach((button) => {
            button.addEventListener('click', async () => {
                try {
                    await API.post(`/community/team-battles/${button.dataset.matchId}/start/`, {});
                    Toast.success('팀전을 시작했습니다.');
                    await loadPage();
                } catch (error) {
                    Toast.error(error.data?.message || error.message);
                }
            });
        });

        teamBattleListEl.querySelectorAll('.team-battle-result-btn').forEach((button) => {
            button.addEventListener('click', async () => {
                try {
                    await API.post(
                        `/community/team-battles/${button.dataset.matchId}/rounds/${button.dataset.roundId}/result/`,
                        { result: button.dataset.result },
                    );
                    Toast.success('라운드 결과를 반영했습니다.');
                    await loadPage();
                } catch (error) {
                    Toast.error(error.data?.message || error.message);
                }
            });
        });
    }

    async function loadPage() {
        const [tournaments, teamBattles, me] = await Promise.all([
            API.get('/community/tournaments/'),
            API.get('/community/team-battles/'),
            API.get('/accounts/me/').catch(() => null),
        ]);
        if (!me || !me.is_staff) {
            createForm?.classList.add('hidden');
        }
        renderTournaments(tournaments.results || []);
        renderTeamBattles(teamBattles.results || []);
    }

    async function createTournament(event) {
        event.preventDefault();
        const payload = {
            title: document.getElementById('tournament-title').value.trim(),
            description: document.getElementById('tournament-description').value.trim(),
            max_participants: Number(document.getElementById('tournament-max-participants').value || 8),
            minimum_rating: Number(document.getElementById('tournament-min-rating').value || 0),
            maximum_rating: Number(document.getElementById('tournament-max-rating').value || 4000),
            start_at: document.getElementById('tournament-start-at').value,
        };
        await API.post('/community/tournaments/', payload);
        Toast.success('컵전을 생성했습니다.');
        event.currentTarget.reset();
        await loadPage();
    }

    document.addEventListener('DOMContentLoaded', () => {
        loadPage().catch((error) => Toast.error(error.data?.message || error.message || '토너먼트 화면을 불러오지 못했습니다.'));
        document.getElementById('tournament-create-form')?.addEventListener('submit', (event) => createTournament(event).catch((error) => Toast.error(error.data?.message || error.message)));
        refreshPoller = Utils.createAdaptivePoller({
            activeIntervalMs: 12000,
            hiddenIntervalMs: 45000,
            callback: loadPage,
        });
        refreshPoller.start();
        window.addEventListener('beforeunload', () => refreshPoller?.stop?.());
    });
})();
