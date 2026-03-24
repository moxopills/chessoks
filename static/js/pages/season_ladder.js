(function () {
    "use strict";

    const subtitleEl = document.getElementById("season-subtitle");
    const minGamesEl = document.getElementById("season-min-games");
    const daysLeftEl = document.getElementById("season-days-left");
    const myBoxEl = document.getElementById("my-season-box");
    const rewardBoxEl = document.getElementById("season-reward-box");
    const goalBoxEl = document.getElementById("season-goal-box");
    const historyBoxEl = document.getElementById("season-history-box");
    const bodyEl = document.getElementById("season-leaderboard-body");
    const paginationEl = document.getElementById("season-pagination");
    const refreshBtn = document.getElementById("season-refresh-btn");
    const claimBtn = document.getElementById("claim-reward-btn");

    let currentSeasonId = null;
    let currentPage = 1;
    let totalPages = 1;
    let currentUserId = null;
    let currentUserStats = null;
    let rewardPreviewRows = [];
    let currentMySeasonRank = null;
    let currentMinGames = 10;
    let mySeasonLoadFailed = false;

    init();

    async function init() {
        await loadCurrentUser();
        bindEvents();
        await Promise.all([loadCurrentSeason(), loadHistory()]);
        await Promise.all([loadLeaderboard(1), loadMySeason(), loadRewards()]);
    }

    function bindEvents() {
        refreshBtn?.addEventListener("click", () => {
            setRefreshLoading(true);
            Promise.all([
                loadLeaderboard(currentPage),
                loadMySeason(),
                loadRewards(),
            ]).finally(() => setRefreshLoading(false));
        });
        claimBtn?.addEventListener("click", claimRewards);
    }

    function setRefreshLoading(isLoading) {
        if (!refreshBtn) return;
        refreshBtn.disabled = isLoading;
        refreshBtn.classList.toggle("is-loading", isLoading);
        refreshBtn.setAttribute("aria-busy", String(isLoading));
    }

    async function loadCurrentUser() {
        try {
            const me = await API.get("/accounts/me/");
            currentUserId = me.id;
            currentUserStats = me.stats || null;
        } catch (_e) {
            currentUserId = null;
            currentUserStats = null;
        }
    }

    async function loadCurrentSeason() {
        try {
            const season = await API.get("/seasons/current/");
            currentSeasonId = season.id;
            subtitleEl.textContent = `${season.name} (${season.start_date} ~ ${season.end_date})`;
            daysLeftEl.textContent = season.days_left;
        } catch (error) {
            subtitleEl.textContent = "시즌 정보를 불러오지 못했습니다.";
            Toast.error(error.message || "시즌 정보를 불러오지 못했습니다.");
        }
    }

    async function loadLeaderboard(page) {
        currentPage = page;
        bodyEl.innerHTML = Array.from({ length: 4 }).map(() => `
            <tr class="skeleton-row">
                <td><div class="skeleton sk-w-20 sk-h-12r"></div></td>
                <td><div class="user-cell"><div class="skeleton skeleton-avatar sk-w-32 sk-h-32"></div><div class="skeleton sk-w-100 sk-h-1r"></div></div></td>
                <td><div class="skeleton sk-w-50 sk-h-1r"></div></td>
                <td><div class="skeleton sk-w-80 sk-h-1r"></div></td>
                <td><div class="skeleton sk-w-40 sk-h-1r"></div></td>
            </tr>
        `).join("");
        try {
            const data = await API.get("/seasons/current/leaderboard/", { page, page_size: 20 });
            totalPages = data.total_pages || 1;
            if (minGamesEl) {
                minGamesEl.textContent = data.min_games_for_rank ?? 10;
            }
            renderLeaderboardRows(data.results || []);
            renderPagination();
        } catch (error) {
            bodyEl.innerHTML = `<tr><td colspan="5" class="text-muted">${Utils.escapeHtml(error.message || "리더보드를 불러오지 못했습니다.")}</td></tr>`;
        }
    }

    function renderLeaderboardRows(rows) {
        if (!rows.length) {
            bodyEl.innerHTML = '<tr><td colspan="5" class="text-muted">아직 시즌 랭크에 진입한 유저가 없습니다.</td></tr>';
            return;
        }
        bodyEl.innerHTML = rows.map((row) => {
            const isMe = currentUserId && row.user_id === currentUserId;
            return `
                <tr class="${isMe ? "is-me" : ""}">
                    <td>${row.rank}</td>
                    <td>
                        <span class="season-user">
                            <span class="avatar">${
                                row.avatar_url
                                    ? `<img src="${Utils.escapeHtml(row.avatar_url)}" alt="${Utils.escapeHtml(row.nickname)}">`
                                    : '<span class="avatar-placeholder">?</span>'
                            }</span>
                            ${Utils.escapeHtml(row.nickname)}
                        </span>
                    </td>
                    <td>${row.rating}</td>
                    <td>${row.wins}승 ${row.losses}패 ${row.draws}무</td>
                    <td>${row.win_rate}%</td>
                </tr>
            `;
        }).join("");
    }

    function renderPagination() {
        if (!paginationEl) return;
        paginationEl.innerHTML = "";
        if (totalPages <= 1) return;

        const prev = document.createElement("button");
        prev.className = "btn btn-secondary btn-sm";
        prev.textContent = "이전";
        prev.disabled = currentPage <= 1;
        prev.addEventListener("click", () => loadLeaderboard(currentPage - 1));
        paginationEl.appendChild(prev);

        const info = document.createElement("span");
        info.className = "pagination-info";
        info.textContent = `${currentPage} / ${totalPages}`;
        paginationEl.appendChild(info);

        const next = document.createElement("button");
        next.className = "btn btn-secondary btn-sm";
        next.textContent = "다음";
        next.disabled = currentPage >= totalPages;
        next.addEventListener("click", () => loadLeaderboard(currentPage + 1));
        paginationEl.appendChild(next);
    }

    async function loadMySeason() {
        if (!currentUserId) {
            myBoxEl.textContent = "로그인 후 확인할 수 있습니다.";
            return;
        }
        try {
            const data = await API.get("/seasons/current/me/");
            if (!data.my_rank) {
                myBoxEl.innerHTML = `배치 기준(${data.min_games_for_rank}판) 미충족입니다. 현재 경기 수가 부족해 랭크에 표시되지 않습니다.`;
                currentMySeasonRank = null;
                currentMinGames = data.min_games_for_rank || currentMinGames;
                mySeasonLoadFailed = false;
                renderGoalSection();
                return;
            }
            const m = data.my_rank;
            currentMySeasonRank = m;
            currentMinGames = data.min_games_for_rank || currentMinGames;
            mySeasonLoadFailed = false;
            myBoxEl.innerHTML = `
                <div>순위: <strong>#${m.rank}</strong></div>
                <div>레이팅: <strong>${m.rating}</strong> (최고 ${m.peak_rating})</div>
                <div>전적: ${m.wins}승 ${m.losses}패 ${m.draws}무 · 승률 ${m.win_rate}%</div>
                <div>현재 시즌 칭호: <strong>${Utils.escapeHtml(currentUserStats?.season_title || '없음')}</strong></div>
            `;
            renderGoalSection();
        } catch (error) {
            myBoxEl.textContent = error.message || "내 시즌 정보를 불러오지 못했습니다.";
            currentMySeasonRank = null;
            mySeasonLoadFailed = true;
            renderGoalSection();
        }
    }

    async function loadRewards() {
        if (!currentSeasonId) return;
        try {
            const data = await API.get(`/seasons/${currentSeasonId}/rewards/`);
            const rows = data.results || [];
            if (!rows.length) {
                rewardBoxEl.textContent = "보상 정보가 없습니다.";
                return;
            }
            rewardBoxEl.innerHTML = rows.map((row) => {
                const rankText = row.rank_min === row.rank_max ? `${row.rank_min}위` : `${row.rank_min}~${row.rank_max}위`;
                const typeClass = row.reward_type === "title"
                    ? "reward-chip-title"
                    : (row.reward_type === "border" ? "reward-chip-frame" : "reward-chip-points");
                const claimedText = row.claimed ? '<span class="reward-state claimed">지급 완료</span>' : '<span class="reward-state pending">예정</span>';
                return `
                    <div class="season-reward-item">
                        <div class="season-reward-head">
                            <span class="season-reward-rank">${rankText}</span>
                            ${claimedText}
                        </div>
                        <div class="season-reward-body">
                            <span class="reward-chip ${typeClass}">${Utils.escapeHtml(row.reward_type_label)}</span>
                            <strong>${Utils.escapeHtml(row.reward_value)}</strong>
                        </div>
                    </div>
                `;
            }).join("");
            rewardPreviewRows = rows.slice(0, 3);
            renderGoalSection();
        } catch (error) {
            rewardBoxEl.textContent = error.message || "보상 정보를 불러오지 못했습니다.";
            if (goalBoxEl) {
                goalBoxEl.textContent = "보상 목표를 불러오지 못했습니다.";
            }
        }
    }

    function renderGoalSection() {
        if (!goalBoxEl) return;
        if (mySeasonLoadFailed) {
            goalBoxEl.textContent = "이번 시즌 목표를 불러오지 못했습니다.";
            return;
        }
        const rewardCards = rewardPreviewRows.length
            ? `<div class="season-goal-grid">${rewardPreviewRows.map((row) => {
                const rankText = row.rank_min === row.rank_max ? `${row.rank_min}위` : `${row.rank_min}~${row.rank_max}위`;
                return `
                    <article class="season-goal-item">
                        <span class="season-goal-rank">${rankText}</span>
                        <strong>${Utils.escapeHtml(row.reward_value)}</strong>
                        <span class="season-goal-type">${Utils.escapeHtml(row.reward_type_label)}</span>
                    </article>
                `;
            }).join("")}</div>`
            : "";
        if (!currentUserId) {
            goalBoxEl.innerHTML = `
                <div class="season-goal-stack">
                    ${rewardCards}
                    <div class="season-goal-empty">
                        <strong>로그인 후 목표를 확인할 수 있습니다.</strong>
                        <span>시즌 래더는 최소 ${currentMinGames || 10}판부터 순위가 반영됩니다.</span>
                    </div>
                </div>
            `;
            return;
        }
        if (!currentMySeasonRank) {
            goalBoxEl.innerHTML = `
                <div class="season-goal-stack">
                    ${rewardCards}
                    <div class="season-goal-empty">
                        <strong>아직 배치 중입니다.</strong>
                        <span>최소 ${currentMinGames || 10}판을 채우면 현재 보상 구간과 순위 목표가 표시됩니다.</span>
                    </div>
                </div>
            `;
            return;
        }
        const nextMilestone =
            currentMySeasonRank.rank <= 3 ? '현재 최상위 보상 구간입니다.' :
            currentMySeasonRank.rank <= 10 ? 'Top 3 진입 시 시즌 상위 프레임 보상이 열립니다.' :
            currentMySeasonRank.rank <= 100 ? 'Top 10 진입 시 시즌 Top 10 칭호와 프레임이 열립니다.' :
            'Top 100 진입 시 추가 포인트 보상 구간에 들어갑니다.';
        goalBoxEl.innerHTML = `
            <div class="season-goal-stack">
                ${rewardCards}
                <div class="season-goal-highlight">
                    <span class="season-goal-badge">현재 위치</span>
                    <strong>#${currentMySeasonRank.rank} · 시즌 레이팅 ${currentMySeasonRank.rating}</strong>
                    <span>${currentMySeasonRank.wins}승 ${currentMySeasonRank.losses}패 ${currentMySeasonRank.draws}무 · 승률 ${currentMySeasonRank.win_rate}%</span>
                </div>
                <div class="season-goal-copy">${Utils.escapeHtml(nextMilestone)}</div>
            </div>
        `;
    }

    async function claimRewards() {
        if (!currentUserId) {
            Toast.error("로그인 후 보상을 수령할 수 있습니다.");
            return;
        }
        if (!currentSeasonId) return;
        try {
            const data = await API.post(`/seasons/${currentSeasonId}/rewards/claim/`, {});
            if ((data.claimed_count || 0) === 0) {
                Toast.info(data.message || "이미 시즌 보상이 자동 지급되었습니다.");
            } else {
                Toast.success(`보상 ${data.claimed_count}개를 수령했습니다.`);
            }
            await loadRewards();
        } catch (error) {
            Toast.error(error.message || "보상 수령에 실패했습니다.");
        }
    }

    async function loadHistory() {
        try {
            const data = await API.get("/seasons/history/", { limit: 6 });
            const rows = data.results || [];
            if (!rows.length) {
                historyBoxEl.textContent = "아직 종료된 시즌이 없습니다.";
                return;
            }
            historyBoxEl.innerHTML = rows.map((row) => `
                <div class="season-history-item">
                    <span>${Utils.escapeHtml(row.name)}</span>
                    <span>${row.start_date} ~ ${row.end_date}</span>
                </div>
            `).join("");
        } catch (error) {
            historyBoxEl.textContent = error.message || "시즌 히스토리를 불러오지 못했습니다.";
        }
    }
})();
