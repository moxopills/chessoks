(function () {
    "use strict";

    const subtitleEl = document.getElementById("season-subtitle");
    const minGamesEl = document.getElementById("season-min-games");
    const daysLeftEl = document.getElementById("season-days-left");
    const myBoxEl = document.getElementById("my-season-box");
    const rewardBoxEl = document.getElementById("season-reward-box");
    const historyBoxEl = document.getElementById("season-history-box");
    const bodyEl = document.getElementById("season-leaderboard-body");
    const paginationEl = document.getElementById("season-pagination");
    const refreshBtn = document.getElementById("season-refresh-btn");
    const claimBtn = document.getElementById("claim-reward-btn");

    let currentSeasonId = null;
    let currentPage = 1;
    let totalPages = 1;
    let currentUserId = null;

    init();

    async function init() {
        await loadCurrentUser();
        bindEvents();
        await Promise.all([loadCurrentSeason(), loadHistory()]);
        await Promise.all([loadLeaderboard(1), loadMySeason(), loadRewards()]);
    }

    function bindEvents() {
        refreshBtn?.addEventListener("click", () => {
            loadLeaderboard(currentPage);
            loadMySeason();
            loadRewards();
        });
        claimBtn?.addEventListener("click", claimRewards);
    }

    async function loadCurrentUser() {
        try {
            const me = await API.get("/accounts/me/");
            currentUserId = me.id;
        } catch (_e) {
            currentUserId = null;
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
        bodyEl.innerHTML = '<tr><td colspan="5" class="text-muted">불러오는 중...</td></tr>';
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
                return;
            }
            const m = data.my_rank;
            myBoxEl.innerHTML = `
                <div>순위: <strong>#${m.rank}</strong></div>
                <div>레이팅: <strong>${m.rating}</strong> (최고 ${m.peak_rating})</div>
                <div>전적: ${m.wins}승 ${m.losses}패 ${m.draws}무 · 승률 ${m.win_rate}%</div>
            `;
        } catch (error) {
            myBoxEl.textContent = error.message || "내 시즌 정보를 불러오지 못했습니다.";
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
            rewardBoxEl.innerHTML = rows.map((row) => `
                <div class="season-history-item">
                    <span>${row.rank_min}~${row.rank_max}위 · ${row.reward_type_label}</span>
                    <strong>${Utils.escapeHtml(row.reward_value)}</strong>
                </div>
            `).join("");
        } catch (error) {
            rewardBoxEl.textContent = error.message || "보상 정보를 불러오지 못했습니다.";
        }
    }

    async function claimRewards() {
        if (!currentUserId) {
            Toast.error("로그인 후 보상을 수령할 수 있습니다.");
            return;
        }
        if (!currentSeasonId) return;
        try {
            const data = await API.post(`/seasons/${currentSeasonId}/rewards/claim/`, {});
            Toast.success(`보상 ${data.claimed_count}개를 수령했습니다.`);
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
