(() => {
    const PIECE_MAP = {
        p: "♟",
        r: "♜",
        n: "♞",
        b: "♝",
        q: "♛",
        k: "♚",
        P: "♙",
        R: "♖",
        N: "♘",
        B: "♗",
        Q: "♕",
        K: "♔",
    };

    const TIMER_SECONDS = 20 * 60;

    let board = [];
    let puzzleMoves = [];
    let selected = null;
    let finished = false;
    let sessionStarted = false;
    let boardLoading = false;
    let timeLeft = TIMER_SECONDS;
    let timerHandle = null;
    let lastMoveSquares = [];
    let hintSquares = [];
    let hintLimit = 3;
    let hintsUsed = 0;
    let progressTotal = 0;
    let progressDone = 0;
    let currentLevel = "medium";

    const boardEl = document.getElementById("puzzle-board");
    const timerEl = document.getElementById("puzzle-timer");
    const statusEl = document.getElementById("puzzle-status");
    const hintBtn = document.getElementById("puzzle-hint-btn");
    const solutionBtn = document.getElementById("puzzle-solution-btn");
    const exitBtn = document.getElementById("puzzle-exit-btn");
    const hintMetaEl = document.getElementById("puzzle-hint-meta");
    const goalTextEl = document.getElementById("puzzle-goal-text");
    const solutionStepsEl = document.getElementById("puzzle-solution-steps");
    const levelButtons = document.querySelectorAll("#puzzle-levels [data-level]");
    const startCardEl = document.getElementById("puzzle-start-card");
    const startSummaryEl = document.getElementById("puzzle-start-summary");
    const startBtn = document.getElementById("puzzle-start-btn");
    const progressLabelEl = document.getElementById("puzzle-progress-label");
    const progressFillEl = document.getElementById("puzzle-progress-fill");
    const resultActionsEl = document.getElementById("puzzle-result-actions");
    const retryBtn = document.getElementById("puzzle-retry-btn");
    const switchLevelBtn = document.getElementById("puzzle-switch-level-btn");

    function setStatus(message) {
        if (statusEl) statusEl.textContent = message || "";
    }

    function renderHintMeta() {
        if (!hintMetaEl) return;
        const remaining = Math.max(0, hintLimit - hintsUsed);
        hintMetaEl.textContent = `힌트 ${hintsUsed}/${hintLimit} (남은 횟수 ${remaining})`;
    }

    function setGoal(text) {
        if (!goalTextEl) return;
        goalTextEl.textContent = text;
    }

    function showStartCard(summary) {
        if (!startCardEl) return;
        if (startSummaryEl) {
            startSummaryEl.textContent = summary || "목표를 확인한 뒤 시작 버튼을 눌러 도전하세요.";
        }
        startCardEl.classList.add("is-visible");
    }

    function hideStartCard() {
        startCardEl?.classList.remove("is-visible");
    }

    function setResultActionsVisible(visible) {
        if (!resultActionsEl) return;
        resultActionsEl.classList.toggle("is-visible", Boolean(visible));
    }

    function updateProgress(done, total) {
        const safeTotal = Math.max(1, Number(total || 0));
        const safeDone = Math.min(safeTotal, Math.max(0, Number(done || 0)));
        progressDone = safeDone;
        progressTotal = safeTotal;
        if (progressLabelEl) {
            progressLabelEl.textContent = `${safeDone}/${safeTotal}`;
        }
        if (progressFillEl) {
            const percent = Math.round((safeDone / safeTotal) * 100);
            progressFillEl.style.width = `${percent}%`;
        }
    }

    function getUserStepTotal(moves) {
        if (!Array.isArray(moves) || moves.length < 2) return 1;
        return Math.max(1, Math.ceil((moves.length - 1) / 2));
    }

    function formatObjectiveText(objective, fallback) {
        if (!objective || typeof objective !== "object") return fallback;
        const lines = [];
        if (objective.primary_goal) lines.push(objective.primary_goal);
        if (objective.action_intent) lines.push(objective.action_intent);
        if (objective.move_guide) lines.push(objective.move_guide);
        if (objective.followup_plan) lines.push(objective.followup_plan);
        if (objective.win_condition) lines.push(objective.win_condition);
        if (!lines.length && objective.message) return objective.message;
        return lines.join("\n");
    }

    function renderSolutionSteps(steps) {
        if (!solutionStepsEl) return;
        solutionStepsEl.innerHTML = "";
        if (!Array.isArray(steps) || !steps.length) {
            const li = document.createElement("li");
            li.textContent = "해설 데이터가 없습니다.";
            solutionStepsEl.appendChild(li);
            return;
        }
        steps.forEach((step) => {
            const li = document.createElement("li");
            const move = step?.san ? `${step.san}` : step?.uci || "-";
            li.textContent = `${step?.step || "?"}. ${move} - ${step?.description || "핵심 수입니다."}`;
            solutionStepsEl.appendChild(li);
        });
    }

    function getGoalText(data) {
        const objective = data?.puzzle?.objective || {};
        const formatted = formatObjectiveText(objective, "");
        if (formatted) return formatted;
        const levelLabel = data?.level_label || "중간";
        const rating = data?.puzzle?.rating ? `퍼즐 레이팅 ${data.puzzle.rating}` : "퍼즐";
        const themes = Array.isArray(data?.puzzle?.themes) ? data.puzzle.themes : [];
        const themeText = themes.length ? ` · 테마: ${themes.slice(0, 2).join(", ")}` : "";
        return `${levelLabel} 난이도 ${rating}입니다. 최선 수순으로 이점을 확보하세요.${themeText}`;
    }

    function getStartSummary(data) {
        const level = data?.level_label || "중간";
        const total = Number(data?.puzzle?.user_steps_total || 1);
        const remainingHints = Number(data?.remaining_hints ?? 3);
        return [
            `${level} 난이도 퍼즐 시작 준비`,
            `목표 수순: ${total}수`,
            `제한시간: 20분`,
            `사용 가능한 힌트: ${remainingHints}회`,
        ].join("\n");
    }

    function fileToIndex(fileChar) {
        return fileChar.charCodeAt(0) - "a".charCodeAt(0);
    }

    function rankToIndex(rankChar) {
        return 8 - Number(rankChar);
    }

    function squareToIndex(square) {
        return { row: rankToIndex(square[1]), col: fileToIndex(square[0]) };
    }

    function parseFenBoard(fen) {
        const rows = fen.split(" ")[0].split("/");
        return rows.map((row) => {
            const parsed = [];
            for (const ch of row) {
                if (/\d/.test(ch)) {
                    const cnt = Number(ch);
                    for (let i = 0; i < cnt; i += 1) parsed.push(null);
                } else {
                    parsed.push(ch);
                }
            }
            return parsed;
        });
    }

    function applyUciMove(uci) {
        if (!uci || uci.length < 4) return;
        const from = squareToIndex(uci.slice(0, 2));
        const to = squareToIndex(uci.slice(2, 4));
        const moving = board[from.row]?.[from.col];
        if (!moving) return;
        board[from.row][from.col] = null;
        let placed = moving;
        if (uci.length >= 5) {
            const promo = uci[4];
            placed = moving === moving.toUpperCase() ? promo.toUpperCase() : promo.toLowerCase();
        }
        board[to.row][to.col] = placed;
        lastMoveSquares = [uci.slice(0, 2), uci.slice(2, 4)];
    }

    function delay(ms) {
        return new Promise((resolve) => setTimeout(resolve, ms));
    }

    function renderBoard() {
        if (!boardEl) return;
        boardEl.innerHTML = "";
        boardEl.classList.toggle("is-loading", boardLoading);

        for (let row = 0; row < 8; row += 1) {
            for (let col = 0; col < 8; col += 1) {
                const coord = `${String.fromCharCode("a".charCodeAt(0) + col)}${8 - row}`;
                const square = document.createElement(boardLoading ? "div" : "button");
                if (!boardLoading) square.type = "button";
                square.className = `puzzle-square ${(row + col) % 2 === 0 ? "light" : "dark"}`;
                square.dataset.square = coord;

                if (boardLoading) {
                    square.classList.add("skeleton");
                    boardEl.appendChild(square);
                    continue;
                }

                if (selected === coord) square.classList.add("selected");
                if (hintSquares.includes(coord)) square.classList.add("hint");
                if (lastMoveSquares.includes(coord)) square.classList.add("last-move");

                const piece = board[row][col];
                square.textContent = piece ? PIECE_MAP[piece] || "" : "";
                square.addEventListener("click", () => onSquareClick(coord));
                boardEl.appendChild(square);
            }
        }
    }

    function mapMoveErrorMessage(rawMessage) {
        const msg = rawMessage || "";
        if (msg.includes("출발 칸")) return msg;
        if (msg.includes("내 차례")) return msg;
        if (msg.includes("불가능한 이동")) return msg;
        if (msg.includes("형식")) return "입력 형식 오류입니다. 예시처럼 e2e4 형태로 시도해주세요.";
        if (msg.includes("둘 수 없는 수")) return "규칙상 불가능한 수입니다. 이동 경로와 체크 상태를 확인해주세요.";
        return msg || "수를 처리하지 못했습니다.";
    }

    async function submitMove(uci) {
        try {
            const data = await API.post("/chess/puzzle/daily/move/", { move: uci, level: currentLevel });
            applyUciMove(uci);
            if (data.next_move) applyUciMove(data.next_move);
            hintSquares = [];
            renderBoard();

            if (Array.isArray(data.moves_made)) {
                updateProgress(data.moves_made.length, progressTotal);
            }
            if (!Array.isArray(data.moves_made) && data.correct) {
                updateProgress(progressDone + 1, progressTotal);
            }

            if (data.correct === false) {
                setStatus(data.message || "합법수지만 퍼즐 정답 수순과 다릅니다.");
                Toast.warning(data.message || "정답 수순이 아닙니다. 다시 시도해보세요.");
                return;
            }

            setStatus(data.message || (data.completed ? "퍼즐 완료!" : "정답 수입니다."));
            if (data.completed) {
                finished = true;
                sessionStarted = false;
                stopTimer();
                setResultActionsVisible(true);
                updateProgress(progressTotal, progressTotal);
                Toast.success(data.message || "축하합니다! 퍼즐을 해결했습니다.");
            }
        } catch (error) {
            const raw = error?.data?.move?.[0] || error?.message || "";
            const msg = mapMoveErrorMessage(raw);
            setStatus(msg);
            Toast.error(msg);
            renderBoard();
        }
    }

    function onSquareClick(square) {
        if (finished) return;
        if (!sessionStarted) {
            Toast.info("시작 버튼을 눌러 퍼즐을 시작해주세요.");
            return;
        }
        if (!selected) {
            selected = square;
            renderBoard();
            return;
        }
        if (selected === square) {
            selected = null;
            renderBoard();
            return;
        }
        const moveUci = `${selected}${square}`;
        selected = null;
        renderBoard();
        submitMove(moveUci);
    }

    function renderTimer() {
        if (!timerEl) return;
        const mm = String(Math.floor(timeLeft / 60)).padStart(2, "0");
        const ss = String(timeLeft % 60).padStart(2, "0");
        timerEl.textContent = `${mm}:${ss}`;
    }

    function stopTimer() {
        if (timerHandle) {
            clearInterval(timerHandle);
            timerHandle = null;
        }
    }

    function startTimer() {
        renderTimer();
        stopTimer();
        timerHandle = setInterval(() => {
            if (finished || !sessionStarted) {
                stopTimer();
                return;
            }
            timeLeft -= 1;
            renderTimer();
            if (timeLeft <= 0) {
                finished = true;
                sessionStarted = false;
                stopTimer();
                setStatus("시간이 종료되었습니다. 내일 다시 도전해보세요.");
                setResultActionsVisible(true);
                Toast.warning("제한시간 20분이 종료되었습니다.");
            }
        }, 1000);
    }

    async function loadDailyPuzzle() {
        try {
            boardLoading = true;
            renderBoard();
            setStatus("퍼즐 데이터를 불러오는 중...");
            setResultActionsVisible(false);

            const data = await API.get(`/chess/puzzle/daily/?level=${encodeURIComponent(currentLevel)}`);
            const fen = data?.puzzle?.fen;
            const firstMove = data?.puzzle?.first_move;
            if (!fen) throw new Error("퍼즐 데이터를 불러오지 못했습니다.");

            hintLimit = Number(data.hint_limit || 3);
            hintsUsed = Number(data.hints_used || 0);
            renderHintMeta();

            progressTotal = Number(data?.puzzle?.user_steps_total || getUserStepTotal(puzzleMoves));
            progressDone = Array.isArray(data?.attempt?.moves_made) ? data.attempt.moves_made.length : 0;
            updateProgress(progressDone, progressTotal);

            board = parseFenBoard(fen);
            if (firstMove) applyUciMove(firstMove);
            hintSquares = [];
            selected = null;
            boardLoading = false;
            renderBoard();

            setGoal(getGoalText(data));
            showStartCard(getStartSummary(data));
            renderSolutionSteps([]);

            const solved = Boolean(data?.attempt?.solved);
            finished = solved;
            sessionStarted = false;
            timeLeft = TIMER_SECONDS;
            renderTimer();
            stopTimer();

            if (solved) {
                hideStartCard();
                setResultActionsVisible(true);
                setStatus("클리어한 퍼즐입니다. 정답 해설로 복기해보세요.");
                updateProgress(progressTotal, progressTotal);
            } else {
                setStatus("목표를 읽고 시작 버튼을 눌러 퍼즐을 시작하세요.");
            }
        } catch (error) {
            boardLoading = false;
            renderBoard();
            const msg = error?.message || "퍼즐을 불러오지 못했습니다.";
            setStatus(msg);
            Toast.error(msg);
        }
    }

    startBtn?.addEventListener("click", () => {
        if (finished) return;
        sessionStarted = true;
        hideStartCard();
        setStatus("퍼즐 시작! 정답 수순을 차례대로 찾아보세요.");
        startTimer();
    });

    hintBtn?.addEventListener("click", async () => {
        if (finished) return;
        if (!sessionStarted) {
            Toast.info("시작 버튼을 눌러 퍼즐을 시작한 뒤 힌트를 사용하세요.");
            return;
        }
        try {
            const data = await API.post("/chess/puzzle/daily/hint/", { level: currentLevel });
            hintsUsed = Number(data.hints_used ?? hintsUsed);
            renderHintMeta();
            if (data.hint_type === "limit") {
                const msg = data.message || "힌트 사용 횟수를 모두 소진했습니다.";
                setStatus(msg);
                Toast.info(msg);
                return;
            }
            if (data.hint_type === "completed") {
                Toast.info(data.message || "이미 완료한 퍼즐입니다.");
                return;
            }

            const from = data.square || null;
            const to = data.target_square || null;
            if (data.hint_type === "piece" && from) {
                hintSquares = [from];
            } else if (data.hint_type === "target") {
                hintSquares = [from, to].filter(Boolean);
            } else if (data.hint_type === "intent") {
                hintSquares = [from, to].filter(Boolean);
            } else {
                hintSquares = [];
            }
            renderBoard();

            const msg = data.message || "힌트를 확인하세요.";
            setStatus(msg);
            Toast.info(msg);
        } catch (error) {
            Toast.error(error?.message || "힌트를 불러오지 못했습니다.");
        }
    });

    solutionBtn?.addEventListener("click", async () => {
        if (!confirm("정답 수순을 실제 이동으로 보시겠습니까?")) return;
        try {
            const data = await API.get(`/chess/puzzle/daily/solution/?level=${encodeURIComponent(currentLevel)}`);
            const replayMoves = Array.isArray(data.replay_moves) ? data.replay_moves : [];
            const steps = Array.isArray(data.steps) ? data.steps : [];
            renderSolutionSteps(steps);

            const daily = await API.get(`/chess/puzzle/daily/?level=${encodeURIComponent(currentLevel)}`);
            board = parseFenBoard(daily?.puzzle?.fen || "");
            if (daily?.puzzle?.first_move) applyUciMove(daily.puzzle.first_move);
            hintSquares = [];
            renderBoard();

            for (const move of replayMoves) {
                await delay(550);
                applyUciMove(move);
                renderBoard();
            }

            setStatus("정답 수순 재생이 완료되었습니다.");
            Toast.info(data.message || "정답 해설을 확인했습니다.");
        } catch (error) {
            Toast.error(error?.message || "정답 해설을 불러오지 못했습니다.");
        }
    });

    exitBtn?.addEventListener("click", async (event) => {
        event.preventDefault();
        try {
            const data = await API.get(`/chess/puzzle/daily/solution/?level=${encodeURIComponent(currentLevel)}`);
            const moves = Array.isArray(data.moves) ? data.moves.join(" ") : "-";
            await Modal.alert(`정답 수순: ${moves}`, {
                title: "퍼즐 정답",
                confirmText: "로비로 이동",
            });
        } catch (_error) {
            await Modal.alert("정답을 불러오지 못해 바로 로비로 이동합니다.", {
                title: "알림",
                confirmText: "로비로 이동",
            });
        } finally {
            window.location.href = "/";
        }
    });

    retryBtn?.addEventListener("click", async () => {
        finished = false;
        sessionStarted = false;
        selected = null;
        lastMoveSquares = [];
        hintSquares = [];
        hintsUsed = 0;
        timeLeft = TIMER_SECONDS;
        await loadDailyPuzzle();
    });

    switchLevelBtn?.addEventListener("click", () => {
        const order = ["easy", "medium", "hard"];
        const idx = order.indexOf(currentLevel);
        const next = order[(idx + 1) % order.length];
        const targetBtn = Array.from(levelButtons).find((btn) => btn.dataset.level === next);
        if (targetBtn) targetBtn.click();
    });

    levelButtons.forEach((button) => {
        button.addEventListener("click", async () => {
            const nextLevel = button.dataset.level;
            if (!nextLevel || nextLevel === currentLevel) return;
            currentLevel = nextLevel;
            levelButtons.forEach((btn) =>
                btn.classList.toggle("is-active", btn.dataset.level === currentLevel)
            );
            finished = false;
            sessionStarted = false;
            selected = null;
            hintSquares = [];
            lastMoveSquares = [];
            timeLeft = TIMER_SECONDS;
            await loadDailyPuzzle();
        });
    });

    loadDailyPuzzle();
})();
