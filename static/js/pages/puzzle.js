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
    let selected = null;
    let finished = false;
    let timeLeft = TIMER_SECONDS;
    let timerHandle = null;
    let lastMoveSquares = [];
    let hintSquare = null;
    let hintLimit = 3;
    let hintsUsed = 0;
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

    function setStatus(message) {
        if (statusEl) {
            statusEl.textContent = message || "";
        }
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
        const objectiveMessage = data?.puzzle?.objective?.message;
        if (objectiveMessage) {
            return objectiveMessage;
        }
        const levelLabel = data?.level_label || "중간";
        const rating = data?.puzzle?.rating ? `퍼즐 레이팅 ${data.puzzle.rating}` : "퍼즐";
        const themes = Array.isArray(data?.puzzle?.themes) ? data.puzzle.themes : [];
        const themeText = themes.length ? ` · 테마: ${themes.slice(0, 2).join(", ")}` : "";
        return `${levelLabel} 난이도 ${rating}입니다. 최선 수순으로 이점을 확보하세요.${themeText}`;
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
        const moving = board[from.row][from.col];
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
        for (let row = 0; row < 8; row += 1) {
            for (let col = 0; col < 8; col += 1) {
                const square = document.createElement("button");
                square.type = "button";
                square.className = `puzzle-square ${(row + col) % 2 === 0 ? "light" : "dark"}`;
                const coord = `${String.fromCharCode("a".charCodeAt(0) + col)}${8 - row}`;
                square.dataset.square = coord;

                if (selected === coord) {
                    square.classList.add("selected");
                }
                if (hintSquare === coord) {
                    square.classList.add("hint");
                }
                if (lastMoveSquares.includes(coord)) {
                    square.classList.add("last-move");
                }

                const piece = board[row][col];
                if (piece) {
                    square.textContent = PIECE_MAP[piece] || "";
                } else {
                    square.textContent = "";
                }
                square.addEventListener("click", () => onSquareClick(coord));
                boardEl.appendChild(square);
            }
        }
    }

    async function submitMove(uci) {
        try {
            const data = await API.post("/chess/puzzle/daily/move/", { move: uci, level: currentLevel });
            applyUciMove(uci);
            if (data.next_move) {
                applyUciMove(data.next_move);
            }
            hintSquare = null;
            renderBoard();
            setStatus(data.message || (data.completed ? "퍼즐 완료!" : "정답 수입니다."));
            if (data.completed) {
                finished = true;
                stopTimer();
                Toast.success(data.message || "축하합니다! 퍼즐을 해결했습니다.");
            }
        } catch (error) {
            const msg = error?.data?.move?.[0] || error?.message || "수를 처리하지 못했습니다.";
            setStatus(msg);
            Toast.error(msg);
            renderBoard();
        }
    }

    function onSquareClick(square) {
        if (finished) return;
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
            if (finished) {
                stopTimer();
                return;
            }
            timeLeft -= 1;
            renderTimer();
            if (timeLeft <= 0) {
                finished = true;
                stopTimer();
                setStatus("시간이 종료되었습니다. 내일 다시 도전해보세요.");
                Toast.warning("제한시간 20분이 종료되었습니다.");
            }
        }, 1000);
    }

    async function loadDailyPuzzle() {
        try {
            const data = await API.get(`/chess/puzzle/daily/?level=${encodeURIComponent(currentLevel)}`);
            const fen = data?.puzzle?.fen;
            const firstMove = data?.puzzle?.first_move;
            if (!fen) {
                throw new Error("퍼즐 데이터를 불러오지 못했습니다.");
            }
            hintLimit = Number(data.hint_limit || 3);
            hintsUsed = Number(data.hints_used || 0);
            renderHintMeta();
            board = parseFenBoard(fen);
            if (firstMove) {
                applyUciMove(firstMove);
            }
            renderBoard();
            setGoal(getGoalText(data));
            renderSolutionSteps([]);
            const solved = Boolean(data?.attempt?.solved);
            finished = solved;
            if (solved) {
                setStatus("클리어한 퍼즐입니다. 정답 해설로 복기해보세요.");
                stopTimer();
                renderTimer();
            } else {
                setStatus("말을 클릭한 뒤 이동할 칸을 선택하세요.");
                startTimer();
            }
        } catch (error) {
            const msg = error?.message || "퍼즐을 불러오지 못했습니다.";
            setStatus(msg);
            Toast.error(msg);
        }
    }

    hintBtn?.addEventListener("click", async () => {
        if (finished) return;
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
            hintSquare = data.square || null;
            renderBoard();
            if (hintSquare) {
                const msg = `힌트: ${hintSquare.toUpperCase()} 칸의 말을 움직여보세요.`;
                setStatus(msg);
                Toast.info(msg);
            }
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

            // 현재 퍼즐 기준 보드 상태를 다시 만들고 정답 수순을 순차 재생
            const daily = await API.get(`/chess/puzzle/daily/?level=${encodeURIComponent(currentLevel)}`);
            board = parseFenBoard(daily?.puzzle?.fen || "");
            if (daily?.puzzle?.first_move) applyUciMove(daily.puzzle.first_move);
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
        } catch (error) {
            await Modal.alert("정답을 불러오지 못해 바로 로비로 이동합니다.", {
                title: "알림",
                confirmText: "로비로 이동",
            });
        } finally {
            window.location.href = "/";
        }
    });

    levelButtons.forEach((button) => {
        button.addEventListener("click", async () => {
            const nextLevel = button.dataset.level;
            if (!nextLevel || nextLevel === currentLevel) return;
            currentLevel = nextLevel;
            levelButtons.forEach((btn) => btn.classList.toggle("is-active", btn.dataset.level === currentLevel));
            finished = false;
            selected = null;
            hintSquare = null;
            lastMoveSquares = [];
            timeLeft = TIMER_SECONDS;
            setStatus("퍼즐을 불러오는 중...");
            await loadDailyPuzzle();
        });
    });

    loadDailyPuzzle();
})();
