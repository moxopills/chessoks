(function() {
    'use strict';

    let lastParsedFen = null;
    let lastParsedPosition = null;

    function setupBoard({
        chessBoard,
        files,
        ranks,
        onSquareClick,
        onSquareKeydown,
        onRightMouseDown,
        onRightMouseUp,
        onTouchStart,
        onTouchMove,
        onTouchEnd,
    }) {
        if (!chessBoard) return;

        chessBoard.classList.remove('chess-board--loading');
        chessBoard.innerHTML = '';

        for (let rank = 0; rank < 8; rank += 1) {
            for (let file = 0; file < 8; file += 1) {
                const square = document.createElement('div');
                const isLight = (rank + file) % 2 === 0;
                const squareName = files[file] + ranks[rank];

                square.className = `square ${isLight ? 'light' : 'dark'}`;
                square.dataset.square = squareName;
                square.tabIndex = 0;
                square.setAttribute('role', 'button');
                square.setAttribute('aria-label', squareName);

                square.addEventListener('click', () => onSquareClick?.(squareName));
                square.addEventListener('keydown', (event) => onSquareKeydown?.(event, squareName));
                square.addEventListener('contextmenu', (event) => event.preventDefault());
                square.addEventListener('mousedown', (event) => onRightMouseDown?.(event, squareName));
                square.addEventListener('mouseup', (event) => onRightMouseUp?.(event, squareName));
                square.addEventListener('touchstart', (event) => onTouchStart?.(event, squareName), { passive: false });

                chessBoard.appendChild(square);
            }
        }

        chessBoard.addEventListener('touchmove', onTouchMove, { passive: false });
        chessBoard.addEventListener('touchend', onTouchEnd, { passive: false });
    }

    function parseFEN(fen) {
        if (fen === lastParsedFen && lastParsedPosition) {
            return lastParsedPosition;
        }

        const position = [];
        const rows = fen.split(' ')[0].split('/');

        for (const row of rows) {
            const rank = [];
            for (const char of row) {
                if (Number.isNaN(Number(char))) {
                    rank.push(char);
                } else {
                    for (let idx = 0; idx < Number(char); idx += 1) {
                        rank.push(null);
                    }
                }
            }
            position.push(rank);
        }

        lastParsedFen = fen;
        lastParsedPosition = position;
        return position;
    }

    function flipSquare(square, files, ranks) {
        if (!square || square.length < 2) return square;
        const file = square[0];
        const rank = square[1];
        const fileIdx = files.indexOf(file);
        const rankIdx = ranks.indexOf(rank);
        if (fileIdx < 0 || rankIdx < 0) return square;
        return files[7 - fileIdx] + ranks[7 - rankIdx];
    }

    function toDisplaySquare(square, files, ranks, isFlipped) {
        if (!isFlipped) return square;
        return flipSquare(square, files, ranks);
    }

    function getPieceAtSquare({ game, squareName }) {
        if (!game?.fen) return null;
        const fen = game.fen.split(' ')[0];
        const fenRanks = fen.split('/');
        const file = squareName.charCodeAt(0) - 97;
        const rank = 8 - Number.parseInt(squareName[1], 10);

        if (rank < 0 || rank > 7 || file < 0 || file > 7) return null;

        const rankStr = fenRanks[rank];
        let currentFile = 0;
        for (const char of rankStr) {
            if (/\d/.test(char)) {
                currentFile += Number.parseInt(char, 10);
                continue;
            }
            if (currentFile === file) return char;
            currentFile += 1;
        }
        return null;
    }

    function createDragPiece({ piece, x, y, getPieceSvgMarkup, getPieceTypeClass }) {
        const dragPiece = document.createElement('div');
        dragPiece.className = 'drag-piece';
        dragPiece.innerHTML = getPieceSvgMarkup(piece);
        dragPiece.classList.add(piece === piece.toUpperCase() ? 'white' : 'black');
        dragPiece.classList.add(getPieceTypeClass(piece));
        dragPiece.style.left = `${x - 32}px`;
        dragPiece.style.top = `${y - 32}px`;
        document.body.appendChild(dragPiece);
        return dragPiece;
    }

    function removeDragPiece(dragPiece) {
        if (dragPiece) {
            dragPiece.remove();
        }
        return null;
    }

    function getSquareFromPoint(x, y) {
        const element = document.elementFromPoint(x, y);
        if (element && element.classList.contains('square')) {
            return element.dataset.square;
        }
        return null;
    }

    function clearDropHighlight(chessBoard) {
        if (!chessBoard) return;
        chessBoard.querySelectorAll('.drop-target').forEach((element) => {
            element.classList.remove('drop-target');
        });
    }

    function highlightDropTarget({ chessBoard, squareName, validMoves, toActualSquare, getSquare }) {
        clearDropHighlight(chessBoard);
        if (!squareName) return;
        const actualSquare = toActualSquare(squareName);
        if (!validMoves.includes(actualSquare)) return;
        const square = getSquare(squareName);
        if (square) {
            square.classList.add('drop-target');
        }
    }

    function applyLastMoveHighlight({ squares, lastMove, getSquare, files, ranks, isFlipped }) {
        squares.forEach((square) => {
            square.classList.remove('last-move');
        });
        if (!lastMove) return;
        const fromSquare = toDisplaySquare(lastMove.from, files, ranks, isFlipped);
        const toSquare = toDisplaySquare(lastMove.to, files, ranks, isFlipped);
        getSquare(fromSquare)?.classList.add('last-move');
        getSquare(toSquare)?.classList.add('last-move');
    }

    function getDangerTargetColor({ lastMove, result, currentTurn }) {
        if (lastMove?.is_checkmate) return currentTurn;
        if (lastMove?.is_check) return currentTurn;
        if (result === 'checkmate_white') return 'black';
        if (result === 'checkmate_black') return 'white';
        return null;
    }

    function applyKingDangerHighlight({
        game,
        lastMove,
        position,
        files,
        ranks,
        getSquare,
        isFlipped,
    }) {
        const targetColor = getDangerTargetColor({
            lastMove,
            result: game?.result,
            currentTurn: game?.current_turn,
        });
        if (!targetColor || !position) return;

        const kingChar = targetColor === 'white' ? 'K' : 'k';
        let actualKingSquare = null;

        for (let rank = 0; rank < 8 && !actualKingSquare; rank += 1) {
            for (let file = 0; file < 8; file += 1) {
                if (position[rank]?.[file] === kingChar) {
                    actualKingSquare = `${files[file]}${ranks[rank]}`;
                    break;
                }
            }
        }

        if (!actualKingSquare) return;

        const displayKingSquare = toDisplaySquare(actualKingSquare, files, ranks, isFlipped);
        const kingSquareEl = getSquare(displayKingSquare);
        if (!kingSquareEl) return;

        if (lastMove?.is_checkmate || game?.result === 'checkmate_white' || game?.result === 'checkmate_black') {
            kingSquareEl.classList.add('checkmate-king');
        } else {
            kingSquareEl.classList.add('check-king');
        }
    }

    function renderBoard({
        game,
        myColor,
        lastMove,
        animatePieceChanges = false,
        files,
        ranks,
        getAllSquareElements,
        getSquare,
        createPieceElement,
        onPieceDragStart,
        updateBoardBrandState,
    }) {
        if (!game?.fen) return null;

        const position = parseFEN(game.fen);
        const isFlipped = myColor === 'black';

        for (const square of getAllSquareElements()) {
            square.classList.remove(
                'selected',
                'valid-move',
                'valid-capture',
                'last-move',
                'check',
                'check-king',
                'checkmate-king',
            );
        }

        for (let rank = 0; rank < 8; rank += 1) {
            for (let file = 0; file < 8; file += 1) {
                const actualFile = isFlipped ? 7 - file : file;
                const actualRank = isFlipped ? 7 - rank : rank;
                const actualSquareName = files[actualFile] + ranks[actualRank];
                const piece = position[rank][file];
                const displayRank = isFlipped ? 7 - rank : rank;
                const displayFile = isFlipped ? 7 - file : file;
                const squareName = files[displayFile] + ranks[displayRank];
                const squareEl = getSquare(squareName);

                if (!squareEl) continue;

                const existingPieceEl = squareEl.querySelector('.piece');
                const existingPiece = existingPieceEl?.dataset.piece;

                if (piece) {
                    squareEl.setAttribute('aria-label', `${actualSquareName} ${piece}`);

                    if (existingPiece !== piece) {
                        if (existingPieceEl) existingPieceEl.remove();

                        const pieceEl = createPieceElement(piece);
                        squareEl.appendChild(pieceEl);

                        if (animatePieceChanges) {
                            pieceEl.style.opacity = '0';
                            pieceEl.style.transform = 'scale(0.6)';
                            requestAnimationFrame(() => {
                                pieceEl.style.opacity = '1';
                                pieceEl.style.transform = 'scale(1)';
                            });
                        } else {
                            pieceEl.style.opacity = '';
                            pieceEl.style.transform = '';
                        }

                        pieceEl.addEventListener('dragstart', (event) => onPieceDragStart?.(event, squareName));
                    }
                } else {
                    if (existingPieceEl) {
                        if (animatePieceChanges) {
                            existingPieceEl.style.opacity = '0';
                            existingPieceEl.style.transform = 'scale(0.6)';
                            setTimeout(() => {
                                if (existingPieceEl.parentNode === squareEl) {
                                    existingPieceEl.remove();
                                }
                            }, 200);
                        } else {
                            existingPieceEl.remove();
                        }
                    }
                    squareEl.setAttribute('aria-label', `${actualSquareName} 빈 칸`);
                }
            }
        }

        const squares = getAllSquareElements();
        applyLastMoveHighlight({
            squares,
            lastMove,
            getSquare,
            files,
            ranks,
            isFlipped,
        });
        applyKingDangerHighlight({
            game,
            lastMove,
            position,
            files,
            ranks,
            getSquare,
            isFlipped,
        });
        updateBoardBrandState?.();
        return position;
    }

    function getSquareCoords(square, files, ranks, isFlipped) {
        if (!square || square.length < 2) return { x: 0, y: 0 };
        let fileIdx = files.indexOf(square[0]);
        let rankIdx = ranks.indexOf(square[1]);
        if (isFlipped) {
            fileIdx = 7 - fileIdx;
            rankIdx = 7 - rankIdx;
        }
        return {
            x: (fileIdx + 0.5) * 12.5,
            y: (rankIdx + 0.5) * 12.5,
        };
    }

    function renderDrawings({ arrowLayer, drawings, files, ranks, isFlipped }) {
        if (!arrowLayer) return;

        let html = `
            <defs>
                <marker id="arrowhead" markerWidth="4" markerHeight="4" refX="2.5" refY="2" orient="auto">
                    <polygon points="0 0, 4 2, 0 4" fill="rgba(235, 97, 80, 0.85)" />
                </marker>
            </defs>
        `;

        (drawings?.circles || []).forEach((square) => {
            const { x, y } = getSquareCoords(square, files, ranks, isFlipped);
            html += `<circle cx="${x}%" cy="${y}%" r="5.5%" fill="none" stroke="rgba(235, 97, 80, 0.85)" stroke-width="1%" />`;
        });

        (drawings?.arrows || []).forEach((arrow) => {
            const from = getSquareCoords(arrow.from, files, ranks, isFlipped);
            const to = getSquareCoords(arrow.to, files, ranks, isFlipped);
            html += `<line x1="${from.x}%" y1="${from.y}%" x2="${to.x}%" y2="${to.y}%" stroke="rgba(235, 97, 80, 0.85)" stroke-width="1.8%" marker-end="url(#arrowhead)" opacity="0.9" stroke-linecap="round" />`;
        });

        arrowLayer.innerHTML = html;
    }

    window.GameBoardUI = {
        setupBoard,
        parseFEN,
        getPieceAtSquare,
        createDragPiece,
        removeDragPiece,
        getSquareFromPoint,
        clearDropHighlight,
        highlightDropTarget,
        renderBoard,
        renderDrawings,
    };
})();
