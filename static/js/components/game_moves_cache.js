(function() {
    'use strict';

    const gameMoveCache = new Map();

    function getCacheEntry(gameId) {
        const key = String(gameId || '');
        if (!gameMoveCache.has(key)) {
            gameMoveCache.set(key, {
                offsetZeroItems: [],
                offsetZeroLimit: 0,
                pages: new Map(),
            });
        }
        return gameMoveCache.get(key);
    }

    async function loadPage(gameId, { limit = 200, offset = 0, force = false } = {}) {
        const entry = getCacheEntry(gameId);
        const pageKey = `${offset}:${limit}`;

        if (!force) {
            if (offset === 0 && entry.offsetZeroLimit >= limit) {
                return entry.offsetZeroItems.slice(0, limit);
            }
            if (entry.pages.has(pageKey)) {
                return entry.pages.get(pageKey);
            }
        }

        const data = await API.get(`/chess/games/${gameId}/moves/`, { limit, offset });
        const results = data.results || [];
        entry.pages.set(pageKey, results);

        if (offset === 0 && limit >= entry.offsetZeroLimit) {
            entry.offsetZeroItems = results;
            entry.offsetZeroLimit = limit;
        }

        return results;
    }

    async function loadLast(gameId, moveCount, { force = false } = {}) {
        const entry = getCacheEntry(gameId);
        const numericMoveCount = Number(moveCount || 0);
        if (!numericMoveCount) return null;

        if (!force && entry.offsetZeroLimit >= numericMoveCount && entry.offsetZeroItems.length >= numericMoveCount) {
            return entry.offsetZeroItems[numericMoveCount - 1] || null;
        }

        const offset = Math.max(0, numericMoveCount - 1);
        const rows = await loadPage(gameId, { limit: 1, offset, force });
        return rows[0] || null;
    }

    function invalidate(gameId) {
        if (!gameId) return;
        gameMoveCache.delete(String(gameId));
    }

    window.GameMovesCache = {
        invalidate,
        loadLast,
        loadPage,
    };
})();
