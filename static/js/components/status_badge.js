/**
 * Global status badge (success / pending / error / info)
 */

const StatusBadge = (function() {
    let container = null;
    const badges = new Map();

    function ensureContainer() {
        if (container) return container;
        container = document.getElementById('status-badge-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'status-badge-container';
            container.className = 'status-badge-container';
            document.body.appendChild(container);
        }
        return container;
    }

    function normalizeType(type) {
        return ['success', 'pending', 'error', 'info'].includes(type) ? type : 'info';
    }

    function show(message, type = 'info', opts = {}) {
        // Backward-compatible API:
        // 1) show(message, "success", { timeout: 2000 })
        // 2) show(message, { type: "success", duration: 2000 })
        if (typeof type === 'object' && type !== null) {
            opts = type;
            type = opts.type || 'info';
        }
        const box = ensureContainer();
        const id = opts.id || `badge-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        const level = normalizeType(type);
        let el = badges.get(id);
        if (!el) {
            el = document.createElement('div');
            el.className = `status-badge status-badge-${level}`;
            el.dataset.badgeId = id;
            box.appendChild(el);
            badges.set(id, el);
        } else {
            el.className = `status-badge status-badge-${level}`;
        }
        el.textContent = String(message || '').trim() || '상태 업데이트';

        if (opts.timeout !== 0 && opts.duration !== 0) {
            const timeout = Number.isFinite(opts.timeout)
                ? opts.timeout
                : (Number.isFinite(opts.duration) ? opts.duration : 2600);
            window.setTimeout(() => hide(id), timeout);
        }
        return id;
    }

    function update(id, message, type = 'info') {
        if (!id || !badges.has(id)) {
            return show(message, type, { id, timeout: 0 });
        }
        const el = badges.get(id);
        el.className = `status-badge status-badge-${normalizeType(type)}`;
        el.textContent = String(message || '').trim() || '상태 업데이트';
        return id;
    }

    function hide(id) {
        if (!id) return;
        const el = badges.get(id);
        if (!el) return;
        el.classList.add('is-leaving');
        window.setTimeout(() => {
            el.remove();
            badges.delete(id);
        }, 180);
    }

    return { show, update, hide };
})();
