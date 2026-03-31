(function() {
    'use strict';

    function normalizeList(items) {
        return Array.isArray(items) ? items : [];
    }

    function buildCard(item) {
        const earnedClass = item.is_earned ? 'is-earned' : 'is-locked';
        const toneClass = item.tone ? `tone-${item.tone}` : 'tone-info';
        const badgeText = item.is_earned ? '달성' : '진행 중';
        const progress = Math.max(0, Math.min(100, Number(item.progress) || 0));

        return `
            <article class="achievement-card ${earnedClass} ${toneClass}">
                <div class="achievement-card-head">
                    <div class="achievement-icon" aria-hidden="true">${Utils.escapeHtml(item.icon || '🏅')}</div>
                    <div class="achievement-copy">
                        <div class="achievement-title-row">
                            <h3 class="achievement-title">${Utils.escapeHtml(item.title || '')}</h3>
                            <span class="achievement-badge">${badgeText}</span>
                        </div>
                        <p class="achievement-description">${Utils.escapeHtml(item.description || '')}</p>
                    </div>
                </div>
                <div class="achievement-progress">
                    <div class="achievement-progress-track">
                        <div class="achievement-progress-fill" style="width:${progress}%"></div>
                    </div>
                    <div class="achievement-progress-meta">
                        <span>${Utils.escapeHtml(item.progress_text || '')}</span>
                        <strong>${progress}%</strong>
                    </div>
                </div>
            </article>
        `;
    }

    function render(container, items, options = {}) {
        if (!container) return;
        const achievements = normalizeList(items);
        const earnedCount = achievements.filter((item) => item.is_earned).length;
        const heading = options.heading || '대표 업적';
        const subheading = options.subheading || `달성 ${earnedCount}/${achievements.length || 0}`;

        if (!achievements.length) {
            container.innerHTML = `
                <div class="achievement-shell">
                    <div class="achievement-shell-header">
                        <div>
                            <h2 class="achievement-shell-title">${Utils.escapeHtml(heading)}</h2>
                            <p class="achievement-shell-subtitle">${Utils.escapeHtml(subheading)}</p>
                        </div>
                    </div>
                    <div class="achievement-empty">아직 표시할 업적이 없습니다.</div>
                </div>
            `;
            return;
        }

        container.innerHTML = `
            <div class="achievement-shell">
                <div class="achievement-shell-header">
                    <div>
                        <h2 class="achievement-shell-title">${Utils.escapeHtml(heading)}</h2>
                        <p class="achievement-shell-subtitle">${Utils.escapeHtml(subheading)}</p>
                    </div>
                    <div class="achievement-shell-summary">
                        <span class="achievement-summary-pill">${earnedCount}개 달성</span>
                    </div>
                </div>
                <div class="achievement-grid">
                    ${achievements.map(buildCard).join('')}
                </div>
            </div>
        `;
    }

    window.ProfileAchievements = {
        render,
    };
})();
