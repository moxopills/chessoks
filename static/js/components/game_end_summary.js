(function() {
    'use strict';

    function appendStatRow(root, label, value) {
        if (!root || value === null || value === undefined || value === '') return;
        const row = document.createElement('div');
        row.className = 'stats-row';
        const labelEl = document.createElement('span');
        labelEl.className = 'stats-label';
        labelEl.textContent = label;
        const valueEl = document.createElement('span');
        valueEl.className = 'stats-value';
        valueEl.textContent = value;
        row.appendChild(labelEl);
        row.appendChild(valueEl);
        root.appendChild(row);
    }

    function render(summary, { statsRoot, ratingRoot }) {
        if (statsRoot) {
            statsRoot.innerHTML = '';
            appendStatRow(
                statsRoot,
                '평균 착수 시간',
                summary?.average_move_time != null ? `${summary.average_move_time.toFixed(1)}초` : '--'
            );
            appendStatRow(
                statsRoot,
                '최장 고민 시간',
                summary?.max_move_time != null ? `${summary.max_move_time.toFixed(1)}초` : '--'
            );
            appendStatRow(
                statsRoot,
                '상대 평균 착수',
                summary?.opponent_average_move_time != null
                    ? `${summary.opponent_average_move_time.toFixed(1)}초`
                    : '--'
            );
        }

        if (!ratingRoot) return;
        const rating = summary?.rating_change;
        if (!rating) {
            ratingRoot.textContent = '';
            return;
        }
        const delta = Number(rating.delta || 0);
        ratingRoot.textContent = '';
        const line = document.createElement('span');
        line.textContent = `${rating.before} → ${rating.after}`;
        const deltaEl = document.createElement('span');
        deltaEl.className = delta >= 0 ? 'positive' : 'negative';
        deltaEl.textContent = `(${delta >= 0 ? '+' : ''}${delta})`;
        ratingRoot.appendChild(line);
        ratingRoot.appendChild(document.createTextNode(' '));
        ratingRoot.appendChild(deltaEl);
    }

    window.GameEndSummary = {
        render,
    };
})();
