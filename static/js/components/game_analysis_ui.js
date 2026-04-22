(function() {
    'use strict';

    const PIECE_VALUE = {
        p: 1,
        n: 3,
        b: 3,
        r: 5,
        q: 9,
        k: 0,
    };

    function avg(arr) {
        if (!arr.length) return 0;
        return arr.reduce((sum, x) => sum + x, 0) / arr.length;
    }

    function scoreFenMaterial(fen) {
        const board = String(fen || '').split(' ')[0];
        let score = 0;
        for (const ch of board) {
            if (ch === '/' || /\d/.test(ch)) continue;
            const value = PIECE_VALUE[ch.toLowerCase()] || 0;
            score += ch === ch.toUpperCase() ? value : -value;
        }
        return score;
    }

    function buildEvalSeries(moves) {
        const series = [0];
        for (const move of moves || []) {
            const fen = move.fen_after_move;
            if (!fen) {
                series.push(series[series.length - 1]);
                continue;
            }
            series.push(scoreFenMaterial(fen));
        }
        return series;
    }

    function drawAnalysisGraph(canvas, series) {
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const w = canvas.width;
        const h = canvas.height;
        ctx.clearRect(0, 0, w, h);
        if (!series.length) return;

        const maxAbs = Math.max(1, ...series.map((v) => Math.abs(v)));
        const pad = 12;
        const graphW = w - pad * 2;
        const graphH = h - pad * 2;
        const yMid = pad + graphH / 2;

        ctx.strokeStyle = '#64748b';
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(pad, yMid);
        ctx.lineTo(w - pad, yMid);
        ctx.stroke();

        ctx.strokeStyle = '#22c55e';
        ctx.lineWidth = 2;
        ctx.beginPath();
        series.forEach((val, index) => {
            const x = pad + (series.length === 1 ? 0 : (index / (series.length - 1)) * graphW);
            const y = yMid - (val / maxAbs) * (graphH / 2 - 4);
            if (index === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        });
        ctx.stroke();
    }

    function render({ canvas, summaryEl, moves }) {
        const series = buildEvalSeries(moves || []);
        drawAnalysisGraph(canvas, series);
        if (!summaryEl) return;
        const maxSwing = series.length > 1
            ? Math.max(...series.map((value, index) => {
                if (index === 0) return 0;
                return Math.abs(value - series[index - 1]);
            }))
            : 0;
        summaryEl.textContent = `평균 평가값: ${avg(series).toFixed(2)} · 최대 변동: ${maxSwing.toFixed(2)}`;
    }

    window.GameAnalysisUI = {
        render,
    };
})();
