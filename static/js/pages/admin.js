(function() {
    'use strict';

    const statsEl = document.getElementById('admin-stats');
    const userTable = document.getElementById('user-table');
    const reportTable = document.getElementById('report-table');
    const suspendedTable = document.getElementById('suspended-table');
    const mutedTable = document.getElementById('muted-table');
    const searchInput = document.getElementById('user-search');
    const searchBtn = document.getElementById('user-search-btn');

    const selectedInfo = document.getElementById('selected-user-info');
    const suspendDays = document.getElementById('suspend-days');
    const suspendReason = document.getElementById('suspend-reason');
    const muteMinutes = document.getElementById('mute-minutes');
    const muteReason = document.getElementById('mute-reason');
    const promoteRole = document.getElementById('promote-role');
    const noticeTitle = document.getElementById('notice-title');
    const noticeMessage = document.getElementById('notice-message');
    const noticeSendBtn = document.getElementById('notice-send-btn');
    const noticeModal = document.getElementById('admin-notice-modal');
    const noticeModalMessage = document.getElementById('admin-notice-modal-message');
    const noticeModalClose = document.getElementById('admin-notice-modal-close');
    const adminTabbar = document.getElementById('admin-tabbar');
    const adminTabs = adminTabbar ? adminTabbar.querySelectorAll('.mobile-tab') : [];
    const aiEasyCurrent = document.getElementById('ai-easy-current');
    const aiMediumCurrent = document.getElementById('ai-medium-current');
    const aiHardCurrent = document.getElementById('ai-hard-current');
    const aiEasyDepth = document.getElementById('ai-easy-depth');
    const aiEasyRandom = document.getElementById('ai-easy-random');
    const aiEasyDelay = document.getElementById('ai-easy-delay');
    const aiMediumDepth = document.getElementById('ai-medium-depth');
    const aiMediumRandom = document.getElementById('ai-medium-random');
    const aiMediumDelay = document.getElementById('ai-medium-delay');
    const aiHardDepth = document.getElementById('ai-hard-depth');
    const aiHardRandom = document.getElementById('ai-hard-random');
    const aiHardDelay = document.getElementById('ai-hard-delay');
    const aiSettingsSave = document.getElementById('ai-settings-save');
    const opsOverallStatus = document.getElementById('ops-overall-status');
    const opsGeneratedAt = document.getElementById('ops-generated-at');
    const opsComponentGrid = document.getElementById('ops-component-grid');
    const opsMetricGrid = document.getElementById('ops-metric-grid');
    const opsRefreshBtn = document.getElementById('ops-refresh-btn');

    const suspendBtn = document.getElementById('suspend-btn');
    const unsuspendBtn = document.getElementById('unsuspend-btn');
    const muteBtn = document.getElementById('mute-btn');
    const unmuteBtn = document.getElementById('unmute-btn');
    const promoteBtn = document.getElementById('promote-btn');
    const forceDeleteBtn = document.getElementById('force-delete-btn');

    let selectedUser = null;

    init();

    async function init() {
        await loadStats();
        await loadUsers();
        await loadReports();
        await loadAiSettings();
        await loadOpsReport();
        setupActions();
        setupMobileTabs();
        window.setInterval(loadOpsReport, 30000);
    }

    async function loadStats() {
        try {
            const data = await API.get('/admin/stats/');
            const values = [
                data.total_users,
                data.active_users,
                data.suspended_users,
                data.muted_users,
                data.pending_reports,
            ];
            const cards = statsEl.querySelectorAll('.stat-card');
            cards.forEach((card, idx) => {
                const value = card.querySelector('.stat-value');
                if (value) value.textContent = values[idx] ?? '-';
            });
            renderSuspendedList(data.suspended_list || []);
            renderMutedList(data.muted_list || []);
        } catch (error) {
            Toast.error('통계를 불러올 수 없습니다.');
        }
    }

    function renderSuspendedList(users) {
        if (!suspendedTable) return;
        const body = suspendedTable.querySelector('tbody');
        if (!users.length) {
            body.innerHTML = '<tr><td colspan="3">정지 유저 없음</td></tr>';
            return;
        }
        body.innerHTML = users.map((user) => {
            const until = user.suspended_until ? formatDateTime(user.suspended_until) : '-';
            const reason = user.suspension_reason ? Utils.escapeHtml(user.suspension_reason) : '-';
            return `
                <tr>
                    <td>${Utils.escapeHtml(user.nickname)}</td>
                    <td>${until}</td>
                    <td>${reason}</td>
                </tr>
            `;
        }).join('');
    }

    function renderMutedList(users) {
        if (!mutedTable) return;
        const body = mutedTable.querySelector('tbody');
        if (!users.length) {
            body.innerHTML = '<tr><td colspan="3">뮤트 유저 없음</td></tr>';
            return;
        }
        body.innerHTML = users.map((user) => {
            const until = user.muted_until ? formatDateTime(user.muted_until) : '-';
            const reason = user.mute_reason ? Utils.escapeHtml(user.mute_reason) : '-';
            return `
                <tr>
                    <td>${Utils.escapeHtml(user.nickname)}</td>
                    <td>${until}</td>
                    <td>${reason}</td>
                </tr>
            `;
        }).join('');
    }

    function formatDateTime(value) {
        const d = new Date(value);
        const y = d.getFullYear();
        const m = String(d.getMonth() + 1).padStart(2, '0');
        const day = String(d.getDate()).padStart(2, '0');
        const hh = String(d.getHours()).padStart(2, '0');
        const mm = String(d.getMinutes()).padStart(2, '0');
        return `${y}-${m}-${day} ${hh}:${mm}`;
    }

    async function loadUsers(query = '') {
        try {
            const data = await API.get('/admin/users/', { q: query, limit: 30, offset: 0 });
            renderUsers(data.results || []);
        } catch {
            userTable.querySelector('tbody').innerHTML = '<tr><td colspan="4">불러오기 실패</td></tr>';
        }
    }

    function renderUsers(users) {
        if (!users.length) {
            userTable.querySelector('tbody').innerHTML = '<tr><td colspan="4">유저가 없습니다.</td></tr>';
            return;
        }
        userTable.querySelector('tbody').innerHTML = users.map(user => {
            const status = user.suspended_until ? '정지' : (user.muted_until ? '뮤트' : (user.is_active ? '활성' : '비활성'));
            return `
                <tr data-user-id="${user.id}" data-nickname="${Utils.escapeHtml(user.nickname)}">
                    <td>${user.id}</td>
                    <td>${Utils.escapeHtml(user.nickname)}</td>
                    <td>${user.rating}</td>
                    <td>${status}</td>
                </tr>
            `;
        }).join('');

        userTable.querySelectorAll('tbody tr').forEach(row => {
            row.addEventListener('click', () => {
                // 이전 선택 해제
                userTable.querySelectorAll('tbody tr.selected').forEach(r => r.classList.remove('selected'));
                // 현재 행 선택
                row.classList.add('selected');
                const id = row.dataset.userId;
                const nickname = row.dataset.nickname;
                selectedUser = { id, nickname };
                selectedInfo.textContent = `${nickname} (#${id})`;
            });
        });
    }

    async function loadReports() {
        try {
            const data = await API.get('/admin/reports/', { status: 'pending', limit: 50, offset: 0 });
            renderReports(data.results || []);
        } catch {
            reportTable.querySelector('tbody').innerHTML = '<tr><td colspan="6">불러오기 실패</td></tr>';
        }
    }

    function renderReports(reports) {
        if (!reports.length) {
            reportTable.querySelector('tbody').innerHTML = '<tr><td colspan="6">대기 중 신고가 없습니다.</td></tr>';
            return;
        }
        reportTable.querySelector('tbody').innerHTML = reports.map(report => {
            const description = report.description ? Utils.escapeHtml(report.description) : '';
            const category = Utils.escapeHtml(report.category || '');
            const summary = description ? `${category} · ${description}` : category;
            return `
                <tr data-report-id="${report.id}">
                    <td>${report.id}</td>
                    <td>${Utils.escapeHtml(report.reporter_nickname || '-') }</td>
                    <td>${Utils.escapeHtml(report.target_nickname)}</td>
                    <td>${summary || '-'}</td>
                    <td>${report.status}</td>
                    <td>
                        <button class="btn btn-primary btn-sm" data-action="resolve">처리</button>
                        <button class="btn btn-secondary btn-sm" data-action="dismiss">무효</button>
                    </td>
                </tr>
            `;
        }).join('');

        reportTable.querySelectorAll('button').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const row = e.target.closest('tr');
                const reportId = row.dataset.reportId;
                const action = e.target.dataset.action;
                await resolveReport(reportId, action === 'resolve' ? 'resolved' : 'dismissed');
            });
        });
    }

    async function resolveReport(reportId, status) {
        try {
            let resolution_note = '';
            if (status === 'dismissed') {
                resolution_note = prompt('무효 처리 사유를 입력하세요 (선택)') || '';
            } else {
                resolution_note = prompt('처리 메모를 입력하세요 (선택)') || '';
            }
            await API.post(`/admin/reports/${reportId}/resolve/`, { status, resolution_note });
            Toast.success('신고가 처리되었습니다.');
            loadReports();
            loadStats();
        } catch (error) {
            Toast.error(error.data?.message || '처리에 실패했습니다.');
        }
    }

    function setupActions() {
        searchBtn.addEventListener('click', () => loadUsers(searchInput.value.trim()));
        if (aiSettingsSave) {
            aiSettingsSave.addEventListener('click', async () => {
                try {
                    const numOr = (value, fallback) => {
                        const parsed = parseInt(value, 10);
                        return Number.isFinite(parsed) ? parsed : fallback;
                    };
                    const items = [
                        {
                            level: 'easy',
                            depth: numOr(aiEasyDepth?.value, 0),
                            randomness: numOr(aiEasyRandom?.value, 1),
                            delay_ms: numOr(aiEasyDelay?.value, 0),
                        },
                        {
                            level: 'medium',
                            depth: numOr(aiMediumDepth?.value, 0),
                            randomness: numOr(aiMediumRandom?.value, 1),
                            delay_ms: numOr(aiMediumDelay?.value, 0),
                        },
                        {
                            level: 'hard',
                            depth: numOr(aiHardDepth?.value, 0),
                            randomness: numOr(aiHardRandom?.value, 1),
                            delay_ms: numOr(aiHardDelay?.value, 0),
                        },
                    ];
                    const response = await API.post('/admin/ai-settings/', { items });
                    if (response.errors?.length) {
                        Toast.error('일부 설정이 저장되지 않았습니다.');
                    } else {
                        Toast.success('AI 설정이 저장되었습니다.');
                    }
                    await loadAiSettings();
                } catch (error) {
                    Toast.error(error.data?.message || 'AI 설정 저장 실패');
                }
            });
        }

        suspendBtn.addEventListener('click', async () => {
            if (!selectedUser) return Toast.error('유저를 선택하세요.');
            const days = parseInt(suspendDays.value, 10);
            if (!days) return Toast.error('정지 일수를 입력하세요.');
            await API.post(`/admin/users/${selectedUser.id}/suspend/`, { days, reason: suspendReason.value || '' });
            Toast.success('정지 처리 완료');
            loadUsers(searchInput.value.trim());
            loadStats();
        });

        unsuspendBtn.addEventListener('click', async () => {
            if (!selectedUser) return Toast.error('유저를 선택하세요.');
            await API.post(`/admin/users/${selectedUser.id}/unsuspend/`);
            Toast.success('정지 해제 완료');
            loadUsers(searchInput.value.trim());
            loadStats();
        });

        muteBtn.addEventListener('click', async () => {
            if (!selectedUser) return Toast.error('유저를 선택하세요.');
            const minutes = parseInt(muteMinutes.value, 10);
            if (!minutes) return Toast.error('뮤트 분을 입력하세요.');
            await API.post(`/admin/users/${selectedUser.id}/mute/`, { minutes, reason: muteReason.value || '' });
            Toast.success('뮤트 처리 완료');
            loadUsers(searchInput.value.trim());
            loadStats();
        });

        unmuteBtn.addEventListener('click', async () => {
            if (!selectedUser) return Toast.error('유저를 선택하세요.');
            await API.post(`/admin/users/${selectedUser.id}/unmute/`);
            Toast.success('뮤트 해제 완료');
            loadUsers(searchInput.value.trim());
            loadStats();
        });

        promoteBtn.addEventListener('click', async () => {
            if (!selectedUser) return Toast.error('유저를 선택하세요.');
            const role = promoteRole.value;
            const payload = role === 'superuser'
                ? { is_staff: true, is_superuser: true }
                : { is_staff: true, is_superuser: false };
            await API.post(`/admin/users/${selectedUser.id}/promote/`, payload);
            Toast.success('권한이 적용되었습니다.');
            loadUsers(searchInput.value.trim());
        });

        forceDeleteBtn.addEventListener('click', async () => {
            if (!selectedUser) return Toast.error('유저를 선택하세요.');
            if (!confirm('정말 강제 탈퇴 처리할까요?')) return;
            await API.delete(`/admin/users/${selectedUser.id}/force-delete/`);
            Toast.success('계정이 삭제되었습니다.');
            selectedUser = null;
            selectedInfo.textContent = '유저를 선택하세요.';
            loadUsers(searchInput.value.trim());
            loadStats();
        });

        noticeSendBtn?.addEventListener('click', async () => {
            const title = noticeTitle?.value.trim() || '공지';
            const message = noticeMessage?.value.trim();
            if (!message) return Toast.error('공지 내용을 입력하세요.');
            try {
                await API.post('/admin/notices/', { title, message });
                if (noticeTitle) noticeTitle.value = '';
                if (noticeMessage) noticeMessage.value = '';
                showNoticeModal(`${title} · ${message}`);
            } catch (error) {
                Toast.error(error.data?.message || '공지 발송에 실패했습니다.');
            }
        });

        noticeModalClose?.addEventListener('click', () => hideNoticeModal());
        noticeModal?.addEventListener('click', (event) => {
            if (event.target === noticeModal) hideNoticeModal();
        });

        opsRefreshBtn?.addEventListener('click', async () => {
            await loadOpsReport();
            Toast.success('운영 리포트를 새로고침했습니다.');
        });
    }

    async function loadAiSettings() {
        if (!aiEasyDepth) return;
        try {
            const data = await API.get('/admin/ai-settings/');
            const byLevel = {};
            data.forEach((item) => {
                byLevel[item.level] = item;
            });

            // 폼 값 설정
            if (aiEasyDepth) aiEasyDepth.value = byLevel.easy?.depth ?? 0;
            if (aiEasyRandom) aiEasyRandom.value = byLevel.easy?.randomness ?? 8;
            if (aiEasyDelay) aiEasyDelay.value = byLevel.easy?.delay_ms ?? 1200;
            if (aiMediumDepth) aiMediumDepth.value = byLevel.medium?.depth ?? 1;
            if (aiMediumRandom) aiMediumRandom.value = byLevel.medium?.randomness ?? 4;
            if (aiMediumDelay) aiMediumDelay.value = byLevel.medium?.delay_ms ?? 900;
            if (aiHardDepth) aiHardDepth.value = byLevel.hard?.depth ?? 2;
            if (aiHardRandom) aiHardRandom.value = byLevel.hard?.randomness ?? 2;
            if (aiHardDelay) aiHardDelay.value = byLevel.hard?.delay_ms ?? 700;

            // 현재 설정 표시 (카드 하단)
            const formatCurrent = (level, defaults) => {
                const d = byLevel[level]?.depth ?? defaults.depth;
                const r = byLevel[level]?.randomness ?? defaults.randomness;
                const delay = byLevel[level]?.delay_ms ?? defaults.delay_ms;
                return `현재: 깊이 ${d} · 랜덤 ${r} · ${delay}ms`;
            };

            if (aiEasyCurrent) {
                aiEasyCurrent.textContent = formatCurrent('easy', { depth: 0, randomness: 8, delay_ms: 1200 });
            }
            if (aiMediumCurrent) {
                aiMediumCurrent.textContent = formatCurrent('medium', { depth: 1, randomness: 4, delay_ms: 900 });
            }
            if (aiHardCurrent) {
                aiHardCurrent.textContent = formatCurrent('hard', { depth: 2, randomness: 2, delay_ms: 700 });
            }
        } catch (error) {
            if (aiEasyCurrent) aiEasyCurrent.textContent = '설정 로드 실패';
            if (aiMediumCurrent) aiMediumCurrent.textContent = '설정 로드 실패';
            if (aiHardCurrent) aiHardCurrent.textContent = '설정 로드 실패';
        }
    }

    function showNoticeModal(message) {
        if (noticeModalMessage) {
            noticeModalMessage.textContent = message;
        }
        noticeModal?.classList.remove('hidden');
    }

    function hideNoticeModal() {
        noticeModal?.classList.add('hidden');
    }

    function setupMobileTabs() {
        if (!adminTabbar || !adminTabs.length) return;
        document.body.classList.add('has-mobile-tabbar', 'admin-tab-users');
        adminTabs.forEach((tab) => {
            tab.addEventListener('click', () => {
                const target = tab.dataset.adminTab;
                adminTabs.forEach((btn) => btn.classList.remove('active'));
                tab.classList.add('active');
                document.body.classList.remove('admin-tab-users', 'admin-tab-reports', 'admin-tab-ops');
                document.body.classList.add(`admin-tab-${target || 'users'}`);
            });
        });
    }

    async function loadOpsReport() {
        if (!opsOverallStatus || !opsComponentGrid || !opsMetricGrid) return;

        opsOverallStatus.textContent = '로딩 중';
        opsOverallStatus.className = 'ops-status-badge is-loading';

        try {
            const data = await API.get('/admin/ops/');
            renderOpsSummary(data);
            renderOpsComponents(data.components || {});
            renderOpsMetrics(data.metrics || {});
        } catch (error) {
            opsOverallStatus.textContent = '오류';
            opsOverallStatus.className = 'ops-status-badge is-error';
            if (opsGeneratedAt) opsGeneratedAt.textContent = '최근 갱신: 불러오기 실패';
            opsComponentGrid.innerHTML = '<div class="admin-section-note">운영 상태를 불러오지 못했습니다.</div>';
            opsMetricGrid.innerHTML = '<div class="admin-section-note">운영 메트릭을 불러오지 못했습니다.</div>';
        }
    }

    function renderOpsSummary(data) {
        const degraded = data.status !== 'ok';
        opsOverallStatus.textContent = degraded ? '주의' : '정상';
        opsOverallStatus.className = `ops-status-badge ${degraded ? 'is-error' : 'is-ok'}`;
        if (opsGeneratedAt) {
            opsGeneratedAt.textContent = `최근 갱신: ${formatDateTime(data.generated_at)}`;
        }
    }

    function renderOpsComponents(components) {
        const entries = Object.entries(components);
        if (!entries.length) {
            opsComponentGrid.innerHTML = '<div class="admin-section-note">표시할 컴포넌트 상태가 없습니다.</div>';
            return;
        }

        opsComponentGrid.innerHTML = entries.map(([name, detail]) => {
            const status = detail.status || 'unknown';
            const badgeClass = status === 'ok' ? 'is-ok' : status === 'disabled' ? 'is-muted' : 'is-error';
            const rows = Object.entries(detail)
                .filter(([key]) => !['status', 'required'].includes(key))
                .map(([key, value]) => `<div class="ops-kv"><span>${labelize(key)}</span><strong>${formatMetricValue(value)}</strong></div>`)
                .join('');
            return `
                <article class="ops-card">
                    <div class="ops-card-head">
                        <h3>${labelize(name)}</h3>
                        <span class="ops-status-badge ${badgeClass}">${status}</span>
                    </div>
                    <div class="ops-card-body">
                        ${rows || '<div class="admin-section-note">추가 정보 없음</div>'}
                    </div>
                </article>
            `;
        }).join('');
    }

    function renderOpsMetrics(metrics) {
        const groups = Object.entries(metrics);
        if (!groups.length) {
            opsMetricGrid.innerHTML = '<div class="admin-section-note">표시할 메트릭이 없습니다.</div>';
            return;
        }

        opsMetricGrid.innerHTML = groups.map(([name, values]) => `
            <article class="ops-card">
                <div class="ops-card-head">
                    <h3>${labelize(name)}</h3>
                </div>
                <div class="ops-card-body">
                    ${renderMetricRows(values)}
                </div>
            </article>
        `).join('');
    }

    function renderMetricRows(values) {
        if (!values || typeof values !== 'object') {
            return `<div class="ops-kv"><span>값</span><strong>${formatMetricValue(values)}</strong></div>`;
        }
        return Object.entries(values).map(([key, value]) => {
            if (value && typeof value === 'object' && !Array.isArray(value)) {
                return `
                    <div class="ops-subgroup">
                        <div class="ops-subgroup-title">${labelize(key)}</div>
                        ${renderMetricRows(value)}
                    </div>
                `;
            }
            return `<div class="ops-kv"><span>${labelize(key)}</span><strong>${formatMetricValue(value)}</strong></div>`;
        }).join('');
    }

    function formatMetricValue(value) {
        if (value === null || value === undefined || value === '') return '-';
        if (typeof value === 'boolean') return value ? '예' : '아니오';
        return Utils.escapeHtml(String(value));
    }

    function labelize(value) {
        const labels = {
            database: '데이터베이스',
            cache: '캐시',
            channels: '웹소켓',
            web_push: '푸시',
            gcs: '스토리지',
            celery: 'Celery',
            games: '게임',
            rooms: '방',
            notifications: '알림',
            queues: '큐',
            queue_depth: '큐 깊이',
            queue_name: '큐 이름',
            active_subscriptions: '활성 구독',
            push_subscriptions_active: '활성 푸시 구독',
            unread: '미읽음',
            waiting: '대기 중',
            playing: '진행 중',
            finished_today: '오늘 종료',
            duration_ms: '응답 시간(ms)',
            bucket_name: '버킷',
            client: '클라이언트',
            reason: '사유',
            broker_scheme: '브로커',
            status: '상태',
        };
        return labels[value] || value.replace(/_/g, ' ');
    }
})();
