(function() {
    'use strict';

    const statsEl = document.getElementById('admin-stats');
    const userTable = document.getElementById('user-table');
    const reportTable = document.getElementById('report-table');
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
        setupActions();
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
        } catch (error) {
            Toast.error('통계를 불러올 수 없습니다.');
        }
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
})();
