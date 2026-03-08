(function() {
    'use strict';

    const boardSkinSelect = document.getElementById('customize-board-skin');
    const pieceSkinSelect = document.getElementById('customize-piece-skin');
    const nicknameColorSelect = document.getElementById('customize-nickname-color');
    const profileBorderSelect = document.getElementById('customize-profile-border');
    const stylePointsText = document.getElementById('customize-style-points-text');
    const previewAvatar = document.getElementById('customize-preview-avatar');
    const previewNickname = document.getElementById('customize-preview-nickname');
    const previewBoard = document.getElementById('customize-skin-preview-board');
    const purchaseBtn = document.getElementById('customize-purchase');
    const saveBtn = document.getElementById('customize-save');

    let me = null;
    let skinCatalog = null;

    function extractErrorMessage(error, fallback) {
        if (error?.data?.message) return error.data.message;
        const data = error?.data;
        if (data && typeof data === 'object') {
            const firstField = Object.keys(data)[0];
            const value = data[firstField];
            if (Array.isArray(value) && value.length > 0) {
                return String(value[0]);
            }
            if (typeof value === 'string' && value.trim()) {
                return value;
            }
        }
        if (error?.message) return error.message;
        return fallback;
    }

    function normalizeNicknameColorKey(key) {
        const value = (key || '').trim();
        const map = {
            mint_color: 'mint',
            mintgreen: 'mint',
            sunset_color: 'sunset',
            gold_color: 'gold',
        };
        return map[value] || value;
    }

    function normalizeProfileBorderKey(key) {
        const value = (key || '').trim();
        const map = {
            mint: 'mint_ring',
            mint_border: 'mint_ring',
            royal: 'royal_ring',
            royal_border: 'royal_ring',
            champion: 'champion_ring',
            champion_border: 'champion_ring',
        };
        return map[value] || value;
    }

    init();

    async function init() {
        try {
            me = await API.get('/accounts/me/');
            if (me?.is_guest) {
                Toast.error('게스트 계정은 커스터마이징을 사용할 수 없습니다.');
                window.location.href = '/';
                return;
            }
            await loadSkinCatalog();
            populateCustomization(me.stats || {});
            bindEvents();
        } catch (error) {
            Toast.error('로그인 후 이용 가능합니다.');
            window.location.href = '/login/';
        }
    }

    function bindEvents() {
        boardSkinSelect?.addEventListener('change', renderPreview);
        pieceSkinSelect?.addEventListener('change', renderPreview);
        nicknameColorSelect?.addEventListener('change', renderPreview);
        profileBorderSelect?.addEventListener('change', renderPreview);
        purchaseBtn?.addEventListener('click', handlePurchase);
        saveBtn?.addEventListener('click', handleApply);
    }

    async function loadSkinCatalog() {
        const preferredBoard = parseInt(boardSkinSelect?.value || '0', 10);
        const preferredPiece = parseInt(pieceSkinSelect?.value || '0', 10);
        const data = await API.get('/accounts/skins/me/');
        skinCatalog = data;
        stylePointsText.textContent = `보유 포인트: ${data?.points ?? 0}P`;
        fillSkinSelect(boardSkinSelect, data?.board || [], preferredBoard);
        fillSkinSelect(pieceSkinSelect, data?.pieces || [], preferredPiece);
    }

    function fillSkinSelect(selectEl, skins, preferredId = 0) {
        if (!selectEl) return;
        const options = skins.map((skin) => {
            const state = skin.selected ? '착용중' : (skin.owned || skin.is_default ? '보유' : `${skin.price}P`);
            const lock = skin.owned || skin.is_default ? '' : ' [구매]';
            return `<option value="${skin.id}" ${skin.selected ? 'selected' : ''}>${Utils.escapeHtml(skin.name)} · ${state}${lock}</option>`;
        });
        selectEl.innerHTML = options.join('');
        if (preferredId && skins.some((skin) => skin.id === preferredId)) {
            selectEl.value = String(preferredId);
        }
    }

    function fillSelect(selectEl, options, selectedKey) {
        if (!selectEl) return;
        selectEl.innerHTML = options
            .map((item) => {
                const owned = item.owned || item.cost === 0;
                const state = owned ? '보유중' : `${item.cost}P`;
                return `<option value="${item.key}">${item.label} · ${state}</option>`;
            })
            .join('');
        selectEl.value = selectedKey || '';
    }

    function populateCustomization(stats) {
        const nicknameColor = normalizeNicknameColorKey(stats.nickname_color || '');
        const profileBorder = normalizeProfileBorderKey(stats.profile_border || '');
        fillSelect(
            nicknameColorSelect,
            stats.unlocked_nickname_colors || [{ key: '', label: '기본', cost: 0 }],
            nicknameColor
        );
        fillSelect(
            profileBorderSelect,
            stats.unlocked_profile_borders || [{ key: '', label: '기본', cost: 0 }],
            profileBorder
        );
        stylePointsText.textContent = `보유 포인트: ${stats.style_points ?? skinCatalog?.points ?? 0}P`;
        renderPreview();
    }

    function getSkinCssClassById(list, skinId, fallback) {
        const selected = (list || []).find((item) => item.id === skinId);
        return selected?.css_class || fallback;
    }

    function renderPreview() {
        const nickname = me?.nickname || '내 닉네임';
        const avatarUrl = me?.avatar_url || '';
        const color = Utils.getNicknameColorValue(nicknameColorSelect?.value || '');
        const ring = Utils.getProfileBorderValue(profileBorderSelect?.value || '');

        previewNickname.textContent = nickname;
        previewNickname.style.color = color;
        previewAvatar.style.boxShadow = ring;
        previewAvatar.innerHTML = avatarUrl
            ? `<img src="${Utils.escapeHtml(avatarUrl)}" alt="${Utils.escapeHtml(nickname)}">`
            : '👤';

        const boardSkinId = parseInt(boardSkinSelect?.value || '0', 10);
        const pieceSkinId = parseInt(pieceSkinSelect?.value || '0', 10);
        const boardClass = getSkinCssClassById(skinCatalog?.board || [], boardSkinId, 'skin-board-classic');
        const pieceClass = getSkinCssClassById(skinCatalog?.pieces || [], pieceSkinId, 'skin-piece-classic');
        previewBoard.className = `customize-skin-preview-board ${boardClass} ${pieceClass}`;
    }

    async function purchaseSkinIfNeeded(skinId) {
        if (!skinId || !skinCatalog) return 0;
        const allSkins = [...(skinCatalog.board || []), ...(skinCatalog.pieces || [])];
        const target = allSkins.find((skin) => skin.id === skinId);
        if (!target || target.owned || target.is_default) return 0;
        try {
            await API.post(`/accounts/skins/${skinId}/purchase/`);
            return 1;
        } catch (error) {
            const msg = error?.data?.message || '';
            if (msg.includes('이미 보유한 스킨')) return 0;
            throw error;
        }
    }

    async function ensureSkinSelected(skinId) {
        if (!skinId || !skinCatalog) return;
        const allSkins = [...(skinCatalog.board || []), ...(skinCatalog.pieces || [])];
        const target = allSkins.find((skin) => skin.id === skinId);
        if (!target) return;
        if (!target.owned && !target.is_default) {
            throw new Error('선택한 스킨이 미구매 상태입니다. 먼저 구매하기를 눌러주세요.');
        }
        await API.post(`/accounts/skins/${skinId}/select/`, {});
    }

    async function handlePurchase() {
        try {
            const boardSkinId = parseInt(boardSkinSelect?.value || '0', 10);
            const pieceSkinId = parseInt(pieceSkinSelect?.value || '0', 10);
            let purchased = 0;
            purchased += await purchaseSkinIfNeeded(boardSkinId);
            purchased += await purchaseSkinIfNeeded(pieceSkinId);
            await loadSkinCatalog();
            renderPreview();
            if (purchased > 0) {
                Toast.success(`선택한 스킨 ${purchased}개를 구매했습니다. 이제 적용하기를 눌러주세요.`);
            } else {
                Toast.info('이미 보유 중인 스킨입니다.');
            }
        } catch (error) {
            Toast.error(extractErrorMessage(error, '스킨 구매에 실패했습니다.'));
        }
    }

    async function handleApply() {
        try {
            const boardSkinId = parseInt(boardSkinSelect?.value || '0', 10);
            const pieceSkinId = parseInt(pieceSkinSelect?.value || '0', 10);
            await ensureSkinSelected(boardSkinId);
            await ensureSkinSelected(pieceSkinId);
            const payload = {
                nickname_color: nicknameColorSelect?.value || '',
                profile_border: profileBorderSelect?.value || '',
            };
            await API.patch('/accounts/profile/', payload);
            // profile/stats 응답 캐시/관계 객체 지연 반영 이슈를 피하기 위해 최신 me를 재조회
            me = await API.get('/accounts/me/');
            await loadSkinCatalog();
            populateCustomization(me.stats || {});
            window.dispatchEvent(new CustomEvent('user:updated', { detail: { user: me } }));
            Toast.success('커스터마이징이 저장되었습니다.');
        } catch (error) {
            Toast.error(extractErrorMessage(error, '커스터마이징 저장에 실패했습니다.'));
        }
    }
})();
