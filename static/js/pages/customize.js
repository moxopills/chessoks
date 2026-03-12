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
    const previewBoardTitle = document.getElementById('customize-board-title');
    const previewBoardDesc = document.getElementById('customize-board-desc');
    const previewPieceTitle = document.getElementById('customize-piece-title');
    const previewPieceDesc = document.getElementById('customize-piece-desc');
    const purchaseBtn = document.getElementById('customize-purchase');
    const saveBtn = document.getElementById('customize-save');

    let me = null;
    let skinCatalog = null;
    let statsSnapshot = null;

    const SKIN_META = {
        board: {
            'skin-board-classic': { name: '클래식', desc: '균형 잡힌 기본 체스 보드' },
            'skin-board-wood': { name: '우드 크래프트', desc: '나무 질감이 강조된 따뜻한 보드' },
            'skin-board-dark': { name: '다크 그리드', desc: '차분한 고대비 톤의 집중형 보드' },
            'skin-board-neon': { name: '네온 아레나', desc: '사이버 감성의 발광 하이라이트 보드' },
            'skin-board-marble': { name: '마블 클래식', desc: '대리석 질감의 고급 테이블 스타일' },
            'skin-board-obsidian': { name: '옵시디언', desc: '흑요석 계열의 묵직한 어둠 테마' },
            'skin-board-sakura': { name: '사쿠라', desc: '벚꽃빛 파스텔 톤의 부드러운 보드' },
        },
        piece: {
            'skin-piece-classic': { name: '클래식 아케이드', desc: '선명한 색 구분과 경쾌한 대비' },
            'skin-piece-pixel': { name: '픽셀 레트로', desc: '8비트 감성의 원색 픽셀 스타일' },
            'skin-piece-modern': { name: '모던 미니멀', desc: '절제된 톤과 깔끔한 윤곽 라인' },
            'skin-piece-3d': { name: '크라운 3D', desc: '입체광과 깊은 그림자의 메탈 질감' },
            'skin-piece-glass': { name: '크리스탈 글라스', desc: '반투명 하이라이트의 유리 질감' },
            'skin-piece-rune': { name: '아케인 룬', desc: '신비로운 룬 감성의 고대 스타일' },
        },
    };

    function showStatus(message, type = 'info', duration = 1800) {
        if (Utils?.showStatusBadge) {
            const mapped = type === 'info' ? 'waiting' : type;
            Utils.showStatusBadge(message, mapped, duration);
        }
        if (window.StatusBadge) {
            window.StatusBadge.show(message, { type, duration });
            return;
        }
        if (type === 'success') return Toast.success(message);
        if (type === 'error') return Toast.error(message);
        return Toast.info(message);
    }

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
                showStatus('게스트 계정은 커스터마이징을 사용할 수 없습니다.', 'error');
                window.location.href = '/';
                return;
            }
            await loadSkinCatalog();
            populateCustomization(me.stats || {});
            bindEvents();
        } catch (error) {
            showStatus('로그인 후 이용 가능합니다.', 'error');
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
        const skinType = selectEl.id === 'customize-board-skin' ? 'board' : 'piece';
        const options = skins.map((skin) => {
            const state = skin.selected
                ? '착용중'
                : (skin.owned || skin.is_default ? '보유중' : `구매 필요 ${skin.price}P`);
            const lock = skin.owned || skin.is_default ? '' : ' [구매 필요]';
            const mappedName = SKIN_META[skinType]?.[skin.css_class]?.name || skin.name;
            return `<option value="${skin.id}" ${skin.selected ? 'selected' : ''}>${Utils.escapeHtml(mappedName)} · ${state}${lock}</option>`;
        });
        selectEl.innerHTML = options.join('');
        if (preferredId && skins.some((skin) => skin.id === preferredId)) {
            selectEl.value = String(preferredId);
        }
    }

    function fillSelect(selectEl, options, selectedKey) {
        if (!selectEl) return;
        const selected = (selectedKey || '').trim();
        selectEl.innerHTML = options
            .map((item) => {
                const key = (item.key || '').trim();
                const owned = item.owned || item.cost === 0 || key === selected;
                const state = key === selected
                    ? '착용중'
                    : (owned ? '보유중' : `구매 필요 ${item.cost}P`);
                return `<option value="${item.key}">${item.label} · ${state}</option>`;
            })
            .join('');
        selectEl.value = selectedKey || '';
    }

    function populateCustomization(stats) {
        statsSnapshot = stats || {};
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
        updateActionState();
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
        Utils.setAvatar(previewAvatar, {
            url: avatarUrl,
            alt: nickname,
            placeholder: '👤',
            placeholderClass: 'customize-avatar-placeholder',
        });

        const boardSkinId = parseInt(boardSkinSelect?.value || '0', 10);
        const pieceSkinId = parseInt(pieceSkinSelect?.value || '0', 10);
        const boardSkin = getSelectedSkin(boardSkinId);
        const pieceSkin = getSelectedSkin(pieceSkinId);
        const boardClass = getSkinCssClassById(skinCatalog?.board || [], boardSkinId, 'skin-board-classic');
        const pieceClass = getSkinCssClassById(skinCatalog?.pieces || [], pieceSkinId, 'skin-piece-classic');
        previewBoard.className = `customize-skin-preview-board ${boardClass} ${pieceClass}`;
        const boardMeta = SKIN_META.board[boardClass] || { name: boardSkin?.name || '클래식', desc: '보드 스타일' };
        const pieceMeta = SKIN_META.piece[pieceClass] || { name: pieceSkin?.name || '클래식 아케이드', desc: '기물 스타일' };
        if (previewBoardTitle) previewBoardTitle.textContent = `보드: ${boardMeta.name}`;
        if (previewBoardDesc) previewBoardDesc.textContent = boardMeta.desc;
        if (previewPieceTitle) previewPieceTitle.textContent = `기물: ${pieceMeta.name}`;
        if (previewPieceDesc) previewPieceDesc.textContent = pieceMeta.desc;
        updateActionState();
    }

    function getSelectedSkin(skinId) {
        const allSkins = [...(skinCatalog?.board || []), ...(skinCatalog?.pieces || [])];
        return allSkins.find((skin) => skin.id === skinId) || null;
    }

    function updateActionState() {
        const boardSkinId = parseInt(boardSkinSelect?.value || '0', 10);
        const pieceSkinId = parseInt(pieceSkinSelect?.value || '0', 10);
        const boardSkin = getSelectedSkin(boardSkinId);
        const pieceSkin = getSelectedSkin(pieceSkinId);
        const needPurchase = [boardSkin, pieceSkin].some((skin) => skin && !skin.owned && !skin.is_default);
        if (purchaseBtn) {
            purchaseBtn.disabled = !needPurchase;
            purchaseBtn.textContent = needPurchase ? '구매하기' : '구매 완료';
        }
        if (saveBtn) {
            saveBtn.disabled = false;
        }
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
            populateCustomization(me?.stats || statsSnapshot || {});
            if (purchased > 0) {
                showStatus(`선택한 스킨 ${purchased}개를 구매했습니다. 이제 적용하기를 눌러주세요.`, 'success');
            } else {
                showStatus('이미 보유 중인 스킨입니다.', 'info');
            }
        } catch (error) {
            showStatus(extractErrorMessage(error, '스킨 구매에 실패했습니다.'), 'error');
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
            showStatus('커스터마이징이 저장되었습니다.', 'success');
        } catch (error) {
            showStatus(extractErrorMessage(error, '커스터마이징 저장에 실패했습니다.'), 'error');
        }
    }
})();
