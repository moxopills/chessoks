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

    function getPreviewPieceSkinVariant(pieceClass) {
        const cls = String(pieceClass || 'skin-piece-classic');
        if (cls.includes('pixel')) return 'pixel';
        if (cls.includes('modern')) return 'modern';
        if (cls.includes('3d')) return '3d';
        if (cls.includes('glass')) return 'glass';
        if (cls.includes('rune')) return 'rune';
        return 'classic';
    }

    function getPreviewShapeSet(variant) {
        const classic = {
            p: `<circle cx="32" cy="15.5" r="5.8"></circle><rect x="29.6" y="21.2" width="4.8" height="5.2" rx="2"></rect><path d="M25.2 33.8c0-5.8 3.1-9.8 6.8-9.8s6.8 4 6.8 9.8v2.8H25.2z"></path><rect x="22.2" y="36.4" width="19.6" height="8.7" rx="4.2"></rect><rect x="18.2" y="46.8" width="27.6" height="2.8" rx="1.4"></rect><rect x="16.8" y="49.8" width="30.4" height="3.4" rx="1.7"></rect>`,
            r: `<rect x="17" y="12.4" width="6" height="8" rx="1"></rect><rect x="29" y="12.4" width="6" height="8" rx="1"></rect><rect x="41" y="12.4" width="6" height="8" rx="1"></rect><rect x="17" y="20.6" width="30" height="5.2" rx="1.8"></rect><rect x="21.4" y="26.8" width="21.2" height="17.8" rx="2.2"></rect><rect x="18.2" y="46.8" width="27.6" height="2.8" rx="1.4"></rect><rect x="16.8" y="49.8" width="30.4" height="3.4" rx="1.7"></rect>`,
            n: `<path d="M16.8 49.8h30.4v3.4H16.8z"></path><path d="M18.2 46.8h27.6v2.8H18.2z"></path><path d="M21.2 44.2c5.8-.6 9.9-2.3 12.6-5.3 2.3-2.5 3.6-6 3.8-10.2-2.6 1-5 .8-6.9-.8-.1-4.7 2.9-8.8 8.6-12.2l7.3 6.6-2.2 6.5c2.7 1.3 4.2 3.8 4.7 7.4-1 5.4-5.8 7.9-14.5 8z"></path><circle cx="37.2" cy="23.4" r="1.8" class="piece-eye"></circle>`,
            b: `<ellipse cx="32" cy="16.2" rx="6.2" ry="8.2"></ellipse><path d="M30.3 13.2h3.4l-1.8 6.3h-1.2z"></path><rect x="30.9" y="22.6" width="2.2" height="4.4" rx="1.1"></rect><path d="M25.3 33.8c0-6.6 3.1-10.7 6.7-10.7s6.7 4.1 6.7 10.7v2.9H25.3z"></path><rect x="22.2" y="36.2" width="19.6" height="8.8" rx="4.2"></rect><rect x="18.2" y="46.8" width="27.6" height="2.8" rx="1.4"></rect><rect x="16.8" y="49.8" width="30.4" height="3.4" rx="1.7"></rect>`,
            q: `<circle cx="19.4" cy="16.2" r="2.5"></circle><circle cx="27.3" cy="13.2" r="2.5"></circle><circle cx="36.7" cy="13.2" r="2.5"></circle><circle cx="44.6" cy="16.2" r="2.5"></circle><path d="M19.4 21.8l5.1 13.7h15l5.1-13.7-6.5 4.7-6.1-6.4-6.1 6.4z"></path><rect x="22.2" y="36.2" width="19.6" height="8.7" rx="4.1"></rect><rect x="18.2" y="46.8" width="27.6" height="2.8" rx="1.4"></rect><rect x="16.8" y="49.8" width="30.4" height="3.4" rx="1.7"></rect>`,
            k: `<rect x="30.9" y="8.2" width="2.2" height="8.8" rx="1"></rect><rect x="26.6" y="11.5" width="10.8" height="3" rx="1.2"></rect><path d="M25.1 33.7c0-7.6 3.1-11.6 6.9-11.6s6.9 4 6.9 11.6v2.8H25.1z"></path><rect x="22.2" y="36.1" width="19.6" height="8.9" rx="4.2"></rect><rect x="18.2" y="46.8" width="27.6" height="2.8" rx="1.4"></rect><rect x="16.8" y="49.8" width="30.4" height="3.4" rx="1.7"></rect>`,
        };
        const pixel = {
            p: `<rect x="28" y="12" width="8" height="8"></rect><rect x="27" y="20" width="10" height="5"></rect><rect x="25" y="25" width="14" height="9"></rect><rect x="22" y="34" width="20" height="10"></rect><rect x="18" y="47" width="28" height="3"></rect><rect x="17" y="50" width="30" height="3"></rect>`,
            r: `<rect x="17" y="13" width="6" height="8"></rect><rect x="29" y="13" width="6" height="8"></rect><rect x="41" y="13" width="6" height="8"></rect><rect x="17" y="21" width="30" height="5"></rect><rect x="22" y="27" width="20" height="17"></rect><rect x="18" y="47" width="28" height="3"></rect><rect x="17" y="50" width="30" height="3"></rect>`,
            n: `<path d="M17 50h30v3H17zM18 47h28v3H18zM22 44h14l8-8-2-7 2-6-4-4c-8 1-13 6-14 13l2 2-6 5z"></path><rect x="36" y="23" width="3" height="3" class="piece-eye"></rect>`,
            b: `<rect x="28" y="10" width="8" height="8"></rect><rect x="31" y="18" width="2" height="5"></rect><rect x="25" y="23" width="14" height="11"></rect><rect x="22" y="34" width="20" height="10"></rect><rect x="18" y="47" width="28" height="3"></rect><rect x="17" y="50" width="30" height="3"></rect>`,
            q: `<rect x="19" y="15" width="4" height="4"></rect><rect x="27" y="12" width="4" height="4"></rect><rect x="33" y="12" width="4" height="4"></rect><rect x="41" y="15" width="4" height="4"></rect><path d="M20 21h24l-4 14H24z"></path><rect x="22" y="36" width="20" height="8"></rect><rect x="18" y="47" width="28" height="3"></rect><rect x="17" y="50" width="30" height="3"></rect>`,
            k: `<rect x="31" y="8" width="2" height="8"></rect><rect x="27" y="11" width="10" height="3"></rect><rect x="25" y="22" width="14" height="11"></rect><rect x="22" y="34" width="20" height="10"></rect><rect x="18" y="47" width="28" height="3"></rect><rect x="17" y="50" width="30" height="3"></rect>`,
        };
        const modern = {
            p: `<circle cx="32" cy="14.8" r="5.1"></circle><rect x="29.8" y="19.6" width="4.4" height="4.8" rx="2"></rect><path d="M26.1 33c0-5.3 2.8-8.9 5.9-8.9s5.9 3.6 5.9 8.9v3.2H26.1z"></path><rect x="22.9" y="36.1" width="18.2" height="8.5" rx="4.4"></rect><rect x="18.7" y="47.1" width="26.6" height="4" rx="2"></rect>`,
            r: `<rect x="19" y="14.1" width="5.1" height="6.2" rx="1.4"></rect><rect x="29.5" y="14.1" width="5.1" height="6.2" rx="1.4"></rect><rect x="39.9" y="14.1" width="5.1" height="6.2" rx="1.4"></rect><rect x="18.9" y="21" width="26.2" height="4.2" rx="2.1"></rect><rect x="23.1" y="27" width="17.8" height="17.4" rx="4.2"></rect><rect x="18.7" y="47.1" width="26.6" height="4" rx="2"></rect>`,
            n: `<path d="M18.7 47.1h26.6v4H18.7z"></path><path d="M23.1 44.4c7.1-.8 11-4.3 12.2-10.1-2.7.8-5 .6-6.8-.8.7-6 5.4-10.8 12.6-12.3l3.5 3.2-1.6 5.1c2.5 1.2 4.1 3.6 4.5 6.9-1.1 5-5.6 7.6-13.7 8z"></path><circle cx="36.1" cy="24.5" r="1.7" class="piece-eye"></circle>`,
            b: `<ellipse cx="32" cy="15.4" rx="5.7" ry="7.1"></ellipse><path d="M30.3 14.3h3.4l-1.5 4.3h-1z"></path><path d="M26.2 33.1c0-6.2 2.8-10 5.8-10s5.8 3.8 5.8 10v3.2H26.2z"></path><rect x="22.9" y="36.1" width="18.2" height="8.5" rx="4.4"></rect><rect x="18.7" y="47.1" width="26.6" height="4" rx="2"></rect>`,
            q: `<circle cx="19.8" cy="16.2" r="2.2"></circle><circle cx="27.9" cy="13.5" r="2.2"></circle><circle cx="36.1" cy="13.5" r="2.2"></circle><circle cx="44.2" cy="16.2" r="2.2"></circle><path d="M20.5 22.2l4.1 12.8h14.8l4.1-12.8-5.8 4.2-5.7-5.8-5.7 5.8z"></path><rect x="22.9" y="36.1" width="18.2" height="8.5" rx="4.4"></rect><rect x="18.7" y="47.1" width="26.6" height="4" rx="2"></rect>`,
            k: `<rect x="31" y="8.9" width="2" height="7.9" rx="1"></rect><rect x="27" y="11.9" width="10" height="2.8" rx="1.3"></rect><path d="M26.2 32.8c0-6.9 2.8-10.9 5.8-10.9s5.8 4 5.8 10.9v3.3H26.2z"></path><rect x="22.9" y="36.1" width="18.2" height="8.5" rx="4.4"></rect><rect x="18.7" y="47.1" width="26.6" height="4" rx="2"></rect>`,
        };
        const rune = {
            p: `<path d="M32 9.8l4.7 5.7-4.7 6.6-4.7-6.6z"></path><rect x="29.8" y="22.1" width="4.4" height="4.8" rx="1.1"></rect><path d="M25 33.6l7-7 7 7v11.2H25z"></path><rect x="18.2" y="46.8" width="27.6" height="2.8" rx="1.2"></rect><rect x="16.8" y="49.8" width="30.4" height="3.4" rx="1.5"></rect>`,
            r: `<path d="M17.4 13h5.8v7.4h-5.8zM29.1 13h5.8v7.4h-5.8zM40.8 13h5.8v7.4h-5.8z"></path><path d="M17.4 21.1h29.2v5H17.4z"></path><path d="M21.8 27.4h20.4v17.1H21.8z"></path><rect x="18.2" y="46.8" width="27.6" height="2.8" rx="1.2"></rect><rect x="16.8" y="49.8" width="30.4" height="3.4" rx="1.5"></rect>`,
            n: `<path d="M16.8 49.8h30.4v3.4H16.8z"></path><path d="M18.2 46.8h27.6v2.8H18.2z"></path><path d="M21.5 44l13-1.1 7.3-6.8-2.6-6.5 3.5-6.7-2.4-3c-7.8 1.3-12.5 5.9-14.3 12.7l1.8 2.2-6.3 5z"></path><circle cx="36.1" cy="24.2" r="1.7" class="piece-eye"></circle>`,
            b: `<path d="M32 9.2l5.6 7.1-5.6 8.1-5.6-8.1z"></path><rect x="30.8" y="23.6" width="2.4" height="4.2" rx="1"></rect><path d="M24.9 33.8l7.1-8.4 7.1 8.4v10.9H24.9z"></path><rect x="18.2" y="46.8" width="27.6" height="2.8" rx="1.2"></rect><rect x="16.8" y="49.8" width="30.4" height="3.4" rx="1.5"></rect>`,
            q: `<path d="M19.4 16.4l3.3-3.3 3.3 3.3-3.3 4.1zM27.8 13.3l3.3-3.3 3.3 3.3-3.3 4.1zM36.2 13.3l3.3-3.3 3.3 3.3-3.3 4.1zM44.6 16.4l3.3-3.3 3.3 3.3-3.3 4.1z"></path><path d="M19.6 22.9l5.2 13h14.4l5.2-13-6.4 4-6-6.4-6 6.4z"></path><rect x="22.2" y="36.3" width="19.6" height="8.6" rx="3.8"></rect><rect x="18.2" y="46.8" width="27.6" height="2.8" rx="1.2"></rect><rect x="16.8" y="49.8" width="30.4" height="3.4" rx="1.5"></rect>`,
            k: `<path d="M30.9 8.4h2.2v8.6h-2.2zM26.5 11.8h11v2.8h-11z"></path><path d="M24.9 33.8l7.1-9.3 7.1 9.3v11.2H24.9z"></path><rect x="22.2" y="36.2" width="19.6" height="8.8" rx="3.9"></rect><rect x="18.2" y="46.8" width="27.6" height="2.8" rx="1.2"></rect><rect x="16.8" y="49.8" width="30.4" height="3.4" rx="1.5"></rect>`,
        };
        const map = { classic, pixel, modern, rune };
        return map[variant] || classic;
    }

    function getPreviewPieceSvgMarkup(piece, pieceClass) {
        const variant = getPreviewPieceSkinVariant(pieceClass);
        const type = String(piece || '').toLowerCase();
        const shapeSet = getPreviewShapeSet(variant === '3d' ? 'classic' : (variant === 'glass' ? 'modern' : variant));
        const body = shapeSet[type] || shapeSet.p;
        const shadowLayer = variant === '3d' ? `<g class="piece-shadow" transform="translate(1.4,1.4)">${body}</g>` : '';
        const accentLayer = variant === 'glass'
            ? `<g class="piece-accent"><ellipse cx="28" cy="22" rx="8.5" ry="5"></ellipse><path d="M20 32h24"></path></g>`
            : '';
        return `
            <svg class="mini-piece-svg variant-${variant}" viewBox="0 0 64 64" aria-hidden="true" focusable="false">
                ${shadowLayer}
                <g class="piece-body">${body}</g>
                ${accentLayer}
            </svg>
        `;
    }

    function renderPreviewPieces(pieceClass) {
        if (!previewBoard) return;
        previewBoard.querySelectorAll('.mini-piece[data-piece]').forEach((el) => {
            el.innerHTML = getPreviewPieceSvgMarkup(el.dataset.piece, pieceClass);
        });
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
        renderPreviewPieces(pieceClass);
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
