(function() {
    'use strict';

    function setActiveSidePanelTab({ sidePanelTabs, sectionId }) {
        sidePanelTabs.forEach((button) => {
            const isActive = button.dataset.panelTarget === sectionId;
            button.classList.toggle('is-active', isActive);
            button.setAttribute('aria-pressed', isActive ? 'true' : 'false');
        });
    }

    function focusSidePanelSection({
        sidePanel,
        sidePanelTabs,
        sectionId,
        onSetActiveSection,
    }) {
        if (!sidePanel || !sectionId) return;
        const section = document.getElementById(sectionId);
        if (!section) return;
        const header = section.querySelector('.panel-header');
        if (header && section.classList.contains('is-collapsed')) {
            header.click();
        } else {
            onSetActiveSection?.(sectionId);
            setActiveSidePanelTab({ sidePanelTabs, sectionId });
        }
        requestAnimationFrame(() => {
            section.scrollIntoView({
                behavior: 'smooth',
                block: window.innerWidth <= 1360 ? 'start' : 'nearest',
            });
        });
    }

    function syncChatFabVisibility({ chatFab, chatSection }) {
        if (!chatFab || !chatSection) return;
        const isMobile = window.innerWidth <= 768;
        if (!isMobile) {
            chatFab.classList.remove('hidden');
            return;
        }
        const chatVisible = !chatSection.classList.contains('is-collapsed') && !chatSection.classList.contains('is-hidden');
        chatFab.classList.toggle('hidden', chatVisible);
    }

    function setupChatToggle({
        chatFab,
        chatSection,
        chatCloseBtn,
        onSetActiveSection,
        onSyncVisibility,
        onOpen,
    }) {
        if (!chatFab || !chatSection) return;
        chatSection.classList.add('is-collapsed');
        onSyncVisibility?.();
        chatFab.addEventListener('click', () => {
            Utils?.Sounds?.unlock?.();
            const willOpen = chatSection.classList.contains('is-collapsed');
            chatSection.classList.toggle('is-collapsed');
            chatSection.classList.toggle('is-floating', willOpen);
            chatFab.classList.toggle('is-active', willOpen);
            onSyncVisibility?.();
            if (willOpen) {
                onSetActiveSection?.('game-chat-section');
                onOpen?.();
            }
        });
        chatCloseBtn?.addEventListener('click', () => {
            chatSection.classList.add('is-collapsed');
            chatSection.classList.remove('is-floating');
            chatFab.classList.remove('is-active');
            onSetActiveSection?.('game-moves-section');
            onSyncVisibility?.();
        });
    }

    function setupSidePanelAccordion({
        sidePanel,
        sidePanelTabs,
        getActiveSectionId,
        setActiveSectionId,
        storageKey,
        defaultStates,
        isNarrow,
        onSyncVisibility,
    }) {
        if (!sidePanel) return;
        const sections = Array.from(sidePanel.querySelectorAll('.panel-section'));
        if (!sections.length) return;

        const getSavedStates = () => Utils.Storage.get(storageKey, { ...defaultStates }) || { ...defaultStates };
        const saveStates = (states) => Utils.Storage.set(storageKey, states);

        const setCollapsed = (section, collapsed) => {
            const header = section.querySelector('.panel-header');
            section.classList.toggle('is-collapsed', collapsed);
            section.dataset.collapsed = collapsed ? 'true' : 'false';
            if (header) {
                header.dataset.accordionLabel = collapsed ? '닫힘' : '열림';
                header.classList.add('is-clickable');
            }
        };

        const applyLayout = () => {
            const narrow = isNarrow();
            const states = getSavedStates();
            sidePanel.classList.add('is-accordion');
            sections.forEach((section) => {
                const header = section.querySelector('.panel-header');
                if (!header) return;
                const collapsed = Boolean(states[section.id]);
                setCollapsed(section, collapsed);
                header.dataset.accordionMode = narrow ? 'single' : 'multi';
            });
            if (states[getActiveSectionId()]) {
                setActiveSectionId(narrow ? 'game-actions' : 'game-moves-section');
            }
            setActiveSidePanelTab({ sidePanelTabs, sectionId: getActiveSectionId() });
            onSyncVisibility?.();
        };

        sections.forEach((section) => {
            const header = section.querySelector('.panel-header');
            if (!header || header.dataset.accordionBound === '1') return;
            header.dataset.accordionBound = '1';
            header.addEventListener('click', () => {
                const states = getSavedStates();
                const nextCollapsed = !section.classList.contains('is-collapsed');
                if (isNarrow() && !nextCollapsed) {
                    sections.forEach((target) => {
                        if (target.id === section.id) return;
                        states[target.id] = true;
                        setCollapsed(target, true);
                    });
                }
                states[section.id] = nextCollapsed;
                setCollapsed(section, nextCollapsed);
                saveStates(states);
                if (!nextCollapsed) {
                    setActiveSectionId(section.id);
                    setActiveSidePanelTab({ sidePanelTabs, sectionId: section.id });
                }
                onSyncVisibility?.();
            });
        });

        applyLayout();
        window.addEventListener('resize', Utils.debounce(applyLayout, 120));
    }

    window.GamePanelUI = {
        setActiveSidePanelTab,
        focusSidePanelSection,
        syncChatFabVisibility,
        setupChatToggle,
        setupSidePanelAccordion,
    };
})();
