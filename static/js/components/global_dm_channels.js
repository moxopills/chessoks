(function() {
    'use strict';

    const SUMMARY_CACHE_TTL = 30000;

    function buildThreadsSignature(threads, unreadMap) {
        return threads.map((thread) => {
            const userId = thread.other_user?.id || '';
            const unread = unreadMap[userId] || 0;
            return [
                userId,
                thread.last_message_at || '',
                thread.last_message || '',
                unread,
            ].join(':');
        }).join('|');
    }

    function buildGroupPreview(messages) {
        const latest = messages?.[0];
        if (!latest?.content) return '';
        const nickname = latest.user?.nickname || '알 수 없음';
        return `최근 · ${nickname}: ${latest.content}`;
    }

    async function loadGroupSummary({ ensureCurrentUser, cache, loadedAt, endpoint, force = false }) {
        await ensureCurrentUser?.();
        const now = Date.now();
        if (!force && cache && now - loadedAt < SUMMARY_CACHE_TTL) {
            return { summary: cache, loadedAt };
        }
        const summary = await API.get(endpoint).catch(() => null);
        return { summary, loadedAt: now };
    }

    async function loadTargetInfo({ userId, roomTitle, roomSubtitle }) {
        try {
            const data = await API.get(`/accounts/users/${userId}/profile/`);
            const nickname = data?.nickname || data?.user?.nickname || '상대';
            const tier = data.stats?.rank_tier ?? data.user?.stats?.rank_tier ?? '-';
            roomTitle.textContent = nickname;
            roomSubtitle.textContent = tier;
        } catch {
            // ignore
        }
    }

    async function loadGuildMessages({
        ensureCurrentUser,
        summary,
        invalidate,
        guildTitle,
        guildSubtitle,
        guildInputEl,
        guildMessagesEl,
        currentUser,
        forceScroll = false,
        messageRenderState,
    }) {
        await ensureCurrentUser?.();
        if (!summary?.id) {
            invalidate?.();
            window.GlobalDMUI?.setChannelEmpty(
                guildMessagesEl,
                guildTitle,
                guildSubtitle,
                guildInputEl,
                summary?.message || '가입 중인 길드가 없습니다.',
                '길드 채팅'
            );
            return { currentGuildId: null };
        }
        const currentGuildId = summary.id;
        guildTitle.textContent = summary.name || '길드 채팅';
        guildSubtitle.textContent = `길드장 ${summary.owner?.nickname || '-'} · 멤버 ${summary.member_count || 0}명`;
        window.GlobalDMUI?.setChannelReady(guildInputEl, '길드 채팅 입력...');

        const data = await API.get(`/community/guilds/${currentGuildId}/chat/`).catch((error) => {
            if (error?.status === 403 || error?.status === 404) {
                invalidate?.();
            }
            return { results: [] };
        });

        const preview = buildGroupPreview(data.results || []);
        if (preview) {
            guildSubtitle.textContent = preview;
        }
        window.GlobalDMUI?.syncMessageList(
            guildMessagesEl,
            data.results || [],
            (item) => window.GlobalDMUI.renderGroupMessageItem(item, currentUser),
            forceScroll,
            '아직 채팅이 없습니다.',
            messageRenderState
        );
        return { currentGuildId };
    }

    async function loadPartyMessages({
        ensureCurrentUser,
        summary,
        invalidate,
        partyTitle,
        partySubtitle,
        partyInputEl,
        partyMessagesEl,
        currentUser,
        forceScroll = false,
        messageRenderState,
    }) {
        await ensureCurrentUser?.();
        if (!summary?.party_id) {
            invalidate?.();
            window.GlobalDMUI?.setChannelEmpty(
                partyMessagesEl,
                partyTitle,
                partySubtitle,
                partyInputEl,
                summary?.message || '참가 중인 파티가 없습니다.',
                '파티 채팅'
            );
            return { currentPartyId: null };
        }
        const currentPartyId = summary.party_id;
        partyTitle.textContent = summary.title || '파티 채팅';
        partySubtitle.textContent = `상태 ${summary.status || '-'} · ${summary.is_leader ? '파티장' : '참가자'}`;
        window.GlobalDMUI?.setChannelReady(partyInputEl, '파티 채팅 입력...');

        const data = await API.get(`/community/parties/${currentPartyId}/chat/`).catch((error) => {
            if (error?.status === 403 || error?.status === 404) {
                invalidate?.();
            }
            return { results: [] };
        });

        const preview = buildGroupPreview(data.results || []);
        if (preview) {
            partySubtitle.textContent = preview;
        }
        window.GlobalDMUI?.syncMessageList(
            partyMessagesEl,
            data.results || [],
            (item) => window.GlobalDMUI.renderGroupMessageItem(item, currentUser),
            forceScroll,
            '아직 채팅이 없습니다.',
            messageRenderState
        );
        return { currentPartyId };
    }

    async function loadDirectMessages({
        ensureCurrentUser,
        currentRoomUserId,
        currentUser,
        messagesEl,
        forceScroll = false,
        messageRenderState,
        lastMessageCount = 0,
        onNewIncomingMessage,
    }) {
        if (!currentRoomUserId) {
            return { lastMessageCount };
        }
        await ensureCurrentUser?.();

        try {
            const data = await API.get(`/accounts/messages/${currentRoomUserId}/`, { limit: 100, offset: 0, no_count: 1 });
            const items = data.results || [];

            if (!items.length) {
                window.GlobalDMUI?.setMessagesEmpty(messagesEl, messageRenderState, '아직 메시지가 없습니다.');
            } else {
                const didRender = window.GlobalDMUI?.syncMessageList(
                    messagesEl,
                    items,
                    (item) => window.GlobalDMUI.renderDirectMessageItem(item, currentUser),
                    forceScroll,
                    '아직 메시지가 없습니다.',
                    messageRenderState
                );
                const orderedItems = items.slice().reverse();

                if (didRender && data.count > lastMessageCount && orderedItems.length) {
                    const lastItem = orderedItems[orderedItems.length - 1];
                    if (lastItem.sender?.id !== currentUser?.id) {
                        Utils?.Sounds?.chat?.();
                        await onNewIncomingMessage?.();
                    }
                }
            }
            return { lastMessageCount: data.count || 0 };
        } catch (error) {
            console.error('Failed to load messages:', error);
            window.GlobalDMUI?.setMessagesEmpty(messagesEl, messageRenderState, '메시지를 불러오지 못했습니다.');
            return { lastMessageCount };
        }
    }

    async function markDirectMessageNotificationsRead({ userId, onAfterMark }) {
        try {
            const data = await API.get('/notifications/', { limit: 50, offset: 0, no_count: 1 });
            const ids = (data.results || [])
                .filter((item) => item.type === 'direct_message' && !item.is_read)
                .filter((item) => item.payload?.sender_id == userId)
                .map((item) => item.id);
            if (ids.length) {
                await API.post('/notifications/read/', { ids });
                await onAfterMark?.();
            }
        } catch {
            // ignore
        }
    }

    window.GlobalDMChannels = {
        buildThreadsSignature,
        loadGroupSummary,
        loadTargetInfo,
        loadGuildMessages,
        loadPartyMessages,
        loadDirectMessages,
        markDirectMessageNotificationsRead,
    };
})();
