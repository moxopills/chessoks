const PartyInvites = (function() {
    let activePartyCache = undefined;
    let activePartyPromise = null;

    function isGuestUser() {
        return document.body?.dataset.guest === 'true';
    }

    function isAuthenticatedUser() {
        return document.body?.dataset.authenticated === 'true' || isGuestUser();
    }

    async function getActiveParty(force = false) {
        if (!isAuthenticatedUser()) return null;
        if (!force && activePartyCache !== undefined) return activePartyCache;
        if (!force && activePartyPromise) return activePartyPromise;

        activePartyPromise = API.get('/community/parties/me/active/')
            .then((data) => {
                activePartyCache = data;
                return data;
            })
            .catch((error) => {
                activePartyPromise = null;
                if (error.status === 404) {
                    activePartyCache = null;
                    return null;
                }
                throw error;
            })
            .finally(() => {
                activePartyPromise = null;
            });
        return activePartyPromise;
    }

    function invalidate() {
        activePartyCache = undefined;
        activePartyPromise = null;
    }

    async function sendInvite(targetUserId) {
        const userId = Number(targetUserId);
        if (!userId) {
            Toast.error('초대할 대상을 확인할 수 없습니다.');
            return { ok: false };
        }
        if (!isAuthenticatedUser()) {
            Toast.error('로그인 시 가능합니다.');
            return { ok: false };
        }
        if (isGuestUser()) {
            Toast.error('게스트는 파티 초대를 보낼 수 없습니다.');
            return { ok: false };
        }

        const activeParty = await getActiveParty();
        if (!activeParty?.party_id) {
            Toast.info('먼저 파티를 만들거나 참가한 뒤 초대를 보내세요.');
            return { ok: false };
        }
        if (!activeParty.can_invite) {
            Toast.error(activeParty.message || '파티장만 초대를 보낼 수 있습니다.');
            return { ok: false };
        }

        await API.post(`/community/parties/${activeParty.party_id}/invite/`, { user_id: userId });
        Toast.success(`${activeParty.title} 파티 초대를 보냈습니다.`);
        return { ok: true, partyId: activeParty.party_id };
    }

    return {
        getActiveParty,
        invalidate,
        sendInvite,
    };
})();
