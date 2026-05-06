(function () {
    let categories = [];
    let activeCategory = null;
    let activePostId = null;
    let currentUserId = null;
    let postsCache = [];
    let lastPostsSignature = '';
    let mineOnly = new URLSearchParams(window.location.search).get('mine') === '1';
    let commentsBeforeId = null;
    let commentsHasMore = false;
    const COMMENT_PAGE_SIZE = 20;
    const initialPostId = Number(new URLSearchParams(window.location.search).get('post') || 0);

    const tabsEl = document.getElementById('board-tabs');
    const listEl = document.getElementById('board-post-list');
    const detailEmptyEl = document.getElementById('board-detail-empty');
    const detailPanelEl = document.getElementById('board-detail-panel');
    const detailEl = document.getElementById('board-post-detail');
    const commentsEl = document.getElementById('board-comments');
    const commentFormEl = document.getElementById('board-comment-form');
    const commentInputEl = document.getElementById('board-comment-input');
    const deleteBtn = document.getElementById('board-delete-btn');
    const detailActionsEl = document.getElementById('board-detail-actions');
    const mineToggleBtn = document.getElementById('board-mine-toggle');
    const scopeAllBtn = document.getElementById('board-scope-all');
    const scopeMineBtn = document.getElementById('board-scope-mine');

    function formatPostTime(value) {
        if (!value) return '-';
        return Utils.formatRelativeTime(value);
    }

    function escape(value) {
        return Utils.escapeHtml(String(value ?? ''));
    }

    function buildPostStats(post) {
        return `
            <span class="community-post-stat">💬 댓글 ${Number(post.comment_count || 0)}</span>
            <span class="community-post-stat">👁 조회 ${Number(post.view_count || 0)}</span>
            <span class="community-post-stat">${escape(formatPostTime(post.created_at))}</span>
        `;
    }

    function buildRecruitmentMeta(post) {
        const parts = [];
        if (post.guild_name) {
            parts.push(`<span class="community-post-pill is-emphasis">${escape(post.guild_name)}</span>`);
        }
        if (post.recruitment_slots) {
            parts.push(`<span class="community-post-pill">모집 ${Number(post.recruitment_slots)}명</span>`);
        }
        if (post.minimum_rating !== null && post.minimum_rating !== undefined) {
            parts.push(`<span class="community-post-pill">최소 ${Number(post.minimum_rating)}점</span>`);
        }
        if (post.active_time_band) {
            parts.push(`<span class="community-post-pill">활동 ${escape(post.active_time_band)}</span>`);
        }
        if (post.join_policy_text) {
            parts.push(`<span class="community-post-pill">가입 ${escape(post.join_policy_text)}</span>`);
        }
        if (post.contact_method) {
            parts.push(`<span class="community-post-pill">연락 ${escape(post.contact_method)}</span>`);
        }
        return parts.length
            ? `<div class="community-post-recruit-meta">${parts.join('')}</div>`
            : '';
    }

    function buildPostListItem(post) {
        const category = post.category?.title || '게시글';
        const author = post.author?.nickname || '익명';
        const previewText = (post.content || '').trim().slice(0, 110);
        const isRecruit = post.category?.code === 'recruit';
        return `
            <span class="community-item-head">
                <span class="community-item-title">${escape(post.title || '제목 없음')}</span>
                <span class="community-post-capsule">${escape(category)}</span>
            </span>
            <span class="community-item-meta">${escape(author)}</span>
            <span class="community-post-stats">${buildPostStats(post)}</span>
            ${isRecruit ? buildRecruitmentMeta(post) : ''}
            <span class="community-item-copy">${escape(previewText || '본문 미리보기가 없습니다.')}</span>
        `;
    }

    function buildPostsSignature(posts) {
        return posts
            .map((post) => [
                post.id,
                post.comment_count || 0,
                post.view_count || 0,
                post.title || '',
                post.created_at || '',
                (post.content || '').slice(0, 110),
            ].join(':'))
            .join('|');
    }

    function syncListActiveState() {
        listEl.querySelectorAll('.community-item[data-post-id]').forEach((item) => {
            const postId = Number(item.dataset.postId || 0);
            item.classList.toggle('is-active', postId === activePostId);
        });
    }

    function upsertCachedPost(post) {
        const index = postsCache.findIndex((item) => item.id === post.id);
        if (index >= 0) {
            postsCache[index] = { ...postsCache[index], ...post };
        } else {
            postsCache.unshift(post);
        }
        lastPostsSignature = buildPostsSignature(postsCache);
    }

    function removeCachedPost(postId) {
        postsCache = postsCache.filter((post) => post.id !== postId);
        lastPostsSignature = buildPostsSignature(postsCache);
    }

    function createPostButton(post) {
        const item = document.createElement('button');
        item.type = 'button';
        item.className = 'community-item';
        item.dataset.postId = String(post.id);
        item.innerHTML = buildPostListItem(post);
        item.addEventListener('click', () => loadPost(post.id));
        return item;
    }

    function patchPostListItem(post) {
        const existing = listEl.querySelector(`[data-post-id="${post.id}"]`);
        if (!existing) return;
        existing.innerHTML = buildPostListItem(post);
        existing.classList.toggle('is-active', post.id === activePostId);
    }

    function buildPostDetail(post) {
        const category = post.category?.title || '게시글';
        const author = post.author?.nickname || '익명';
        const recruitMeta = post.category?.code === 'recruit' ? buildRecruitmentMeta(post) : '';
        return `
            <div class="community-item community-item--detail">
                <span class="community-item-head">
                    <span class="community-item-title">${escape(post.title || '제목 없음')}</span>
                    <span class="community-post-capsule">${escape(category)}</span>
                </span>
                <span class="community-item-meta">${escape(author)}</span>
                <span class="community-post-stats">${buildPostStats(post)}</span>
                ${recruitMeta}
                <span class="community-item-copy community-item-copy--detail">${escape(post.content || '')}</span>
            </div>
        `;
    }

    function buildCommentItem(comment) {
        const author = comment.author?.nickname || '익명';
        const likedClass = comment.liked_by_me ? ' active' : '';
        const likedLabel = comment.liked_by_me ? '좋아요 취소' : '좋아요';
        const deleteButton = comment.can_delete
            ? `<button class="btn btn-secondary btn-xs" type="button" data-comment-delete="${comment.id}">삭제</button>`
            : '';
        return `
            <div class="community-item community-comment-item" data-comment-id="${comment.id}">
                <span class="community-item-head">
                    <span class="community-item-title">${escape(author)}</span>
                    <span class="community-post-capsule">${escape(formatPostTime(comment.created_at))}</span>
                </span>
                <span class="community-item-copy">${escape(comment.content || '')}</span>
                <div class="community-comment-actions">
                    <button class="reaction-btn community-comment-like${likedClass}" type="button" data-comment-like="${comment.id}" aria-label="${likedLabel}">
                        <span>👍</span>
                        <span class="community-comment-like-count">${Number(comment.like_count || 0)}</span>
                    </button>
                    ${deleteButton}
                </div>
            </div>
        `;
    }

    function createEmptyState(message) {
        const empty = document.createElement('div');
        empty.className = 'community-empty';
        empty.textContent = message;
        return empty;
    }

    function createCommentElement(comment) {
        const item = document.createElement('div');
        item.className = 'community-item community-comment-item';
        item.dataset.commentId = String(comment.id);
        item.innerHTML = buildCommentItem(comment);
        return item;
    }

    function updateCommentsLoadMore() {
        commentsEl?.querySelector('[data-board-comments-more]')?.remove();
        if (!commentsHasMore || !activePostId || !commentsEl) return;
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'btn btn-secondary btn-sm';
        button.dataset.boardCommentsMore = '1';
        button.textContent = '이전 댓글 더보기';
        commentsEl.prepend(button);
    }

    function renderCommentsPage(comments, { reset = false } = {}) {
        if (!commentsEl) return;
        if (reset) {
            commentsEl.replaceChildren();
        }

        commentsEl.querySelector('.community-empty')?.remove();
        commentsEl.querySelector('[data-board-comments-more]')?.remove();

        if (!comments.length && !commentsEl.querySelector('[data-comment-id]')) {
            commentsEl.replaceChildren(createEmptyState('아직 댓글이 없습니다.'));
            commentsHasMore = false;
            return;
        }

        const fragment = document.createDocumentFragment();
        comments.forEach((comment) => {
            fragment.appendChild(createCommentElement(comment));
        });

        if (reset || !commentsEl.firstChild) {
            commentsEl.appendChild(fragment);
        } else {
            commentsEl.prepend(fragment);
        }

        updateCommentsLoadMore();
    }

    function updateScopeButtons() {
        const canUseMine = Boolean(currentUserId);
        mineToggleBtn?.classList.toggle('hidden', !canUseMine);
        scopeMineBtn?.classList.toggle('hidden', !canUseMine);
        mineToggleBtn?.classList.toggle('btn-primary', mineOnly);
        mineToggleBtn?.classList.toggle('btn-secondary', !mineOnly);
        scopeAllBtn?.classList.toggle('btn-primary', !mineOnly);
        scopeAllBtn?.classList.toggle('btn-secondary', mineOnly);
        scopeMineBtn?.classList.toggle('btn-primary', mineOnly);
        scopeMineBtn?.classList.toggle('btn-secondary', !mineOnly);
    }

    async function loadCurrentUser() {
        const body = document.body;
        if (body?.dataset?.authenticated !== 'true') {
            currentUserId = null;
            return;
        }
        try {
            const me = await API.get('/accounts/me/');
            currentUserId = me?.id || null;
        } catch {
            currentUserId = null;
        }
    }

    function renderCategories() {
        tabsEl.innerHTML = '';
        categories.forEach((category, index) => {
            const tab = document.createElement('button');
            tab.type = 'button';
            tab.className = `community-tab${category.code === activeCategory ? ' is-active' : ''}`;
            tab.textContent = category.title;
            tab.addEventListener('click', () => {
                activeCategory = category.code;
                renderCategories();
                loadPosts().catch((error) => Toast.error(error.data?.message || error.message));
            });
            tabsEl.appendChild(tab);
            if (!activeCategory && index === 0) activeCategory = category.code;
        });
    }

    function renderPosts(posts) {
        listEl.innerHTML = '';
        if (!posts.length) {
            listEl.innerHTML = '<div class="community-empty">게시글이 없습니다.</div>';
            return;
        }
        posts.forEach((post) => {
            const item = createPostButton(post);
            item.classList.toggle('is-active', post.id === activePostId);
            listEl.appendChild(item);
        });
    }

    function renderPost(post) {
        detailEmptyEl.classList.add('hidden');
        detailPanelEl.classList.remove('hidden');
        detailEl.innerHTML = buildPostDetail(post);
        detailActionsEl?.classList.toggle('hidden', !post.can_delete);
        if (deleteBtn) {
            deleteBtn.dataset.postId = String(post.id);
        }
        if (commentInputEl) {
            commentInputEl.disabled = !currentUserId;
            commentInputEl.placeholder = currentUserId ? '댓글 입력...' : '로그인 후 댓글을 작성할 수 있습니다.';
        }
        if (commentFormEl?.querySelector('button[type="submit"]')) {
            commentFormEl.querySelector('button[type="submit"]').disabled = !currentUserId;
        }
    }

    async function loadComments(postId, { reset = false, beforeId = null } = {}) {
        const params = { limit: String(COMMENT_PAGE_SIZE) };
        if (beforeId) {
            params.before_id = String(beforeId);
        }
        const data = await API.get(`/community/boards/posts/${postId}/comments/`, params);
        commentsBeforeId = data.next_before_id || null;
        commentsHasMore = Boolean(data.has_more);
        renderCommentsPage(data.results || [], { reset });
    }

    async function loadCategories() {
        const data = await API.get('/community/boards/categories/');
        categories = data.results || [];
        renderCategories();
    }

    async function loadPosts() {
        const params = activeCategory ? { category: activeCategory, no_count: 1 } : { no_count: 1 };
        if (mineOnly && currentUserId) {
            params.mine = '1';
        }
        const data = await API.get('/community/boards/posts/', params);
        const posts = data.results || [];
        const nextSignature = buildPostsSignature(posts);
        postsCache = posts;
        if (nextSignature !== lastPostsSignature) {
            renderPosts(posts);
            lastPostsSignature = nextSignature;
        } else {
            syncListActiveState();
        }
        if (activePostId && !posts.some((post) => post.id === activePostId)) {
            activePostId = null;
            detailPanelEl.classList.add('hidden');
            detailEmptyEl.classList.remove('hidden');
            detailActionsEl?.classList.add('hidden');
        }
        updateScopeButtons();
    }

    async function loadPost(postId, { incrementView = true, syncList = true, loadCommentsAfter = true } = {}) {
        activePostId = postId;
        const params = incrementView ? {} : { no_view: '1' };
        const post = await API.get(`/community/boards/posts/${postId}/`, params);
        if (post.category?.code && post.category.code !== activeCategory) {
            activeCategory = post.category.code;
            renderCategories();
        }
        renderPost(post);
        if (loadCommentsAfter) {
            await loadComments(post.id, { reset: true });
        }
        if (syncList) {
            upsertCachedPost(post);
            patchPostListItem(post);
        }
        syncListActiveState();
        return post;
    }

    async function createComment(event) {
        event.preventDefault();
        if (!activePostId || !currentUserId) return;
        const content = commentInputEl?.value.trim();
        if (!content) return;
        await API.post(`/community/boards/posts/${activePostId}/comments/`, { content });
        commentInputEl.value = '';
        await loadPost(activePostId, { incrementView: false, syncList: true, loadCommentsAfter: false });
        await loadComments(activePostId, { reset: true });
    }

    async function toggleCommentLike(commentId) {
        if (!currentUserId) {
            Toast.info('로그인 후 좋아요를 누를 수 있습니다.');
            return;
        }
        await API.post(`/community/boards/comments/${commentId}/like/`, {});
        if (activePostId) {
            await loadComments(activePostId, { reset: true });
        }
    }

    async function deleteComment(commentId) {
        if (!commentId) return;
        if (!window.confirm('이 댓글을 삭제할까요?')) return;
        await API.delete(`/community/boards/comments/${commentId}/`);
        Toast.success('댓글을 삭제했습니다.');
        if (activePostId) {
            await loadPost(activePostId, { incrementView: false, syncList: true, loadCommentsAfter: false });
            await loadComments(activePostId, { reset: true });
        }
    }

    async function deleteActivePost() {
        if (!activePostId) return;
        if (!window.confirm('이 게시글을 삭제할까요?')) return;
        await API.delete(`/community/boards/posts/${activePostId}/`);
        Toast.success('게시글을 삭제했습니다.');
        const deletedPostId = activePostId;
        activePostId = null;
        removeCachedPost(deletedPostId);
        listEl.querySelector(`[data-post-id="${deletedPostId}"]`)?.remove();
        detailPanelEl.classList.add('hidden');
        detailEmptyEl.classList.remove('hidden');
        detailActionsEl?.classList.add('hidden');
        if (!postsCache.length) {
            renderPosts([]);
            return;
        }
        const nextPostId = postsCache[0]?.id;
        if (nextPostId) {
            await loadPost(nextPostId, { incrementView: false, syncList: false });
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        loadCurrentUser()
            .then(() => Promise.all([loadCategories(), loadPosts()]))
            .then(async () => {
                if (initialPostId) {
                    await loadPost(initialPostId);
                    return;
                }
                const first = listEl.querySelector('.community-item');
                if (first) first.click();
            })
            .catch((error) => Toast.error(error.data?.message || error.message || '게시판을 불러오지 못했습니다.'));

        commentFormEl?.addEventListener('submit', (event) => {
            createComment(event).catch((error) => Toast.error(error.data?.message || error.message));
        });

        commentsEl?.addEventListener('click', (event) => {
            const moreButton = event.target.closest('[data-board-comments-more]');
            if (moreButton) {
                if (!activePostId || !commentsBeforeId) return;
                loadComments(activePostId, { beforeId: commentsBeforeId }).catch((error) => Toast.error(error.data?.message || error.message));
                return;
            }
            const deleteButton = event.target.closest('[data-comment-delete]');
            if (deleteButton) {
                const commentId = Number(deleteButton.dataset.commentDelete || 0);
                if (!commentId) return;
                deleteComment(commentId).catch((error) => Toast.error(error.data?.message || error.message));
                return;
            }
            const button = event.target.closest('[data-comment-like]');
            if (!button) return;
            const commentId = Number(button.dataset.commentLike || 0);
            if (!commentId) return;
            toggleCommentLike(commentId).catch((error) => Toast.error(error.data?.message || error.message));
        });

        deleteBtn?.addEventListener('click', () => {
            deleteActivePost().catch((error) => Toast.error(error.data?.message || error.message));
        });

        const switchScope = (nextMineOnly) => {
            if (nextMineOnly && !currentUserId) {
                Toast.info('로그인 후 내 글 모아보기를 사용할 수 있습니다.');
                return;
            }
            mineOnly = nextMineOnly;
            const url = new URL(window.location.href);
            if (mineOnly) url.searchParams.set('mine', '1');
            else url.searchParams.delete('mine');
            window.history.replaceState({}, '', url);
            loadPosts().catch((error) => Toast.error(error.data?.message || error.message));
        };

        mineToggleBtn?.addEventListener('click', () => switchScope(!mineOnly));
        scopeAllBtn?.addEventListener('click', () => switchScope(false));
        scopeMineBtn?.addEventListener('click', () => switchScope(true));
    });
})();
