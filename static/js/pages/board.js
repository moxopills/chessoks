(function () {
    let categories = [];
    let activeCategory = null;
    let activePostId = null;
    const initialPostId = Number(new URLSearchParams(window.location.search).get('post') || 0);

    const tabsEl = document.getElementById('board-tabs');
    const listEl = document.getElementById('board-post-list');
    const detailEmptyEl = document.getElementById('board-detail-empty');
    const detailPanelEl = document.getElementById('board-detail-panel');
    const detailEl = document.getElementById('board-post-detail');
    const commentsEl = document.getElementById('board-comments');
    const categorySelectEl = document.getElementById('board-category');
    const recruitFieldsEl = document.getElementById('board-recruit-fields');

    function formatPostTime(value) {
        if (!value) return '-';
        return Utils.formatRelativeTime(value);
    }

    function buildPostStats(post) {
        return `
            <span class="community-post-stat">💬 댓글 ${Number(post.comment_count || 0)}</span>
            <span class="community-post-stat">👁 조회 ${Number(post.view_count || 0)}</span>
            <span class="community-post-stat">${Utils.escapeHtml(formatPostTime(post.created_at))}</span>
        `;
    }

    function buildRecruitmentMeta(post) {
        const parts = [];
        if (post.guild_name) {
            parts.push(`<span class="community-post-pill is-emphasis">${Utils.escapeHtml(post.guild_name)}</span>`);
        }
        if (post.recruitment_slots) {
            parts.push(`<span class="community-post-pill">모집 ${Number(post.recruitment_slots)}명</span>`);
        }
        if (post.minimum_rating !== null && post.minimum_rating !== undefined) {
            parts.push(`<span class="community-post-pill">최소 ${Number(post.minimum_rating)}점</span>`);
        }
        if (post.active_time_band) {
            parts.push(`<span class="community-post-pill">활동 ${Utils.escapeHtml(post.active_time_band)}</span>`);
        }
        return parts.length
            ? `<div class="community-post-recruit-meta">${parts.join('')}</div>`
            : '';
    }

    function buildPostListItem(post) {
        const category = post.category?.title || '게시글';
        const author = post.author?.nickname || '익명';
        const previewText = (post.content || '').trim().slice(0, 96);
        const isRecruit = post.category?.code === 'recruit';
        return `
            <span class="community-item-head">
                <span class="community-item-title">${Utils.escapeHtml(post.title)}</span>
                <span class="community-post-capsule">${Utils.escapeHtml(category)}</span>
            </span>
            <span class="community-item-meta">${Utils.escapeHtml(author)}</span>
            <span class="community-post-stats">${buildPostStats(post)}</span>
            ${isRecruit ? buildRecruitmentMeta(post) : ''}
            <span class="community-item-copy">${Utils.escapeHtml(previewText || '본문 미리보기가 없습니다.')}</span>
        `;
    }

    function buildPostDetail(post) {
        const category = post.category?.title || '게시글';
        const author = post.author?.nickname || '익명';
        const recruitMeta = post.category?.code === 'recruit' ? buildRecruitmentMeta(post) : '';
        const contactMeta = [];
        if (post.join_policy_text) {
            contactMeta.push(`<span class="community-post-pill">가입 방식 ${Utils.escapeHtml(post.join_policy_text)}</span>`);
        }
        if (post.contact_method) {
            contactMeta.push(`<span class="community-post-pill">연락 ${Utils.escapeHtml(post.contact_method)}</span>`);
        }
        return `
            <div class="community-item community-item--detail">
                <span class="community-item-head">
                    <span class="community-item-title">${Utils.escapeHtml(post.title)}</span>
                    <span class="community-post-capsule">${Utils.escapeHtml(category)}</span>
                </span>
                <span class="community-item-meta">${Utils.escapeHtml(author)}</span>
                <span class="community-post-stats">${buildPostStats(post)}</span>
                ${recruitMeta}
                ${contactMeta.length ? `<div class="community-post-recruit-meta">${contactMeta.join('')}</div>` : ''}
                <span class="community-item-copy community-item-copy--detail">${Utils.escapeHtml(post.content)}</span>
            </div>
        `;
    }

    function renderCategories() {
        tabsEl.innerHTML = '';
        categorySelectEl.innerHTML = '';
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

            const option = document.createElement('option');
            option.value = category.code;
            option.textContent = category.title;
            categorySelectEl.appendChild(option);
            if (!activeCategory && index === 0) activeCategory = category.code;
        });
        toggleRecruitFields();
    }

    function toggleRecruitFields() {
        const category = categories.find((item) => item.code === categorySelectEl.value);
        recruitFieldsEl.style.display = category?.is_recruitment ? 'grid' : 'none';
    }

    function renderPosts(posts) {
        listEl.innerHTML = '';
        if (!posts.length) {
            listEl.innerHTML = '<div class="community-empty">게시글이 없습니다.</div>';
            return;
        }
        posts.forEach((post) => {
            const item = document.createElement('button');
            item.type = 'button';
            item.className = `community-item${post.id === activePostId ? ' is-active' : ''}`;
            item.innerHTML = buildPostListItem(post);
            item.addEventListener('click', () => loadPost(post.id));
            listEl.appendChild(item);
        });
    }

    function renderPost(post) {
        detailEmptyEl.classList.add('hidden');
        detailPanelEl.classList.remove('hidden');
        detailEl.innerHTML = buildPostDetail(post);
        commentsEl.innerHTML = (post.comments || []).map((comment) => `
            <div class="community-item">
                <span class="community-item-head">
                    <span class="community-item-title">${Utils.escapeHtml(comment.author.nickname)}</span>
                    <span class="community-post-capsule">${Utils.escapeHtml(formatPostTime(comment.created_at))}</span>
                </span>
                <span class="community-item-copy">${Utils.escapeHtml(comment.content)}</span>
            </div>
        `).join('') || '<div class="community-empty">아직 댓글이 없습니다.</div>';
    }

    async function loadCategories() {
        const data = await API.get('/community/boards/categories/');
        categories = data.results || [];
        renderCategories();
    }

    async function loadPosts() {
        const data = await API.get('/community/boards/posts/', activeCategory ? { category: activeCategory } : {});
        renderPosts(data.results || []);
    }

    async function loadPost(postId) {
        activePostId = postId;
        const post = await API.get(`/community/boards/posts/${postId}/`);
        if (post.category?.code && post.category.code !== activeCategory) {
            activeCategory = post.category.code;
            renderCategories();
        }
        renderPost(post);
        await loadPosts();
    }

    async function createPost(event) {
        event.preventDefault();
        const payload = {
            category_code: categorySelectEl.value,
            title: document.getElementById('board-title').value.trim(),
            content: document.getElementById('board-content').value.trim(),
            guild_name: document.getElementById('board-guild-name').value.trim(),
            recruitment_slots: document.getElementById('board-recruitment-slots').value || null,
            minimum_rating: document.getElementById('board-minimum-rating').value || null,
            active_time_band: document.getElementById('board-active-time-band').value.trim(),
            join_policy_text: document.getElementById('board-join-policy-text').value.trim(),
            contact_method: document.getElementById('board-contact-method').value.trim(),
        };
        const post = await API.post('/community/boards/posts/', payload);
        Toast.success('게시글을 작성했습니다.');
        event.currentTarget.reset();
        toggleRecruitFields();
        await loadPosts();
        await loadPost(post.id);
    }

    async function createComment(event) {
        event.preventDefault();
        if (!activePostId) return;
        const input = document.getElementById('board-comment-input');
        const content = input.value.trim();
        if (!content) return;
        await API.post(`/community/boards/posts/${activePostId}/comments/`, { content });
        input.value = '';
        await loadPost(activePostId);
    }

    document.addEventListener('DOMContentLoaded', () => {
        Promise.all([loadCategories(), loadPosts()])
            .then(async () => {
                if (initialPostId) {
                    await loadPost(initialPostId);
                    return;
                }
                if (listEl.firstElementChild?.classList.contains('community-item')) {
                    const first = listEl.firstElementChild;
                    first.click();
                }
            })
            .catch((error) => Toast.error(error.data?.message || error.message || '게시판을 불러오지 못했습니다.'));
        categorySelectEl?.addEventListener('change', toggleRecruitFields);
        document.getElementById('board-post-form')?.addEventListener('submit', (event) => createPost(event).catch((error) => Toast.error(error.data?.message || error.message)));
        document.getElementById('board-comment-form')?.addEventListener('submit', (event) => createComment(event).catch((error) => Toast.error(error.data?.message || error.message)));
    });
})();
