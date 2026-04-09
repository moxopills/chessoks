(function () {
    const categorySelectEl = document.getElementById('board-category');
    const recruitFieldsEl = document.getElementById('board-recruit-fields');
    const formEl = document.getElementById('board-post-form');

    function toggleRecruitFields() {
        const category = (window.__boardCategories || []).find((item) => item.code === categorySelectEl.value);
        recruitFieldsEl.style.display = category?.is_recruitment ? 'grid' : 'none';
    }

    async function loadCategories() {
        const data = await API.get('/community/boards/categories/');
        window.__boardCategories = data.results || [];
        categorySelectEl.innerHTML = window.__boardCategories.map((category) => (
            `<option value="${Utils.escapeHtml(category.code)}">${Utils.escapeHtml(category.title)}</option>`
        )).join('');
        toggleRecruitFields();
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
        window.location.href = `/board/?post=${post.id}`;
    }

    document.addEventListener('DOMContentLoaded', () => {
        loadCategories().catch((error) => Toast.error(error.data?.message || error.message || '카테고리를 불러오지 못했습니다.'));
        categorySelectEl?.addEventListener('change', toggleRecruitFields);
        formEl?.addEventListener('submit', (event) => {
            createPost(event).catch((error) => Toast.error(error.data?.message || error.message));
        });
    });
})();
