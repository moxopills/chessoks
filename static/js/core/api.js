/**
 * API Client Module
 * CSRF 토큰 자동 포함, 에러 핸들링
 */

const API = (function() {
    const BASE_URL = '/api';

    /**
     * CSRF 토큰 가져오기
     */
    function getCSRFToken() {
        if (window.CSRF_TOKEN) {
            return window.CSRF_TOKEN;
        }
        const match = document.cookie.match(/(?:^|; )csrftoken=([^;]+)/);
        return match ? decodeURIComponent(match[1]) : '';
    }

    /**
     * 게스트 토큰 가져오기
     */
    function getGuestToken() {
        return localStorage.getItem('guest_token') || '';
    }

    /**
     * 기본 헤더 생성
     */
    function getHeaders(isFormData = false) {
        const headers = {
            'X-CSRFToken': getCSRFToken(),
        };

        // 게스트 토큰이 있으면 헤더에 추가
        const guestToken = getGuestToken();
        if (guestToken) {
            headers['X-Guest-Token'] = guestToken;
        }

        if (!isFormData) {
            headers['Content-Type'] = 'application/json';
        }

        return headers;
    }

    /**
     * 응답 처리
     */
    async function handleResponse(response) {
        const contentType = response.headers.get('content-type');
        const isJson = contentType && contentType.includes('application/json');

        if (response.ok) {
            if (response.status === 204) {
                return null;
            }
            return isJson ? response.json() : response.text();
        }

        // 에러 응답 처리
        let errorData = { message: '요청 처리 중 오류가 발생했습니다.' };

        if (isJson) {
            try {
                const data = await response.json();
                errorData = data.error || data;
            } catch (e) {
                // JSON 파싱 실패
            }
        }

        if (response.status === 401) {
            errorData = { ...errorData, message: '로그인 시 가능합니다.' };
        }
        if (response.status === 403 && !errorData?.message) {
            errorData = { ...errorData, message: '권한이 없습니다.' };
        }

        const code = errorData?.code || '';
        const humanMessageByCode = {
            validation_error: '입력값을 다시 확인해주세요.',
            permission_denied: '권한이 없습니다.',
            not_found: '요청한 정보를 찾을 수 없습니다.',
            auth_required: '로그인 시 가능합니다.',
            bad_request: '요청을 처리할 수 없습니다.',
            conflict: '이미 처리된 요청입니다.',
            rate_limited: '요청이 너무 많습니다. 잠시 후 다시 시도해주세요.',
        };
        if (code && humanMessageByCode[code]) {
            errorData.message = errorData.message || humanMessageByCode[code];
        }

        const error = new Error(errorData.message || `HTTP ${response.status}`);
        error.status = response.status;
        error.data = errorData;
        try {
            window.dispatchEvent(new CustomEvent('api:error', { detail: { status: response.status, data: errorData } }));
        } catch {}
        throw error;
    }

    /**
     * GET 요청
     */
    async function get(endpoint, params = {}) {
        const url = new URL(BASE_URL + endpoint, window.location.origin);
        Object.entries(params).forEach(([key, value]) => {
            if (value !== undefined && value !== null) {
                url.searchParams.append(key, value);
            }
        });

        const response = await fetch(url, {
            method: 'GET',
            headers: getHeaders(),
            credentials: 'same-origin',
        });

        return handleResponse(response);
    }

    /**
     * POST 요청
     */
    async function post(endpoint, data = {}, isFormData = false) {
        const response = await fetch(BASE_URL + endpoint, {
            method: 'POST',
            headers: getHeaders(isFormData),
            credentials: 'same-origin',
            body: isFormData ? data : JSON.stringify(data),
        });

        return handleResponse(response);
    }

    /**
     * PUT 요청
     */
    async function put(endpoint, data = {}) {
        const response = await fetch(BASE_URL + endpoint, {
            method: 'PUT',
            headers: getHeaders(),
            credentials: 'same-origin',
            body: JSON.stringify(data),
        });

        return handleResponse(response);
    }

    /**
     * PATCH 요청
     */
    async function patch(endpoint, data = {}, isFormData = false) {
        const response = await fetch(BASE_URL + endpoint, {
            method: 'PATCH',
            headers: getHeaders(isFormData),
            credentials: 'same-origin',
            body: isFormData ? data : JSON.stringify(data),
        });

        return handleResponse(response);
    }

    /**
     * DELETE 요청
     */
    async function del(endpoint) {
        const response = await fetch(BASE_URL + endpoint, {
            method: 'DELETE',
            headers: getHeaders(),
            credentials: 'same-origin',
        });

        return handleResponse(response);
    }

    // Public API
    return {
        get,
        post,
        put,
        patch,
        delete: del,
    };
})();
