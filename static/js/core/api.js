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
        return window.CSRF_TOKEN || '';
    }

    /**
     * 기본 헤더 생성
     */
    function getHeaders(isFormData = false) {
        const headers = {
            'X-CSRFToken': getCSRFToken(),
        };

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

        const error = new Error(errorData.message || `HTTP ${response.status}`);
        error.status = response.status;
        error.data = errorData;
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
