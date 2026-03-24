/**
 * VoteSecure API Client
 * Handles all backend communication with JWT auth
 */

const API_BASE = '/api';

class ApiClient {
    constructor() {
        this.token = localStorage.getItem('vs_token') || null;
        this.user = JSON.parse(localStorage.getItem('vs_user') || 'null');
    }

    setAuth(token, user) {
        this.token = token;
        this.user = user;
        localStorage.setItem('vs_token', token);
        localStorage.setItem('vs_user', JSON.stringify(user));
    }

    clearAuth() {
        this.token = null;
        this.user = null;
        localStorage.removeItem('vs_token');
        localStorage.removeItem('vs_user');
    }

    isLoggedIn() {
        return !!this.token;
    }

    isAdmin() {
        return this.user && this.user.role === 'admin';
    }

    async request(endpoint, options = {}) {
        const url = `${API_BASE}${endpoint}`;
        const headers = options.headers || {};

        if (this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }

        if (!(options.body instanceof FormData)) {
            headers['Content-Type'] = 'application/json';
        }

        try {
            const response = await fetch(url, {
                ...options,
                headers
            });

            const data = await response.json();

            if (!response.ok) {
                throw { status: response.status, ...data };
            }

            return data;
        } catch (error) {
            if (error.status === 401) {
                this.clearAuth();
                if (!window.location.pathname.includes('index.html') && window.location.pathname !== '/') {
                    window.location.href = '/';
                }
            }
            throw error;
        }
    }

    // Auth endpoints
    async login(username, password) {
        const data = await this.request('/auth/login', {
            method: 'POST',
            body: JSON.stringify({ username, password })
        });
        this.setAuth(data.token, data.user);
        return data;
    }

    async register(formData) {
        return this.request('/auth/register', {
            method: 'POST',
            body: formData,
            headers: { 'Authorization': `Bearer ${this.token}` }
        });
    }

    async getProfile() {
        return this.request('/auth/me');
    }

    async generateOtp() {
        return this.request('/auth/generate-otp', { method: 'POST' });
    }

    async verifyOtp(userId, otpCode) {
        return this.request('/auth/verify-otp', {
            method: 'POST',
            body: JSON.stringify({ user_id: userId, otp_code: otpCode })
        });
    }

    async verifyFingerprint(formData) {
        return this.request('/auth/verify-fingerprint', {
            method: 'POST',
            body: formData,
            headers: { 'Authorization': `Bearer ${this.token}` }
        });
    }

    async enrollFingerprint(formData) {
        return this.request('/auth/enroll-fingerprint', {
            method: 'POST',
            body: formData,
            headers: { 'Authorization': `Bearer ${this.token}` }
        });
    }

    async logout() {
        try {
            await this.request('/auth/logout', { method: 'POST' });
        } catch(e) {}
        this.clearAuth();
    }

    // Voting endpoints
    async getActiveElections() {
        return this.request('/vote/elections');
    }

    async getAllElections() {
        return this.request('/vote/all-elections');
    }

    async castVote(candidateId, electionId) {
        return this.request('/vote/cast', {
            method: 'POST',
            body: JSON.stringify({ candidate_id: candidateId, election_id: electionId })
        });
    }

    async getResults(electionId) {
        return this.request(`/vote/results/${electionId}`);
    }

    async verifyBlockchain() {
        return this.request('/vote/blockchain/verify');
    }

    async getDashboardStats() {
        return this.request('/vote/dashboard-stats');
    }

    // Admin endpoints
    async getAdminStats() {
        return this.request('/admin/stats');
    }

    async getCandidates(electionId) {
        const params = electionId ? `?election_id=${electionId}` : '';
        return this.request(`/admin/candidates${params}`);
    }

    async createCandidate(formData) {
        return this.request('/admin/candidates', {
            method: 'POST',
            body: formData,
            headers: { 'Authorization': `Bearer ${this.token}` }
        });
    }

    async updateCandidate(id, formData) {
        return this.request(`/admin/candidates/${id}`, {
            method: 'PUT',
            body: formData,
            headers: { 'Authorization': `Bearer ${this.token}` }
        });
    }

    async deleteCandidate(id) {
        return this.request(`/admin/candidates/${id}`, { method: 'DELETE' });
    }

    async getVoters(page = 1, search = '') {
        return this.request(`/admin/voters?page=${page}&search=${search}`);
    }

    async verifyVoter(id) {
        return this.request(`/admin/voters/${id}/verify`, { method: 'POST' });
    }

    async toggleVoterStatus(id) {
        return this.request(`/admin/voters/${id}/toggle-status`, { method: 'POST' });
    }

    async getAdminElections() {
        return this.request('/admin/elections');
    }

    async createElection(data) {
        return this.request('/admin/elections', {
            method: 'POST',
            body: JSON.stringify(data)
        });
    }

    async updateElection(id, data) {
        return this.request(`/admin/elections/${id}`, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    }

    async deleteElection(id) {
        return this.request(`/admin/elections/${id}`, { method: 'DELETE' });
    }

    async runFraudAnalysis(electionId) {
        return this.request(`/admin/fraud-analysis/${electionId}`);
    }

    async getFraudAlerts(electionId) {
        const params = electionId ? `?election_id=${electionId}` : '';
        return this.request(`/admin/fraud-alerts${params}`);
    }

    async getAuditLogs(page = 1) {
        return this.request(`/admin/audit-logs?page=${page}`);
    }
}

// Global API instance
const api = new ApiClient();

// ---- Toast Notification System ----
function showToast(message, type = 'info') {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container';
        document.body.appendChild(container);
    }

    const icons = {
        success: '✓',
        error: '✕',
        info: 'ℹ',
        warning: '⚠'
    };

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `<span>${icons[type] || 'ℹ'}</span><span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100px)';
        setTimeout(() => toast.remove(), 400);
    }, 4000);
}

// ---- Utility functions ----
function formatDate(dateStr) {
    if (!dateStr || dateStr === 'None') return 'N/A';
    const date = new Date(dateStr);
    return date.toLocaleDateString('en-US', {
        year: 'numeric', month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit'
    });
}

function formatDateInput(dateStr) {
    if (!dateStr || dateStr === 'None') return '';
    const date = new Date(dateStr);
    return date.toISOString().slice(0, 16);
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
