// Dashboard functionality
let currentTab = 'users';
let currentUsersPage = 1;
let currentLogsPage = 1;

document.addEventListener('DOMContentLoaded', function() {
    initializeDashboard();
});

function initializeDashboard() {
    // Check authentication
    const token = localStorage.getItem('access_token');
    const userData = localStorage.getItem('user_data');
    
    if (!token || !userData) {
        window.location.href = '/login';
        return;
    }
    
    try {
        currentUser = JSON.parse(userData);
        setupDashboard();
    } catch (error) {
        console.error('Error parsing user data:', error);
        window.location.href = '/login';
    }
}

function setupDashboard() {
    loadUserProfile();
    
    if (currentUser.role === 'Admin') {
        showAdminDashboard();
        loadUsers();
        loadStats();
    } else {
        showUserDashboard();
    }
    
    setupEventListeners();
}

function setupEventListeners() {
    // Profile form
    const profileForm = document.getElementById('profile-form');
    if (profileForm) {
        profileForm.addEventListener('submit', handleProfileUpdate);
    }
    
    // Password form
    const passwordForm = document.getElementById('password-form');
    if (passwordForm) {
        passwordForm.addEventListener('submit', handlePasswordChange);
    }
}

function showUserDashboard() {
    const userDashboard = document.getElementById('user-dashboard');
    const adminDashboard = document.getElementById('admin-dashboard');
    
    if (userDashboard) userDashboard.style.display = 'block';
    if (adminDashboard) adminDashboard.style.display = 'none';
}

function showAdminDashboard() {
    const userDashboard = document.getElementById('user-dashboard');
    const adminDashboard = document.getElementById('admin-dashboard');
    
    if (userDashboard) userDashboard.style.display = 'block';
    if (adminDashboard) adminDashboard.style.display = 'block';
}

function loadUserProfile() {
    if (!currentUser) return;
    
    // Update profile information
    const elements = {
        'profile-username': currentUser.username,
        'profile-email': currentUser.email,
        'profile-role': currentUser.role,
        'profile-created': AppUtils.formatDateShort(currentUser.created_at),
        'profile-last-login': AppUtils.formatDate(currentUser.last_login)
    };
    
    Object.entries(elements).forEach(([id, value]) => {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = value || 'N/A';
        }
    });
    
    // Set role badge color
    const roleBadge = document.getElementById('profile-role');
    if (roleBadge && currentUser.role === 'Admin') {
        roleBadge.style.background = 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)';
    }
}

// Tab Management
function showTab(tabName) {
    currentTab = tabName;
    
    // Update tab buttons
    document.querySelectorAll('.tab-button').forEach(btn => {
        btn.classList.remove('active');
    });
    document.querySelector(`[onclick="showTab('${tabName}')"]`).classList.add('active');
    
    // Update tab content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    document.getElementById(`${tabName}-tab`).classList.add('active');
    
    // Load tab data
    switch (tabName) {
        case 'users':
            loadUsers();
            break;
        case 'stats':
            loadStats();
            break;
        case 'logs':
            loadLoginLogs();
            break;
    }
}

// User Management
function loadUsers(page = 1) {
    currentUsersPage = page;
    
    AppUtils.makeAuthenticatedRequest(`/admin/users?page=${page}&per_page=10`)
        .then(data => {
            if (data.error) {
                AppUtils.showAlert(data.error, 'error');
                return;
            }
            
            displayUsers(data.users);
            AppUtils.createPagination('users-pagination', page, data.pages, 'loadUsers');
        })
        .catch(error => {
            console.error('Error loading users:', error);
            AppUtils.showAlert('Failed to load users', 'error');
        });
}

function displayUsers(users) {
    const tbody = document.getElementById('users-tbody');
    if (!tbody) return;
    
    if (users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center">No users found</td></tr>';
        return;
    }
    
    tbody.innerHTML = users.map(user => `
        <tr>
            <td>${user.id}</td>
            <td>${user.username}</td>
            <td>${user.email}</td>
            <td><span class="role-badge">${user.role}</span></td>
            <td>
                <span class="status-badge ${user.is_active ? 'status-active' : 'status-inactive'}">
                    ${user.is_active ? 'Active' : 'Inactive'}
                </span>
            </td>
            <td>${AppUtils.formatDateShort(user.created_at)}</td>
            <td>
                <div class="action-buttons">
                    <button class="btn btn-sm btn-${user.is_active ? 'warning' : 'success'}" 
                            onclick="toggleUserStatus(${user.id})">
                        <i class="fas fa-${user.is_active ? 'ban' : 'check'}"></i>
                        ${user.is_active ? 'Deactivate' : 'Activate'}
                    </button>
                    <button class="btn btn-sm btn-info" onclick="unlockUser(${user.id})">
                        <i class="fas fa-unlock"></i> Unlock
                    </button>
                    <button class="btn btn-sm btn-primary" onclick="changeUserRole(${user.id}, '${user.role}')">
                        <i class="fas fa-user-tag"></i> Role
                    </button>
                    ${user.id !== currentUser.id ? `
                        <button class="btn btn-sm btn-danger" onclick="deleteUser(${user.id})">
                            <i class="fas fa-trash"></i> Delete
                        </button>
                    ` : ''}
                </div>
            </td>
        </tr>
    `).join('');
}

function refreshUsers() {
    loadUsers(currentUsersPage);
}

function toggleUserStatus(userId) {
    if (!confirm('Are you sure you want to change this user\'s status?')) {
        return;
    }
    
    AppUtils.makeAuthenticatedRequest(`/admin/users/${userId}/toggle-status`, {
        method: 'POST'
    })
    .then(data => {
        if (data.error) {
            AppUtils.showAlert(data.error, 'error');
        } else {
            AppUtils.showAlert(data.message, 'success');
            loadUsers(currentUsersPage);
        }
    })
    .catch(error => {
        console.error('Error toggling user status:', error);
        AppUtils.showAlert('Failed to update user status', 'error');
    });
}

function unlockUser(userId) {
    AppUtils.makeAuthenticatedRequest(`/admin/users/${userId}/unlock`, {
        method: 'POST'
    })
    .then(data => {
        if (data.error) {
            AppUtils.showAlert(data.error, 'error');
        } else {
            AppUtils.showAlert(data.message, 'success');
            loadUsers(currentUsersPage);
        }
    })
    .catch(error => {
        console.error('Error unlocking user:', error);
        AppUtils.showAlert('Failed to unlock user', 'error');
    });
}

function changeUserRole(userId, currentRole) {
    const newRole = currentRole === 'Admin' ? 'User' : 'Admin';
    
    if (!confirm(`Are you sure you want to change this user's role to ${newRole}?`)) {
        return;
    }
    
    AppUtils.makeAuthenticatedRequest(`/admin/users/${userId}/role`, {
        method: 'PUT',
        body: JSON.stringify({ role: newRole })
    })
    .then(data => {
        if (data.error) {
            AppUtils.showAlert(data.error, 'error');
        } else {
            AppUtils.showAlert(data.message, 'success');
            loadUsers(currentUsersPage);
        }
    })
    .catch(error => {
        console.error('Error changing user role:', error);
        AppUtils.showAlert('Failed to change user role', 'error');
    });
}

function deleteUser(userId) {
    if (!confirm('Are you sure you want to delete this user? This action cannot be undone.')) {
        return;
    }
    
    AppUtils.makeAuthenticatedRequest(`/admin/users/${userId}`, {
        method: 'DELETE'
    })
    .then(data => {
        if (data.error) {
            AppUtils.showAlert(data.error, 'error');
        } else {
            AppUtils.showAlert(data.message, 'success');
            loadUsers(currentUsersPage);
        }
    })
    .catch(error => {
        console.error('Error deleting user:', error);
        AppUtils.showAlert('Failed to delete user', 'error');
    });
}

// Statistics
function loadStats() {
    AppUtils.makeAuthenticatedRequest('/admin/stats')
        .then(data => {
            if (data.error) {
                AppUtils.showAlert(data.error, 'error');
                return;
            }
            
            displayStats(data);
        })
        .catch(error => {
            console.error('Error loading stats:', error);
            AppUtils.showAlert('Failed to load statistics', 'error');
        });
}

function displayStats(stats) {
    const statElements = {
        'stat-total-users': stats.total_users,
        'stat-active-users': stats.active_users,
        'stat-admin-users': stats.admin_users,
        'stat-locked-users': stats.locked_users,
        'stat-recent-logins': stats.recent_login_attempts,
        'stat-failed-attempts': stats.failed_attempts_week
    };
    
    Object.entries(statElements).forEach(([id, value]) => {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = value || '0';
        }
    });
}

// Login Logs
function loadLoginLogs(page = 1) {
    currentLogsPage = page;
    
    AppUtils.makeAuthenticatedRequest(`/admin/login-attempts?page=${page}&per_page=20`)
        .then(data => {
            if (data.error) {
                AppUtils.showAlert(data.error, 'error');
                return;
            }
            
            displayLoginLogs(data.attempts);
            AppUtils.createPagination('logs-pagination', page, data.pages, 'loadLoginLogs');
        })
        .catch(error => {
            console.error('Error loading login logs:', error);
            AppUtils.showAlert('Failed to load login logs', 'error');
        });
}

function displayLoginLogs(logs) {
    const tbody = document.getElementById('logs-tbody');
    if (!tbody) return;
    
    if (logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center">No login attempts found</td></tr>';
        return;
    }
    
    tbody.innerHTML = logs.map(log => `
        <tr>
            <td>${AppUtils.formatDate(log.timestamp)}</td>
            <td>${log.email || 'N/A'}</td>
            <td>${log.ip_address}</td>
            <td>
                <span class="status-badge ${log.success ? 'status-success' : 'status-failed'}">
                    ${log.success ? 'Success' : 'Failed'}
                </span>
            </td>
            <td title="${log.user_agent || 'N/A'}" style="max-width: 200px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                ${log.user_agent || 'N/A'}
            </td>
        </tr>
    `).join('');
}

function refreshLogs() {
    loadLoginLogs(currentLogsPage);
}

// Profile Management
function showProfileModal() {
    const modal = document.getElementById('profile-modal');
    const usernameInput = document.getElementById('edit-username');
    
    if (modal && usernameInput) {
        usernameInput.value = currentUser.username;
        modal.style.display = 'block';
    }
}

function closeProfileModal() {
    const modal = document.getElementById('profile-modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

function handleProfileUpdate(event) {
    event.preventDefault();
    
    const formData = new FormData(event.target);
    const username = formData.get('username').trim();
    
    if (!username) {
        AppUtils.showAlert('Username is required', 'error');
        return;
    }
    
    const submitBtn = event.target.querySelector('button[type="submit"]');
    const originalText = submitBtn.innerHTML;
    AppUtils.setButtonLoading(submitBtn, true, originalText);
    
    AppUtils.makeAuthenticatedRequest('/user/profile', {
        method: 'PUT',
        body: JSON.stringify({ username })
    })
    .then(data => {
        if (data.error) {
            AppUtils.showAlert(data.error, 'error');
        } else {
            AppUtils.showAlert(data.message, 'success');
            currentUser.username = data.user.username;
            localStorage.setItem('user_data', JSON.stringify(currentUser));
            loadUserProfile();
            AppUtils.checkAuthStatus();
            closeProfileModal();
        }
    })
    .catch(error => {
        console.error('Error updating profile:', error);
        AppUtils.showAlert('Failed to update profile', 'error');
    })
    .finally(() => {
        AppUtils.setButtonLoading(submitBtn, false, originalText);
    });
}

// Password Management
function showChangePasswordModal() {
    const modal = document.getElementById('password-modal');
    if (modal) {
        // Clear form
        const form = document.getElementById('password-form');
        if (form) form.reset();
        
        modal.style.display = 'block';
    }
}

function closePasswordModal() {
    const modal = document.getElementById('password-modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

function handlePasswordChange(event) {
    event.preventDefault();
    
    const formData = new FormData(event.target);
    const currentPassword = formData.get('current_password');
    const newPassword = formData.get('new_password');
    const confirmPassword = formData.get('confirm_new_password');
    
    // Validate passwords
    if (!currentPassword || !newPassword || !confirmPassword) {
        AppUtils.showAlert('All password fields are required', 'error');
        return;
    }
    
    if (newPassword !== confirmPassword) {
        AppUtils.showAlert('New passwords do not match', 'error');
        return;
    }
    
    const passwordValidation = AppUtils.validatePassword(newPassword);
    if (!passwordValidation.isValid) {
        AppUtils.showAlert('New password does not meet security requirements', 'error');
        return;
    }
    
    const submitBtn = event.target.querySelector('button[type="submit"]');
    const originalText = submitBtn.innerHTML;
    AppUtils.setButtonLoading(submitBtn, true, originalText);
    
    AppUtils.makeAuthenticatedRequest('/user/change-password', {
        method: 'POST',
        body: JSON.stringify({
            current_password: currentPassword,
            new_password: newPassword
        })
    })
    .then(data => {
        if (data.error) {
            AppUtils.showAlert(data.error, 'error');
        } else {
            AppUtils.showAlert(data.message, 'success');
            closePasswordModal();
        }
    })
    .catch(error => {
        console.error('Error changing password:', error);
        AppUtils.showAlert('Failed to change password', 'error');
    })
    .finally(() => {
        AppUtils.setButtonLoading(submitBtn, false, originalText);
    });
}

// Export functions for global access
window.DashboardUtils = {
    showTab,
    loadUsers,
    refreshUsers,
    toggleUserStatus,
    unlockUser,
    changeUserRole,
    deleteUser,
    loadStats,
    loadLoginLogs,
    refreshLogs,
    showProfileModal,
    closeProfileModal,
    showChangePasswordModal,
    closePasswordModal
};
