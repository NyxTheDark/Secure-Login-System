// Global variables and utility functions
let currentUser = null;

// Initialize app
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    setupEventListeners();
});

function initializeApp() {
    checkAuthStatus();
    setupMobileMenu();
}

function setupEventListeners() {
    // Mobile menu toggle
    const navToggle = document.getElementById('nav-toggle');
    if (navToggle) {
        navToggle.addEventListener('click', toggleMobileMenu);
    }
    
    // Close modals when clicking outside
    window.addEventListener('click', function(event) {
        const modals = document.querySelectorAll('.modal');
        modals.forEach(modal => {
            if (event.target === modal) {
                modal.style.display = 'none';
            }
        });
    });
}

function setupMobileMenu() {
    const navToggle = document.getElementById('nav-toggle');
    const navMenu = document.getElementById('nav-menu');
    
    if (navToggle && navMenu) {
        navToggle.addEventListener('click', function() {
            navMenu.classList.toggle('active');
        });
    }
}

function toggleMobileMenu() {
    const navMenu = document.getElementById('nav-menu');
    if (navMenu) {
        navMenu.classList.toggle('active');
    }
}

// Authentication functions
function checkAuthStatus() {
    const token = localStorage.getItem('access_token');
    const userData = localStorage.getItem('user_data');
    
    if (token && userData) {
        try {
            currentUser = JSON.parse(userData);
            updateNavigation(true);
            updateUserGreeting();
        } catch (error) {
            console.error('Error parsing user data:', error);
            logout();
        }
    } else {
        updateNavigation(false);
    }
}

function updateNavigation(isLoggedIn) {
    const loginLink = document.getElementById('login-link');
    const registerLink = document.getElementById('register-link');
    const dashboardLink = document.getElementById('dashboard-link');
    const logoutLink = document.getElementById('logout-link');
    
    if (isLoggedIn) {
        if (loginLink) loginLink.style.display = 'none';
        if (registerLink) registerLink.style.display = 'none';
        if (dashboardLink) dashboardLink.style.display = 'block';
        if (logoutLink) logoutLink.style.display = 'block';
    } else {
        if (loginLink) loginLink.style.display = 'block';
        if (registerLink) registerLink.style.display = 'block';
        if (dashboardLink) dashboardLink.style.display = 'none';
        if (logoutLink) logoutLink.style.display = 'none';
    }
}

function updateUserGreeting() {
    const userGreeting = document.getElementById('user-greeting');
    if (userGreeting && currentUser) {
        userGreeting.textContent = `Welcome back, ${currentUser.username}!`;
    }
}

function logout() {
    // Call logout endpoint
    const token = localStorage.getItem('access_token');
    if (token) {
        fetch('/auth/logout', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        }).catch(error => {
            console.error('Logout error:', error);
        });
    }
    
    // Clear local storage
    localStorage.removeItem('access_token');
    localStorage.removeItem('user_data');
    currentUser = null;
    
    // Update UI
    updateNavigation(false);
    
    // Redirect to home
    window.location.href = '/';
}

// Utility functions
function parseJWT(token) {
    try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
        return JSON.parse(jsonPayload);
    } catch (error) {
        console.error('Error parsing JWT:', error);
        return null;
    }
}

function formatDate(dateString) {
    if (!dateString) return 'Never';
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

function formatDateShort(dateString) {
    if (!dateString) return 'Never';
    const date = new Date(dateString);
    return date.toLocaleDateString();
}

// Alert system
function showAlert(message, type = 'info') {
    const modal = document.getElementById('alert-modal');
    const content = document.getElementById('alert-content');
    
    if (modal && content) {
        let icon = '';
        let bgColor = '';
        
        switch (type) {
            case 'success':
                icon = 'fas fa-check-circle';
                bgColor = '#d4edda';
                break;
            case 'error':
                icon = 'fas fa-exclamation-circle';
                bgColor = '#f8d7da';
                break;
            case 'warning':
                icon = 'fas fa-exclamation-triangle';
                bgColor = '#fff3cd';
                break;
            default:
                icon = 'fas fa-info-circle';
                bgColor = '#d1ecf1';
        }
        
        content.innerHTML = `
            <div style="padding: 1rem; background: ${bgColor}; border-radius: 5px; display: flex; align-items: center; gap: 0.5rem;">
                <i class="${icon}"></i>
                <span>${message}</span>
            </div>
        `;
        
        modal.style.display = 'block';
        
        // Auto-close after 5 seconds for success messages
        if (type === 'success') {
            setTimeout(() => {
                modal.style.display = 'none';
            }, 5000);
        }
    }
}

function closeModal() {
    const modal = document.getElementById('alert-modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

// API helper functions
function makeAuthenticatedRequest(url, options = {}) {
    const token = localStorage.getItem('access_token');
    
    if (!token) {
        window.location.href = '/login';
        return Promise.reject('No token found');
    }
    
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        }
    };
    
    const mergedOptions = {
        ...defaultOptions,
        ...options,
        headers: {
            ...defaultOptions.headers,
            ...options.headers
        }
    };
    
    return fetch(url, mergedOptions)
        .then(response => {
            if (response.status === 401) {
                logout();
                throw new Error('Authentication required');
            }
            return response.json();
        });
}

// Form validation
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

function validatePassword(password) {
    const minLength = password.length >= 8;
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    
    return {
        isValid: minLength && hasUpper && hasLower && hasNumber && hasSpecial,
        checks: {
            minLength,
            hasUpper,
            hasLower,
            hasNumber,
            hasSpecial
        }
    };
}

// Loading states
function setButtonLoading(button, isLoading, originalText) {
    if (isLoading) {
        button.disabled = true;
        button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Loading...';
    } else {
        button.disabled = false;
        button.innerHTML = originalText;
    }
}

// Pagination
function createPagination(containerId, currentPage, totalPages, onPageClick) {
    const container = document.getElementById(containerId);
    if (!container) return;
    
    let html = '';
    
    // Previous button
    if (currentPage > 1) {
        html += `<button onclick="${onPageClick}(${currentPage - 1})">Previous</button>`;
    }
    
    // Page numbers
    const startPage = Math.max(1, currentPage - 2);
    const endPage = Math.min(totalPages, currentPage + 2);
    
    if (startPage > 1) {
        html += `<button onclick="${onPageClick}(1)">1</button>`;
        if (startPage > 2) {
            html += '<span>...</span>';
        }
    }
    
    for (let i = startPage; i <= endPage; i++) {
        const activeClass = i === currentPage ? ' active' : '';
        html += `<button class="${activeClass}" onclick="${onPageClick}(${i})">${i}</button>`;
    }
    
    if (endPage < totalPages) {
        if (endPage < totalPages - 1) {
            html += '<span>...</span>';
        }
        html += `<button onclick="${onPageClick}(${totalPages})">${totalPages}</button>`;
    }
    
    // Next button
    if (currentPage < totalPages) {
        html += `<button onclick="${onPageClick}(${currentPage + 1})">Next</button>`;
    }
    
    container.innerHTML = html;
}

// Local storage helpers
function saveToLocalStorage(key, data) {
    try {
        localStorage.setItem(key, JSON.stringify(data));
    } catch (error) {
        console.error('Error saving to localStorage:', error);
    }
}

function getFromLocalStorage(key) {
    try {
        const data = localStorage.getItem(key);
        return data ? JSON.parse(data) : null;
    } catch (error) {
        console.error('Error reading from localStorage:', error);
        return null;
    }
}

// Debounce function for search inputs
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Copy to clipboard
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showAlert('Copied to clipboard!', 'success');
    }).catch(err => {
        console.error('Could not copy text: ', err);
        showAlert('Failed to copy to clipboard', 'error');
    });
}

// Download data as JSON
function downloadAsJSON(data, filename) {
    const dataStr = JSON.stringify(data, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
    
    const exportFileDefaultName = filename || 'data.json';
    
    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
}

// Print table
function printTable(tableId) {
    const table = document.getElementById(tableId);
    if (!table) return;
    
    const printWindow = window.open('', '', 'height=600,width=800');
    printWindow.document.write('<html><head><title>Print</title>');
    printWindow.document.write('<style>table { border-collapse: collapse; width: 100%; } th, td { border: 1px solid #ddd; padding: 8px; text-align: left; } th { background-color: #f2f2f2; }</style>');
    printWindow.document.write('</head><body>');
    printWindow.document.write(table.outerHTML);
    printWindow.document.write('</body></html>');
    printWindow.document.close();
    printWindow.print();
}

// Initialize tooltips (if using a tooltip library)
function initializeTooltips() {
    // Add tooltip initialization code here if needed
}

// Theme switcher (for future enhancement)
function toggleTheme() {
    const body = document.body;
    body.classList.toggle('dark-theme');
    
    const theme = body.classList.contains('dark-theme') ? 'dark' : 'light';
    localStorage.setItem('theme', theme);
}

function loadTheme() {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'dark') {
        document.body.classList.add('dark-theme');
    }
}

// Error handling
window.addEventListener('error', function(event) {
    console.error('Global error:', event.error);
    // You can add error reporting here
});

window.addEventListener('unhandledrejection', function(event) {
    console.error('Unhandled promise rejection:', event.reason);
    // You can add error reporting here
});

// Export functions for use in other scripts
window.AppUtils = {
    parseJWT,
    formatDate,
    formatDateShort,
    showAlert,
    closeModal,
    makeAuthenticatedRequest,
    validateEmail,
    validatePassword,
    setButtonLoading,
    createPagination,
    saveToLocalStorage,
    getFromLocalStorage,
    debounce,
    copyToClipboard,
    downloadAsJSON,
    printTable,
    logout,
    checkAuthStatus
};
