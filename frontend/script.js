// API Configuration
const API_BASE_URL = 'http://localhost:5000/api';

// DOM Elements
const urlInput = document.getElementById('urlInput');
const checkBtn = document.getElementById('checkBtn');
const resultsSection = document.getElementById('resultsSection');
const exampleSafe = document.getElementById('exampleSafe');
const examplePhishing = document.getElementById('examplePhishing');
const batchCheckBtn = document.getElementById('batchCheck');
const batchModal = document.getElementById('batchModal');
const newCheckBtn = document.getElementById('newCheckBtn');
const reportBtn = document.getElementById('reportBtn');
const refreshHistory = document.getElementById('refreshHistory');
const updateBlacklist = document.getElementById('updateBlacklist');

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    loadStatistics();
    loadHistory();
    setupEventListeners();
});

// Event Listeners
function setupEventListeners() {
    checkBtn.addEventListener('click', checkURL);
    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') checkURL();
    });
    
    exampleSafe.addEventListener('click', () => {
        urlInput.value = 'https://www.google.com';
        checkURL();
    });
    
    examplePhishing.addEventListener('click', () => {
        urlInput.value = 'http://secure-account-verify.tk/login';
        checkURL();
    });
    
    batchCheckBtn.addEventListener('click', () => {
        batchModal.style.display = 'flex';
    });
    
    document.querySelector('.close').addEventListener('click', () => {
        batchModal.style.display = 'none';
    });
    
    document.getElementById('batchCheckBtn').addEventListener('click', checkBatchURLs);
    
    newCheckBtn.addEventListener('click', () => {
        resultsSection.style.display = 'none';
        urlInput.value = '';
        urlInput.focus();
    });
    
    reportBtn.addEventListener('click', reportPhishing);
    refreshHistory.addEventListener('click', loadHistory);
    updateBlacklist.addEventListener('click', updateBlacklistData);
}

// Check Single URL
async function checkURL() {
    const url = urlInput.value.trim();
    
    if (!url) {
        showToast('Please enter a URL', 'warning');
        return;
    }
    
    // Show loading state
    showLoading(true);
    
    try {
        const response = await fetch(`${API_BASE_URL}/check`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            displayResults(data);
            loadStatistics();
            loadHistory();
        } else {
            showToast(data.error || 'Error analyzing URL', 'error');
        }
    } catch (error) {
        showToast('Failed to connect to API', 'error');
        console.error('Error:', error);
    } finally {
        showLoading(false);
    }
}

// Display Results
function displayResults(data) {
    // Show results section
    resultsSection.style.display = 'block';
    resultsSection.scrollIntoView({ behavior: 'smooth' });
    
    // Update risk badge
    const riskBadge = document.getElementById('riskBadge');
    riskBadge.className = `risk-badge ${data.risk_level}`;
    riskBadge.textContent = data.risk_level.toUpperCase();
    
    // Update summary
    document.getElementById('checkedUrl').textContent = data.url;
    document.getElementById('riskLevel').textContent = data.risk_level.toUpperCase();
    document.getElementById('confidence').textContent = `${(data.confidence * 100).toFixed(1)}%`;
    document.getElementById('threatScore').textContent = `${data.total_score} points`;
    
    // Update recommendation
    const recommendation = document.getElementById('recommendation');
    const rec = data.recommendation;
    recommendation.className = `recommendation ${data.risk_level}`;
    recommendation.innerHTML = `<span style="font-size: 24px;">${rec.icon}</span> ${rec.message}`;
    
    // Display threats
    displayThreats(data.threats_detected);
    
    // Display details
    displayDetails(data.details);
}

// Display Threats
function displayThreats(threats) {
    const threatCount = document.getElementById('threatCount');
    const threatsList = document.getElementById('threatsList');
    
    threatCount.textContent = threats.length;
    
    if (threats.length === 0) {
        threatsList.innerHTML = '<p class="empty-state-text">No threats detected</p>';
        return;
    }
    
    threatsList.innerHTML = threats.map(threat => `
        <div class="threat-item ${threat.severity}">
            <div class="threat-header">
                <span class="threat-type">${threat.type.replace(/_/g, ' ')}</span>
                <span class="threat-severity" style="background: ${getSeverityColor(threat.severity)}">${threat.severity}</span>
            </div>
            <div class="threat-description">${threat.description}</div>
            <div style="margin-top: 8px; font-size: 12px; color: #64748b;">
                Score Impact: +${threat.score} points
            </div>
        </div>
    `).join('');
}

// Display Details
function displayDetails(details) {
    const detailsGrid = document.getElementById('detailsGrid');
    
    detailsGrid.innerHTML = Object.entries(details).map(([key, value]) => `
        <div class="detail-item">
            <div class="detail-label">${key.replace(/_/g, ' ')}</div>
            <div class="detail-value">${formatValue(value)}</div>
        </div>
    `).join('');
}

// Check Batch URLs
async function checkBatchURLs() {
    const batchInput = document.getElementById('batchInput');
    const urls = batchInput.value.split('\n').filter(url => url.trim());
    
    if (urls.length === 0) {
        showToast('Please enter at least one URL', 'warning');
        return;
    }
    
    if (urls.length > 100) {
        showToast('Maximum 100 URLs per batch', 'warning');
        return;
    }
    
    const batchResults = document.getElementById('batchResults');
    batchResults.innerHTML = '<div class="loading-text">Analyzing URLs...</div>';
    
    try {
        const response = await fetch(`${API_BASE_URL}/batch`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ urls })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            displayBatchResults(data);
            showToast(`Analyzed ${data.total} URLs`, 'success');
        } else {
            showToast(data.error || 'Error analyzing URLs', 'error');
        }
    } catch (error) {
        showToast('Failed to connect to API', 'error');
        console.error('Error:', error);
    }
}

// Display Batch Results
function displayBatchResults(data) {
    const batchResults = document.getElementById('batchResults');
    
    const summaryHTML = `
        <div style="background: var(--bg-color); padding: 15px; border-radius: 10px; margin-bottom: 15px;">
            <h3>Summary</h3>
            <p>Safe: ${data.summary.safe} | Suspicious: ${data.summary.suspicious} | Dangerous: ${data.summary.dangerous}</p>
        </div>
    `;
    
    const resultsHTML = data.results.map(result => `
        <div class="batch-item">
            <span class="batch-url">${result.url}</span>
            <span class="history-badge ${result.risk_level}">${result.risk_level}</span>
            <span style="margin-left: 10px; font-weight: 600;">${result.total_score}</span>
        </div>
    `).join('');
    
    batchResults.innerHTML = summaryHTML + resultsHTML;
}

// Load Statistics
async function loadStatistics() {
    try {
        const response = await fetch(`${API_BASE_URL}/stats`);
        const data = await response.json();
        
        document.getElementById('totalAnalyzed').textContent = data.total_analyzed || 0;
        document.getElementById('phishingDetected').textContent = data.phishing_detected || 0;
        document.getElementById('safeUrls').textContent = data.safe_urls || 0;
        document.getElementById('cacheHits').textContent = data.cache_hits || 0;
    } catch (error) {
        console.error('Error loading statistics:', error);
    }
}

// Load History
async function loadHistory() {
    const historyContainer = document.getElementById('historyContainer');
    
    try {
        const response = await fetch(`${API_BASE_URL}/history?limit=20`);
        const data = await response.json();
        
        if (data.history && data.history.length > 0) {
            historyContainer.innerHTML = data.history.map(item => `
                <div class="history-item">
                    <span class="history-url" title="${item.url}">${item.url}</span>
                    <span class="history-badge ${item.risk_level}">${item.risk_level}</span>
                    <span class="history-time">${formatTime(item.timestamp)}</span>
                </div>
            `).join('');
        } else {
            historyContainer.innerHTML = '<p class="empty-state-text">No history yet</p>';
        }
    } catch (error) {
        console.error('Error loading history:', error);
        historyContainer.innerHTML = '<p class="empty-state-text">Error loading history</p>';
    }
}

// Report Phishing
async function reportPhishing() {
    const url = document.getElementById('checkedUrl').textContent;
    const comment = prompt('Optional: Add a comment about this phishing URL');
    
    try {
        const response = await fetch(`${API_BASE_URL}/report`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url, comment: comment || '' })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast('Thank you for reporting!', 'success');
        } else {
            showToast(data.error || 'Error reporting URL', 'error');
        }
    } catch (error) {
        showToast('Failed to report URL', 'error');
        console.error('Error:', error);
    }
}

// Update Blacklist
async function updateBlacklistData() {
    if (!confirm('This will update the blacklist from PhishTank and OpenPhish. Continue?')) {
        return;
    }
    
    showToast('Updating blacklist... This may take a minute', 'warning');
    
    try {
        const response = await fetch(`${API_BASE_URL}/update-blacklist`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast('Blacklist updated successfully!', 'success');
        } else {
            showToast(data.error || 'Error updating blacklist', 'error');
        }
    } catch (error) {
        showToast('Failed to update blacklist', 'error');
        console.error('Error:', error);
    }
}

// Utility Functions
function showLoading(show) {
    const btnText = checkBtn.querySelector('.btn-text');
    const loader = checkBtn.querySelector('.loader');
    
    if (show) {
        btnText.style.display = 'none';
        loader.style.display = 'block';
        checkBtn.disabled = true;
    } else {
        btnText.style.display = 'block';
        loader.style.display = 'none';
        checkBtn.disabled = false;
    }
}

function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = `toast ${type} show`;
    
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

function formatValue(value) {
    if (typeof value === 'boolean') {
        return value ? '✓ Yes' : '✗ No';
    }
    if (value === null || value === undefined) {
        return 'N/A';
    }
    return value.toString();
}

function formatTime(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = Math.floor((now - date) / 1000); // seconds
    
    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
}

function getSeverityColor(severity) {
    const colors = {
        critical: '#dc2626',
        high: '#ef4444',
        medium: '#f59e0b',
        low: '#64748b'
    };
    return colors[severity] || colors.low;
}

// Close modal when clicking outside
window.addEventListener('click', (e) => {
    if (e.target === batchModal) {
        batchModal.style.display = 'none';
    }
});