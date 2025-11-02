const API_BASE_URL = 'http://localhost:5000/api';

// Get current tab URL and analyze
chrome.tabs.query({active: true, currentWindow: true}, async (tabs) => {
    const currentUrl = tabs[0].url;
    
    // Don't analyze chrome:// or extension pages
    if (currentUrl.startsWith('chrome://') || currentUrl.startsWith('chrome-extension://')) {
        document.getElementById('content').innerHTML = `
            <div class="result-badge" style="background: #e2e8f0; color: #475569;">
                <div>Cannot analyze this page</div>
            </div>
            <p style="font-size: 12px; color: #64748b; text-align: center;">
                Browser internal pages cannot be checked
            </p>
        `;
        return;
    }
    
    // Display URL
    document.getElementById('content').innerHTML = `
        <div class="url-display">${currentUrl}</div>
        <div class="loading">Analyzing URL...</div>
    `;
    
    try {
        const response = await fetch(`${API_BASE_URL}/check`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: currentUrl })
        });
        
        const data = await response.json();
        displayResults(data);
        
    } catch (error) {
        document.getElementById('content').innerHTML = `
            <div class="url-display">${currentUrl}</div>
            <div class="result-badge" style="background: #fee2e2; color: #991b1b;">
                <div>❌ Connection Error</div>
            </div>
            <p style="font-size: 12px; color: #64748b; text-align: center;">
                Please ensure the API server is running on localhost:5000
            </p>
        `;
    }
});

function displayResults(data) {
    const icon = {
        'safe': '✅',
        'suspicious': '⚠️',
        'dangerous': '🚫'
    }[data.risk_level] || '❓';
    
    let threatsHTML = '';
    if (data.threats_detected && data.threats_detected.length > 0) {
        threatsHTML = `
            <div class="threats">
                <strong>Threats Found (${data.threats_detected.length}):</strong>
                ${data.threats_detected.slice(0, 3).map(t => `
                    <div class="threat-item">
                        <strong>${t.type.replace(/_/g, ' ')}:</strong> ${t.description}
                    </div>
                `).join('')}
                ${data.threats_detected.length > 3 ? `<div style="text-align: center; margin-top: 5px;">+${data.threats_detected.length - 3} more</div>` : ''}
            </div>
        `;
    }
    
    document.getElementById('content').innerHTML = `
        <div class="url-display">${data.url}</div>
        <div class="result-badge ${data.risk_level}">
            <div style="font-size: 32px; margin-bottom: 5px;">${icon}</div>
            <div>${data.risk_level.toUpperCase()}</div>
        </div>
        <div class="score">Threat Score: ${data.total_score}</div>
        <div style="text-align: center; color: #64748b; font-size: 12px; margin-bottom: 15px;">
            Confidence: ${(data.confidence * 100).toFixed(1)}%
        </div>
        ${threatsHTML}
        <button onclick="openDashboard()">View Full Report</button>
        ${data.risk_level !== 'safe' ? '<button onclick="reportPhishing()" style="background: #f59e0b;">Report as Phishing</button>' : ''}
    `;
}

function openDashboard() {
    chrome.tabs.create({ url: 'http://localhost:5000' });
}

function reportPhishing() {
    chrome.tabs.query({active: true, currentWindow: true}, async (tabs) => {
        const currentUrl = tabs[0].url;
        
        try {
            await fetch(`${API_BASE_URL}/report`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: currentUrl, comment: 'Reported from extension' })
            });
            alert('Thank you for reporting!');
        } catch (error) {
            alert('Failed to report URL');
        }
    });
}