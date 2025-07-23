// Enhanced JavaScript with better UX
let logTrendChart, ruleDistChart, modalRuleChart;
let currentIssueId = null;
let issueChatHistory = [];
let chatHistory = [];
let countdownInterval = null;
let lastUpdateTime = null;
let processingInterval = 300; // Default 5 minutes
let allIssues = []; // Store all issues for filtering
let isGridView = true;
let selectedRuleFilter = null;
let dashboard_data = {};

// Utility Functions
function showToast(message, type = 'success') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);
    
    setTimeout(() => toast.classList.add('show'), 100);
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => document.body.removeChild(toast), 300);
    }, 3000);
}

function renderMarkdown(text) {
    if (!text || typeof text !== 'string') return '';
    
    // Simple markdown rendering for basic formatting
    return text
        // Bold text
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        // Italic text  
        .replace(/\*(.*?)\*/g, '<em>$1</em>')
        // Inline code
        .replace(/`(.*?)`/g, '<code class="bg-gray-700 px-1 py-0.5 rounded text-sm">$1</code>')
        // Code blocks
        .replace(/```(.*?)```/gs, '<pre class="bg-gray-800 p-3 rounded mt-2 mb-2 overflow-x-auto"><code>$1</code></pre>')
        // Line breaks
        .replace(/\n/g, '<br>');
}

function startCountdownTimer() {
    if (countdownInterval) {
        clearInterval(countdownInterval);
    }
    
    const updateCountdown = () => {
        if (!lastUpdateTime) return;
        
        const now = Date.now();
        const nextScan = lastUpdateTime + (processingInterval * 1000);
        const timeLeft = Math.max(0, nextScan - now);
        
        if (timeLeft === 0) {
            document.getElementById('countdown-container').style.display = 'none';
            return;
        }
        
        const minutes = Math.floor(timeLeft / 60000);
        const seconds = Math.floor((timeLeft % 60000) / 1000);
        
        document.getElementById('countdown-timer').textContent = 
            `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
        document.getElementById('countdown-container').style.display = 'flex';
    };
    
    updateCountdown();
    countdownInterval = setInterval(updateCountdown, 1000);
}

function setLoadingState(button, isLoading, originalText) {
    const spinner = button.querySelector('.loading-spinner');
    const text = button.querySelector('.query-btn-text') || button;
    
    if (isLoading) {
        button.disabled = true;
        if (spinner) spinner.classList.remove('hidden');
        if (text !== button) text.textContent = 'Thinking...';
        else button.innerHTML = '<div class="loading-spinner"></div>';
    } else {
        button.disabled = false;
        if (spinner) spinner.classList.add('hidden');
        if (text !== button) text.textContent = originalText;
        else button.textContent = originalText;
    }
}

function initializeCharts() {
    const logTrendCanvas = document.getElementById('logTrendChart');
    const ruleDistCanvas = document.getElementById('ruleDistChart');
    
    if (!logTrendCanvas || !ruleDistCanvas) {
        console.error('Chart canvas elements not found');
        return;
    }
    
    const chartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { 
            legend: { display: false },
            tooltip: {
                backgroundColor: 'rgba(30, 41, 59, 0.9)',
                titleColor: '#f8fafc',
                bodyColor: '#cbd5e1',
                borderColor: 'rgba(148, 163, 184, 0.2)',
                borderWidth: 1,
                cornerRadius: 8,
            }
        },
        scales: {
            x: { 
                ticks: { color: '#94a3b8' }, 
                grid: { color: 'rgba(148, 163, 184, 0.1)' },
                border: { color: 'rgba(148, 163, 184, 0.2)' }
            },
            y: { 
                ticks: { color: '#94a3b8' }, 
                grid: { color: 'rgba(148, 163, 184, 0.1)' },
                border: { color: 'rgba(148, 163, 184, 0.2)' }
            }
        }
    };

    try {
        const trendCtx = logTrendCanvas.getContext('2d');
        logTrendChart = new Chart(trendCtx, {
            type: 'line',
            data: { 
                labels: [], 
                datasets: [{
                    label: 'Logs per Minute', 
                    data: [], 
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    tension: 0.4,
                    fill: true,
                    pointBackgroundColor: '#3b82f6',
                    pointBorderColor: '#1e40af',
                    pointRadius: 4,
                    pointHoverRadius: 6
                }] 
            },
            options: { 
                ...chartOptions,
                height: 200,
                scales: { 
                    ...chartOptions.scales, 
                    x: { 
                        ...chartOptions.scales.x,
                        type: 'category'  // Changed from 'time' to fix display issues
                    } 
                } 
            }
        });
        console.log('Log trend chart initialized');
    } catch (error) {
        console.error('Error initializing log trend chart:', error);
    }

    try {
        const ruleCtx = ruleDistCanvas.getContext('2d');
        ruleDistChart = new Chart(ruleCtx, {
            type: 'doughnut',
            data: { 
                labels: [], 
                datasets: [{
                    label: 'Rule Events', 
                    data: [], 
                    backgroundColor: [
                        '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6',
                        '#06b6d4', '#84cc16', '#f97316', '#ec4899', '#6366f1'
                    ],
                    borderWidth: 2,
                    borderColor: 'rgba(30, 41, 59, 0.8)'
                }] 
            },
            options: { 
                ...chartOptions,
                height: 200,
                onClick: (event, elements) => {
                    if (elements.length > 0) {
                        const index = elements[0].index;
                        const ruleName = ruleDistChart.data.labels[index];
                        openRuleAnalysisModal(ruleName);
                    }
                },
                plugins: { 
                    legend: { 
                        position: 'bottom', 
                        labels: { 
                            color: '#cbd5e1',
                            usePointStyle: true,
                            padding: 15,
                            font: { size: 11 }
                        } 
                    },
                    tooltip: {
                        backgroundColor: 'rgba(30, 41, 59, 0.9)',
                        titleColor: '#f8fafc',
                        bodyColor: '#cbd5e1',
                        borderColor: 'rgba(148, 163, 184, 0.2)',
                        borderWidth: 1,
                        cornerRadius: 8,
                        callbacks: {
                            afterLabel: function(context) {
                                return 'Click to view details';
                            }
                        }
                    }
                } 
            }
        });
        console.log('Rule distribution chart initialized');
    } catch (error) {
        console.error('Error initializing rule distribution chart:', error);
    }
}

function openRuleAnalysisModal(selectedRule = null) {
    const modal = document.getElementById('rule-analysis-modal');
    selectedRuleFilter = selectedRule;
    
    // Update the large chart in the modal
    updateRuleAnalysisModal();
    
    modal.style.display = 'flex';
}

function updateRuleAnalysisModal() {
    const container = document.getElementById('rule-issues-container');
    
    // Initialize or update the large chart
    if (!modalRuleChart) {
        const ctx = document.getElementById('modalRuleChart').getContext('2d');
        
        modalRuleChart = new Chart(ctx, {
            type: 'doughnut',
            data: { 
                labels: [], 
                datasets: [{
                    label: 'Rule Events', 
                    data: [], 
                    backgroundColor: [
                        '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6',
                        '#06b6d4', '#84cc16', '#f97316', '#ec4899', '#6366f1',
                        '#14b8a6', '#a855f7', '#f59e0b', '#ef4444', '#3b82f6'
                    ],
                    borderWidth: 2,
                    borderColor: 'rgba(30, 41, 59, 0.8)'
                }] 
            },
            options: { 
                responsive: true,
                maintainAspectRatio: false,
                height: 400,
                onClick: (event, elements) => {
                    if (elements.length > 0) {
                        const index = elements[0].index;
                        const ruleName = modalRuleChart.data.labels[index];
                        selectedRuleFilter = ruleName;
                        filterRuleIssues();
                    }
                },
                plugins: { 
                    legend: { 
                        position: 'bottom', 
                        labels: { 
                            color: '#cbd5e1',
                            usePointStyle: true,
                            padding: 15,
                            font: { size: 12 }
                        } 
                    },
                    tooltip: {
                        backgroundColor: 'rgba(30, 41, 59, 0.9)',
                        titleColor: '#f8fafc',
                        bodyColor: '#cbd5e1',
                        borderColor: 'rgba(148, 163, 184, 0.2)',
                        borderWidth: 1,
                        cornerRadius: 8,
                        callbacks: {
                            afterLabel: function(context) {
                                return 'Click to filter issues by this rule';
                            }
                        }
                    }
                } 
            }
        });
    }
    
    // Update chart data
    const ruleData = dashboard_data.rule_distribution || {};
    const sortedRules = Object.entries(ruleData)
        .sort(([,a],[,b]) => b-a)
        .slice(0, 15); // Show top 15 in the modal
    
    modalRuleChart.data.labels = sortedRules.map(([rule]) => rule);
    modalRuleChart.data.datasets[0].data = sortedRules.map(([,count]) => count);
    modalRuleChart.update();
    
    // Filter issues based on selected rule
    filterRuleIssues();
}

function filterRuleIssues() {
    const severityFilter = document.getElementById('rule-severity-filter').value;
    const searchTerm = document.getElementById('rule-search-issues').value.toLowerCase();
    const container = document.getElementById('rule-issues-container');
    
    let filteredIssues = [...allIssues];
    
    // Filter by rule if one is selected
    if (selectedRuleFilter) {
        filteredIssues = filteredIssues.filter(issue => {
            return issue.summary.toLowerCase().includes(selectedRuleFilter.toLowerCase()) ||
                   issue.title.toLowerCase().includes(selectedRuleFilter.toLowerCase()) ||
                   issue.recommendation.toLowerCase().includes(selectedRuleFilter.toLowerCase());
        });
    }
    
    // Apply severity filter
    if (severityFilter) {
        filteredIssues = filteredIssues.filter(issue => issue.severity === severityFilter);
    }
    
    // Apply search filter
    if (searchTerm) {
        filteredIssues = filteredIssues.filter(issue => 
            issue.title.toLowerCase().includes(searchTerm) ||
            issue.summary.toLowerCase().includes(searchTerm)
        );
    }
    
    // Update counter
    document.getElementById('rule-filtered-count').textContent = 
        `Showing ${filteredIssues.length} of ${allIssues.length} issues`;
    
    // Display issues
    displayRuleIssues(filteredIssues);
}

function displayRuleIssues(issues) {
    const container = document.getElementById('rule-issues-container');
    container.innerHTML = '';
    
    if (issues.length === 0) {
        container.innerHTML = `
            <div class="col-span-full text-center py-12">
                <div class="w-16 h-16 mx-auto mb-4 rounded-full bg-blue-500/20 flex items-center justify-center">
                    <span class="text-2xl">🔍</span>
                </div>
                <p class="text-gray-400 text-lg">${selectedRuleFilter ? `No issues found for rule: ${selectedRuleFilter}` : 'No issues match your filters'}</p>
                <p class="text-gray-500 text-sm mt-2">Try adjusting your search criteria</p>
            </div>
        `;
        return;
    }

    issues.forEach((issue, index) => {
        const issueEl = document.createElement('div');
        issueEl.className = `glass-card p-4 severity-${issue.severity} h-fit`;
        
        const severityIcons = {
            'Critical': '🚨',
            'High': '⚠️',
            'Medium': '🔶',
            'Low': 'ℹ️'
        };
        
        const severityColors = {
            'Critical': 'text-red-400 bg-red-500/20',
            'High': 'text-orange-400 bg-orange-500/20',
            'Medium': 'text-yellow-400 bg-yellow-500/20',
            'Low': 'text-green-400 bg-green-500/20'
        };

        const relatedLogsHtml = issue.related_logs && issue.related_logs.length > 0 
            ? issue.related_logs.slice(0, 3).map(logId => 
                `<button class="log-button text-xs" data-log-id="${logId}" title="Click to view log details">
                    ${logId.substring(0, 6)}...
                </button>`
              ).join('')
            : '<span class="text-gray-500 text-xs">No logs</span>';

        issueEl.innerHTML = `
            <div class="flex justify-between items-start mb-3">
                <div class="flex items-center gap-2">
                    <div class="w-6 h-6 rounded ${severityColors[issue.severity]} flex items-center justify-center text-sm">
                        ${severityIcons[issue.severity]}
                    </div>
                    <div>
                        <span class="text-xs font-bold uppercase ${severityColors[issue.severity].split(' ')[0]} block">
                            ${issue.severity}
                        </span>
                        <h3 class="font-bold text-sm text-white leading-tight">${issue.title}</h3>
                    </div>
                </div>
                <span class="text-xs text-gray-500 bg-gray-800/50 px-2 py-1 rounded">
                    ${new Date(issue.timestamp).toLocaleTimeString()}
                </span>
            </div>
            
            <div class="text-gray-300 mb-3 text-sm leading-relaxed line-clamp-3">${renderMarkdown(issue.summary)}</div>
            
            <details class="mb-3">
                <summary class="cursor-pointer text-blue-400 hover:text-blue-300 text-sm mb-2">
                    📋 Details & Logs
                </summary>
                <div class="mt-2 p-3 bg-black/20 rounded border border-gray-700/50">
                    <div class="mb-3">
                        <h4 class="font-semibold text-white text-sm mb-1">🎯 Actions:</h4>
                        <div class="text-gray-300 text-sm">${renderMarkdown(issue.recommendation.substring(0, 200))}${issue.recommendation.length > 200 ? '...' : ''}</div>
                    </div>
                    <div>
                        <h4 class="font-semibold text-white text-sm mb-1">📄 Logs (${issue.related_logs ? issue.related_logs.length : 0}):</h4>
                        <div class="flex flex-wrap gap-1">
                            ${relatedLogsHtml}
                        </div>
                    </div>
                </div>
            </details>
            
            <div class="flex gap-1 flex-wrap">
                <button class="action-btn ignore-btn text-xs py-1 px-2" data-issue-id="${issue.id}">
                    🗑️ Ignore
                </button>
                <button class="action-btn chat-btn text-xs py-1 px-2" data-issue-id="${issue.id}" data-issue-title="${issue.title}">
                    💬 Chat
                </button>
                <button class="action-btn script-btn text-xs py-1 px-2" data-issue-id="${issue.id}" data-issue-title="${issue.title}">
                    🔧 Script
                </button>
            </div>
        `;
        container.appendChild(issueEl);
    });
}

async function updateUI(data) {
    dashboard_data = data;
    
    // Update header info
    document.getElementById('last-run').textContent = data.last_run ? 
        new Date(data.last_run).toLocaleString() : 'Never';
    document.getElementById('ai-summary').innerHTML = renderMarkdown(data.summary);
    document.getElementById('active-api-key').textContent = `Key ${(data.active_api_key_index || 0) + 1}`;
    
    // Update application status and handle countdown
    const status = data.status || 'Unknown';
    document.getElementById('app-status').textContent = status;
    
    // Update processing interval and start countdown if idle/ready
    if (data.settings && data.settings.processing_interval) {
        processingInterval = data.settings.processing_interval;
    }
    
    if (data.last_run) {
        lastUpdateTime = new Date(data.last_run).getTime();
        if (status === 'Ready' || status === 'Idle') {
            startCountdownTimer();
        } else {
            document.getElementById('countdown-container').style.display = 'none';
        }
    }
    
    // Store all issues for filtering
    allIssues = data.issues || [];
    
    // Update statistics with animations
    updateStatWithAnimation('total-logs', data.stats.total_logs);
    updateStatWithAnimation('new-logs', data.stats.new_logs);
    updateStatWithAnimation('anomalies', data.stats.anomalies);
    
    // Sort issues by timestamp (most recent first) and show first 10 in widget
    const sortedIssues = [...allIssues].sort((a, b) => 
        new Date(b.timestamp) - new Date(a.timestamp)
    );
    const displayIssues = sortedIssues.slice(0, 10);
    
    updateIssuesDisplay(displayIssues, false); // false = no filtering controls in main widget

    // Update charts
    updateCharts(data);
}

function updateStatWithAnimation(elementId, newValue) {
    const element = document.getElementById(elementId);
    const currentValue = parseInt(element.textContent.replace(/,/g, '')) || 0;
    
    if (currentValue !== newValue) {
        element.style.transform = 'scale(1.1)';
        setTimeout(() => {
            element.textContent = newValue.toLocaleString();
            element.style.transform = 'scale(1)';
        }, 150);
    }
}

function updateIssuesDisplay(issues, showFilters = true) {
    const container = document.getElementById('issues-container');
    
    if (!container) {
        console.error('Issues container not found');
        return;
    }
    
    container.innerHTML = '';
    
    if (!issues || issues.length === 0) {
        container.innerHTML = `
            <div class="text-center py-12">
                <div class="w-16 h-16 mx-auto mb-4 rounded-full bg-green-500/20 flex items-center justify-center">
                    <span class="text-2xl">✅</span>
                </div>
                <p class="text-gray-400 text-lg">No security issues found</p>
                <p class="text-gray-500 text-sm mt-2">Your systems appear secure</p>
            </div>
        `;
        return;
    }

    console.log(`Displaying ${issues.length} issues in main widget`);

    issues.forEach((issue, index) => {
        try {
            const issueEl = document.createElement('div');
            issueEl.className = `glass-card p-6 severity-${issue.severity || 'Low'}`;
            issueEl.style.animationDelay = `${index * 0.1}s`;
            
            const severityIcons = {
                'Critical': '🚨',
                'High': '⚠️',
                'Medium': '🔶',
                'Low': 'ℹ️'
            };
            
            const severityColors = {
                'Critical': 'text-red-400 bg-red-500/20',
                'High': 'text-orange-400 bg-orange-500/20',
                'Medium': 'text-yellow-400 bg-yellow-500/20',
                'Low': 'text-green-400 bg-green-500/20'
            };

            // Format related logs with proper display - Fixed to ensure logs are shown
            const relatedLogsHtml = issue.related_logs && issue.related_logs.length > 0 
                ? issue.related_logs.map((logId, idx) => {
                    // Handle both string IDs and objects
                    const actualLogId = typeof logId === 'string' ? logId : (logId.id || logId.sha256 || String(logId));
                    return `<button class="log-button" data-log-id="${actualLogId}" title="Click to view log details">
                        Log ${idx + 1}: ${actualLogId.substring(0, 8)}...
                    </button>`;
                  }).join('')
                : '<span class="text-gray-500 text-sm">No related logs available</span>';

            const severity = issue.severity || 'Low';
            const title = escapeHtml(issue.title || 'Untitled Issue');
            const summary = issue.summary || 'No summary available';
            const recommendation = issue.recommendation || 'No recommendations available';
            const timestamp = issue.timestamp ? new Date(issue.timestamp).toLocaleTimeString() : 'Unknown time';

            issueEl.innerHTML = `
                <div class="flex justify-between items-start mb-4">
                    <div class="flex items-center gap-3">
                        <div class="w-8 h-8 rounded-lg ${severityColors[severity]} flex items-center justify-center">
                            ${severityIcons[severity]}
                        </div>
                        <div>
                            <span class="text-xs font-bold uppercase ${severityColors[severity].split(' ')[0]} block mb-1">
                                ${severity} Severity
                            </span>
                            <h3 class="font-bold text-lg text-white">${title}</h3>
                        </div>
                    </div>
                    <span class="text-xs text-gray-500 bg-gray-800/50 px-2 py-1 rounded">
                        ${timestamp}
                    </span>
                </div>
                
                <div class="text-gray-300 mb-4 leading-relaxed">${renderMarkdown(summary)}</div>
                
                <details class="mb-4">
                    <summary class="cursor-pointer text-blue-400 hover:text-blue-300 font-medium mb-2" onclick="event.stopPropagation();">
                        📋 View Recommendations & Related Logs
                    </summary>
                    <div class="mt-3 p-4 bg-black/20 rounded-lg border border-gray-700/50" onclick="event.stopPropagation();">
                        <div class="mb-4">
                            <h4 class="font-semibold text-white mb-2">🎯 Recommended Actions:</h4>
                            <div class="text-gray-300 whitespace-pre-wrap leading-relaxed">${renderMarkdown(recommendation)}</div>
                        </div>
                        <div>
                            <h4 class="font-semibold text-white mb-2">📄 Related Logs (${issue.related_logs ? issue.related_logs.length : 0}):</h4>
                            <div class="flex flex-wrap gap-2">
                                ${relatedLogsHtml}
                            </div>
                        </div>
                    </div>
                </details>
                
                <div class="issue-actions">
                    <button class="action-btn ignore-btn" data-issue-id="${issue.id || ''}">
                        🗑️ Ignore Issue
                    </button>
                    <button class="action-btn chat-btn" data-issue-id="${issue.id || ''}" data-issue-title="${title}">
                        💬 Chat About This
                    </button>
                    <button class="action-btn script-btn" data-issue-id="${issue.id || ''}" data-issue-title="${title}">
                        🔧 Generate Fix Script
                    </button>
                </div>
            `;
            container.appendChild(issueEl);
        } catch (error) {
            console.error(`Error rendering issue ${index}:`, error, issue);
        }
    });
    
    // Update issue count to show total issues
    const countElement = document.getElementById('issue-count');
    if (countElement) {
        countElement.textContent = allIssues.length;
    }
}

function updateCharts(data) {
    // Update trend chart with proper data formatting
    if (data.log_trend && data.log_trend.length > 0) {
        const trendLabels = data.log_trend.map(d => d.time);
        const trendData = data.log_trend.map(d => d.count);
        
        logTrendChart.data.labels = trendLabels;
        logTrendChart.data.datasets[0].data = trendData;
    } else {
        // Show empty state with sample data points
        logTrendChart.data.labels = ['Now-60min', 'Now-45min', 'Now-30min', 'Now-15min', 'Now'];
        logTrendChart.data.datasets[0].data = [0, 0, 0, 0, 0];
    }
    
    logTrendChart.options.maintainAspectRatio = false;
    logTrendChart.options.responsive = true;
    logTrendChart.update('none');

    // Update rule distribution chart with bounds checking
    if (data.rule_distribution && Object.keys(data.rule_distribution).length > 0) {
        const sortedRules = Object.entries(data.rule_distribution)
            .sort(([,a],[,b]) => b-a)
            .slice(0, 10);
            
        ruleDistChart.data.labels = sortedRules.map(([rule]) => 
            rule.length > 30 ? rule.substring(0, 27) + '...' : rule
        );
        ruleDistChart.data.datasets[0].data = sortedRules.map(([,count]) => count);
    } else {
        // Show empty state
        ruleDistChart.data.labels = ['No data available'];
        ruleDistChart.data.datasets[0].data = [1];
    }
    
    ruleDistChart.options.maintainAspectRatio = false;
    ruleDistChart.options.responsive = true;
    ruleDistChart.update('none');
    
    // Update modal chart if it exists
    if (modalRuleChart) {
        updateRuleAnalysisModal();
    }
}

async function fetchData() {
    const statusIndicator = document.getElementById('status-indicator');
    
    try {
        console.log('Fetching dashboard data...');
        statusIndicator.className = 'w-4 h-4 rounded-full status-connecting animate-pulse';
        statusIndicator.title = 'Connecting...';
        
        const response = await fetch('/api/dashboard');
        console.log('Dashboard API response status:', response.status);
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        console.log('Dashboard data received:', {
            issueCount: data.issues ? data.issues.length : 0,
            totalLogs: data.stats ? data.stats.total_logs : 0,
            status: data.status
        });
        
        await updateUI(data);
        statusIndicator.className = 'w-4 h-4 rounded-full status-connected';
        statusIndicator.title = `Connected. Last update: ${new Date(data.last_run || Date.now()).toLocaleString()}`;
        
    } catch (error) {
        console.error("Failed to fetch dashboard data:", error);
        
        // Update UI with error state
        document.getElementById('ai-summary').textContent = 'Error: Could not connect to the backend service. Please check if the server is running.';
        statusIndicator.className = 'w-4 h-4 rounded-full status-disconnected';
        statusIndicator.title = `Connection failed: ${error.message}`;
        
        // Show error in issues container
        const issuesContainer = document.getElementById('issues-container');
        if (issuesContainer) {
            issuesContainer.innerHTML = `
                <div class="text-center py-12">
                    <div class="w-16 h-16 mx-auto mb-4 rounded-full bg-red-500/20 flex items-center justify-center">
                        <span class="text-2xl">❌</span>
                    </div>
                    <p class="text-red-400 text-lg">Connection Failed</p>
                    <p class="text-gray-500 text-sm mt-2">Unable to fetch security data from server</p>
                    <button onclick="fetchData()" class="mt-4 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">
                        Retry Connection
                    </button>
                </div>
            `;
        }
        
        showToast('Failed to fetch dashboard data. Check console for details.', 'error');
    }
}

async function triggerAnalysis() {
    const btn = document.getElementById('find-more-btn');
    const originalText = btn.textContent;
    
    try {
        setLoadingState(btn, true, originalText);
        document.getElementById('issues-loading').classList.remove('hidden');
        
        const response = await fetch('/api/analyze', { method: 'POST' });
        if (!response.ok) throw new Error('Failed to trigger analysis');
        
        showToast('Analysis triggered successfully!');
        fetchData();
    } catch (error) {
        console.error("Failed to trigger analysis:", error);
        showToast('Failed to trigger analysis', 'error');
    } finally {
        setLoadingState(btn, false, '🔍 Find More Issues');
        document.getElementById('issues-loading').classList.add('hidden');
    }
}

async function ignoreIssue(issueId) {
    try {
        const response = await fetch(`/api/issues/${issueId}/ignore`, { method: 'POST' });
        if (!response.ok) throw new Error('Failed to ignore issue');
        
        showToast('Issue ignored successfully');
        fetchData();
    } catch (error) {
        console.error("Failed to ignore issue:", error);
        showToast('Failed to ignore issue', 'error');
    }
}

async function openIssueQueryModal(issueId, issueTitle) {
    currentIssueId = issueId;
    issueChatHistory = [];
    document.getElementById('issue-title').textContent = issueTitle;
    const issueChatContainer = document.getElementById('issue-chat-container');
    issueChatContainer.innerHTML = `
        <div class="chat-bubble chat-ai">
            👋 I'm here to help you understand and resolve this security issue. What would you like to know?
        </div>
    `;
    document.getElementById('issue-query-modal').style.display = 'flex';
    document.getElementById('issue-query-input').focus();
}

async function handleIssueQuery() {
    const query = document.getElementById('issue-query-input').value.trim();
    if (!query || !currentIssueId) return;
    
    const btn = document.getElementById('issue-query-btn');
    const issueChatContainer = document.getElementById('issue-chat-container');
    
    appendChatMessage(issueChatContainer, query, 'chat-user');
    document.getElementById('issue-query-input').value = '';
    
    setLoadingState(btn, true, 'Send');
    
    try {
        const response = await fetch(`/api/issues/${currentIssueId}/query`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query: query, history: issueChatHistory })
        });
        const result = await response.json();
        appendChatMessage(issueChatContainer, result.answer, 'chat-ai');
        issueChatHistory.push({ user: query, ai: result.answer });
    } catch (error) {
        appendChatMessage(issueChatContainer, `❌ Error: ${error.message}`, 'chat-ai');
    } finally {
        setLoadingState(btn, false, 'Send');
        issueChatContainer.scrollTop = issueChatContainer.scrollHeight;
    }
}

async function handleQuery() {
    const query = document.getElementById('query-input').value.trim();
    if (!query) return;
    
    const btn = document.getElementById('query-btn');
    const chatContainer = document.getElementById('chat-container');
    
    appendChatMessage(chatContainer, query, 'chat-user');
    document.getElementById('query-input').value = '';
    
    setChatButtonStatus(btn, 'Starting analysis...');
    
    try {
        // Step 1: Initial analysis and planning
        setChatButtonStatus(btn, 'Analyzing query...');
        const response = await fetch('/api/chat/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                query: query, 
                history: chatHistory.slice(-3) // Last 3 exchanges
            })
        });
        
        if (!response.ok) {
            throw new Error(`Analysis failed: ${response.status}`);
        }
        
        const analysisResult = await response.json();
        
        // Step 2: Execute the planned searches and get final response
        setChatButtonStatus(btn, 'Searching logs...');
        const finalResponse = await fetch('/api/chat/execute', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                query: query,
                analysis: analysisResult,
                history: chatHistory.slice(-3)
            })
        });
        
        if (!finalResponse.ok) {
            throw new Error(`Execution failed: ${finalResponse.status}`);
        }
        
        const result = await finalResponse.json();
        appendChatMessage(chatContainer, result.answer, 'chat-ai');
        chatHistory.push({ user: query, ai: result.answer });
        
    } catch (error) {
        console.error('Chat error:', error);
        appendChatMessage(chatContainer, `❌ Error: ${error.message}`, 'chat-ai');
    } finally {
        setChatButtonStatus(btn, 'idle');
        chatContainer.scrollTop = chatContainer.scrollHeight;
    }
}

function clearChat() {
    const chatContainer = document.getElementById('chat-container');
    chatHistory = [];
    chatContainer.innerHTML = `
        <div class="chat-bubble chat-ai">
            👋 Hello! I'm your AI security analyst. Ask me anything about your logs, threats, or security issues.
        </div>
    `;
}

function appendChatMessage(container, message, className) {
    const bubble = document.createElement('div');
    bubble.className = `chat-bubble ${className} text-white whitespace-pre-wrap`;
    
    if (className === 'chat-ai') {
        bubble.innerHTML = renderMarkdown(message);
    } else {
        bubble.textContent = message;
    }
    
    container.appendChild(bubble);
    container.scrollTop = container.scrollHeight;
}

function setChatButtonStatus(button, status) {
    const spinner = button.querySelector('.loading-spinner');
    const text = button.querySelector('.query-btn-text');
    
    if (status === 'idle') {
        button.disabled = false;
        if (spinner) spinner.classList.add('hidden');
        text.textContent = 'Send';
    } else {
        button.disabled = true;
        if (spinner) spinner.classList.remove('hidden');
        text.textContent = status;
    }
}

async function generateScript(issueId, issueTitle) {
    document.getElementById('script-issue-title').textContent = issueTitle;
    document.getElementById('script-content').innerHTML = `
        <div class="flex items-center gap-2 text-blue-400">
            <div class="loading-spinner"></div>
            Generating comprehensive diagnosis and repair script...
        </div>
    `;
    document.getElementById('script-modal').style.display = 'flex';
    
    try {
        const response = await fetch(`/api/issues/${issueId}/generate-script`, { method: 'POST' });
        if (!response.ok) throw new Error('Failed to generate script');
        const result = await response.json();
        document.getElementById('script-content').textContent = result.script;
        showToast('Script generated successfully!');
    } catch (error) {
        document.getElementById('script-content').textContent = `❌ Error generating script: ${error.message}`;
        showToast('Failed to generate script', 'error');
    }
}

function openFullIssuesModal(issues) {
    const modal = document.getElementById('full-issues-modal');
    const container = document.getElementById('full-issues-container');
    allIssues = issues; // Store for filtering
    
    displayModalIssues(issues);
    modal.style.display = 'flex';
}

function displayModalIssues(issues) {
    const container = document.getElementById('full-issues-container');
    
    if (!container) {
        console.error('Full issues container not found');
        return;
    }
    
    container.innerHTML = '';
    
    if (!issues || issues.length === 0) {
        container.innerHTML = `
            <div class="col-span-full text-center py-12">
                <div class="w-16 h-16 mx-auto mb-4 rounded-full bg-green-500/20 flex items-center justify-center">
                    <span class="text-2xl">✅</span>
                </div>
                <p class="text-gray-400 text-lg">No security issues match your filters</p>
                <p class="text-gray-500 text-sm mt-2">Try adjusting your search criteria</p>
            </div>
        `;
        return;
    }

    // Update grid/list classes
    if (isGridView) {
        container.className = 'grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 max-h-[70vh] overflow-y-auto custom-scrollbar';
    } else {
        container.className = 'space-y-4 max-h-[70vh] overflow-y-auto custom-scrollbar';
    }

    // Limit issues to prevent performance issues
    const issuesToDisplay = issues.slice(0, 100); // Show max 100 issues in modal
    
    console.log(`Displaying ${issuesToDisplay.length} issues in modal`);

    issuesToDisplay.forEach((issue, index) => {
        try {
            const issueEl = document.createElement('div');
            issueEl.className = `glass-card p-4 severity-${issue.severity} ${isGridView ? 'h-fit' : ''}`;
            
            const severityIcons = {
                'Critical': '🚨',
                'High': '⚠️',
                'Medium': '🔶',
                'Low': 'ℹ️'
            };
            
            const severityColors = {
                'Critical': 'text-red-400 bg-red-500/20',
                'High': 'text-orange-400 bg-orange-500/20',
                'Medium': 'text-yellow-400 bg-yellow-500/20',
                'Low': 'text-green-400 bg-green-500/20'
            };

            const relatedLogsHtml = issue.related_logs && issue.related_logs.length > 0 
                ? issue.related_logs.slice(0, 3).map((logId, idx) => {
                    // Handle both string IDs and objects
                    const actualLogId = typeof logId === 'string' ? logId : (logId.id || logId.sha256 || String(logId));
                    return `<button class="log-button text-xs" data-log-id="${actualLogId}" title="Click to view log details">
                        ${actualLogId.substring(0, 6)}...
                    </button>`;
                  }).join('')
                : '<span class="text-gray-500 text-xs">No logs</span>';

            issueEl.innerHTML = `
                <div class="flex justify-between items-start mb-3">
                    <div class="flex items-center gap-2">
                        <div class="w-6 h-6 rounded ${severityColors[issue.severity]} flex items-center justify-center text-sm">
                            ${severityIcons[issue.severity]}
                        </div>
                        <div>
                            <span class="text-xs font-bold uppercase ${severityColors[issue.severity].split(' ')[0]} block">
                                ${issue.severity}
                            </span>
                            <h3 class="font-bold text-sm text-white leading-tight">${escapeHtml(issue.title || 'Untitled Issue')}</h3>
                        </div>
                    </div>
                    <span class="text-xs text-gray-500 bg-gray-800/50 px-2 py-1 rounded">
                        ${new Date(issue.timestamp).toLocaleTimeString()}
                    </span>
                </div>
                
                <div class="text-gray-300 mb-3 text-sm leading-relaxed ${isGridView ? 'line-clamp-3' : ''}">${renderMarkdown(issue.summary || 'No summary available')}</div>
                
                <details class="mb-3">
                    <summary class="cursor-pointer text-blue-400 hover:text-blue-300 text-sm mb-2" onclick="event.stopPropagation();">
                        📋 Details & Logs
                    </summary>
                    <div class="mt-2 p-3 bg-black/20 rounded border border-gray-700/50" onclick="event.stopPropagation();">
                        <div class="mb-3">
                            <h4 class="font-semibold text-white text-sm mb-1">🎯 Actions:</h4>
                            <div class="text-gray-300 text-sm">${renderMarkdown((issue.recommendation || 'No recommendations available').substring(0, 200))}${(issue.recommendation && issue.recommendation.length > 200) ? '...' : ''}</div>
                        </div>
                        <div>
                            <h4 class="font-semibold text-white text-sm mb-1">📄 Logs (${issue.related_logs ? issue.related_logs.length : 0}):</h4>
                            <div class="flex flex-wrap gap-1">
                                ${relatedLogsHtml}
                            </div>
                        </div>
                    </div>
                </details>
                
                <div class="flex gap-1 flex-wrap">
                    <button class="action-btn ignore-btn text-xs py-1 px-2" data-issue-id="${issue.id}">
                        🗑️ Ignore
                    </button>
                    <button class="action-btn chat-btn text-xs py-1 px-2" data-issue-id="${issue.id}" data-issue-title="${escapeHtml(issue.title || '')}">
                        💬 Chat
                    </button>
                    <button class="action-btn script-btn text-xs py-1 px-2" data-issue-id="${issue.id}" data-issue-title="${escapeHtml(issue.title || '')}">
                        🔧 Script
                    </button>
                </div>
            `;
            container.appendChild(issueEl);
        } catch (error) {
            console.error(`Error rendering issue ${index}:`, error, issue);
        }
    });
    
    console.log(`Successfully displayed ${issuesToDisplay.length} issues in modal`);
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function applyModalFilters() {
    const severityFilter = document.getElementById('modal-severity-filter').value;
    const sortBy = document.getElementById('modal-sort-issues').value;
    const searchTerm = document.getElementById('modal-search-issues').value.toLowerCase();
    
    let filteredIssues = [...allIssues];
    
    // Apply severity filter
    if (severityFilter) {
        filteredIssues = filteredIssues.filter(issue => issue.severity === severityFilter);
    }
    
    // Apply search filter
    if (searchTerm) {
        filteredIssues = filteredIssues.filter(issue => 
            issue.title.toLowerCase().includes(searchTerm) ||
            issue.summary.toLowerCase().includes(searchTerm)
        );
    }
    
    // Apply sorting
    filteredIssues.sort((a, b) => {
        switch(sortBy) {
            case 'timestamp-desc':
                return new Date(b.timestamp) - new Date(a.timestamp);
            case 'timestamp-asc':
                return new Date(a.timestamp) - new Date(b.timestamp);
            case 'severity-desc':
                const severityOrder = { Critical: 4, High: 3, Medium: 2, Low: 1 };
                return severityOrder[b.severity] - severityOrder[a.severity];
            case 'severity-asc':
                const severityOrderAsc = { Critical: 4, High: 3, Medium: 2, Low: 1 };
                return severityOrderAsc[a.severity] - severityOrderAsc[b.severity];
            case 'title-asc':
                return a.title.localeCompare(b.title);
            default:
                return 0;
        }
    });
    
    displayModalIssues(filteredIssues);
}

// Modal Functions
const logModal = document.getElementById('log-modal');
const issueQueryModal = document.getElementById('issue-query-modal');
const settingsModal = document.getElementById('settings-modal');
const scriptModal = document.getElementById('script-modal');
const fullIssuesModal = document.getElementById('full-issues-modal');
const ruleAnalysisModal = document.getElementById('rule-analysis-modal');

async function showLogModal(logId) {
    const logContent = document.getElementById('log-content');
    logContent.innerHTML = '<div class="loading-spinner"></div> Loading log details...';
    logModal.style.display = 'flex';
    
    try {
        const res = await fetch(`/api/logs/${logId}`);
        if (!res.ok) throw new Error(`Failed to fetch log ${logId}`);
        const data = await res.json();
        logContent.textContent = JSON.stringify(data, null, 2);
    } catch (e) {
        logContent.textContent = `❌ Error: ${e.message}`;
    }
}

// Event Listeners
document.addEventListener('click', (event) => {
    // Log buttons
    if (event.target.matches('.log-button')) {
        showLogModal(event.target.dataset.logId);
    }
    
    // Issue action buttons
    if (event.target.matches('.ignore-btn')) {
        if (confirm('Are you sure you want to ignore this security issue?')) {
            ignoreIssue(event.target.dataset.issueId);
        }
    }
    
    if (event.target.matches('.chat-btn')) {
        openIssueQueryModal(event.target.dataset.issueId, event.target.dataset.issueTitle);
    }
    
    if (event.target.matches('.script-btn')) {
        generateScript(event.target.dataset.issueId, event.target.dataset.issueTitle);
    }
});

document.addEventListener('DOMContentLoaded', () => {
    initializeCharts();
    fetchData();
    setInterval(fetchData, 30000); // Refresh data every 30 seconds

    // Main chat
    document.getElementById('query-btn').addEventListener('click', handleQuery);
    document.getElementById('query-input').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') handleQuery();
    });
    document.getElementById('clear-chat-btn').addEventListener('click', clearChat);

    // Issue chat
    document.getElementById('issue-query-btn').addEventListener('click', handleIssueQuery);
    document.getElementById('issue-query-input').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') handleIssueQuery();
    });

    // Modals
    document.getElementById('close-log-modal-btn').addEventListener('click', () => logModal.style.display = 'none');
    document.getElementById('close-issue-query-modal-btn').addEventListener('click', () => issueQueryModal.style.display = 'none');
    document.getElementById('close-settings-modal-btn').addEventListener('click', () => settingsModal.style.display = 'none');
    document.getElementById('close-script-modal-btn').addEventListener('click', () => scriptModal.style.display = 'none');
    document.getElementById('close-full-issues-modal-btn').addEventListener('click', () => fullIssuesModal.style.display = 'none');
    document.getElementById('close-rule-analysis-modal-btn').addEventListener('click', () => ruleAnalysisModal.style.display = 'none');

    document.getElementById('settings-btn').addEventListener('click', () => settingsModal.style.display = 'flex');
    document.getElementById('find-more-btn').addEventListener('click', triggerAnalysis);

    // Full issues modal filtering
    document.getElementById('modal-severity-filter').addEventListener('change', applyModalFilters);
    document.getElementById('modal-sort-issues').addEventListener('change', applyModalFilters);
    document.getElementById('modal-search-issues').addEventListener('input', applyModalFilters);
    document.getElementById('modal-clear-filters').addEventListener('click', () => {
        document.getElementById('modal-severity-filter').value = '';
        document.getElementById('modal-sort-issues').value = 'timestamp-desc';
        document.getElementById('modal-search-issues').value = '';
        applyModalFilters();
    });

    // Rule analysis modal filtering
    document.getElementById('rule-severity-filter').addEventListener('change', filterRuleIssues);
    document.getElementById('rule-search-issues').addEventListener('input', filterRuleIssues);
    document.getElementById('rule-clear-filters').addEventListener('click', () => {
        document.getElementById('rule-severity-filter').value = '';
        document.getElementById('rule-search-issues').value = '';
        selectedRuleFilter = null;
        filterRuleIssues();
    });

    // Grid/List view toggle
    document.getElementById('grid-view-btn').addEventListener('click', () => {
        isGridView = true;
        applyModalFilters();
    });
    document.getElementById('list-view-btn').addEventListener('click', () => {
        isGridView = false;
        applyModalFilters();
    });

    // Click handlers for opening modals
    document.getElementById('security-issues-header').addEventListener('click', () => openFullIssuesModal(allIssues));
    document.getElementById('rule-chart-card').addEventListener('click', () => openRuleAnalysisModal());
});
