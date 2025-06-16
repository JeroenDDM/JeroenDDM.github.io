class QueueMonitor {
    constructor() {
        this.platformClient = null;
        this.clientApp = null;
        this.routingApi = null;
        this.analyticsApi = null;
        this.queues = [];
        this.filteredQueues = [];
        this.refreshInterval = null;
        this.isLoading = false;
        
        this.initializeApp();
        this.setupEventListeners();
    }

    async initializeApp() {
        try {
            // Initialize the Client App SDK
            // Try to get environment from query parameters first (for interaction widgets)
            const urlParams = new URLSearchParams(window.location.search);
            let clientAppConfig = {};
            
            if (urlParams.has('gcHostOrigin') && urlParams.has('gcTargetEnv')) {
                // Running as interaction widget with Genesys Cloud query params
                clientAppConfig = {
                    gcHostOriginQueryParam: 'gcHostOrigin',
                    gcTargetEnvQueryParam: 'gcTargetEnv'
                };
            } else if (urlParams.has('pcEnvironment')) {
                // Alternative parameter format
                clientAppConfig = {
                    pcEnvironmentQueryParam: 'pcEnvironment'
                };
            } else {
                // Fallback to default environment for testing
                clientAppConfig = {
                    pcEnvironment: 'mypurecloud.com'
                };
            }
            
            this.clientApp = new window.purecloud.apps.ClientApp(clientAppConfig);

            // Initialize the Platform Client
            this.platformClient = require('platformClient');
            
            // Set the environment for the Platform Client
            const environment = this.clientApp.gcEnvironment || this.clientApp.pcEnvironment;
            if (environment) {
                this.platformClient.ApiClient.instance.setEnvironment(environment);
            }
            
            // Get APIs
            this.routingApi = new this.platformClient.RoutingApi();
            this.analyticsApi = new this.platformClient.AnalyticsApi();

            // Set up authentication using Client App SDK
            await this.authenticateWithGenesys();
            
            // Load initial data
            await this.loadQueues();
            
            // Set up auto-refresh if enabled
            this.setupAutoRefresh();
            
        } catch (error) {
            console.error('Failed to initialize app:', error);
            this.showError('Failed to initialize application: ' + error.message);
        }
    }

    async authenticateWithGenesys() {
        try {
            this.updateConnectionStatus('connecting', 'Authenticating...');
            
            // Use the Client App SDK lifecycle to get authenticated session
            // The app should bootstrap and provide access to the authenticated context
            const bootstrapData = await new Promise((resolve, reject) => {
                const timeout = setTimeout(() => {
                    reject(new Error('Timeout waiting for app bootstrap'));
                }, 15000); // 15 second timeout
                
                // Try to get the bootstrap data from the lifecycle API
                if (this.clientApp && this.clientApp.lifecycle) {
                    this.clientApp.lifecycle.bootstrapped()
                        .then((data) => {
                            clearTimeout(timeout);
                            resolve(data);
                        })
                        .catch((error) => {
                            clearTimeout(timeout);
                            reject(error);
                        });
                } else {
                    // Fallback - assume we're authenticated in the Genesys Cloud context
                    setTimeout(() => {
                        clearTimeout(timeout);
                        resolve({ authenticated: true });
                    }, 2000);
                }
            });
            
            console.log('Bootstrap data:', bootstrapData);
            
            // The Platform Client should automatically use the authenticated session
            // when running in the Genesys Cloud environment
            this.updateConnectionStatus('connected', 'Connected');
            console.log('Authentication successful - running in authenticated Genesys Cloud context');
            
        } catch (error) {
            console.error('Authentication failed:', error);
            this.updateConnectionStatus('error', 'Authentication failed');
            throw new Error('Authentication failed: ' + error.message);
        }
    }

    async loadQueues() {
        if (this.isLoading) return;
        
        try {
            this.isLoading = true;
            this.showLoading(true);
            this.hideError();
            
            // Fetch all queues
            const queuesResponse = await this.routingApi.getRoutingQueues({
                pageSize: 100,
                sortBy: 'name'
            });
            
            if (!queuesResponse || !queuesResponse.entities) {
                throw new Error('No queue data received');
            }

            // Get queue statistics
            const queueIds = queuesResponse.entities.map(queue => queue.id);
            const queueStats = await this.getQueueStatistics(queueIds);
            
            // Combine queue info with statistics
            this.queues = queuesResponse.entities.map(queue => {
                const stats = queueStats[queue.id] || {};
                return {
                    ...queue,
                    stats: {
                        waiting: stats.oWaiting || 0,
                        interacting: stats.oInteracting || 0,
                        abandoned: stats.oAbandonedToday || 0,
                        answered: stats.oAnsweredToday || 0,
                        avgWaitTime: stats.oWaitingAvgTime || 0,
                        longestWait: stats.oWaitingMaxTime || 0
                    }
                };
            });

            this.filteredQueues = [...this.queues];
            this.renderQueues();
            this.updateLastRefreshTime();
            
        } catch (error) {
            console.error('Failed to load queues:', error);
            this.showError('Failed to load queue data: ' + error.message);
        } finally {
            this.isLoading = false;
            this.showLoading(false);
        }
    }

    async getQueueStatistics(queueIds) {
        try {
            if (!queueIds || queueIds.length === 0) return {};

            // Create analytics query for real-time queue statistics
            const query = {
                interval: `${new Date().toISOString().split('T')[0]}T00:00:00.000Z/${new Date().toISOString()}`,
                granularity: 'PT30M',
                timeZone: 'UTC',
                groupBy: ['queueId'],
                filter: {
                    type: 'and',
                    clauses: [
                        {
                            type: 'or',
                            predicates: queueIds.map(queueId => ({
                                type: 'dimension',
                                dimension: 'queueId',
                                operator: 'matches',
                                value: queueId
                            }))
                        }
                    ]
                },
                metrics: ['oWaiting', 'oInteracting', 'oAbandonedToday', 'oAnsweredToday', 'oWaitingAvgTime', 'oWaitingMaxTime']
            };

            const response = await this.analyticsApi.postAnalyticsQueuesObservationsQuery(query);
            
            // Process the response to create a lookup by queue ID
            const stats = {};
            if (response && response.results) {
                response.results.forEach(result => {
                    if (result.group && result.group.queueId && result.data) {
                        const queueId = result.group.queueId;
                        const latestData = result.data[result.data.length - 1] || {};
                        stats[queueId] = latestData.stats || {};
                    }
                });
            }

            return stats;
            
        } catch (error) {
            console.error('Failed to get queue statistics:', error);
            // Return empty stats if analytics query fails
            return {};
        }
    }

    renderQueues() {
        const container = document.getElementById('queueContainer');
        const noQueuesElement = document.getElementById('noQueues');
        
        if (this.filteredQueues.length === 0) {
            container.innerHTML = '';
            noQueuesElement.style.display = 'block';
            return;
        }
        
        noQueuesElement.style.display = 'none';
        
        container.innerHTML = this.filteredQueues.map(queue => {
            const waitingCount = queue.stats.waiting || 0;
            const priorityClass = this.getQueuePriorityClass(waitingCount);
            const priorityLabel = this.getQueuePriorityLabel(waitingCount);
            
            return `
                <div class="queue-item ${priorityClass}" data-queue-id="${queue.id}">
                    <div class="queue-header">
                        <h3 class="queue-name">${this.escapeHtml(queue.name)}</h3>
                        <span class="queue-badge ${priorityLabel.toLowerCase()}">${priorityLabel}</span>
                    </div>
                    
                    <div class="queue-stats">
                        <div class="stat-item">
                            <span class="stat-number">${waitingCount}</span>
                            <span class="stat-label">Waiting</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-number">${queue.stats.interacting || 0}</span>
                            <span class="stat-label">Interacting</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-number">${queue.stats.answered || 0}</span>
                            <span class="stat-label">Answered Today</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-number">${queue.stats.abandoned || 0}</span>
                            <span class="stat-label">Abandoned Today</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-number">${this.formatTime(queue.stats.avgWaitTime)}</span>
                            <span class="stat-label">Avg Wait</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-number">${this.formatTime(queue.stats.longestWait)}</span>
                            <span class="stat-label">Longest Wait</span>
                        </div>
                    </div>
                    
                    ${queue.description ? `<div class="queue-description">${this.escapeHtml(queue.description)}</div>` : ''}
                </div>
            `;
        }).join('');
    }

    getQueuePriorityClass(waitingCount) {
        if (waitingCount >= 10) return 'high-queue';
        if (waitingCount >= 5) return 'medium-queue';
        return 'low-queue';
    }

    getQueuePriorityLabel(waitingCount) {
        if (waitingCount >= 10) return 'High';
        if (waitingCount >= 5) return 'Medium';
        return 'Low';
    }

    formatTime(seconds) {
        if (!seconds || seconds === 0) return '0s';
        
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = Math.floor(seconds % 60);
        
        if (hours > 0) {
            return `${hours}h ${minutes}m`;
        } else if (minutes > 0) {
            return `${minutes}m ${secs}s`;
        } else {
            return `${secs}s`;
        }
    }

    setupEventListeners() {
        // Refresh button
        document.getElementById('refreshBtn').addEventListener('click', () => {
            this.refreshQueues();
        });

        // Auto-refresh checkbox
        document.getElementById('autoRefresh').addEventListener('change', (e) => {
            if (e.target.checked) {
                this.setupAutoRefresh();
            } else {
                this.clearAutoRefresh();
            }
        });

        // Search functionality
        document.getElementById('searchInput').addEventListener('input', (e) => {
            this.filterQueues(e.target.value);
        });

        // Queue item click events
        document.getElementById('queueContainer').addEventListener('click', (e) => {
            const queueItem = e.target.closest('.queue-item');
            if (queueItem) {
                this.handleQueueClick(queueItem.dataset.queueId);
            }
        });
    }

    async refreshQueues() {
        const refreshBtn = document.getElementById('refreshBtn');
        refreshBtn.classList.add('loading');
        
        try {
            await this.loadQueues();
        } finally {
            refreshBtn.classList.remove('loading');
        }
    }

    setupAutoRefresh() {
        this.clearAutoRefresh();
        this.refreshInterval = setInterval(() => {
            if (!this.isLoading) {
                this.loadQueues();
            }
        }, 30000); // Refresh every 30 seconds
    }

    clearAutoRefresh() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
            this.refreshInterval = null;
        }
    }

    filterQueues(searchTerm) {
        if (!searchTerm.trim()) {
            this.filteredQueues = [...this.queues];
        } else {
            const term = searchTerm.toLowerCase();
            this.filteredQueues = this.queues.filter(queue => 
                queue.name.toLowerCase().includes(term) ||
                (queue.description && queue.description.toLowerCase().includes(term))
            );
        }
        this.renderQueues();
    }

    handleQueueClick(queueId) {
        // This can be extended to show queue details or perform actions
        console.log('Queue clicked:', queueId);
        
        // You can implement additional functionality here, such as:
        // - Opening queue details in a modal
        // - Navigating to queue management
        // - Showing historical data
    }

    updateConnectionStatus(status, message) {
        const statusElement = document.getElementById('connectionStatus');
        const dot = statusElement.querySelector('.status-dot');
        const text = statusElement.querySelector('span:last-child');
        
        dot.className = `status-dot ${status}`;
        text.textContent = message;
    }

    updateLastRefreshTime() {
        const now = new Date();
        const timeString = now.toLocaleTimeString();
        document.getElementById('lastUpdate').querySelector('span').textContent = `Last updated: ${timeString}`;
    }

    showLoading(show) {
        document.getElementById('loadingIndicator').style.display = show ? 'flex' : 'none';
    }

    showError(message) {
        const errorElement = document.getElementById('errorMessage');
        const errorText = document.getElementById('errorText');
        
        errorText.textContent = message;
        errorElement.style.display = 'flex';
    }

    hideError() {
        document.getElementById('errorMessage').style.display = 'none';
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize the application when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new QueueMonitor();
});

// Handle page visibility change to pause/resume auto-refresh
document.addEventListener('visibilitychange', () => {
    const app = window.queueMonitorApp;
    if (app) {
        if (document.hidden) {
            app.clearAutoRefresh();
        } else if (document.getElementById('autoRefresh').checked) {
            app.setupAutoRefresh();
        }
    }
});

// Export for global access if needed
window.QueueMonitor = QueueMonitor; 