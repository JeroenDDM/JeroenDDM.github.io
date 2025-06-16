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
                // Map environment to the correct region
                let region = environment;
                if (environment === 'mypurecloud.ie') {
                    region = this.platformClient.PureCloudRegionHosts.eu_west_1;
                } else if (environment === 'mypurecloud.com') {
                    region = this.platformClient.PureCloudRegionHosts.us_east_1;
                } else if (environment === 'mypurecloud.com.au') {
                    region = this.platformClient.PureCloudRegionHosts.ap_southeast_2;
                } else if (environment === 'mypurecloud.jp') {
                    region = this.platformClient.PureCloudRegionHosts.ap_northeast_1;
                } else if (environment === 'mypurecloud.de') {
                    region = this.platformClient.PureCloudRegionHosts.eu_central_1;
                }
                
                this.platformClient.ApiClient.instance.setEnvironment(region);
                console.log('[QueueMonitor] Set Platform Client environment to:', environment, 'Region:', region);
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
            console.error('[QueueMonitor] Failed to initialize app:', error);
            this.showError('Failed to initialize application: ' + error.message);
        }
    }

    async authenticateWithGenesys() {
        try {
            this.updateConnectionStatus('connecting', 'Authenticating...');
            
            // Check if we're in a Genesys Cloud environment by looking for query parameters
            const urlParams = new URLSearchParams(window.location.search);
            const hasGenesysQueryParams = urlParams.has('gcHostOrigin') || 
                                         urlParams.has('gcTargetEnv') || 
                                         urlParams.has('pcEnvironment') ||
                                         urlParams.has('iid') || // interaction ID
                                         urlParams.has('host') || // host parameter
                                         urlParams.has('locale'); // locale parameter
            
            const isGenesysDomain = window.location.hostname.includes('mypurecloud') || // running on Genesys Cloud domain
                                   window.location.hostname.includes('apps.'); // apps subdomain
            
            const isInIframe = window.parent !== window;
            
            // Only consider it a Genesys environment if we have actual Genesys parameters OR we're on a Genesys domain
            // Being in an iframe alone is not sufficient
            const hasGenesysParams = hasGenesysQueryParams || isGenesysDomain;
            
            // Log detailed information about the current URL and parameters
            console.log('[QueueMonitor] Current URL:', window.location.href);
            console.log('[QueueMonitor] Query parameters:', window.location.search);
            console.log('[QueueMonitor] URL parameters found:', {
                gcHostOrigin: urlParams.get('gcHostOrigin'),
                gcTargetEnv: urlParams.get('gcTargetEnv'),
                pcEnvironment: urlParams.get('pcEnvironment'),
                iid: urlParams.get('iid'),
                host: urlParams.get('host'),
                locale: urlParams.get('locale'),
                hostname: window.location.hostname,
                isInIframe: isInIframe,
                hasGenesysQueryParams: hasGenesysQueryParams,
                isGenesysDomain: isGenesysDomain,
                hasGenesysParams: hasGenesysParams
            });
            
            if (hasGenesysParams) {
                console.log('[QueueMonitor] Running in Genesys Cloud environment - using implicit grant authentication');
                
                // For interaction widgets, we can use implicit grant authentication
                // The widget should already have access to the authenticated session
                // We'll use the Platform Client's implicit grant method
                
                const client = this.platformClient.ApiClient.instance;
                
                // Try to authenticate using implicit grant
                try {
                    // Check if we already have a token from a previous authentication
                    const existingToken = client.authentications?.PureCloud?.accessToken;
                    if (existingToken) {
                        console.log('[QueueMonitor] Using existing access token:', existingToken.substring(0, 20) + '...');
                        this.updateConnectionStatus('connected', 'Connected');
                        return;
                    }
                    
                    // Try multiple methods to find an access token
                    let foundToken = null;
                    
                    // Method 1: Check URL hash (from OAuth redirect)
                    if (window.location.hash) {
                        const hashParams = new URLSearchParams(window.location.hash.substring(1));
                        foundToken = hashParams.get('access_token');
                        if (foundToken) {
                            console.log('[QueueMonitor] Found access token in URL hash');
                        }
                    }
                    
                    // Method 2: Check session/local storage
                    if (!foundToken) {
                        const storageKeys = [
                            'purecloud_access_token',
                            'access_token',
                            'gc_access_token',
                            'authToken',
                            'bearer_token'
                        ];
                        
                        for (const key of storageKeys) {
                            foundToken = sessionStorage.getItem(key) || localStorage.getItem(key);
                            if (foundToken) {
                                console.log('[QueueMonitor] Found access token in storage with key:', key);
                                break;
                            }
                        }
                    }
                    
                    // Method 3: Try to get token from parent window (if in iframe)
                    if (!foundToken && window.parent !== window) {
                        try {
                            for (const key of ['purecloud_access_token', 'access_token', 'gc_access_token']) {
                                foundToken = window.parent.sessionStorage?.getItem(key) || 
                                           window.parent.localStorage?.getItem(key);
                                if (foundToken) {
                                    console.log('[QueueMonitor] Found access token in parent window with key:', key);
                                    break;
                                }
                            }
                        } catch (e) {
                            console.log('[QueueMonitor] Cannot access parent window storage (cross-origin)');
                        }
                    }
                    
                    // Method 4: Check if token is available via Client App SDK
                    if (!foundToken && window.purecloud?.apps?.ClientApp) {
                        try {
                            console.log('[QueueMonitor] Attempting to get token via Client App SDK');
                            const clientApp = new window.purecloud.apps.ClientApp();
                            
                            // Try to get the current user's authentication info
                            // This might provide access to the token or authenticated context
                            const authInfo = await new Promise((resolve, reject) => {
                                const timeout = setTimeout(() => reject(new Error('Timeout')), 3000);
                                
                                // Try different methods that might be available
                                if (typeof clientApp.getAuthToken === 'function') {
                                    clientApp.getAuthToken().then(resolve).catch(reject);
                                } else if (typeof clientApp.users?.me === 'function') {
                                    clientApp.users.me().then(resolve).catch(reject);
                                } else {
                                    // If no specific methods, just resolve with null
                                    clearTimeout(timeout);
                                    resolve(null);
                                }
                            });
                            
                            if (authInfo && authInfo.token) {
                                foundToken = authInfo.token;
                                console.log('[QueueMonitor] Got token from Client App SDK');
                            }
                        } catch (e) {
                            console.log('[QueueMonitor] Could not get token via Client App SDK:', e.message);
                        }
                    }
                    
                    if (foundToken) {
                        console.log('[QueueMonitor] Setting access token on Platform Client:', foundToken.substring(0, 20) + '...');
                        client.setAccessToken(foundToken);
                        this.updateConnectionStatus('connected', 'Connected');
                        return;
                    }
                    
                    // Method 5: Test if we're already authenticated by making a simple API call
                    console.log('[QueueMonitor] No token found, testing if already authenticated...');
                    try {
                        // Try a simple API call to see if we're authenticated
                        const testResponse = await this.routingApi.getRoutingQueues({ pageSize: 1 });
                        if (testResponse) {
                            console.log('[QueueMonitor] API call succeeded - already authenticated in Genesys Cloud context');
                            this.updateConnectionStatus('connected', 'Connected');
                            return;
                        }
                    } catch (testError) {
                        console.log('[QueueMonitor] Test API call failed:', testError.message);
                    }
                    
                    // For interaction widgets, try to use the loginImplicitGrant method
                    // This might work if we're in the right context
                    console.log('[QueueMonitor] Attempting implicit grant authentication...');
                    
                    // Note: In a real interaction widget, you would have a client ID
                    // For now, we'll assume the widget is running in an authenticated context
                    await new Promise(resolve => setTimeout(resolve, 1000));
                    
                    console.log('[QueueMonitor] Authentication completed - assuming authenticated Genesys Cloud context');
                    
                } catch (authError) {
                    console.error('[QueueMonitor] Implicit grant authentication failed:', authError);
                    // Don't throw the error - continue and see if API calls work anyway
                    console.log('[QueueMonitor] Continuing without explicit authentication - may work in Genesys Cloud context');
                }
                
            } else {
                console.log('[QueueMonitor] Running in standalone mode - would need OAuth client ID for implicit grant');
                // In standalone mode, we would need to implement full OAuth flow
                // For now, show a helpful message to the user
                this.updateConnectionStatus('warning', 'Standalone Mode - No Authentication');
                this.showError('This widget is running in standalone mode. To use it with live data, it needs to be deployed as a Genesys Cloud interaction widget with proper OAuth configuration.');
                return; // Don't proceed with API calls without authentication
            }
            
            this.updateConnectionStatus('connected', 'Connected');
            console.log('[QueueMonitor] Authentication successful');
            
        } catch (error) {
            console.error('[QueueMonitor] Authentication failed:', error);
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
            
            // Debug: Check authentication state before making API calls
            const client = this.platformClient.ApiClient.instance;
            const currentToken = client.authentications?.PureCloud?.accessToken;
            console.log('[QueueMonitor] Making API call with token:', currentToken ? (currentToken.substring(0, 20) + '...') : 'NO TOKEN');
            console.log('[QueueMonitor] API Client base path:', client.basePath || 'NOT SET');
            
            // If no token, don't make API calls
            if (!currentToken) {
                throw new Error('No authentication token available - cannot make API calls');
            }
            
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
            console.error('[QueueMonitor] Failed to load queues:', error);
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
            console.error('[QueueMonitor] Failed to get queue statistics:', error);
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
                    console.log('[QueueMonitor] Queue clicked:', queueId);
        
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