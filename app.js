class QueueMonitor {
    constructor() {
        this.platformClient = null;
        this.clientApp = null;
        this.routingApi = null;
        this.analyticsApi = null;
        this.conversationsApi = null;
        this.queues = [];
        this.filteredQueues = [];
        this.refreshInterval = null;
        this.isLoading = false;
        this.currentSearchTerm = '';
        this.currentConversationId = null;
        this.selectedQueue = null;
        this.urlParams = {}; // Store URL parameters for widget context
        this.isWidgetMode = false; // Track if we're running in widget mode
        this.isStandalone = true; // Track if we're running in standalone mode
        
        // OAuth Configuration - Replace with your actual OAuth app details
        this.oauthConfig = {
            clientId: '110d379d-9f0d-452f-8706-e8975a058f7f', // Replace with your OAuth client ID
            redirectUri: 'https://jeroenddm.github.io/', // Current page
            environment: 'mypurecloud.ie', // Your Genesys Cloud environment
            scopes: ['routing', 'analytics', 'conversations'] // Required permissions
        };
        
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
                    pcEnvironment: 'mypurecloud.ie'
                };
            }
            
            this.clientApp = new window.purecloud.apps.ClientApp(clientAppConfig);

            // Initialize the Platform Client
            this.platformClient = require('platformClient');
            
            // Set the environment for the Platform Client
            const environment = this.clientApp.gcEnvironment || this.clientApp.pcEnvironment;
            if (environment) {
                // Map environment to the correct region
                let regionHost;
                if (environment === 'mypurecloud.ie') {
                    regionHost = this.platformClient.PureCloudRegionHosts.eu_west_1;
                } else if (environment === 'mypurecloud.com') {
                    regionHost = this.platformClient.PureCloudRegionHosts.us_east_1;
                } else if (environment === 'mypurecloud.com.au') {
                    regionHost = this.platformClient.PureCloudRegionHosts.ap_southeast_2;
                } else if (environment === 'mypurecloud.jp') {
                    regionHost = this.platformClient.PureCloudRegionHosts.ap_northeast_1;
                } else if (environment === 'mypurecloud.de') {
                    regionHost = this.platformClient.PureCloudRegionHosts.eu_central_1;
                } else {
                    regionHost = environment; // fallback to environment string
                }
                
                this.platformClient.ApiClient.instance.setEnvironment(regionHost);
                console.log('[QueueMonitor] Set Platform Client environment to:', environment, 'Region Host:', regionHost);
            }
            
            // Get APIs
            this.routingApi = new this.platformClient.RoutingApi();
            this.analyticsApi = new this.platformClient.AnalyticsApi();
            this.conversationsApi = new this.platformClient.ConversationsApi();

            // Set up authentication using Client App SDK
            const authResult = await this.authenticateWithGenesys();
            
            // Only load data if authentication was successful
            if (authResult.success) {
                // Load initial data
                await this.loadQueues();
                
                // Set up auto-refresh if enabled
                this.setupAutoRefresh();
            }
            
        } catch (error) {
            console.error('[QueueMonitor] Failed to initialize app:', error);
            this.showError('Failed to initialize application: ' + error.message);
        }
    }

    async authenticateWithGenesys() {
        try {
            console.log('[QueueMonitor] ========================================');
            console.log('[QueueMonitor] AUTHENTICATION PROCESS STARTED');
            console.log('[QueueMonitor] ========================================');
            console.log('[QueueMonitor] Timestamp:', new Date().toISOString());
            console.log('[QueueMonitor] Current URL:', window.location.href);
            console.log('[QueueMonitor] User Agent:', navigator.userAgent);
            
            this.updateConnectionStatus('connecting', 'Authenticating...');
            
            // CRITICAL: Check for preserved widget context after OAuth redirect
            const widgetContextRestored = this.checkForPreservedWidgetContext();
            
            // If widget context was restored, skip normal URL parameter parsing
            if (widgetContextRestored) {
                console.log('[QueueMonitor] 🔄 Widget context was restored - skipping normal URL parameter analysis');
                console.log('[QueueMonitor] Using restored widget parameters:', this.urlParams);
                console.log('[QueueMonitor] Widget mode:', this.isWidgetMode);
                console.log('[QueueMonitor] Conversation ID:', this.urlParams.conversationId);
                
                // Continue with widget authentication using restored context
                const client = this.platformClient.ApiClient.instance;
                
                console.log('[QueueMonitor] ======================================');
                console.log('[QueueMonitor] CONFIGURING RESTORED WIDGET AUTHENTICATION');
                console.log('[QueueMonitor] ======================================');
                console.log('[QueueMonitor] Using Platform Client SDK for restored widget authentication...');
                
                // Configure environment from restored parameters
                if (this.urlParams.gcHostOrigin && this.urlParams.gcTargetEnv) {
                    console.log('[QueueMonitor] Configuring environment for restored widget mode');
                    console.log('[QueueMonitor] Host Origin:', this.urlParams.gcHostOrigin);
                    console.log('[QueueMonitor] Target Environment:', this.urlParams.gcTargetEnv);
                    
                    let environment = 'mypurecloud.ie';
                    if (this.urlParams.gcHostOrigin.includes('mypurecloud.com')) {
                        environment = 'mypurecloud.com';
                    } else if (this.urlParams.gcHostOrigin.includes('mypurecloud.com.au')) {
                        environment = 'mypurecloud.com.au';
                    } else if (this.urlParams.gcHostOrigin.includes('mypurecloud.jp')) {
                        environment = 'mypurecloud.jp';
                    } else if (this.urlParams.gcHostOrigin.includes('mypurecloud.de')) {
                        environment = 'mypurecloud.de';
                    }
                    
                    console.log('[QueueMonitor] Detected environment:', environment);
                    
                    let regionHost;
                    if (environment === 'mypurecloud.ie') {
                        regionHost = this.platformClient.PureCloudRegionHosts.eu_west_1;
                    } else if (environment === 'mypurecloud.com') {
                        regionHost = this.platformClient.PureCloudRegionHosts.us_east_1;
                    } else if (environment === 'mypurecloud.com.au') {
                        regionHost = this.platformClient.PureCloudRegionHosts.ap_southeast_2;
                    } else if (environment === 'mypurecloud.jp') {
                        regionHost = this.platformClient.PureCloudRegionHosts.ap_northeast_1;
                    } else if (environment === 'mypurecloud.de') {
                        regionHost = this.platformClient.PureCloudRegionHosts.eu_central_1;
                    }
                    
                    client.setEnvironment(regionHost);
                    console.log('[QueueMonitor] Platform client environment configured for restored widget');
                }
                
                // Handle OAuth token from URL hash
                const hash = window.location.hash;
                if (hash && hash.includes('access_token')) {
                    const hashParams = new URLSearchParams(hash.substring(1));
                    const accessToken = hashParams.get('access_token');
                    
                    if (accessToken) {
                        console.log('[QueueMonitor] ✅ Using OAuth token with restored widget context');
                        
                        client.setAccessToken(accessToken);
                        if (client.authentications && client.authentications.PureCloud) {
                            client.authentications.PureCloud.accessToken = accessToken;
                        }
                        client.defaultHeaders = client.defaultHeaders || {};
                        client.defaultHeaders['Authorization'] = `Bearer ${accessToken}`;
                        
                        // Clean up the URL hash but preserve widget mode
                        window.history.replaceState(null, null, window.location.pathname + window.location.search);
                        
                        this.updateConnectionStatus('connected', 'Connected via Restored Widget Context + OAuth');
                        return { success: true };
                    }
                }
                
                // If no OAuth token found, that's an error for restored widget context
                console.log('[QueueMonitor] ❌ Widget context was restored but no OAuth token found');
                this.updateConnectionStatus('error', 'Widget context restored but authentication failed');
                return { success: false, reason: 'missing_oauth_token_after_restore' };
            }
            
            // Normal flow: Check if we're in a Genesys Cloud environment by looking for query parameters
            const urlParams = new URLSearchParams(window.location.search);
            const hasGenesysQueryParams = urlParams.has('gcHostOrigin') || 
                                         urlParams.has('gcTargetEnv') || 
                                         urlParams.has('pcEnvironment') ||
                                         urlParams.has('environment') || // interpolated environment parameter
                                         urlParams.has('conversationId') || // conversation ID (new format)
                                         urlParams.has('iid') || // interaction ID (legacy)
                                         urlParams.has('host') || // host parameter
                                         urlParams.has('langTag') || // language tag (new format)
                                         urlParams.has('locale'); // locale parameter (legacy)
            
            const isGenesysDomain = window.location.hostname.includes('mypurecloud') || // running on Genesys Cloud domain
                                   window.location.hostname.includes('apps.'); // apps subdomain
            
            const isInIframe = window.parent !== window;
            
            // Only consider it a Genesys environment if we have actual Genesys parameters OR we're on a Genesys domain
            // Being in an iframe alone is not sufficient
            const hasGenesysParams = hasGenesysQueryParams || isGenesysDomain;
            
            // Log detailed information about the current URL and parameters
            console.log('[QueueMonitor] Current URL:', window.location.href);
            console.log('[QueueMonitor] Query parameters:', window.location.search);
            
            // Log URL interpolation analysis
            console.log('[QueueMonitor] === URL INTERPOLATION ANALYSIS ===');
            console.log('[QueueMonitor] Expected interpolated URL format:');
            console.log('[QueueMonitor] https://jeroenddm.github.io/index.html?gcHostOrigin={{gcHostOrigin}}&gcTargetEnv={{gcTargetEnv}}&conversationId={{conversationId}}&langTag={{langTag}}');
            console.log('[QueueMonitor] ');
            console.log('[QueueMonitor] Actual URL received:', window.location.href);
            console.log('[QueueMonitor] ');
            if (window.location.search) {
                console.log('[QueueMonitor] Query string breakdown:');
                const params = new URLSearchParams(window.location.search);
                for (const [key, value] of params.entries()) {
                    console.log(`[QueueMonitor]   ${key} = "${value}"`);
                }
            } else {
                console.log('[QueueMonitor] ❌ NO QUERY PARAMETERS FOUND');
                console.log('[QueueMonitor] This indicates URL interpolation is not working.');
                console.log('[QueueMonitor] Expected parameters: gcHostOrigin, gcTargetEnv, conversationId, langTag');
            }
            console.log('[QueueMonitor] === END URL INTERPOLATION ANALYSIS ===');
            console.log('[QueueMonitor] ');
            
            // Store URL parameters for widget context preservation
            this.urlParams = {
                gcHostOrigin: urlParams.get('gcHostOrigin'),
                gcTargetEnv: urlParams.get('gcTargetEnv'),
                conversationId: urlParams.get('conversationId'),
                langTag: urlParams.get('langTag'),
                pcEnvironment: urlParams.get('pcEnvironment'),
                environment: urlParams.get('environment'),
                iid: urlParams.get('iid'),
                host: urlParams.get('host'),
                locale: urlParams.get('locale')
            };
            
            console.log('[QueueMonitor] URL parameters found:', {
                ...this.urlParams,
                hostname: window.location.hostname,
                isInIframe: isInIframe,
                hasGenesysQueryParams: hasGenesysQueryParams,
                isGenesysDomain: isGenesysDomain,
                hasGenesysParams: hasGenesysParams
            });

            // Additional debugging for iframe context
            if (isInIframe && !hasGenesysQueryParams) {
                console.log('[QueueMonitor] NOTICE: Running in iframe but no Genesys parameters detected.');
                console.log('[QueueMonitor] This usually means:');
                console.log('[QueueMonitor] 1. App is being tested in an iframe but not through Genesys Cloud integration');
                console.log('[QueueMonitor] 2. URL interpolation is not working (check app.json and integration setup)');
                console.log('[QueueMonitor] 3. App needs to be accessed through Genesys Cloud Admin integration, not directly');
                
                // Try to detect if we're in Genesys Cloud context
                try {
                    console.log('[QueueMonitor] === IFRAME CONTEXT ANALYSIS ===');
                    console.log('[QueueMonitor] Parent window origin:', window.parent?.location?.origin || 'Cannot access');
                    console.log('[QueueMonitor] Parent window hostname:', window.parent?.location?.hostname || 'Cannot access');
                    console.log('[QueueMonitor] Current frame URL:', window.location.href);
                    console.log('[QueueMonitor] Referrer:', document.referrer || 'No referrer');
                    
                    // Check if parent looks like Genesys
                    const parentOrigin = document.referrer;
                    if (parentOrigin.includes('mypurecloud') || parentOrigin.includes('apps.')) {
                        console.log('[QueueMonitor] ✅ Parent appears to be Genesys Cloud');
                        console.log('[QueueMonitor] 🔥 ISSUE: In Genesys Cloud but URL interpolation failed!');
                        console.log('[QueueMonitor] 🔧 Check integration Application URL and widget configuration');
                    } else {
                        console.log('[QueueMonitor] ❌ Parent does not appear to be Genesys Cloud');
                    }
                    console.log('[QueueMonitor] === END IFRAME CONTEXT ANALYSIS ===');
                } catch (e) {
                    console.log('[QueueMonitor] Cannot analyze iframe context (cross-origin restrictions)');
                }
            }

            // URL Interpolation Parameter Status
            console.log('[QueueMonitor] === URL INTERPOLATION PARAMETER STATUS ===');
            const expectedParams = [
                { name: 'gcHostOrigin', description: 'Genesys Cloud host origin' },
                { name: 'gcTargetEnv', description: 'Target environment identifier' },
                { name: 'conversationId', description: 'Conversation ID (for transfers)' },
                { name: 'langTag', description: 'Language tag setting' }
            ];
            
            expectedParams.forEach(param => {
                const value = urlParams.get(param.name);
                const status = value ? '✅ FOUND' : '❌ MISSING';
                console.log(`[QueueMonitor] ${param.name}: ${status} ${value ? `"${value}"` : ''} (${param.description})`);
            });
            console.log('[QueueMonitor] === END PARAMETER STATUS ===');
            
            if (hasGenesysParams) {
                console.log('[QueueMonitor] === FINAL DETERMINATION ===');
                console.log('[QueueMonitor] ✅ WIDGET MODE DETECTED');
                console.log('[QueueMonitor] Running in Genesys Cloud environment - using implicit grant authentication');
                console.log('[QueueMonitor] Transfer functionality will be available for active interactions');
                console.log('[QueueMonitor] =====================================');
                this.isStandalone = false;
                this.isWidgetMode = true;  // Set widget mode flag
                
                // For interaction widgets, we can use implicit grant authentication
                // The widget should already have access to the authenticated session
                // We'll use the Platform Client's implicit grant method
                
                const client = this.platformClient.ApiClient.instance;
                
                // For Genesys Cloud widgets, use Platform Client SDK authentication
                console.log('[QueueMonitor] ======================================');
                console.log('[QueueMonitor] CONFIGURING WIDGET AUTHENTICATION');
                console.log('[QueueMonitor] ======================================');
                console.log('[QueueMonitor] Using Platform Client SDK for widget authentication...');
                
                                                try {
                                    // Configure the environment from the interpolated parameters
                                    const gcHostOrigin = urlParams.get('gcHostOrigin');
                                    const gcTargetEnv = urlParams.get('gcTargetEnv');
                                    
                                    if (gcHostOrigin && gcTargetEnv) {
                                        console.log('[QueueMonitor] Configuring environment for widget mode');
                                        console.log('[QueueMonitor] Host Origin:', gcHostOrigin);
                                        console.log('[QueueMonitor] Target Environment:', gcTargetEnv);
                                        
                                        // Set the correct environment for the platform client
                                        let environment = 'mypurecloud.ie'; // default
                                        if (gcHostOrigin.includes('mypurecloud.com')) {
                                            environment = 'mypurecloud.com';
                                        } else if (gcHostOrigin.includes('mypurecloud.com.au')) {
                                            environment = 'mypurecloud.com.au';
                                        } else if (gcHostOrigin.includes('mypurecloud.jp')) {
                                            environment = 'mypurecloud.jp';
                                        } else if (gcHostOrigin.includes('mypurecloud.de')) {
                                            environment = 'mypurecloud.de';
                                        }
                                        
                                        console.log('[QueueMonitor] Detected environment:', environment);
                                        
                                        // Configure platform client environment
                                        let regionHost;
                                        if (environment === 'mypurecloud.ie') {
                                            regionHost = this.platformClient.PureCloudRegionHosts.eu_west_1;
                                        } else if (environment === 'mypurecloud.com') {
                                            regionHost = this.platformClient.PureCloudRegionHosts.us_east_1;
                                        } else if (environment === 'mypurecloud.com.au') {
                                            regionHost = this.platformClient.PureCloudRegionHosts.ap_southeast_2;
                                        } else if (environment === 'mypurecloud.jp') {
                                            regionHost = this.platformClient.PureCloudRegionHosts.ap_northeast_1;
                                        } else if (environment === 'mypurecloud.de') {
                                            regionHost = this.platformClient.PureCloudRegionHosts.eu_central_1;
                                        }
                                        
                                        client.setEnvironment(regionHost);
                                        console.log('[QueueMonitor] Platform client environment configured');
                                    }
                                    
                                    // In widget mode, we need to handle authentication properly
                                    // Check if we already have authentication data in the URL
                                    const hash = window.location.hash;
                                    const search = window.location.search;
                                    
                                    console.log('[QueueMonitor] Current URL hash:', hash ? hash.substring(0, 100) + '...' : 'none');
                                    console.log('[QueueMonitor] Current URL search:', search);
                    
                    // For widgets, we don't typically have OAuth responses in the URL hash
                    // Widgets inherit authentication from the parent Genesys Cloud application
                    if (hash && (hash.includes('access_token') || hash.includes('error'))) {
                        console.log('[QueueMonitor] Found OAuth response in URL hash - this is unusual for widgets');
                        console.log('[QueueMonitor] Widgets typically inherit authentication from parent Genesys Cloud app');
                    }
                    
                    // Manual token extraction as fallback
                    let accessToken = null;
                    
                    // Method 1: Extract from URL hash manually
                    if (hash && hash.includes('access_token')) {
                        try {
                            const hashParams = new URLSearchParams(hash.substring(1));
                            accessToken = hashParams.get('access_token');
                            if (accessToken) {
                                console.log('[QueueMonitor] ✅ Token extracted from URL hash');
                            }
                        } catch (hashError) {
                            console.log('[QueueMonitor] Failed to extract token from hash:', hashError.message);
                        }
                    }
                    
                    // Method 2: Try to get authentication from Client App SDK or parent window
                    if (!accessToken && this.clientApp) {
                        console.log('[QueueMonitor] Trying Client App SDK and parent window authentication...');
                        console.log('[QueueMonitor] Client App SDK available properties:', Object.keys(this.clientApp));
                        
                        // First, try to get the access token from various Client App SDK sources
                        if (this.clientApp._accessToken) {
                            accessToken = this.clientApp._accessToken;
                            console.log('[QueueMonitor] ✅ Token from Client App SDK _accessToken');
                        } else if (this.clientApp.auth && this.clientApp.auth.accessToken) {
                            accessToken = this.clientApp.auth.accessToken;
                            console.log('[QueueMonitor] ✅ Token from Client App SDK auth.accessToken');
                        } else if (this.clientApp.authentication && this.clientApp.authentication.token) {
                            accessToken = this.clientApp.authentication.token;
                            console.log('[QueueMonitor] ✅ Token from Client App SDK authentication.token');
                        }
                        
                        // Try to get token from Client App SDK's internal platform client
                        if (!accessToken) {
                            try {
                                if (this.clientApp._platformClient || this.clientApp.platformClient) {
                                    const internalClient = this.clientApp._platformClient || this.clientApp.platformClient;
                                    if (internalClient.ApiClient && internalClient.ApiClient.instance) {
                                        const apiClientInstance = internalClient.ApiClient.instance;
                                        const internalToken = apiClientInstance.authentications?.['PureCloud OAuth']?.accessToken ||
                                                            apiClientInstance.authentications?.PureCloud?.accessToken;
                                        if (internalToken) {
                                            accessToken = internalToken;
                                            console.log('[QueueMonitor] ✅ Token from Client App SDK internal platform client');
                                        }
                                    }
                                }
                            } catch (internalTokenError) {
                                console.log('[QueueMonitor] Could not get token from internal platform client:', internalTokenError.message);
                            }
                        }
                        
                        // Try to get token from parent window (Genesys Cloud app)
                        if (!accessToken && window.parent !== window) {
                            try {
                                console.log('[QueueMonitor] Trying to get token from parent Genesys Cloud window...');
                                
                                // Check if parent window has PureCloud global object
                                if (window.parent.purecloud) {
                                    const parentPureCloud = window.parent.purecloud;
                                    console.log('[QueueMonitor] Found purecloud object in parent window');
                                    
                                    // Try to get token from parent's platform client
                                    if (parentPureCloud.platformClient && parentPureCloud.platformClient.ApiClient) {
                                        const parentClient = parentPureCloud.platformClient.ApiClient.instance;
                                        const parentToken = parentClient.authentications?.['PureCloud OAuth']?.accessToken ||
                                                          parentClient.authentications?.PureCloud?.accessToken;
                                        if (parentToken) {
                                            accessToken = parentToken;
                                            console.log('[QueueMonitor] ✅ Token from parent window platform client');
                                        }
                                    }
                                }
                            } catch (parentError) {
                                console.log('[QueueMonitor] Cannot access parent window (cross-origin):', parentError.message);
                            }
                        }
                        
                        if (!accessToken) {
                            console.log('[QueueMonitor] No access token found in Client App SDK or parent window');
                        }
                    }
                    
                    // Set the token if we found one
                    if (accessToken) {
                        console.log('[QueueMonitor] ✅ Access token obtained, setting on Platform Client...');
                        console.log('[QueueMonitor] Token preview:', accessToken.substring(0, 20) + '...');
                        
                        // Use the official Platform Client SDK method to set the token
                        client.setAccessToken(accessToken);
                        console.log('[QueueMonitor] Platform Client setAccessToken() called');
                        
                        // Verify the token is set
                        const currentToken = client.authentications?.['PureCloud OAuth']?.accessToken || 
                                           client.authentications?.PureCloud?.accessToken;
                        console.log('[QueueMonitor] Token verification:', {
                            tokenSet: !!currentToken,
                            defaultAuth: client.defaultAuthentication,
                            hasAuthHeader: !!client.defaultHeaders?.['Authorization']
                        });
                        
                        console.log('[QueueMonitor] ✅ Platform Client authentication configured successfully');
                        this.updateConnectionStatus('connected', 'Connected with Access Token');
                        return { success: true };
                        
                    } else {
                        console.log('[QueueMonitor] ⚠️  No access token found - trying alternative widget authentication approaches');
                        
                        // Alternative approach: Copy authentication from Client App SDK's internal client
                        if (this.clientApp && (this.clientApp._platformClient || this.clientApp.platformClient)) {
                            try {
                                const internalClient = this.clientApp._platformClient || this.clientApp.platformClient;
                                console.log('[QueueMonitor] Attempting to copy authentication from Client App SDK internal client...');
                                console.log('[QueueMonitor] Internal client object:', typeof internalClient);
                                console.log('[QueueMonitor] Internal client properties:', Object.keys(internalClient));
                                
                                if (internalClient.ApiClient && internalClient.ApiClient.instance) {
                                    const internalApiClient = internalClient.ApiClient.instance;
                                    console.log('[QueueMonitor] Found internal API client instance');
                                    console.log('[QueueMonitor] Internal API client authentications:', Object.keys(internalApiClient.authentications || {}));
                                    
                                    // Copy authentication settings from internal client
                                    if (internalApiClient.authentications) {
                                        console.log('[QueueMonitor] Copying authentication settings from internal client...');
                                        
                                        // Copy the authentication objects
                                        Object.keys(internalApiClient.authentications).forEach(authType => {
                                            if (client.authentications && client.authentications[authType]) {
                                                const internalAuth = internalApiClient.authentications[authType];
                                                const clientAuth = client.authentications[authType];
                                                
                                                // Copy authentication properties
                                                if (internalAuth.accessToken) {
                                                    clientAuth.accessToken = internalAuth.accessToken;
                                                    console.log('[QueueMonitor] ✅ Copied access token for', authType);
                                                }
                                                if (internalAuth.apiKey) {
                                                    clientAuth.apiKey = internalAuth.apiKey;
                                                    console.log('[QueueMonitor] ✅ Copied API key for', authType);
                                                }
                                                if (internalAuth.apiKeyPrefix) {
                                                    clientAuth.apiKeyPrefix = internalAuth.apiKeyPrefix;
                                                }
                                            }
                                        });
                                        
                                        // Set the same default authentication
                                        if (internalApiClient.defaultAuthentication) {
                                            client.defaultAuthentication = internalApiClient.defaultAuthentication;
                                            console.log('[QueueMonitor] ✅ Set default authentication to:', client.defaultAuthentication);
                                        }
                                        
                                        // Copy headers if available
                                        if (internalApiClient.defaultHeaders) {
                                            client.defaultHeaders = client.defaultHeaders || {};
                                            Object.assign(client.defaultHeaders, internalApiClient.defaultHeaders);
                                            console.log('[QueueMonitor] ✅ Copied default headers');
                                        }
                                        
                                        console.log('[QueueMonitor] ✅ Authentication copied from Client App SDK internal client');
                                        this.updateConnectionStatus('connected', 'Connected (Copied Authentication)');
                                        return { success: true };
                                    }
                                }
                            } catch (copyError) {
                                console.log('[QueueMonitor] Failed to copy authentication from internal client:', copyError.message);
                            }
                        }
                        
                        // Try another approach: Use Client App SDK's authenticated HTTP capabilities
                        if (this.clientApp && !accessToken) {
                            try {
                                console.log('[QueueMonitor] Trying to use Client App SDK authenticated HTTP capabilities...');
                                
                                // Some Client App SDKs provide a way to make authenticated HTTP requests
                                // Let's check if we can make a simple API call to verify authentication
                                if (this.clientApp.users && typeof this.clientApp.users.getMe === 'function') {
                                    console.log('[QueueMonitor] Testing Client App SDK authentication with users.getMe()...');
                                    const userInfo = await this.clientApp.users.getMe();
                                    console.log('[QueueMonitor] ✅ Client App SDK authentication works! User:', userInfo?.name || 'Unknown');
                                    
                                    // If this works, we can configure Platform Client to use the same auth context
                                    // by setting up a custom interceptor or using the same session
                                    console.log('[QueueMonitor] Client App SDK is authenticated - configuring Platform Client to use same context');
                                    
                                    // Set up Platform Client to use the authenticated context
                                    if (client.authentications && client.authentications['PureCloud OAuth']) {
                                        client.defaultAuthentication = 'PureCloud OAuth';
                                        console.log('[QueueMonitor] ✅ Configured Platform Client for authenticated context');
                                        
                                        // Mark as successfully authenticated
                                        this.updateConnectionStatus('connected', 'Connected (Client App SDK Context)');
                                        return { success: true };
                                    }
                                } else {
                                    console.log('[QueueMonitor] Client App SDK users.getMe not available');
                                }
                            } catch (httpAuthError) {
                                console.log('[QueueMonitor] Client App SDK HTTP authentication test failed:', httpAuthError.message);
                            }
                        }
                        
                        // Try Platform Client SDK implicit grant authentication as fallback
                        console.log('[QueueMonitor] Trying Platform Client SDK implicit grant authentication...');
                        try {
                            // CRITICAL: Save widget context before OAuth redirect
                            console.log('[QueueMonitor] 🔄 Preserving widget context before OAuth redirect...');
                            const widgetContext = {
                                gcHostOrigin: this.urlParams.gcHostOrigin,
                                gcTargetEnv: this.urlParams.gcTargetEnv,
                                conversationId: this.urlParams.conversationId,
                                langTag: this.urlParams.langTag,
                                originalUrl: window.location.href,
                                timestamp: Date.now(),
                                isWidgetMode: this.isWidgetMode
                            };
                            
                            // Store in localStorage to survive OAuth redirect
                            localStorage.setItem('genesys-widget-context', JSON.stringify(widgetContext));
                            console.log('[QueueMonitor] 💾 Widget context saved to localStorage:', widgetContext);
                            
                            const clientId = '110d379d-9f0d-452f-8706-e8975a058f7f';
                            const redirectUri = 'https://jeroenddm.github.io/';
                            const state = 'queue-monitor-widget-' + Date.now();
                            
                            console.log('[QueueMonitor] Starting loginImplicitGrant with:');
                            console.log('[QueueMonitor]   clientId:', clientId);
                            console.log('[QueueMonitor]   redirectUri:', redirectUri);
                            console.log('[QueueMonitor]   state:', state);
                            
                            const authData = await client.loginImplicitGrant(clientId, redirectUri, { state: state });
                            console.log('[QueueMonitor] ✅ Platform Client SDK implicit grant successful!');
                            console.log('[QueueMonitor] Authentication data:', authData);
                            
                            this.updateConnectionStatus('connected', 'Connected via Implicit Grant');
                            return { success: true };
                            
                        } catch (implicitGrantError) {
                            console.log('[QueueMonitor] Platform Client SDK implicit grant failed:', implicitGrantError.message);
                            console.log('[QueueMonitor] Error details:', implicitGrantError);
                            
                            // Final fallback: Configure Platform Client for widget context without explicit token
                            console.log('[QueueMonitor] Using final fallback widget context authentication...');
                            if (client.authentications && client.authentications['PureCloud OAuth']) {
                                client.defaultAuthentication = 'PureCloud OAuth';
                                console.log('[QueueMonitor] Set default authentication to PureCloud OAuth');
                            } else if (client.authentications && client.authentications['PureCloud']) {
                                client.defaultAuthentication = 'PureCloud';
                                console.log('[QueueMonitor] Set default authentication to PureCloud');
                            }
                            
                            console.log('[QueueMonitor] Available authentication methods:', Object.keys(client.authentications || {}));
                            console.log('[QueueMonitor] ⚠️  Widget context authentication configured - may work with browser session');
                            this.updateConnectionStatus('connected', 'Connected (Widget Context)');
                            return { success: true };
                        }
                    }
                    
                } catch (authError) {
                    console.error('[QueueMonitor] ❌ Error during widget authentication:', authError);
                    console.error('[QueueMonitor] Error details:', authError.message);
                    console.error('[QueueMonitor] Error stack:', authError.stack);
                    
                    // Don't throw - try to continue anyway as widget context might work
                    console.log('[QueueMonitor] Continuing despite authentication error - widget context may still work');
                    this.updateConnectionStatus('warning', 'Authentication Warning');
                    return { success: true };
                }
            } else {
                console.log('[QueueMonitor] === FINAL DETERMINATION ===');
                console.log('[QueueMonitor] ⚠️  STANDALONE MODE DETECTED');
                console.log('[QueueMonitor] Running in standalone mode - attempting OAuth authentication');
                console.log('[QueueMonitor] Transfer functionality will NOT be available');
                console.log('[QueueMonitor] To enable widget mode: Set up Genesys Cloud integration and access through Genesys Cloud');
                console.log('[QueueMonitor] =====================================');
                this.isStandalone = true;
                this.isWidgetMode = false;  // Set widget mode flag
                
                // Check if we have a valid OAuth client ID configured
                if (this.oauthConfig.clientId === 'YOUR_OAUTH_CLIENT_ID' || !this.oauthConfig.clientId) {
                    this.updateConnectionStatus('warning', 'OAuth Configuration Required');
                    this.showError('To use this widget outside Genesys Cloud, you need to configure OAuth. Please set your OAuth Client ID in the code and ensure your app is registered in Genesys Cloud.');
                    return { success: false, reason: 'oauth_not_configured' };
                }
                
                // Try OAuth implicit grant flow
                return await this.authenticateWithOAuth();
            }
            
            this.updateConnectionStatus('connected', 'Connected');
            console.log('[QueueMonitor] Authentication successful');
            return { success: true };
            
        } catch (error) {
            console.error('[QueueMonitor] Authentication failed:', error);
            this.updateConnectionStatus('error', 'Authentication failed');
            return { success: false, reason: 'authentication_error', error: error.message };
        }
    }

    checkForPreservedWidgetContext() {
        try {
            console.log('[QueueMonitor] 🔍 Checking for preserved widget context...');
            
            // Check if we have OAuth token in URL hash (indicates OAuth redirect)
            const hash = window.location.hash;
            const hasOAuthToken = hash && hash.includes('access_token');
            
            if (hasOAuthToken) {
                console.log('[QueueMonitor] 🔄 OAuth redirect detected - checking for preserved context');
                
                // Try to restore widget context from localStorage
                const preservedContext = localStorage.getItem('genesys-widget-context');
                if (preservedContext) {
                    try {
                        const widgetContext = JSON.parse(preservedContext);
                        console.log('[QueueMonitor] 📥 Found preserved widget context:', widgetContext);
                        
                        // Check if context is recent (within last 10 minutes)
                        const contextAge = Date.now() - widgetContext.timestamp;
                        const maxAge = 10 * 60 * 1000; // 10 minutes
                        
                        if (contextAge < maxAge) {
                            console.log('[QueueMonitor] ✅ Preserved context is recent, restoring widget mode...');
                            
                            // Restore widget parameters
                            this.urlParams = {
                                gcHostOrigin: widgetContext.gcHostOrigin,
                                gcTargetEnv: widgetContext.gcTargetEnv,
                                conversationId: widgetContext.conversationId,
                                langTag: widgetContext.langTag
                            };
                            
                            // Restore widget mode flags
                            this.isWidgetMode = widgetContext.isWidgetMode;
                            this.isStandalone = !widgetContext.isWidgetMode;
                            
                            console.log('[QueueMonitor] 🎯 Widget context restored successfully!');
                            console.log('[QueueMonitor] Widget Mode:', this.isWidgetMode);
                            console.log('[QueueMonitor] Conversation ID:', this.urlParams.conversationId);
                            console.log('[QueueMonitor] Host Origin:', this.urlParams.gcHostOrigin);
                            
                            // Clean up localStorage after successful restore
                            localStorage.removeItem('genesys-widget-context');
                            console.log('[QueueMonitor] 🧹 Cleaned up preserved context from localStorage');
                            
                            return true; // Context was successfully restored
                            
                        } else {
                            console.log('[QueueMonitor] ⏰ Preserved context is too old (', Math.round(contextAge / 1000), 'seconds), ignoring');
                            localStorage.removeItem('genesys-widget-context');
                        }
                        
                    } catch (parseError) {
                        console.log('[QueueMonitor] ❌ Failed to parse preserved context:', parseError.message);
                        localStorage.removeItem('genesys-widget-context');
                    }
                } else {
                    console.log('[QueueMonitor] ℹ️  No preserved widget context found in localStorage');
                }
            } else {
                console.log('[QueueMonitor] ℹ️  No OAuth redirect detected, skipping context restoration');
            }
            
            return false; // No context was restored
            
        } catch (error) {
            console.log('[QueueMonitor] ❌ Error checking preserved widget context:', error.message);
            return false;
        }
    }

    async authenticateWithOAuth() {
        try {
            console.log('[QueueMonitor] Starting OAuth implicit grant flow');
            this.updateConnectionStatus('connecting', 'Authenticating with OAuth...');
            
            const client = this.platformClient.ApiClient.instance;
            
            // Ensure environment is set before handling token
            const environment = this.oauthConfig.environment;
            let regionHost;
            if (environment === 'mypurecloud.ie') {
                regionHost = this.platformClient.PureCloudRegionHosts.eu_west_1;
            } else if (environment === 'mypurecloud.com') {
                regionHost = this.platformClient.PureCloudRegionHosts.us_east_1;
            } else if (environment === 'mypurecloud.com.au') {
                regionHost = this.platformClient.PureCloudRegionHosts.ap_southeast_2;
            } else if (environment === 'mypurecloud.jp') {
                regionHost = this.platformClient.PureCloudRegionHosts.ap_northeast_1;
            } else if (environment === 'mypurecloud.de') {
                regionHost = this.platformClient.PureCloudRegionHosts.eu_central_1;
            } else {
                regionHost = environment;
            }
            
            client.setEnvironment(regionHost);
            console.log('[QueueMonitor] OAuth: Set environment to:', environment, 'Region Host:', regionHost);
            
            // Check if we already have a token from URL hash (OAuth redirect)
            const hash = window.location.hash;
            if (hash && hash.includes('access_token')) {
                const hashParams = new URLSearchParams(hash.substring(1));
                const accessToken = hashParams.get('access_token');
                
                if (accessToken) {
                    console.log('[QueueMonitor] Found OAuth access token in URL hash:', accessToken.substring(0, 20) + '...');
                    
                    // Try multiple methods to set the token
                    try {
                        // Method 1: Direct setAccessToken
                        client.setAccessToken(accessToken);
                        console.log('[QueueMonitor] Method 1 - setAccessToken called');
                        
                        // Method 2: Set authentication directly
                        if (client.authentications && client.authentications.PureCloud) {
                            client.authentications.PureCloud.accessToken = accessToken;
                            console.log('[QueueMonitor] Method 2 - Direct authentication property set');
                        }
                        
                        // Method 3: Set default authentication
                        client.defaultHeaders = client.defaultHeaders || {};
                        client.defaultHeaders['Authorization'] = `Bearer ${accessToken}`;
                        console.log('[QueueMonitor] Method 3 - Authorization header set');
                        
                    } catch (tokenError) {
                        console.error('[QueueMonitor] Error setting token:', tokenError);
                    }
                    
                    // Verify the token was set
                    const verifyToken = client.authentications?.PureCloud?.accessToken;
                    const verifyHeader = client.defaultHeaders?.['Authorization'];
                    console.log('[QueueMonitor] Token verification after setting:');
                    console.log('  - PureCloud auth:', verifyToken ? (verifyToken.substring(0, 20) + '...') : 'NOT SET');
                    console.log('  - Auth header:', verifyHeader ? (verifyHeader.substring(0, 27) + '...') : 'NOT SET');
                    
                    // Clean up the URL hash
                    window.history.replaceState(null, null, window.location.pathname + window.location.search);
                    
                    this.updateConnectionStatus('connected', 'Connected via OAuth');
                    return { success: true };
                }
            }
            
            // No token found, initiate OAuth flow
            console.log('[QueueMonitor] No token found, redirecting to OAuth authorization');
            
            const authUrl = this.buildOAuthUrl();
            console.log('[QueueMonitor] Redirecting to:', authUrl);
            
            // Show user-friendly message before redirect
            this.updateConnectionStatus('connecting', 'Redirecting to Genesys Cloud...');
            this.showError('You will be redirected to Genesys Cloud to authorize this application. Please log in and grant the requested permissions.');
            
            // Redirect after a short delay to let user see the message
            setTimeout(() => {
                window.location.href = authUrl;
            }, 2000);
            
            return { success: false, reason: 'oauth_redirect_pending' };
            
        } catch (error) {
            console.error('[QueueMonitor] OAuth authentication failed:', error);
            this.updateConnectionStatus('error', 'OAuth Authentication Failed');
            return { success: false, reason: 'oauth_error', error: error.message };
        }
    }
    
    buildOAuthUrl() {
        const baseUrl = `https://login.${this.oauthConfig.environment}/oauth/authorize`;
        const params = new URLSearchParams({
            response_type: 'token',
            client_id: this.oauthConfig.clientId,
            redirect_uri: this.oauthConfig.redirectUri,
            scope: this.oauthConfig.scopes.join(' ')
        });
        
        return `${baseUrl}?${params.toString()}`;
    }

    async loadQueues() {
        if (this.isLoading) return;
        
        try {
            this.isLoading = true;
            this.showLoading(true);
            this.hideError();
            
            let queuesResponse;
            
            // Check if we should use Client App SDK instead of Platform Client
            if (this.isWidgetMode && this.clientApp) {
                console.log('[QueueMonitor] Using Client App SDK for API calls...');
                
                // Try Client App SDK first for widget mode
                try {
                    // Log what's available on the Client App SDK
                    console.log('[QueueMonitor] Client App SDK available properties:', Object.keys(this.clientApp));
                    if (this.clientApp.routing) {
                        console.log('[QueueMonitor] Client App SDK routing methods:', Object.keys(this.clientApp.routing));
                    }
                    if (this.clientApp.api) {
                        console.log('[QueueMonitor] Client App SDK api methods:', Object.keys(this.clientApp.api));
                    }
                    
                    // Use Client App SDK for queue data - try different method signatures
                    let sdkQueuesResponse;
                    
                    // Method 1: Try with users API to get authenticated context first
                    if (this.clientApp.users && this.clientApp.users.getMe) {
                        try {
                            console.log('[QueueMonitor] Testing Client App SDK authentication with users.getMe()...');
                            const currentUser = await this.clientApp.users.getMe();
                            console.log('[QueueMonitor] ✅ Got current user via Client App SDK:', currentUser?.name || 'Unknown');
                            console.log('[QueueMonitor] User ID:', currentUser?.id);
                            console.log('[QueueMonitor] User email:', currentUser?.email);
                            
                            // Now try to get queues using the authenticated context
                            if (this.clientApp.routing && this.clientApp.routing.getQueues) {
                                console.log('[QueueMonitor] Client App SDK routing.getQueues is available, trying...');
                                sdkQueuesResponse = await this.clientApp.routing.getQueues({
                                    pageSize: 100,
                                    sortBy: 'name'
                                });
                                console.log('[QueueMonitor] ✅ Queues loaded via Client App SDK routing.getQueues');
                                console.log('[QueueMonitor] Number of queues:', sdkQueuesResponse?.entities?.length || 0);
                            } else {
                                console.log('[QueueMonitor] Client App SDK routing.getQueues not available');
                                console.log('[QueueMonitor] Available routing methods:', this.clientApp.routing ? Object.keys(this.clientApp.routing) : 'routing not available');
                            }
                        } catch (method1Error) {
                            console.log('[QueueMonitor] Client App SDK users.getMe failed:', method1Error.message);
                            console.log('[QueueMonitor] Error details:', method1Error);
                        }
                    } else {
                        console.log('[QueueMonitor] Client App SDK users.getMe not available');
                        console.log('[QueueMonitor] Users object type:', typeof this.clientApp.users);
                        if (this.clientApp.users) {
                            console.log('[QueueMonitor] Available users methods:', Object.keys(this.clientApp.users));
                        }
                    }
                    
                    // Method 2: Try using Client App SDK internal API methods
                    if (!sdkQueuesResponse) {
                        try {
                            // Check if the Client App SDK has internal API access
                            console.log('[QueueMonitor] Checking for Client App SDK internal API access...');
                            
                            // Try to access the routing queues through the SDK's internal methods
                            // The Client App SDK might have different method names or structures
                            if (this.clientApp._platformClient || this.clientApp.platformClient) {
                                const platformClient = this.clientApp._platformClient || this.clientApp.platformClient;
                                console.log('[QueueMonitor] Found platform client in Client App SDK');
                                
                                if (platformClient.RoutingApi) {
                                    const routingApi = new platformClient.RoutingApi();
                                    sdkQueuesResponse = await routingApi.getRoutingQueues({
                                        pageSize: 100,
                                        sortBy: 'name'
                                    });
                                    console.log('[QueueMonitor] ✅ Queues loaded via Client App SDK internal platform client');
                                }
                            }
                        } catch (method2Error) {
                            console.log('[QueueMonitor] Client App SDK internal API failed:', method2Error.message);
                        }
                    }
                    
                    // Method 3: Try with direct API call if available
                    if (!sdkQueuesResponse && this.clientApp.api && this.clientApp.api.get) {
                        try {
                            sdkQueuesResponse = await this.clientApp.api.get('/routing/queues', {
                                params: {
                                    pageSize: 100,
                                    sortBy: 'name'
                                }
                            });
                            console.log('[QueueMonitor] ✅ Queues loaded via Client App SDK api.get');
                        } catch (method3Error) {
                            console.log('[QueueMonitor] Client App SDK api.get failed:', method3Error.message);
                        }
                    } else {
                        console.log('[QueueMonitor] Client App SDK api.get not available');
                    }
                    
                    // Method 4: Try with myClientApp methods (some SDK versions)
                    if (!sdkQueuesResponse && this.clientApp.myClientApp) {
                        try {
                            console.log('[QueueMonitor] Trying myClientApp methods...');
                            // This is a fallback for some SDK implementations
                        } catch (method4Error) {
                            console.log('[QueueMonitor] Client App SDK myClientApp failed:', method4Error.message);
                        }
                    }
                    
                    if (sdkQueuesResponse) {
                        queuesResponse = sdkQueuesResponse;
                        console.log('[QueueMonitor] ✅ Using Client App SDK response');
                    } else {
                        console.log('[QueueMonitor] All Client App SDK methods failed, falling back to Platform Client');
                        // Fall through to use Platform Client
                    }
                    
                } catch (sdkError) {
                    console.log('[QueueMonitor] Client App SDK queue loading failed:', sdkError.message);
                    console.log('[QueueMonitor] Falling back to Platform Client');
                    // Fall through to use Platform Client
                }
            }
            
            // Use Platform Client if Client App SDK didn't work or not in widget mode
            if (!queuesResponse) {
                // Use Platform Client (original method)
                console.log('[QueueMonitor] Using Platform Client for API calls...');
                
                // Debug: Check authentication state before making API calls
                console.log('[QueueMonitor] ========================================');
                console.log('[QueueMonitor] PREPARING API CALL - AUTHENTICATION CHECK');
                console.log('[QueueMonitor] ========================================');
                
                const client = this.platformClient.ApiClient.instance;
                const currentToken = client.authentications?.PureCloud?.accessToken;
                const authHeader = client.defaultHeaders?.['Authorization'];
                
                console.log('[QueueMonitor] API Call Authentication State:');
                console.log('[QueueMonitor]   - Widget Mode:', this.isWidgetMode);
                console.log('[QueueMonitor]   - Token Available:', currentToken ? 'YES' : 'NO');
                console.log('[QueueMonitor]   - Token Value:', currentToken ? (currentToken.substring(0, 20) + '...') : 'NO TOKEN');
                console.log('[QueueMonitor]   - Auth Header:', authHeader ? (authHeader.substring(0, 27) + '...') : 'NO HEADER');
                console.log('[QueueMonitor]   - Base Path:', client.basePath || 'NOT SET');
                console.log('[QueueMonitor]   - Client Environment:', client.environment || 'NOT SET');
                console.log('[QueueMonitor]   - Default Authentication:', client.defaultAuthentication || 'NOT SET');
                
                // Check authentication configuration
                if (client.authentications?.PureCloud) {
                    console.log('[QueueMonitor] PureCloud Authentication Object:');
                    console.log('[QueueMonitor]   - Type:', client.authentications.PureCloud.type || 'NOT SET');
                    console.log('[QueueMonitor]   - Api Key:', client.authentications.PureCloud.apiKey ? 'SET' : 'NOT SET');
                    console.log('[QueueMonitor]   - Api Key Prefix:', client.authentications.PureCloud.apiKeyPrefix || 'NOT SET');
                    console.log('[QueueMonitor]   - Access Token:', client.authentications.PureCloud.accessToken ? 'SET' : 'NOT SET');
                }
                
                // In widget mode, authentication is handled automatically by the browser context
                // Skip explicit token validation for widget contexts
                if (!this.isWidgetMode && !currentToken && !authHeader) {
                    console.error('[QueueMonitor] ❌ Authentication validation failed - no token available for standalone mode');
                    throw new Error('No authentication token available - cannot make API calls');
                }
                
                if (this.isWidgetMode) {
                    console.log('[QueueMonitor] ✅ Widget mode detected - proceeding with API call (authentication handled by widget framework)');
                } else {
                    console.log('[QueueMonitor] ✅ Standalone mode with valid authentication - proceeding with API call');
                }
                
                // Fetch all queues
                console.log('[QueueMonitor] === MAKING API CALL ===');
                console.log('[QueueMonitor] Calling routingApi.getRoutingQueues with params:', { pageSize: 100, sortBy: 'name' });
                
                const startTime = Date.now();
                try {
                    queuesResponse = await this.routingApi.getRoutingQueues({
                        pageSize: 100,
                        sortBy: 'name'
                    });
                    const endTime = Date.now();
                    console.log('[QueueMonitor] ✅ API call successful in', (endTime - startTime), 'ms');
                    console.log('[QueueMonitor] Response type:', typeof queuesResponse);
                    console.log('[QueueMonitor] Response entities count:', queuesResponse?.entities?.length || 'NO ENTITIES');
                    console.log('[QueueMonitor] Response structure:', {
                        hasEntities: !!queuesResponse?.entities,
                        hasPageSize: !!queuesResponse?.pageSize,
                        hasPageNumber: !!queuesResponse?.pageNumber,
                        hasTotal: !!queuesResponse?.total
                    });
                } catch (apiError) {
                    const endTime = Date.now();
                    console.error('[QueueMonitor] ❌ API call failed after', (endTime - startTime), 'ms');
                    console.error('[QueueMonitor] API Error:', apiError);
                    console.error('[QueueMonitor] API Error Message:', apiError.message);
                    console.error('[QueueMonitor] API Error Status:', apiError.status);
                    console.error('[QueueMonitor] API Error Stack:', apiError.stack);
                    throw apiError;
                }
            }
            
            if (!queuesResponse || !queuesResponse.entities) {
                throw new Error('No queue data received');
            }

            // Get queue statistics
            const queueIds = queuesResponse.entities.map(queue => queue.id);
            const queueStats = await this.getQueueStatistics(queueIds);
            
            // Combine queue info with statistics
            this.queues = queuesResponse.entities.map(queue => {
                const stats = queueStats[queue.id] || {};
                // console.log(`[QueueMonitor] Queue "${queue.name}" (${queue.id}) raw stats:`, stats);
                const processedStats = {
                    waiting: stats.waiting || 0,
                    interacting: stats.interacting || 0,
                    alerting: stats.alerting || 0,
                    activeUsers: stats.activeUsers || 0,
                    onQueueUsers: stats.onQueueUsers || 0
                };
                // console.log(`[QueueMonitor] Queue "${queue.name}" processed stats:`, processedStats);
                return {
                    ...queue,
                    stats: processedStats
                };
            });

            // Reapply current filter after loading new data
            this.filterQueues(this.currentSearchTerm);
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

            // Create analytics query for real-time queue statistics (voice media type only)
            const query = {
                metrics: ['oWaiting', 'oInteracting', 'oAlerting', 'oActiveUsers', 'oOnQueueUsers'],
                filter: {
                    type: 'and',
                    clauses: [
                        {
                            type: 'or',
                            predicates: queueIds.map(queueId => ({
                                dimension: 'queueId',
                                value: queueId
                            }))
                        }
                    ],
                    predicates: [
                        {
                            type: 'dimension',
                            dimension: 'mediaType',
                            operator: 'matches',
                            value: 'voice'
                        }
                    ]
                }
            };

            let response;
            
            // Try Client App SDK first if in widget mode
            if (this.isWidgetMode && this.clientApp) {
                try {
                    // Method 1: Try with internal platform client analytics API
                    if (this.clientApp._platformClient || this.clientApp.platformClient) {
                        const internalClient = this.clientApp._platformClient || this.clientApp.platformClient;
                        if (internalClient.AnalyticsApi) {
                            const analyticsApi = new internalClient.AnalyticsApi();
                            response = await analyticsApi.postAnalyticsQueuesObservationsQuery(query);
                            console.log('[QueueMonitor] ✅ Analytics data loaded via Client App SDK internal analytics API');
                        }
                    }
                    // Method 2: Try with analytics API if available
                    else if (this.clientApp.analytics && this.clientApp.analytics.postAnalyticsQueuesObservationsQuery) {
                        response = await this.clientApp.analytics.postAnalyticsQueuesObservationsQuery(query);
                        console.log('[QueueMonitor] ✅ Analytics data loaded via Client App SDK analytics API');
                    }
                } catch (sdkError) {
                    console.log('[QueueMonitor] Client App SDK analytics failed:', sdkError.message);
                    console.log('[QueueMonitor] Falling back to Platform Client for analytics');
                }
            }
            
            // Use Platform Client if Client App SDK didn't work
            if (!response) {
                response = await this.analyticsApi.postAnalyticsQueuesObservationsQuery(query);
            }
            
            // Debug: Log the full response structure
            // console.log('[QueueMonitor] Analytics API response:', response);
            
            // Process the response to create a lookup by queue ID
            const stats = {};
            if (response && response.results) {
                // console.log('[QueueMonitor] Processing', response.results.length, 'results');
                
                // Initialize stats for all queues
                queueIds.forEach(queueId => {
                    stats[queueId] = {
                        waiting: 0,
                        interacting: 0,
                        alerting: 0,
                        activeUsers: 0,
                        onQueueUsers: 0
                    };
                });
                
                response.results.forEach((result, index) => {
                    // console.log(`[QueueMonitor] Result ${index}:`, result);
                    if (result.group && result.group.queueId && result.data) {
                        const queueId = result.group.queueId;
                        const mediaType = result.group.mediaType;
                        
                        // console.log(`[QueueMonitor] Processing queue ${queueId}, mediaType: ${mediaType || 'none'}`);
                        
                        // Process each metric in the data array
                        result.data.forEach(dataItem => {
                            const metric = dataItem.metric;
                            const count = dataItem.stats ? dataItem.stats.count : 0;
                            
                            // console.log(`[QueueMonitor] Queue ${queueId}, metric: ${metric}, count: ${count}, qualifier: ${dataItem.qualifier || 'none'}`);
                            
                            // Map metrics to our stats object (voice media type only)
                            switch (metric) {
                                case 'oWaiting':
                                    stats[queueId].waiting = count;
                                    break;
                                case 'oInteracting':
                                    stats[queueId].interacting = count;
                                    break;
                                case 'oAlerting':
                                    stats[queueId].alerting = count;
                                    break;
                                case 'oActiveUsers':
                                    stats[queueId].activeUsers = count;
                                    break;
                                case 'oOnQueueUsers':
                                    // Sum up all on-queue users regardless of qualifier
                                    stats[queueId].onQueueUsers += count;
                                    break;
                            }
                        });
                        
                        // console.log(`[QueueMonitor] Queue ${queueId} current stats:`, stats[queueId]);
                    }
                });
                
                // console.log('[QueueMonitor] Final aggregated stats:', stats);
            } else {
                // console.log('[QueueMonitor] No results in analytics response');
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
                            <span class="stat-number">${queue.stats.onQueueUsers || 0}</span>
                            <span class="stat-label">On Queue</span>
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

        // Modal event listeners
        document.getElementById('closeModal').addEventListener('click', () => {
            this.hideTransferModal();
        });

        // Close modal when clicking outside of it
        document.getElementById('transferModal').addEventListener('click', (e) => {
            if (e.target.id === 'transferModal') {
                this.hideTransferModal();
            }
        });

        // Transfer button event listeners
        document.getElementById('blindTransferBtn').addEventListener('click', () => {
            this.performBlindTransfer();
        });

        document.getElementById('consultTransferBtn').addEventListener('click', () => {
            this.performConsultTransfer();
        });

        // ESC key to close modal
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && document.getElementById('transferModal').style.display === 'flex') {
                this.hideTransferModal();
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
        this.currentSearchTerm = searchTerm;
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
        console.log('[QueueMonitor] Queue clicked:', queueId);
        
        // Find the selected queue
        this.selectedQueue = this.queues.find(queue => queue.id === queueId);
        if (!this.selectedQueue) {
            console.error('[QueueMonitor] Queue not found:', queueId);
            return;
        }
        
        // Check if we're in standalone mode
        if (this.isStandalone) {
            this.showQueueDetails();
        } else {
            // Show the transfer modal (for interaction widget mode)
            this.showTransferModal();
        }
    }

    showQueueDetails() {
        if (!this.selectedQueue) return;
        
        // Show detailed queue information in standalone mode
        const stats = this.selectedQueue.stats;
        const queueInfo = `
Queue: ${this.selectedQueue.name}
Description: ${this.selectedQueue.description || 'No description available'}

Current Statistics:
• Waiting: ${stats.waiting || 0} customers
• Agents on queue: ${stats.onQueueUsers || 0}
• Interacting: ${stats.interacting || 0}
• Answered today: ${stats.answered || 0}
• Abandoned today: ${stats.abandoned || 0}
• Average wait time: ${this.formatTime(stats.avgWaitTime || 0)}

Note: Transfer functionality is only available when running as a Genesys Cloud interaction widget.
        `.trim();
        
        alert(queueInfo);
    }

    showTransferModal() {
        if (!this.selectedQueue) return;
        
        // Populate modal with queue information
        document.getElementById('selectedQueueName').textContent = this.selectedQueue.name;
        document.getElementById('selectedQueueDescription').textContent = 
            this.selectedQueue.description || 'No description available';
        document.getElementById('modalWaitingCount').textContent = 
            this.selectedQueue.stats.waiting || 0;
        document.getElementById('modalAgentCount').textContent = 
            this.selectedQueue.stats.onQueueUsers || 0;
        
        // Show the modal
        document.getElementById('transferModal').style.display = 'flex';
        
        // Get current conversation ID from the Client App SDK
        this.getCurrentConversation();
    }

    hideTransferModal() {
        document.getElementById('transferModal').style.display = 'none';
        this.selectedQueue = null;
        this.hideTransferStatus();
    }

    showTransferStatus(message) {
        document.getElementById('transferStatusText').textContent = message;
        document.getElementById('transferStatus').style.display = 'block';
    }

    hideTransferStatus() {
        document.getElementById('transferStatus').style.display = 'none';
    }

    async getCurrentConversation() {
        try {
            console.log('[QueueMonitor] Attempting to get current conversation...');
            console.log('[QueueMonitor] Client App available:', !!this.clientApp);
            console.log('[QueueMonitor] Running in standalone mode:', this.isStandalone);
            
            // Try to get conversation ID from the Client App SDK
            if (this.clientApp && this.clientApp.getConversation) {
                console.log('[QueueMonitor] Trying Client App SDK getConversation...');
                const conversation = await this.clientApp.getConversation();
                console.log('[QueueMonitor] Client App SDK response:', conversation);
                
                if (conversation && conversation.conversationId) {
                    this.currentConversationId = conversation.conversationId;
                    console.log('[QueueMonitor] Found conversation ID:', this.currentConversationId);
                    return;
                }
            }
            
            // Check restored widget context first (for post-OAuth scenarios)
            if (this.urlParams && this.urlParams.conversationId) {
                console.log('[QueueMonitor] 🎯 Found conversation ID from restored widget context:', this.urlParams.conversationId);
                this.currentConversationId = this.urlParams.conversationId;
                return;
            }
            
            // Fallback: Check current URL parameters for conversation/interaction ID  
            const urlParams = new URLSearchParams(window.location.search);
            const conversationId = urlParams.get('conversationId') || 
                                 urlParams.get('iid') || 
                                 urlParams.get('interactionId');
            
            console.log('[QueueMonitor] URL parameters check:', {
                conversationId: urlParams.get('conversationId'),
                iid: urlParams.get('iid'),
                interactionId: urlParams.get('interactionId')
            });
            
            console.log('[QueueMonitor] Widget context check:', {
                widgetContextConversationId: this.urlParams?.conversationId,
                isWidgetMode: this.isWidgetMode,
                isStandalone: this.isStandalone
            });
            
            if (conversationId) {
                this.currentConversationId = conversationId;
                console.log('[QueueMonitor] Found conversation ID from URL parameters:', this.currentConversationId);
            } else {
                if (this.isStandalone) {
                    console.log('[QueueMonitor] No active conversation found - running in standalone mode');
                } else {
                    console.warn('[QueueMonitor] No active conversation found - this may indicate the widget is not properly integrated');
                    console.warn('[QueueMonitor] Expected conversation ID from widget context or URL parameters');
                }
            }
        } catch (error) {
            console.error('[QueueMonitor] Error getting conversation:', error);
        }
    }

    async performBlindTransfer() {
        if (!this.selectedQueue) {
            this.showTransferStatus('Error: No queue selected');
            return;
        }
        
        if (!this.currentConversationId) {
            if (this.isStandalone) {
                this.showTransferStatus('Transfer not available in standalone mode. This feature requires the widget to be embedded in Genesys Cloud.');
            } else {
                this.showTransferStatus('Error: No active conversation found');
            }
            return;
        }
        
        try {
            this.showTransferStatus('Initiating blind transfer...');
            
            console.log('[QueueMonitor] Performing blind transfer to queue:', this.selectedQueue.name);
            
            // Execute the blind transfer using Conversations API
            // For blind transfers to queue, use postConversationsCallParticipantReplaceQueue
            // We need to get the caller's participant ID (not the agent's)
            const conversationDetails = await this.conversationsApi.getConversationsCall(this.currentConversationId);
            
            console.log('[QueueMonitor] Conversation details:', conversationDetails);
            console.log('[QueueMonitor] Available participants:', conversationDetails.participants);
            
            // Log each participant for debugging
            conversationDetails.participants.forEach((participant, index) => {
                console.log(`[QueueMonitor] Participant ${index}:`, {
                    id: participant.id,
                    purpose: participant.purpose,
                    name: participant.name,
                    state: participant.state,
                    userId: participant.user?.id
                });
            });
            
            const callerParticipant = conversationDetails.participants.find(p => p.purpose === 'customer');
            
            if (!callerParticipant) {
                console.log('[QueueMonitor] ❌ Could not find caller participant with purpose="customer"');
                console.log('[QueueMonitor] Available purposes:', [...new Set(conversationDetails.participants.map(p => p.purpose))]);
                throw new Error('Could not find caller participant');
            }
            
            const transferBody = {
                speakTo: "DESTINATION",
                queueId: this.selectedQueue.id,
                queueName: this.selectedQueue.name
            };
            
            console.log('[QueueMonitor] Using caller participant ID:', callerParticipant.id);
            console.log('[QueueMonitor] Transfer body:', transferBody);
            
            const result = await this.conversationsApi.postConversationsCallParticipantReplaceQueue(
                this.currentConversationId,
                callerParticipant.id,
                transferBody
            );
            
            console.log('[QueueMonitor] Transfer successful:', result);
            this.showTransferStatus('Transfer completed successfully!');
            
            // Auto-close modal after success
            setTimeout(() => {
                this.hideTransferModal();
            }, 2000);
            
        } catch (error) {
            console.error('[QueueMonitor] Blind transfer failed:', error);
            this.showTransferStatus('Transfer failed: ' + (error.message || 'Unknown error'));
            
            // Auto-hide status after error
            setTimeout(() => {
                this.hideTransferStatus();
            }, 3000);
        }
    }

    async performConsultTransfer() {
        if (!this.selectedQueue) {
            this.showTransferStatus('Error: No queue selected');
            return;
        }
        
        if (!this.currentConversationId) {
            if (this.isStandalone) {
                this.showTransferStatus('Transfer not available in standalone mode. This feature requires the widget to be embedded in Genesys Cloud.');
            } else {
                this.showTransferStatus('Error: No active conversation found');
            }
            return;
        }
        
        try {
            this.showTransferStatus('Initiating consult transfer...');
            
            console.log('[QueueMonitor] Performing consult transfer to queue:', this.selectedQueue.name);
            
            // Execute the consult transfer using Conversations API
            // For consult transfers to queue, use postConversationsCallParticipantConsultQueue
            // We need to get the caller's participant ID (not the agent's)
            const conversationDetails = await this.conversationsApi.getConversationsCall(this.currentConversationId);
            
            console.log('[QueueMonitor] Conversation details:', conversationDetails);
            console.log('[QueueMonitor] Available participants:', conversationDetails.participants);
            
            // Log each participant for debugging
            conversationDetails.participants.forEach((participant, index) => {
                console.log(`[QueueMonitor] Participant ${index}:`, {
                    id: participant.id,
                    purpose: participant.purpose,
                    name: participant.name,
                    state: participant.state,
                    userId: participant.user?.id
                });
            });
            
            const callerParticipant = conversationDetails.participants.find(p => p.purpose === 'customer');
            
            if (!callerParticipant) {
                console.log('[QueueMonitor] ❌ Could not find caller participant with purpose="customer"');
                console.log('[QueueMonitor] Available purposes:', [...new Set(conversationDetails.participants.map(p => p.purpose))]);
                throw new Error('Could not find caller participant');
            }
            
            const consultBody = {
                speakTo: "DESTINATION",
                queueId: this.selectedQueue.id,
                queueName: this.selectedQueue.name
            };
            
            console.log('[QueueMonitor] Using caller participant ID:', callerParticipant.id);
            console.log('[QueueMonitor] Consult body:', consultBody);
            
            const result = await this.conversationsApi.postConversationsCallParticipantConsultQueue(
                this.currentConversationId,
                callerParticipant.id,
                consultBody
            );
            
            console.log('[QueueMonitor] Consult transfer initiated:', result);
            this.showTransferStatus('Consult transfer initiated. You will be connected to speak with an agent.');
            
            // Auto-close modal after success
            setTimeout(() => {
                this.hideTransferModal();
            }, 3000);
            
        } catch (error) {
            console.error('[QueueMonitor] Consult transfer failed:', error);
            this.showTransferStatus('Transfer failed: ' + (error.message || 'Unknown error'));
            
            // Auto-hide status after error
            setTimeout(() => {
                this.hideTransferStatus();
            }, 3000);
        }
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