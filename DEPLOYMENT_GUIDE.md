# Genesys Cloud Queue Monitor - Deployment Guide

This guide covers two deployment scenarios for the Queue Monitor widget.

## 🌐 Option 1: Standalone Deployment (Outside Genesys Cloud)

### Prerequisites
1. **Genesys Cloud Organization** with admin access
2. **OAuth Application** registered in Genesys Cloud
3. **Web hosting** (GitHub Pages, Netlify, etc.)

### Step 1: Create OAuth Application in Genesys Cloud

1. **Log into Genesys Cloud Admin**
   - Go to Admin → Integrations → OAuth
   - Click "Add Client"

2. **Configure OAuth Client**
   ```
   Name: Queue Monitor Widget
   Description: External queue monitoring dashboard
   Grant Types: ☑️ Token Implicit Grant (Browser)
   Scope: routing, analytics
   Authorized Redirect URIs: https://yourdomain.com/path-to-widget/
   ```

3. **Save and Copy Client ID**
   - Note down the generated Client ID

### Step 2: Configure the Widget

1. **Update OAuth Configuration in `app.js`**
   ```javascript
   this.oauthConfig = {
       clientId: 'your-actual-client-id-here', // Replace with your Client ID
       redirectUri: 'https://yourdomain.com/path-to-widget/', // Your hosting URL
       environment: 'mypurecloud.ie', // Your Genesys Cloud environment
       scopes: ['routing', 'analytics']
   };
   ```

2. **Set Your Environment**
   - `mypurecloud.com` (US East)
   - `mypurecloud.ie` (EU West) 
   - `mypurecloud.com.au` (Asia Pacific)
   - `mypurecloud.jp` (Asia Pacific Northeast)
   - `mypurecloud.de` (EU Central)

### Step 3: Deploy and Test

1. **Deploy to your web hosting**
2. **Access the widget URL**
3. **You'll be redirected to Genesys Cloud for authentication**
4. **After login, you'll return with live queue data**

---

## 🏢 Option 2: Genesys Cloud Interaction Widget

### Prerequisites
1. **Genesys Cloud Organization** with admin access
2. **Interaction Widget permissions**

### Step 1: Prepare Widget Files

1. **Ensure all files are accessible via HTTPS**
   - `index.html`
   - `styles.css` 
   - `app.js`
   - `app.json`

2. **Update `app.json` configuration**
   ```json
   {
       "name": "Queue Monitor",
       "displayName": "Queue Monitor",
       "description": "Real-time queue monitoring dashboard",
       "url": "https://yourdomain.com/path-to-widget/",
       "type": "interaction-widget",
       "icon": "https://yourdomain.com/path-to-widget/icon.png",
       "permissions": [
           "routing",
           "analytics"
       ]
   }
   ```

### Step 2: Install in Genesys Cloud

1. **Go to Admin → Integrations**
2. **Click "Install Integration"**
3. **Choose "Install from URL"**
4. **Enter your `app.json` URL**: `https://yourdomain.com/path-to-widget/app.json`
5. **Click "Install"**

### Step 3: Configure Widget

1. **After installation, go to Integration details**
2. **Configure permissions** (routing, analytics)
3. **Set up user/group assignments**
4. **Activate the integration**

### Step 4: Access Widget

1. **Log into Genesys Cloud**
2. **Go to your interaction workspace**
3. **Find "Queue Monitor" in your widgets panel**
4. **Widget will load with automatic authentication**

---

## 🔧 Configuration Options

### Environment Settings
```javascript
// In app.js constructor
this.oauthConfig = {
    environment: 'mypurecloud.ie', // Change to your region
    // ... other settings
};
```

### Refresh Interval
```javascript
// In setupAutoRefresh method (default: 30 seconds)
this.refreshInterval = setInterval(() => {
    if (!this.isLoading) {
        this.loadQueues();
    }
}, 30000); // Change to desired interval in milliseconds
```

### Queue Priority Thresholds
```javascript
// In getQueuePriorityClass method
getQueuePriorityClass(waitingCount) {
    if (waitingCount >= 10) return 'high-queue';    // Red - High priority
    if (waitingCount >= 5) return 'medium-queue';   // Yellow - Medium priority
    return 'low-queue';                             // Green - Low priority
}
```

---

## 🚨 Troubleshooting

### Common Issues

1. **"OAuth Configuration Required" Error**
   - Update the `clientId` in `app.js`
   - Ensure OAuth app is properly configured in Genesys Cloud

2. **"Cross-Origin" Errors**
   - Ensure all files are served over HTTPS
   - Check that redirect URI matches exactly

3. **"Permission Denied" Errors**
   - Verify OAuth app has `routing` and `analytics` scopes
   - Check user has appropriate permissions in Genesys Cloud

4. **Widget Not Loading in Genesys Cloud**
   - Verify `app.json` is accessible via HTTPS
   - Check integration is activated
   - Ensure user/group assignments are correct

### Debug Mode
Enable detailed logging by opening browser console and filtering for `[QueueMonitor]`.

---

## 📋 Required Permissions

### OAuth Scopes
- `routing` - Access to queue information
- `analytics` - Access to queue statistics and metrics

### Genesys Cloud User Permissions
- **Routing > Queue > View** - View queue details
- **Analytics > Queue Observation > View** - View real-time queue metrics

---

## 🔒 Security Considerations

1. **Use HTTPS** for all deployments
2. **Restrict OAuth redirect URIs** to your specific domains
3. **Regularly rotate OAuth client secrets** (if using confidential clients)
4. **Monitor OAuth application usage** in Genesys Cloud logs
5. **Implement proper error handling** for authentication failures

---

## 📞 Support

For issues related to:
- **Genesys Cloud configuration**: Contact your Genesys Cloud administrator
- **Widget functionality**: Check browser console for `[QueueMonitor]` logs
- **OAuth setup**: Refer to [Genesys Cloud OAuth documentation](https://developer.genesys.cloud/authorization/) 