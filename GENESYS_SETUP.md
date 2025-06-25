# Genesys Cloud Integration Setup Guide

## Quick Setup Steps

### 1. Admin Console Setup
1. Login to Genesys Cloud Admin: `https://apps.mypurecloud.ie/directory/#/admin`
2. Navigate to **Admin** → **Integrations**
3. Click **"+ Add Integration"**
4. Search for **"Custom Client Application"**
5. Click **"Install"**

### 2. Configure Integration
Fill in these details:
- **Integration Name**: `Queue Monitor Widget`
- **Application URL**: `https://jeroenddm.github.io/`
- **Application Type**: `Widget`
- **Categories**: Check `Analytics` and `Monitoring`

**Important**: The app.json now uses URL interpolation to automatically pass context parameters from Genesys Cloud to the widget. This means when the widget loads, it will receive parameters like:
- `gcHostOrigin` - The Genesys Cloud host origin
- `gcTargetEnv` - The target environment
- `iid` - The current interaction ID
- `locale` - The user's locale
- `environment` - The PureCloud environment

This allows the widget to automatically detect it's running in widget mode instead of standalone mode.

### 3. Permissions Required
Ensure these permissions are enabled:
- ✅ **analytics** - For reading queue statistics
- ✅ **routing** - For accessing queue information  
- ✅ **conversations** - For transfer functionality

### 4. Widget Configuration
- **Widget Type**: `Interaction Widget`
- **Interaction Types**: Enable all (Voice, Chat, Email, Callback, Message)
- **Sandbox**: `allow-same-origin allow-scripts allow-popups allow-forms`

### 5. Activation
1. Click **"Save"** 
2. Set status to **"Active"**
3. Click **"Save"** again

### 6. User Assignment
- Go to **Admin** → **People & Permissions** → **People**
- Select users who need the widget
- Add the "Queue Monitor Widget" integration to their profile

## Testing the Widget

Once deployed, agents will see the Queue Monitor widget:
1. **During a call/chat**: The widget appears in the interaction panel
2. **Click on any queue**: Opens transfer options (Blind Transfer/Consult Transfer)
3. **Auto-refresh**: Updates every 30 seconds automatically

## Troubleshooting

### Widget Not Appearing
- Check if integration is **Active**
- Verify user has the integration assigned
- Confirm permissions are granted

### Authentication Issues
- Ensure app URL is correct: `https://jeroenddm.github.io/`
- Check browser console for error messages
- Verify organization region (mypurecloud.ie)

### Transfer Not Working
- Confirm agent is on an active interaction
- Check conversations permission is granted
- Verify queue IDs are accessible to the agent

## URL Interpolation

This widget uses [URL interpolation](https://developer.genesys.cloud/platform/integrations/client-apps/) to automatically receive context from Genesys Cloud. The interpolated URL format is:

```
https://jeroenddm.github.io/index.html?gcHostOrigin={{gcHostOrigin}}&gcTargetEnv={{gcTargetEnv}}&iid={{iid}}&locale={{locale}}&environment={{pcEnvironment}}
```

### Available Interpolation Variables:
- `{{gcHostOrigin}}` - Genesys Cloud host origin URL
- `{{gcTargetEnv}}` - Target environment identifier  
- `{{iid}}` - Current interaction ID (for transfers)
- `{{locale}}` - User's locale setting
- `{{pcEnvironment}}` - PureCloud environment name

When Genesys Cloud loads the widget, these placeholders are automatically replaced with actual values, allowing the widget to:
1. Detect it's running in widget mode (not standalone)
2. Access the current interaction for transfer functionality
3. Use the correct environment settings

## Support
For issues, check the browser console logs and refer to:
- [Genesys Cloud Developer Center](https://developer.genesys.cloud/)
- [Client Apps SDK Documentation](https://developer.genesys.cloud/devapps/sdk/)
- [URL Interpolation Documentation](https://developer.genesys.cloud/platform/integrations/client-apps/) 