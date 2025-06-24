# Genesys Cloud Queue Monitor Widget

A real-time queue monitoring widget for Genesys Cloud agents that displays queue statistics including waiting customers, active interactions, and performance metrics.

## Features

- **Real-time Queue Statistics**: Monitor waiting customers, active interactions, and queue performance
- **Visual Priority Indicators**: Color-coded queues based on waiting customer count
- **Call Transfer Controls**: Click on any queue to transfer active calls
  - 📞 **Blind Transfer**: Transfer call directly to the selected queue
  - 👥 **Consult Transfer**: Speak with an agent before completing the transfer
- **Auto-refresh**: Automatically updates every 30 seconds
- **Search Functionality**: Filter queues by name or description
- **Responsive Design**: Works on desktop and mobile devices
- **Modern UI**: Clean, professional interface designed for agent productivity

## Queue Statistics Displayed

- **Waiting**: Number of customers currently waiting in queue
- **Interacting**: Number of active interactions
- **Answered Today**: Total interactions answered today
- **Abandoned Today**: Total interactions abandoned today
- **Average Wait Time**: Current average wait time
- **Longest Wait**: Current longest wait time

## Priority Levels

- **High Priority** (Red): 10+ customers waiting
- **Medium Priority** (Yellow): 5-9 customers waiting
- **Low Priority** (Green): 0-4 customers waiting

## Setup for Genesys Cloud

### Prerequisites

- Genesys Cloud organization with appropriate permissions
- Access to routing and analytics APIs
- Web hosting for the widget files

### Installation Steps

1. **Host the Widget Files**
   - Upload `index.html`, `styles.css`, `app.js`, and `app.json` to your web server
   - Ensure HTTPS is enabled for security

2. **Create Integration in Genesys Cloud**
   - Navigate to Admin > Integrations
   - Click "+" to add a new integration
   - Select "Custom Client Application"
   - Upload the `app.json` configuration file
   - Set the URL to your hosted `index.html` file

3. **Configure Permissions**
   - Grant the integration the following permissions:
     - `routing` - To access queue information
     - `analytics` - To retrieve queue statistics
     - `conversations` - To enable call transfer functionality

4. **Activate the Integration**
   - Install the integration in your organization
   - Activate it for the desired groups or users

### Usage

1. **As an Interaction Widget**
   - The widget will appear in the interaction panel during customer interactions
   - Agents can monitor queue status while handling interactions

2. **Manual Refresh**
   - Click the "Refresh" button to manually update queue data

3. **Auto-refresh**
   - Toggle the auto-refresh checkbox to enable/disable automatic updates
   - Updates occur every 30 seconds when enabled

4. **Search Queues**
   - Use the search box to filter queues by name or description

5. **Transfer Calls**
   - Click on any queue to open the transfer modal
   - Choose between blind transfer (immediate) or consult transfer (speak first)
   - Transfer is only available during active interactions

## Technical Details

### Dependencies

- `purecloud-platform-client-v2`: Genesys Cloud Platform API client
- `purecloud-client-app-sdk`: Genesys Cloud Client App SDK

### Browser Support

- Chrome 70+
- Firefox 65+
- Safari 12+
- Edge 79+

### Security

- All API calls are authenticated using Genesys Cloud OAuth
- Widget runs in a sandboxed environment within Genesys Cloud
- No sensitive data is stored locally

## Development

### File Structure

```
├── index.html          # Main HTML file
├── styles.css          # Stylesheet
├── app.js             # Main application logic
├── app.json           # Genesys Cloud app configuration
├── package.json       # Node.js dependencies
└── README.md          # This file
```

### Local Development

1. Install dependencies:
   ```bash
   npm install
   ```

2. Serve the files using a local web server:
   ```bash
   # Using Python
   python -m http.server 8000
   
   # Using Node.js
   npx http-server
   ```

3. Access the widget at `http://localhost:8000`

### API Usage

The widget uses the following Genesys Cloud APIs:

- **Routing API**: `getRoutingQueues()` - Retrieves queue configuration
- **Analytics API**: `postAnalyticsQueuesObservationsQuery()` - Gets real-time statistics
- **Conversations API**: `postConversationTransfer()` - Handles call transfers

## Troubleshooting

### Common Issues

1. **Authentication Failed**
   - Ensure the integration is properly configured in Genesys Cloud
   - Check that the widget URL is accessible via HTTPS

2. **No Queue Data**
   - Verify routing permissions are granted
   - Check that queues exist and are active

3. **Statistics Not Loading**
   - Ensure analytics permissions are granted
   - Check browser console for API errors

### Support

For issues or questions, please refer to the [Genesys Cloud Developer Center](https://developer.genesys.cloud/) or create an issue in this repository.

## License

This project is licensed under the ISC License. 