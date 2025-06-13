# Queue Transfer Demo App

A Genesys Cloud embedded client application that enables agents to transfer conversations to queues. This app provides a user-friendly interface to view available queues and their current metrics, allowing agents to initiate consult transfers with a single click.

## Features

- Real-time queue metrics display
- Easy-to-use interface for initiating consult transfers
- Support for multiple Genesys Cloud environments
- Automatic authentication with Genesys Cloud
- Responsive design

## Setup

1. Host this application on a web server with HTTPS enabled
2. Create a new Embedded Client App integration in Genesys Cloud:
   - Go to Admin > Integrations > Web/Custom Apps
   - Click "Install App"
   - Select "Embedded Client App"
   - Configure the following:
     - Name: Queue Transfer Demo
     - URL: Your hosted application URL
     - Group: Select the groups that should have access to this app
     - Communication Type: iframe
     - Sandbox: allow-scripts,allow-same-origin,allow-forms,allow-modals

## Development

The application uses:
- Genesys Cloud Client App SDK (v2.6.3)
- Genesys Cloud Platform API Client (latest)
- Pure HTML/CSS/JavaScript

## Usage

1. Open Genesys Cloud
2. During an active conversation, launch the Queue Transfer Demo app
3. View available queues and their current metrics
4. Click on a queue to initiate a consult transfer

## Environment Support

The application supports all Genesys Cloud environments:
- US East (Virginia)
- EMEA (Ireland)
- Asia Pacific (Sydney)
- Asia Pacific (Tokyo)
- European Union (Frankfurt)
- US West (Oregon)
- Canada (Central)
- South America (São Paulo)
- Asia Pacific (Seoul)
- Asia Pacific (Mumbai)

## Security

This application uses secure authentication through the Genesys Cloud Client App SDK. No credentials are stored in the application.
