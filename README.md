# WebC2Go
## 🚧 Under construction and still thinking of Public Release 
### You can watch the low-Quality Video Demo for an Idea as it was in development
Yes the video is only 10MB


https://github.com/user-attachments/assets/a8fbaa40-6306-41d7-be45-84a3e2e72afc


## ⚠️ Ethical Warning
**This project is for educational and research purposes only. Unauthorized use of botnets or network attacks is illegal and unethical. Always obtain proper consent before any network testing. Blah blah blah**


```bash
Yes, this IS / WILL be an Updated Version of the Preivous Repos I have Published
The Bot Connection Protocol is the same but yet to be changed for the release.
```
[BotnetGO](https://github.com/Birdo1221/Better-Go-Cnc/)

[Golang-Net](https://github.com/Birdo1221/Better-Go-Cnc/)



```bash
The Main Different is converting it to a web interface with a better Codebase in-General
I WILL be Implementing CERTBOT to this as well for better self-siging certs and will stick to TLS 1.3

You can do this yourself by changing the Hard-Coded Certificates location with the ones you have Generated with CERTBOT
By default it should be like:
  Only Examples: 
  key: fs.readFileSync('/etc/letsencrypt/live/demokey.birdo.uk/privkey.pem'),
  cert: fs.readFileSync('/etc/letsencrypt/live/demochain.birdo.uk/fullchain.pem'),
  ```

## Overview
This is a secure web-based dashboard for managing and monitoring a network of connected bots, providing real-time insights into bot infrastructure, launching network tests, and user management.

### Key Features

- 🔒 Secure HTTPS web interface with TLS 1.3
- 👥 Multi-user authentication system
- 🌍 Geolocation tracking for connected bots
- 📊 Real-time bot and attack monitoring
- 🚀 Network testing capabilities
- 🔐 Role-based access control

## Architecture

The application consists of two main servers:
1. **Bot Server**: Manages incoming bot connections (TCP)
2. **Web Server**: Provides management interface (HTTPS)

### Technologies
- Language: Go (Golang)
- Web Server: Standard `net/http`
- Authentication: Session-based
- Security: TLS 1.3, secure cookie management
- Geolocation: External API integration

## Prerequisites

- Go 1.20+
- OpenSSL (for certificate generation) | To-do = implement CERTBOT for better self-signing 
- Internet connection for geolocation services

## Installation

### 1. Clone the Repository
```bash
git clone https://github.com/Birdo1221/WebC2Go.git
cd WebC2Go
```

### 2. Generate SSL Certificates
The application will guide you to generate self-signed certificates using OpenSSL during first run.

### 3. Build the Application
```bash
go mod tidy
go build -o WebC2dashboard
```

### 4. Run the Application
```bash
./botnet-dashboard
```

### Optional . Run without building 
```bash
go run main.go
```

## Setup

On first run, the application will:
- Generate self-signed SSL certificates
- Create a `users.json` file
- Generate a root user with random credentials

🔑 **Note**: The root user credentials will be printed in the console log. Save them securely.

## User Management

- **Root User**: Full system access
- **Admin Users**: Partial management rights
- **Standard Users**: Limited access

### Adding Users
Only root users can add new users through the web interface.

## Security Considerations

- Uses TLS 1.3 with secure cipher suites
- Session timeout mechanism
- Strict access controls
- Geolocation data sanitization
- CSRF protection
- Secure cookie management

## Bot Connection Protocol
   WILL CHANGE 🚧 Under construction 
Bots communicate via a simple text-based protocol:
- Handshake with system information
- Periodic ping to maintain connection
- Command execution for network testing

## Logging

Comprehensive logging for:
- Bot connections
- User actions
- System events
- Attack launch/stop operations

## Development
Warning This is in Development so no code has been published as of yet 

## Contact
For questions or concerns, please open an issue on the GitHub repository or visit my site to contact me.
