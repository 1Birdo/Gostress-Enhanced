
>No files yet — still in development, so just hang tight for now.
>
>The proxy setup is optional, and I've included a certificate and private key for convenience.
>That said, I highly recommend generating your own for proper security. You can easily create one using tools like Let's Encrypt, Certbot, or OpenSSL.
>Some hosting or DNS providers also offer their own certificate solutions if you prefer that route.




## 🌟 Features Overview
### Core Infrastructure
- **Multi-layer Architecture**: [Bots] ↔ [P2P Proxies] ↔ [C2 Server]
- **TLS 1.3 Encryption**: All communications secured with modern cryptography
- **Command Encrpption**: Thoughout transit every command is encrypted

| Startup  |
|---------|
| ![Startup](https://github.com/user-attachments/assets/9ff3101e-cea6-4a7c-8d13-af54f8c891cc) | 

| Login | Dashboard |
|-------|----------|
| ![Login](https://github.com/user-attachments/assets/ba0135b7-b7fa-4e12-8b30-562765bab8d5) | ![Dashboard](https://github.com/user-attachments/assets/ca2355e7-3d10-4e97-9061-880657b931e9) |

### Web Dashboard
- **Real-time Monitoring**: Live bot metrics and attack statistics
- **Geolocation Tracking**: Visualize bot distribution worldwide
- **Role-Based Access**: Granular permission system (Owner/Admin/Pro/User)
- **Session Management**: Secure authentication with timeout protection

### Bot Capabilities
- **Multiple Attack Vectors**: UDP/TCP/SYN/ACK/DNS/HTTP/TLS floods
- **Persistence Mechanisms**: Systemd services, cron jobs, hidden directories
- **Resource Reporting**: CPU, RAM, architecture details
- **Auto-Update**: Secure update system with integrity checks

## 🛠️ Technical Specifications
| Component       | Technology Stack                          |
|-----------------|-------------------------------------------|
| Language        | Go (Golang)                               |
| Web Framework   | Gorilla WebSocket + net/http              |
| Encryption      | AES-256-GCM + HMAC-SHA256                 |
| Network         | TLS 1.3, P2P Proxy Network                |
| Data Storage    | JSON-based configuration                  |

## 🚀 Getting Started
### Prerequisites
- Go 1.20+ (with module support)
- OpenSSL (for certificate generation) , Must Change to using Certbot for verified trusted Certs
- Linux/Unix environment (for full feature support)

### Installation
  ```bash
  # Clone repository
  git clone https://github.com/Birdo1221/Gostress-Enhanced.git
  cd WebC2Go
  # Install dependencies
  go mod tidy
  # Build (production)
  go build -ldflags="-s -w" -o WebC2
  # Or run directly (development)
  go run main.go
  ```
