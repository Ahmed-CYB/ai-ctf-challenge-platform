# Terminal Access Alternatives - Test Environment

This is an **isolated test environment** to evaluate alternatives to Guacamole for browser-based terminal access to attacker machines.

## ⚠️ IMPORTANT
- **This is for testing only** - does not affect production code
- **Isolated network** - uses separate Docker network (172.30.1.0/24)
- **No integration** - completely separate from main CTF platform

## Available Tools

### 1. **ttyd** (Recommended for simplicity)
- **URL**: http://localhost:7681
- **Pros**: 
  - Very simple, lightweight
  - Direct terminal access
  - No authentication needed (for testing)
- **Cons**:
  - Basic features
  - No built-in authentication
- **Use Case**: Simple, direct terminal access

### 2. **Wetty** (Web-based SSH client)
- **URL**: http://localhost:3000
- **Pros**:
  - Full SSH client in browser
  - Supports authentication
  - Good terminal emulation
- **Cons**:
  - Requires SSH connection
  - More complex setup
- **Use Case**: SSH-based terminal access

### 3. **Shellinabox** (Web-based terminal)
- **URL**: https://localhost:4200 (self-signed certificate - accept warning)
- **Pros**:
  - Mature, stable
  - Good terminal emulation
  - Supports multiple protocols
- **Cons**:
  - Uses HTTPS (self-signed cert warning)
  - Older codebase
- **Use Case**: Traditional web terminal

## Quick Start

### Start Test Environment
```bash
cd test-terminal-access
docker compose -f docker-compose.test.yml up -d
```

### Access Terminals
1. **ttyd**: Open http://localhost:7681 in browser
2. **Wetty**: Open http://localhost:3000 in browser
3. **Shellinabox**: Open https://localhost:4200 in browser (accept SSL warning)

### Stop Test Environment
```bash
docker compose -f docker-compose.test.yml down
```

## Test Attacker Container

The test attacker container:
- **IP**: 172.30.1.3
- **OS**: Kali Linux
- **SSH**: Enabled (kali:kali, root:toor)
- **Tools**: nmap, python3, basic networking tools

### SSH Access (for testing)
```bash
ssh kali@172.30.1.3
# Password: kali
```

## Comparison with Guacamole

| Feature | Guacamole | ttyd | Wetty | Shellinabox |
|---------|-----------|------|-------|-------------|
| **Complexity** | High | Low | Medium | Medium |
| **Authentication** | Yes (MySQL) | No (basic) | Yes (SSH) | Yes (basic) |
| **Protocol Support** | SSH, RDP, VNC | Terminal only | SSH only | SSH, Telnet |
| **User Management** | Advanced | None | SSH-based | Basic |
| **Multi-Protocol** | Yes | No | No | Limited |
| **Setup Complexity** | High | Very Low | Low | Medium |
| **Resource Usage** | High | Low | Medium | Medium |

## Recommendations

### For Simple Use Cases
- **ttyd**: Best for simple, direct terminal access without complex authentication

### For SSH-Based Access
- **Wetty**: Good if you want a full SSH client experience in the browser

### For Production
- **Guacamole**: Still recommended for production due to:
  - Advanced user management
  - Multi-protocol support (SSH, RDP, VNC)
  - Session management
  - Better security features

## Testing Notes

1. All tools are accessible simultaneously
2. Test network is isolated (172.30.1.0/24)
3. No impact on main CTF platform
4. Can be safely deleted after testing

## Cleanup

```bash
# Remove test environment
docker compose -f docker-compose.test.yml down -v

# Remove test network (if needed)
docker network rm test-terminal-access_test-network
```

