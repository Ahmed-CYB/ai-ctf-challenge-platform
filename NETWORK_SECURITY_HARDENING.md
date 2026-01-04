# Network Security Hardening

## Overview

Implemented comprehensive network isolation to prevent attacker containers from accessing infrastructure components (gateway, Guacamole network, other challenges).

## Security Issues Fixed

### 1. **Attacker Network Access**
- **Problem**: Attacker was connected to `ctf-instances-network` (172.22.0.0/24), allowing it to:
  - Scan and discover other challenges
  - Access Guacamole infrastructure
  - Potentially attack the platform itself
  - Access the gateway (172.23.x.1)

- **Solution**: 
  - Removed attacker from `ctf-instances-network`
  - Guacamole (guacd) now connects to challenge network instead
  - Attacker can only access victim machines in its challenge network

### 2. **Gateway Access**
- **Problem**: Attacker could scan and access the Docker gateway (172.23.x.1)
- **Solution**: Added iptables rules to block all gateway access (except DNS on port 53)

### 3. **Infrastructure Network Access**
- **Problem**: Attacker could access infrastructure networks (172.20.x.x, 172.21.x.x, 172.22.x.x)
- **Solution**: Added iptables rules to block all infrastructure networks

## Implementation

### 1. Network Configuration (`compose-generator.js`)

**Before:**
```yaml
attacker:
  networks:
    ctf-challenge-net: {}
    ctf-instances-network: {}  # ❌ Security risk
```

**After:**
```yaml
attacker:
  networks:
    ctf-challenge-net: {}  # ✅ Only challenge network
  # ctf-instances-network removed
```

### 2. Guacamole Connection Strategy

**Before:**
- Attacker connected to `ctf-instances-network`
- Guacamole accessed attacker via `ctf-instances-network` IP

**After:**
- Attacker only on challenge network
- Guacamole (guacd) connects to challenge network
- Guacamole accesses attacker via challenge network IP

### 3. Firewall Rules (iptables)

Added to all attacker Dockerfiles:

```bash
# Block gateway (except DNS)
iptables -A OUTPUT -d $GATEWAY -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -d $GATEWAY -j DROP

# Block infrastructure networks
iptables -A OUTPUT -d 172.20.0.0/16 -j DROP
iptables -A OUTPUT -d 172.21.0.0/16 -j DROP
iptables -A OUTPUT -d 172.22.0.0/16 -j DROP
```

### 4. Startup Script

All attacker containers now use `/start-secure.sh` which:
1. Applies network isolation rules
2. Starts SSH daemon

## Security Benefits

1. **Network Isolation**: Attacker can only communicate with victim machines in its challenge
2. **Infrastructure Protection**: Gateway and Guacamole network are inaccessible
3. **Challenge Isolation**: Attackers cannot discover or access other challenges
4. **Platform Security**: Prevents attacks on the CTF platform itself

## Network Architecture

```
┌─────────────────────────────────────┐
│  Challenge Network (172.23.x.0/24)  │
│                                     │
│  ┌─────────────┐  ┌──────────────┐ │
│  │  Attacker   │  │   Victim     │ │
│  │  (172.23.x.3)│  │ (172.23.x.16)│ │
│  │             │  │              │ │
│  │ 🔒 Blocked: │  │              │ │
│  │ - Gateway   │  │              │ │
│  │ - 172.22/16 │  │              │ │
│  │ - 172.21/16 │  │              │ │
│  │ - 172.20/16 │  │              │ │
│  └─────────────┘  └──────────────┘ │
│        ↑                            │
│        │ (guacd connects here)      │
└────────┼────────────────────────────┘
         │
    ┌────┴────┐
    │  guacd   │
    └──────────┘
```

## Testing

To verify network isolation:

1. **Deploy a challenge**
2. **Connect to attacker via Guacamole**
3. **Run nmap scans:**
   ```bash
   # Should work - victim machine
   nmap 172.23.x.16
   
   # Should be blocked - gateway
   nmap 172.23.x.1
   # Result: All ports filtered/dropped
   
   # Should be blocked - Guacamole network
   nmap 172.22.0.0/24
   # Result: No hosts found or all filtered
   ```

## Additional Security Recommendations

1. **Resource Limits**: Add CPU/memory limits to prevent DoS
2. **Network Policies**: Use Docker network policies for additional isolation
3. **Logging**: Monitor blocked connection attempts
4. **Rate Limiting**: Limit network scanning tools' output
5. **Container Hardening**: Remove unnecessary capabilities

## Files Modified

1. `packages/ctf-automation/src/challenge/compose-generator.js`
   - Removed `ctf-instances-network` from attacker
   - Removed external network reference

2. `packages/ctf-automation/src/challenge/dockerfile-generator.js`
   - Added iptables installation
   - Added network isolation script
   - Added secure startup script

3. `packages/ctf-automation/src/agents/tool-installation-agent.js`
   - Added security hardening to all attacker Dockerfiles
   - Updated CMD to use secure startup script

## Notes

- DNS (port 53) is still allowed to gateway for name resolution
- Rules are applied at container startup
- iptables rules persist for container lifetime
- Guacamole access still works via challenge network

