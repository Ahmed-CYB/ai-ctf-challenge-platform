# Base Kali Linux Images for CTF Challenges

These are pre-configured, minimal Kali Linux images optimized for different challenge categories.

## Available Images

### 1. Web Exploitation (`Dockerfile.web`)
**Size**: ~800MB  
**Tools**:
- BurpSuite - Web proxy and scanner
- sqlmap - SQL injection tool
- nikto - Web server scanner
- gobuster - Directory brute-forcer
- ffuf - Fast web fuzzer
- wfuzz - Web application fuzzer
- curl, wget - HTTP clients
- Python3 with pip

**Use Case**: SQL injection, XSS, authentication bypasses, web vulnerabilities

### 2. Network Analysis (`Dockerfile.network`)
**Size**: ~700MB  
**Tools**:
- nmap - Port scanner
- masscan - Fast port scanner
- wireshark - Packet analyzer (GUI)
- tshark - Packet analyzer (CLI)
- tcpdump - Network sniffer
- netcat - Network utility
- hping3 - Packet crafting
- arp-scan, netdiscover - Network discovery

**Use Case**: Port scanning, packet analysis, network reconnaissance

### 3. Forensics (`Dockerfile.forensics`)
**Size**: ~900MB  
**Tools**:
- binwalk - Firmware analysis
- foremost - File carving
- volatility3 - Memory forensics
- autopsy - Digital forensics
- exiftool - Metadata extraction
- steghide - Steganography
- strings, hexedit - Binary analysis
- file - File type identification

**Use Case**: File analysis, steganography, memory forensics, data recovery

### 4. PWN/Reverse Engineering (`Dockerfile.pwn`)
**Size**: ~1.2GB  
**Tools**:
- gdb with pwndbg - Debugger
- ghidra - Reverse engineering suite
- radare2 - Binary analysis framework
- pwntools - Python exploitation framework
- ltrace, strace - System call tracers
- objdump, binutils - Binary utilities

**Use Case**: Buffer overflows, binary exploitation, reverse engineering

### 5. Cryptography (`Dockerfile.crypto`)
**Size**: ~600MB  
**Tools**:
- hashcat - Password cracker
- john the ripper - Password cracker
- openssl - Cryptography toolkit
- Python crypto libraries (pycryptodome, gmpy2, z3-solver)

**Use Case**: Hash cracking, encryption/decryption, cryptographic attacks

## Building Images

Build a specific base image:
```bash
# Web exploitation
docker build -f base-images/Dockerfile.web -t kali-web-base .

# Network analysis
docker build -f base-images/Dockerfile.network -t kali-network-base .

# Forensics
docker build -f base-images/Dockerfile.forensics -t kali-forensics-base .

# PWN/RE
docker build -f base-images/Dockerfile.pwn -t kali-pwn-base .

# Cryptography
docker build -f base-images/Dockerfile.crypto -t kali-crypto-base .
```

## Using Base Images

The CTF automation system automatically generates custom Dockerfiles based on these templates. When you create a challenge:

1. **AI detects challenge type** (web, network, forensics, pwn, crypto)
2. **Identifies required tools** from challenge description
3. **Generates minimal Dockerfile** with only needed tools
4. **Docker layer caching** speeds up subsequent builds

## Automatic vs Manual

### Automatic (Default)
The system automatically generates custom Dockerfiles per challenge. First build takes time, but Docker caches layers for future builds.

### Manual (Optional)
Pre-build base images for faster deployment:
```bash
# Build all base images
cd base-images
./build-all.sh

# Use in docker-compose.yml
services:
  attacker:
    image: kali-web-base  # Instead of building from Dockerfile
```

## Size Comparison

| Image Type | Size | Full Kali Desktop |
|------------|------|-------------------|
| Web | 800MB | 2.0GB |
| Network | 700MB | 2.0GB |
| Forensics | 900MB | 2.0GB |
| PWN | 1.2GB | 2.0GB |
| Crypto | 600MB | 2.0GB |

**Storage Savings**: 40-70% reduction per category

## Customization

Add tools to a category by editing the Dockerfile:

```dockerfile
# Add custom tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    your-tool-here \
    another-tool \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
```

## VNC Access

All images include VNC server on port 5901:
- **Default Password**: `password`
- **Resolution**: 1280x720
- **Desktop**: XFCE4 (lightweight)

Access via:
- VNC client: `vnc://localhost:5901`
- Web browser (Guacamole): `http://localhost/guacamole`

## Best Practices

1. **Use specific tools**: Only install what's needed for the challenge
2. **Layer caching**: Group related packages in single RUN commands
3. **Clean apt cache**: Always add `&& apt-get clean && rm -rf /var/lib/apt/lists/*`
4. **Security**: Run as non-root user in production (add USER directive)
5. **Testing**: Test images before deployment

## Maintenance

Update base images periodically:
```bash
docker pull kalilinux/kali-rolling
docker build --no-cache -f Dockerfile.web -t kali-web-base .
```
