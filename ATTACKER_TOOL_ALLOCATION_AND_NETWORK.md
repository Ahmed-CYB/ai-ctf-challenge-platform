# Attacker Tool Allocation & Network Configuration

## ✅ **Answer: YES, tools ARE dynamically allocated (but there's a conflict)**

## ⚠️ **Answer: Attacker is on TWO networks**

---

## 🔧 **Dynamic Tool Allocation**

### **Current System (Universal Structure Agent):** ✅ **DYNAMIC**

**Location:** `packages/ctf-automation/src/agents/universal-structure-agent.js`

**How it works:**

1. **Collect Tools Based on Category:**
```javascript
// Line 467
tools: await collectAllTools(scenarioPlan.categories, classification.requiredTools)
```

2. **collectAllTools Function:**
```javascript
// Line 793-803
async function collectAllTools(categories, additionalTools = []) {
  const { getToolsByCategory } = await import('../package-mapping-db-manager.js');
  
  const tools = new Set(additionalTools);
  for (const category of categories) {
    const categoryTools = await getToolsByCategory(category);
    categoryTools.forEach(tool => tools.add(tool));
  }
  
  return Array.from(tools);
}
```

3. **Generate Dockerfile with Tools:**
```javascript
// Line 998-1004
const attackerDockerfile = await generateToolInstallationDockerfile({
  category: compiledChallenge.scenarioPlan.categories[0],
  challengeType: compiledChallenge.scenarioPlan.scenario.title,
  scenario: compiledChallenge.scenarioPlan.scenario.description,
  requiredTools: content.tools  // ← Dynamic tools passed here
});
```

**Result:** ✅ **Tools ARE dynamically allocated based on:**
- Challenge categories (web, network, crypto)
- Required tools from classification
- Database tool mappings

---

### **Problem: Two Different Systems** ⚠️

**System 1: Universal Structure Agent** ✅ **Dynamic**
- Uses `generateToolInstallationDockerfile()`
- Dynamically allocates tools based on category
- Location: `universal-structure-agent.js`

**System 2: Dockerfile Generator** ❌ **Static**
- Uses hardcoded template
- Always same tools (nmap, wireshark, tcpdump)
- Location: `dockerfile-generator.js` (line 78-128)

**Which one is used?**
- Depends on which creation flow is used
- `universal-structure-agent.js` → Dynamic ✅
- `dockerfile-generator.js` → Static ❌

---

## 🌐 **Attacker Network Configuration**

### **Attacker is on TWO Networks:**

**Location:** `packages/ctf-automation/src/agents/universal-structure-agent.js` (line 1136-1144)

```yaml
networks:
  ctf-${challengeName}-net:        # ✅ Challenge network
    ipv4_address: ${ip}             # Attacker IP (e.g., 172.23.210.3)
  ctf-instances-network:           # ✅ Guacamole network (external)
    # No IP - just connected for routing
```

### **Network 1: Challenge Network** ✅
- **Name:** `ctf-${challengeName}-net` (e.g., `ctf-corporate-ftp-infiltration-net`)
- **Purpose:** Communication with victim machines
- **IP:** Static IP (always `.3`, e.g., `172.23.210.3`)
- **Isolation:** Each challenge has its own network
- **Access:** Attacker can reach all victims on this network

### **Network 2: Guacamole Network** ✅
- **Name:** `ctf-instances-network` (external network)
- **Purpose:** Guacamole access to attacker
- **IP:** No static IP (just connected for routing)
- **Access:** Guacamole can reach attacker for SSH/VNC

---

## 📊 **How Tools Are Allocated**

### **Step 1: Determine Challenge Categories**
```javascript
// From scenario plan
categories: ['network', 'crypto', 'web']
```

### **Step 2: Query Database for Tools**
```javascript
// For each category
const categoryTools = await getToolsByCategory(category);

// Examples:
// 'network' → ['nmap', 'masscan', 'wireshark', 'tcpdump', 'netcat']
// 'web' → ['burpsuite', 'sqlmap', 'nikto', 'gobuster', 'ffuf']
// 'crypto' → ['hashcat', 'john', 'openssl', 'hashid']
```

### **Step 3: Add Required Tools**
```javascript
// From classification
requiredTools: ['custom-tool-1', 'custom-tool-2']
```

### **Step 4: Generate Dockerfile**
```javascript
// Pass all tools to generator
generateToolInstallationDockerfile({
  category: 'network',
  requiredTools: ['nmap', 'masscan', 'wireshark', 'custom-tool-1']
})
```

---

## 🎯 **Example: FTP Challenge**

**Challenge:** "create ftp ctf challenge"

**Categories:** `['network']`

**Tools Allocated:**
```javascript
// From database (network category)
['nmap', 'masscan', 'wireshark', 'tshark', 'tcpdump', 
 'netcat-traditional', 'hping3', 'arp-scan', 'netdiscover', 
 'traceroute', 'whois', 'dnsutils']

// Plus base tools (always included)
['openssh-server', 'sudo', 'vim', 'nano', 'curl', 'wget', 'git', 'net-tools']
```

**Dockerfile Generated:**
```dockerfile
FROM kalilinux/kali-rolling:latest

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    openssh-server \
    sudo \
    vim \
    nano \
    curl \
    wget \
    git \
    net-tools \
    nmap \
    masscan \
    wireshark \
    tcpdump \
    netcat-traditional \
    hping3 \
    arp-scan \
    netdiscover \
    traceroute \
    whois \
    dnsutils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# SSH configuration...
```

---

## ⚠️ **Current Issue**

### **Problem: Two Different Systems**

1. **Universal Structure Agent** (used in new system):
   - ✅ Dynamic tool allocation
   - ✅ Category-based tools
   - ✅ Database-driven

2. **Dockerfile Generator** (used in old system):
   - ❌ Static hardcoded tools
   - ❌ Always same tools
   - ❌ No category awareness

**Which one is actually used?**
- Need to check which creation flow is active
- If `universal-structure-agent.js` → Dynamic ✅
- If `dockerfile-generator.js` → Static ❌

---

## 🔧 **Fix Needed**

### **Make Dockerfile Generator Dynamic:**

Update `dockerfile-generator.js` to:
1. Accept tools parameter
2. Use `generateToolInstallationDockerfile()` instead of hardcoded template
3. Pass challenge category and required tools

**Current Code (Static):**
```javascript
async generateAttackerDockerfile(machine, osInfo) {
  // Hardcoded tools
  const dockerfile = `FROM kalilinux/kali-rolling:latest
  RUN apt-get update && apt-get install -y --no-install-recommends \\
    openssh-server \\
    nmap \\
    wireshark \\
    tcpdump \\
    ...`;
}
```

**Should Be (Dynamic):**
```javascript
async generateAttackerDockerfile(machine, osInfo, structure) {
  // Get tools from structure
  const tools = structure.attackerTools || [];
  const categories = structure.categories || [];
  
  // Use dynamic generator
  const { generateToolInstallationDockerfile } = await import('../agents/tool-installation-agent.js');
  return await generateToolInstallationDockerfile({
    category: categories[0] || 'misc',
    requiredTools: tools
  });
}
```

---

## 📋 **Summary**

### **Tool Allocation:**
- ✅ **Universal Structure Agent:** Dynamic (category-based)
- ❌ **Dockerfile Generator:** Static (hardcoded)
- ⚠️ **Issue:** Two systems, need to ensure dynamic one is used

### **Network Configuration:**
- ✅ **Challenge Network:** `ctf-${challengeName}-net` (IP: `.3`)
- ✅ **Guacamole Network:** `ctf-instances-network` (external, for routing)
- ✅ **Attacker on BOTH networks** for:
  - Challenge network: Access to victims
  - Guacamole network: Remote access via Guacamole

---

## 🎯 **Recommendations**

1. **Ensure Dynamic Tool Allocation:**
   - Update `dockerfile-generator.js` to use dynamic tool allocation
   - Or ensure `universal-structure-agent.js` is always used

2. **Verify Network Configuration:**
   - Attacker should be on both networks ✅ (already correct)
   - Challenge network for victim access
   - Guacamole network for remote access

3. **Document Tool Allocation:**
   - Show which tools are installed for each category
   - Make it clear tools are dynamic, not static

---

**Last Updated**: 2025-01-03

