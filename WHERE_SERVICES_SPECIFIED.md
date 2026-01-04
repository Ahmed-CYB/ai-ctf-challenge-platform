# Where Services Are Specified

This document shows all the places where services are specified in the CTF challenge creation flow.

## 📍 Service Specification Flow

### 1. **Initial Specification: Scenario Analysis** 
**File**: `packages/ctf-automation/src/agents/universal-structure-agent.js`

**Location**: Lines 98-119 in `SCENARIO_ANALYSIS_PROMPT`

The AI is instructed to return a JSON with machines that include a `services` array:

```javascript
{
  "machines": [
    {
      "name": "machine-name",
      "type": "victim|attacker",
      "role": "description of purpose",
      "services": ["service1", "service2"],  // ← SERVICES SPECIFIED HERE
      "contains": ["what content this machine holds"],
      "categories": ["crypto", "web", etc.]
    }
  ]
}
```

**Service Definition Rules** (Lines 98-107):
- **SERVICES** (for victim machines): ssh, ftp, samba, http, https, telnet, dns, ldap, snmp, nfs, mysql, postgresql, redis, etc.
- **TOOLS** (for attacker machines ONLY): nmap, netcat, ping, traceroute, tcpdump, wireshark, etc.
- **NEVER** put tools in victim machine services array
- **ONLY** put actual network services in victim machine services array

### 2. **Service Usage: Content Generation**
**File**: `packages/ctf-automation/src/agents/universal-structure-agent.js`

**Location**: Lines 672, 738, 756, 838, 1037, 1044

Services are extracted from machine objects and passed to content generation agents:

```javascript
// Line 672
services: m.services

// Line 738
services: machine.services

// Line 756
services: machine.services

// Line 838
services: m.services

// Line 1037
services: content.services

// Line 1044
services: content.services
```

### 3. **Service Processing: Dockerfile Generation**
**File**: `packages/ctf-automation/src/agents/tool-installation-agent.js`

**Location**: Line 571 - `generateVictimDockerfileWithSSH` function

Services are received as a parameter:

```javascript
export async function generateVictimDockerfileWithSSH({ 
  category, 
  services = [],  // ← SERVICES RECEIVED HERE
  scenario,
  osImage = 'ubuntu:22.04',
  packageManager = 'apt-get',
  machineName = 'victim',
  configurations = {},
  difficulty = 'medium',
  isAttacker = false
})
```

**Service Processing** (Lines 580-598):
1. **Filter out tools** (Lines 583-591): Removes attack tools from services array
2. **Filter invalid services** (Lines 594-598): Removes invalid service names
3. **Resolve package names** (Lines 605-609): Converts service names to package names
4. **Build startup script** (Lines 726-777): Uses services to generate startup commands

### 4. **Service Port Mapping**
**File**: `packages/ctf-automation/src/agents/tool-installation-agent.js`

**Location**: Lines 526-553 - `SERVICE_PORT_MAP` constant

Maps service names to their default ports:

```javascript
const SERVICE_PORT_MAP = {
  'ssh': 22,
  'ftp': 21,
  'samba': 445,
  'http': 80,
  'https': 443,
  'telnet': 23,
  'dns': 53,
  'mysql': 3306,
  'postgresql': 5432,
  'redis': 6379,
  // ... more services
};
```

**Usage** (Lines 784-791):
- Used to determine which ports to EXPOSE in Dockerfile
- Maps service names to ports for docker-compose.yml

### 5. **Service Normalization**
**File**: `packages/ctf-automation/src/agents/tool-installation-agent.js`

**Location**: Lines 557-567 - `normalizeServiceName` function

Normalizes service names (handles aliases):

```javascript
function normalizeServiceName(serviceName) {
  const normalized = serviceName.toLowerCase().trim();
  if (normalized === 'web') return 'http';
  if (normalized === 'smb') {
    console.warn(`⚠️  'smb' service detected - converting to 'samba'`);
    return 'samba';
  }
  return normalized;
}
```

### 6. **Service Package Resolution**
**File**: `packages/ctf-automation/src/agents/tool-installation-agent.js`

**Location**: Lines 605-609

Converts service names to package names (OS-specific):

```javascript
for (const serviceName of finalFilteredServices) {
  const packageName = await getServicePackageName(serviceName, packageManager);
  // packageName is used to install the service package
}
```

**Database**: `packages/ctf-automation/src/package-mapping-db-manager.js`
- `getServicePackageName(serviceName, packageManager)` - Returns package name for service

### 7. **Service Configuration (AI-Generated)**
**File**: `packages/ctf-automation/src/agents/content/network-content-agent.js`

**Location**: Lines 86-94 - Return JSON format

The AI generates service configurations based on services:

```javascript
{
  "configuration": {
    "serviceType": "ftp|samba|ssh|pcap",
    "servicePort": 21,  // ← Port for the service
    "setup": "service setup commands",  // ← Startup commands
    "decoyPorts": [25, 53, 1433]
  }
}
```

### 8. **Service Startup Script Generation**
**File**: `packages/ctf-automation/src/agents/tool-installation-agent.js`

**Location**: Lines 726-777

Services are used to generate the startup script:

```javascript
// Extract setup commands from AI-generated configurations
for (const [category, config] of Object.entries(configurations)) {
  if (config.setup) {
    aiGeneratedSetup += config.setup;
  }
  if (config.servicePort) {
    servicePorts.add(config.servicePort);
  }
}
```

## 🔄 Complete Flow

```
1. User Request
   ↓
2. Scenario Analysis (universal-structure-agent.js)
   → AI returns machines with "services" array
   ↓
3. Content Generation (network-content-agent.js, web-content-agent.js)
   → Receives services array
   → Generates service configurations
   ↓
4. Dockerfile Generation (tool-installation-agent.js)
   → Receives services array
   → Filters tools and invalid services
   → Resolves package names
   → Generates startup script
   ↓
5. Docker Compose Generation (universal-structure-agent.js)
   → Uses services to determine exposed ports
   → Creates service definitions
```

## 📝 Key Files

| File | Purpose | Line Range |
|------|---------|------------|
| `universal-structure-agent.js` | Defines service specification format in prompt | 98-119 |
| `universal-structure-agent.js` | Extracts services from machines | 672, 738, 756, 838, 1037, 1044 |
| `tool-installation-agent.js` | Receives services parameter | 571 |
| `tool-installation-agent.js` | Filters and processes services | 580-609 |
| `tool-installation-agent.js` | Service port mapping | 526-553 |
| `tool-installation-agent.js` | Service normalization | 557-567 |
| `network-content-agent.js` | Uses services for content generation | 154 |
| `web-content-agent.js` | Uses services for content generation | 136 |

## 🎯 Summary

**Services are specified in:**
1. **AI Response** - In the scenario analysis JSON (`machines[].services`)
2. **Machine Objects** - Each machine has a `services` array
3. **Function Parameters** - Passed to `generateVictimDockerfileWithSSH({ services })`
4. **Content Agents** - Passed to `generateNetworkContent({ services })` and `generateWebContent({ services })`

**Services are processed in:**
1. **Filtering** - Remove tools and invalid services
2. **Normalization** - Convert aliases (web→http, smb→samba)
3. **Package Resolution** - Convert to OS-specific package names
4. **Port Mapping** - Map to default ports
5. **Startup Script** - Generate service startup commands

