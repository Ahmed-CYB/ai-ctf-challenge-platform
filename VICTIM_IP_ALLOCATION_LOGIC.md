# Victim IP Allocation Logic

## ✅ **Answer: It CHECKS how many victims first, then allocates**

The system **intelligently counts** the number of victim services in the CTF before allocating IPs.

---

## 🔍 **How It Works**

### **Step 1: Read docker-compose.yml**
```javascript
const composeContent = await fs.readFile(composeFile, 'utf8');
const composeConfig = yaml.load(composeContent);
```

### **Step 2: Count Victim Services**
```javascript
// Count services to determine victim count
const services = composeConfig.services || {};
const victimServices = Object.keys(services).filter(name => 
  !name.includes('attacker') && 
  !name.includes('database') && 
  !name.includes('api')
);
const victimCount = victimServices.length;
```

**What it does:**
- Gets all services from docker-compose.yml
- Filters out:
  - ❌ Services with "attacker" in name
  - ❌ Services with "database" in name
  - ❌ Services with "api" in name
- ✅ Everything else = **Victim service**
- Counts them: `victimCount = victimServices.length`

### **Step 3: Allocate Exact Number of Random IPs**
```javascript
const newSubnet = await subnetAllocator.allocateSubnet(challengeName, 'default', {
  victimCount,              // ← Exact count passed here
  randomizeIPs: true,
  needsDatabase: hasDatabase,
  needsAPI: hasAPI
});
```

### **Step 4: Assign IPs to Each Victim**
```javascript
// Victim service - use allocated victim IPs
const victimIPs = newSubnet.ips.victims || [];
if (victimIndex < victimIPs.length) {
  service.networks[challengeNetwork].ipv4_address = victimIPs[victimIndex];
  victimIndex++;
}
```

---

## 📊 **Example Scenarios**

### **Scenario 1: Single Victim**
```yaml
services:
  attacker:
    # ...
  ftp-server:  # ← Victim (counted)
    # ...
```

**Result:**
- `victimCount = 1`
- Allocates: `[172.25.193.147]` (1 random IP)
- Assigns: `ftp-server` → `172.25.193.147`

---

### **Scenario 2: Multiple Victims**
```yaml
services:
  attacker:
    # ...
  ftp-server:      # ← Victim 1 (counted)
    # ...
  web-server:      # ← Victim 2 (counted)
    # ...
  samba-server:    # ← Victim 3 (counted)
    # ...
```

**Result:**
- `victimCount = 3`
- Allocates: `[172.25.193.83, 172.25.193.192, 172.25.193.47]` (3 random IPs)
- Assigns:
  - `ftp-server` → `172.25.193.83`
  - `web-server` → `172.25.193.192`
  - `samba-server` → `172.25.193.47`

---

### **Scenario 3: With Database**
```yaml
services:
  attacker:
    # ...
  ftp-server:      # ← Victim 1 (counted)
    # ...
  database:        # ← NOT counted (excluded)
    # ...
```

**Result:**
- `victimCount = 1`
- `hasDatabase = true`
- Allocates:
  - Victim IPs: `[172.25.193.147]` (1 random IP)
  - Database IP: `172.25.193.89` (1 random IP)
- Assigns:
  - `ftp-server` → `172.25.193.147`
  - `database` → `172.25.193.89`

---

## 🎯 **Key Points**

### **✅ What It Does:**
1. **Reads docker-compose.yml** before allocation
2. **Counts victim services** (excludes attacker, database, API)
3. **Allocates exact number** of random IPs needed
4. **Assigns sequentially** to each victim service
5. **Handles edge cases** (fallback if not enough IPs)

### **✅ Smart Detection:**
- Identifies victim services by exclusion:
  - Not "attacker" → Victim
  - Not "database" → Victim
  - Not "api" → Victim
- Counts them accurately
- Allocates exactly what's needed

### **✅ Randomization:**
- Each victim gets a **unique random IP**
- IPs are in range: `.10` to `.200`
- Uses `crypto.randomBytes()` for true randomness
- No conflicts (checks excluded IPs)

---

## 🔄 **Complete Flow**

```
Deployment starts
  ↓
Read docker-compose.yml
  ↓
Extract all services
  ↓
Filter services:
  - Exclude: attacker, database, api
  - Count remaining = victimCount
  ↓
Allocate subnet with:
  - victimCount (exact number)
  - randomizeIPs: true
  ↓
Get victimIPs array:
  - [IP1, IP2, IP3, ...] (exactly victimCount IPs)
  ↓
Assign to services:
  - Victim 1 → IP1
  - Victim 2 → IP2
  - Victim 3 → IP3
  ↓
Update docker-compose.yml
  ↓
Deploy with correct IPs
```

---

## 📝 **Code Location**

**File:** `packages/ctf-automation/src/deployment/deployer.js`

**Key Function:** `revalidateIPAllocation()`

**Lines:**
- 207-212: Count victim services
- 224-229: Allocate with exact count
- 281-291: Assign IPs to victims

---

## ✅ **Summary**

**Question:** Does it check how many victims or just allocate?

**Answer:** ✅ **It CHECKS first, then allocates exactly what's needed**

1. ✅ Reads docker-compose.yml
2. ✅ Counts victim services (excludes attacker/database/api)
3. ✅ Allocates exact number of random IPs
4. ✅ Assigns sequentially to each victim
5. ✅ Handles edge cases with fallback

**Result:** Perfect IP allocation - no waste, no shortage!

---

**Last Updated**: 2025-01-03

