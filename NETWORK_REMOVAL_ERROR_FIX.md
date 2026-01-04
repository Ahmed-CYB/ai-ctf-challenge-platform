# Network Removal Error Fix

## Error Description

**Error Message:**
```
Error response from daemon: error while removing network: network corporate-data-breach-investigation_ctf-corporate-data-breach-investigation-net has active endpoints (name:"ctf-guacd-new" id:"1a20a94e5a18")
```

## Root Cause

When deploying a challenge, Docker Compose tries to remove the old network before creating a new one. However, if `ctf-guacd-new` (Guacamole daemon) is still connected to that network, Docker cannot remove it because networks with active endpoints cannot be deleted.

**Why this happens:**
1. Previous deployment connected `ctf-guacd-new` to the challenge network
2. New deployment tries to remove/recreate the network
3. Docker Compose fails because `ctf-guacd-new` is still connected
4. Deployment fails with exit code 1

## Solution

### 1. **Pre-Deployment Disconnect** (Primary Fix)
Before running `docker compose up`, the system now:
- Inspects `ctf-guacd-new` container to find all connected networks
- Identifies challenge-related networks using multiple patterns:
  - Direct challenge name match
  - Docker Compose naming pattern: `{challenge-name-with-underscores}_{ctf-challenge-name-with-hyphens}-net`
  - Example: `corporate_data_breach_investigation_ctf-corporate-data-breach-investigation-net`
- Disconnects `ctf-guacd-new` from all challenge-related networks
- Logs the disconnection for debugging

**Location**: `packages/ctf-automation/src/docker-manager.js` (lines 472-541)

### 2. **Error Detection & Graceful Handling** (Fallback)
If the disconnect fails or the error still occurs, the system:
- Detects the specific error pattern:
  - Contains "active endpoints"
  - Contains "network" or "removing network"
  - Contains "removed" or "removing" or "error while removing"
  - OR contains "has active endpoints" and "ctf-guacd-new"
- Treats it as **non-fatal** (containers are built and running)
- Continues deployment (guacd will be reconnected automatically)

**Location**: `packages/ctf-automation/src/docker-manager.js` (lines 583-597, 585-595)

## Network Naming Patterns

Docker Compose creates network names using this pattern:
```
{directory-name-with-underscores}_{network-name-from-compose-yml}
```

**Example:**
- Challenge name: `corporate-data-breach-investigation`
- Directory: `corporate-data-breach-investigation` (hyphens)
- Network in docker-compose.yml: `ctf-corporate-data-breach-investigation-net`
- **Actual Docker network name**: `corporate_data_breach_investigation_ctf-corporate-data-breach-investigation-net`

**Key Points:**
- Directory name: hyphens converted to underscores
- Network name: keeps hyphens from docker-compose.yml
- Combined with underscore: `{dir}_` + `{net}`

## Code Changes

### 1. Enhanced Network Detection
```javascript
// Docker Compose network naming: {directory-with-underscores}_{network-name-with-hyphens}
const composeNetworkPrefix = challengeName.replace(/-/g, '_'); // corporate_data_breach_investigation
const composeNetworkSuffix = `ctf-${challengeName}-net`; // ctf-corporate-data-breach-investigation-net
const composeNetworkPattern = `${composeNetworkPrefix}_${composeNetworkSuffix}`;

// Check for exact match and partial matches
if (netLower === composeNetworkPattern.toLowerCase()) return true;
if (netLower.includes(composeNetworkPrefix.toLowerCase()) && 
    netLower.includes(composeNetworkSuffix.toLowerCase())) return true;
```

### 2. Improved Error Detection
```javascript
const isNetworkRemovalError = (
  errorOutput.includes('active endpoints') && 
  (errorOutput.includes('network') || errorOutput.includes('removing network')) &&
  (errorOutput.includes('removed') || errorOutput.includes('removing') || errorOutput.includes('error while removing'))
) || (
  errorOutput.includes('has active endpoints') &&
  errorOutput.includes('ctf-guacd-new')
);
```

## Testing

To verify the fix works:

1. **Deploy a challenge** that previously failed
2. **Check logs** for:
   - `🔍 Found X challenge-related networks to disconnect guacd from`
   - `🔌 Disconnected guacd from network: ...`
3. **If error still occurs**, check for:
   - `⚠️ Network removal warning (guacd connected) - this is expected, continuing...`
   - Deployment should continue successfully

## Prevention

The fix prevents this error by:
1. **Proactively disconnecting** guacd before deployment
2. **Gracefully handling** the error if it still occurs
3. **Automatically reconnecting** guacd after deployment completes

## Related Issues

- This error can occur when:
  - Redeploying the same challenge
  - Deploying a challenge with a similar name
  - Guacd was manually connected to a challenge network
  - Previous deployment didn't clean up properly

## Status

✅ **Fixed** - The system now:
- Disconnects guacd before deployment
- Handles the error gracefully if it occurs
- Continues deployment even if network removal fails (non-fatal)

