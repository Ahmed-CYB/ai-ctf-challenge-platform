# EternalBlue Vulnerability Recognition Fix

## Problem

When user requested "create eternal blue vulnerability ctf challenge", the system created an FTP challenge instead of an SMB/Samba challenge.

## Root Cause

1. **Challenge Designer** wasn't extracting specific vulnerability names from user requests
2. **Request Validator** wasn't mapping "eternal blue" to SMB/Samba service
3. **Design Prompt** didn't emphasize the specific vulnerability requested

## Fixes Applied

### 1. Enhanced Challenge Designer (`designer.js`)

**Added:**
- `extractVulnerability()` - Extracts specific vulnerability names from messages
- `vulnerabilityToService()` - Maps vulnerabilities to services
- `extractOriginalMessage()` - Gets original user message from conversation history

**Vulnerability Recognition:**
- "eternal blue" → "eternalblue" → Samba service
- "ms17-010" → "eternalblue" → Samba service
- "cve-2017-0144" → "eternalblue" → Samba service
- And many more...

**Updated Design Prompt:**
- Now explicitly mentions the specific vulnerability requested
- Emphasizes creating challenge for EXACT vulnerability, not generic
- Maps EternalBlue to Samba/SMB on Linux (Windows not supported)

### 2. Enhanced Request Validator (`request-validator.js`)

**Updated `extractServices()`:**
- Now checks for specific vulnerabilities first
- Maps "eternal blue" / "eternalblue" / "ms17-010" → Samba service
- Prevents creating wrong service type

### 3. Updated System Prompt

Added to designer system prompt:
```
SPECIFIC VULNERABILITY HANDLING:
- If user requests "EternalBlue" or "MS17-010", create a Samba/SMB challenge with misconfiguration that mimics EternalBlue behavior on Linux
- If user requests a specific CVE or vulnerability, focus the challenge on that EXACT vulnerability
- Do NOT create a generic challenge when a specific vulnerability is requested
```

## How It Works Now

**Before:**
```
User: "create eternal blue vulnerability ctf challenge"
System: Creates FTP challenge ❌
```

**After:**
```
User: "create eternal blue vulnerability ctf challenge"
System:
1. Extracts: "eternalblue" vulnerability
2. Maps to: Samba service
3. Creates: SMB/Samba challenge with EternalBlue-like misconfiguration ✅
```

## Supported Vulnerability Mappings

| User Request | Detected Vulnerability | Service | Notes |
|-------------|----------------------|---------|-------|
| "eternal blue" | eternalblue | samba | MS17-010 on Linux |
| "ms17-010" | eternalblue | samba | CVE-2017-0144/0145 |
| "sql injection" | sql-injection | mysql | Database vulnerability |
| "xss" | xss | http | Web vulnerability |
| "anonymous ftp" | anonymous-ftp | ftp | FTP misconfiguration |
| "null session" | null-session | samba | SMB vulnerability |

## Testing

To verify the fix:

1. **Test EternalBlue:**
   ```
   User: "create eternal blue vulnerability ctf challenge"
   Expected: SMB/Samba challenge (not FTP)
   ```

2. **Test Other Vulnerabilities:**
   ```
   User: "create sql injection challenge"
   Expected: MySQL/web challenge
   
   User: "create anonymous ftp challenge"
   Expected: FTP challenge with anonymous access
   ```

## Files Modified

1. `packages/ctf-automation/src/challenge/designer.js`
   - Added vulnerability extraction
   - Enhanced design prompt building
   - Added service mapping

2. `packages/ctf-automation/src/core/request-validator.js`
   - Enhanced service extraction
   - Added vulnerability-to-service mapping

---

**Status**: ✅ Fixed - System now correctly recognizes EternalBlue and creates SMB/Samba challenges

