# AI-Powered OS Detection for Vulnerabilities

## Overview

Replaced static pattern matching with AI-powered OS detection to intelligently determine if a vulnerability is Windows-specific, Linux-specific, or platform-agnostic. This allows the system to handle **any vulnerability**, not just hardcoded ones.

## Implementation

### 1. New OS Detection Agent (`packages/ctf-automation/src/agents/os-detection-agent.js`)

Uses **Anthropic Claude** to analyze vulnerability requests and determine OS requirements:

```javascript
const osDetection = await osDetectionAgent.detectOS(message, conversationHistory);
if (osDetection.isWindows) {
  // Reject with user-friendly message
}
```

### 2. AI Detection Process

1. **Analyzes the user's request** for vulnerability mentions
2. **Considers conversation context** for better understanding
3. **Identifies CVE numbers, service names, protocols**
4. **Determines OS requirement** (Windows/Linux/Agnostic)
5. **Provides reasoning** and alternatives if Windows

### 3. Integration

**Before (Static):**
```javascript
// Static pattern matching
const windowsVulnCheck = this.checkWindowsVulnerability(message);
```

**After (AI-Powered):**
```javascript
// AI-powered detection
const osDetection = await osDetectionAgent.detectOS(message, conversationHistory);
```

## AI Detection Capabilities

### Windows Vulnerabilities Detected
- **BlueKeep** (CVE-2019-0708) - RDP
- **PrintNightmare** (CVE-2021-1675) - Print Spooler
- **Zerologon** (CVE-2020-1472) - Netlogon
- **MS08-067** - Windows Server Service
- **Windows SMB exploits** - MS17-010 (Windows version)
- **RDP vulnerabilities** - Windows Remote Desktop
- **Active Directory exploits** - Windows AD
- **PowerShell exploits** - Windows PowerShell
- **Any Windows-specific vulnerability** - AI can detect new ones

### Linux/Platform-Agnostic Allowed
- **EternalBlue/Samba** - Linux SMB (Samba)
- **FTP vulnerabilities** - Platform-agnostic
- **SSH vulnerabilities** - Platform-agnostic
- **SQL injection** - Platform-agnostic
- **XSS** - Platform-agnostic
- **Network protocols** - Platform-agnostic

## AI Response Format

```json
{
  "os": "windows" | "linux" | "agnostic" | "unknown",
  "confidence": 0.0-1.0,
  "reasoning": "Detailed explanation",
  "vulnerability": "Vulnerability name",
  "cve": "CVE-XXXX-XXXX",
  "services": ["service1", "service2"],
  "alternative": "Suggested Linux alternative" | null
}
```

## Example Detections

### Example 1: BlueKeep
**User:** "create bluekeep vulnerability challenge"

**AI Response:**
```json
{
  "os": "windows",
  "confidence": 0.98,
  "reasoning": "BlueKeep (CVE-2019-0708) is a critical Windows RDP vulnerability that specifically affects Windows 7, Windows Server 2008 R2, and other Windows versions. It does not affect Linux systems.",
  "vulnerability": "BlueKeep",
  "cve": "CVE-2019-0708",
  "services": ["rdp"],
  "alternative": "EternalBlue (Samba on Linux) or other Linux SMB vulnerabilities"
}
```

### Example 2: EternalBlue (Linux Context)
**User:** "create eternal blue vulnerability challenge"

**AI Response:**
```json
{
  "os": "linux",
  "confidence": 0.95,
  "reasoning": "EternalBlue (MS17-010) can refer to Windows SMB exploit, but in CTF context on Linux platforms, this typically means Samba (Linux SMB) vulnerabilities. The platform only supports Linux, so this should be implemented as a Samba challenge.",
  "vulnerability": "EternalBlue",
  "cve": "CVE-2017-0144",
  "services": ["samba", "smb"],
  "alternative": null
}
```

### Example 3: SQL Injection
**User:** "create sql injection challenge"

**AI Response:**
```json
{
  "os": "agnostic",
  "confidence": 0.99,
  "reasoning": "SQL injection is a web application vulnerability that is platform-agnostic. It works regardless of the underlying operating system (Windows, Linux, etc.).",
  "vulnerability": "SQL Injection",
  "cve": null,
  "services": ["http", "database"],
  "alternative": null
}
```

## Benefits

1. **Flexible**: Handles any vulnerability, not just hardcoded ones
2. **Intelligent**: Understands context and CVE numbers
3. **Accurate**: AI can distinguish between Windows and Linux versions of similar vulnerabilities
4. **Extensible**: Automatically handles new vulnerabilities without code changes
5. **Context-Aware**: Uses conversation history for better understanding

## Fallback Strategy

If AI detection fails:
1. Logs the error
2. Falls back to static pattern matching (kept as backup)
3. Returns "unknown" OS with low confidence
4. Allows challenge creation to proceed (safe default)

## Configuration

Uses the same AI model as other agents:
- **Model**: `ANTHROPIC_MODEL` env var or `claude-sonnet-4-20250514` (default)
- **Temperature**: 0.1 (low for consistent detection)
- **Max Tokens**: 500

## Testing

To test AI detection:

```bash
# Should be rejected (Windows)
"create bluekeep vulnerability challenge"
"create printnightmare challenge"
"create windows rdp vulnerability"

# Should be allowed (Linux/Agnostic)
"create eternal blue vulnerability challenge"  # → Linux Samba
"create sql injection challenge"  # → Agnostic
"create ftp challenge"  # → Agnostic
```

## Files Modified

1. **New File**: `packages/ctf-automation/src/agents/os-detection-agent.js`
   - AI-powered OS detection agent
   - Uses Anthropic Claude for intelligent analysis

2. **Updated**: `packages/ctf-automation/src/core/request-validator.js`
   - Replaced static `checkWindowsVulnerability()` with AI detection
   - Kept static method as fallback

3. **Updated**: `packages/ctf-automation/src/core/error-handler.js`
   - Enhanced to use AI detection results
   - Provides detailed reasoning to users

## Notes

- AI detection happens **before** challenge creation, saving API calls
- Static pattern matching is kept as a fallback for reliability
- AI can handle edge cases and new vulnerabilities automatically
- Confidence scores help with uncertain cases

