# Windows vs Linux CTF Classification Logic

## Overview

The system classifies whether a CTF challenge request is for Windows or Linux by checking for Windows-specific vulnerabilities and keywords **before** any challenge creation begins.

## Classification Process

### Step 1: Early Detection (Request Validator)

The classification happens in `RequestValidator.validate()` **before** any AI processing or challenge creation:

```javascript
// Check for Windows-specific vulnerabilities - we don't support Windows challenges
const windowsVulnCheck = this.checkWindowsVulnerability(message);
if (windowsVulnCheck.isWindowsVuln) {
  return {
    valid: false,
    error: 'Windows challenges are not supported',
    message: windowsVulnCheck.message,
    type: 'windows_not_supported'
  };
}
```

### Step 2: Detection Methods

The `checkWindowsVulnerability()` method uses **three detection strategies**:

#### 1. **Normalized String Matching**
- Removes spaces, hyphens, and underscores from the message
- Example: "blue keep" → "bluekeep", "print-nightmare" → "printnightmare"
- Checks if normalized message contains vulnerability keys

#### 2. **Explicit Variation Matching**
- Checks for all known variations of vulnerability names:
  - `bluekeep`, `blue keep`, `blue-keep`, `blue_keep`
  - `printnightmare`, `print nightmare`, `print-nightmare`, `print_nightmare`
  - etc.

#### 3. **CVE and Name Matching**
- Checks for CVE numbers (e.g., "CVE-2019-0708")
- Checks for official vulnerability names (e.g., "BlueKeep", "PrintNightmare")

### Step 3: Windows-Specific Vulnerabilities Detected

The system detects these Windows vulnerabilities:

| Vulnerability | CVE | Variations Detected |
|--------------|-----|-------------------|
| **BlueKeep** | CVE-2019-0708 | bluekeep, blue keep, blue-keep, blue_keep |
| **PrintNightmare** | CVE-2021-1675, CVE-2021-34527 | printnightmare, print nightmare, print-nightmare, print_nightmare |
| **Zerologon** | CVE-2020-1472 | zerologon, zero logon, zero-logon, zero_logon |
| **MS08-067** | MS08-067 | ms08-067, ms08 067, ms08067, ms08_067 |
| **EternalRomance** | CVE-2017-0145 | eternalromance, eternal romance, eternal-romance, eternal_romance |
| **EternalChampion** | CVE-2017-0146 | eternalchampion, eternal champion, eternal-champion, eternal_champion |

### Step 4: Windows Context Detection

The system also detects Windows-specific context phrases:

- `windows vulnerability`
- `windows exploit`
- `windows ctf`
- `windows challenge`
- `rdp vulnerability`
- `rdp exploit`
- `rdp challenge`
- `active directory vulnerability`
- `ad exploit`
- `ad challenge`

## Classification Flow

```
User Request
    ↓
RequestValidator.validate()
    ↓
checkWindowsVulnerability()
    ↓
┌─────────────────────────────┐
│ Is Windows vulnerability?   │
└─────────────────────────────┘
    ↓                    ↓
   YES                  NO
    ↓                    ↓
Reject with        Continue to
message            AI classification
```

## Example Classifications

### ✅ Windows (Rejected)
- `"create ctf challenge bluekeep"` → ❌ Rejected
- `"create blue keep ctf challenge"` → ❌ Rejected (normalized to "bluekeep")
- `"create ctf challenge printnightmare"` → ❌ Rejected
- `"create ctf challenge CVE-2019-0708"` → ❌ Rejected
- `"create windows rdp vulnerability challenge"` → ❌ Rejected

### ✅ Linux (Allowed)
- `"create ctf challenge eternal blue"` → ✅ Allowed (Linux SMB/Samba)
- `"create ctf challenge samba"` → ✅ Allowed
- `"create ctf challenge ftp"` → ✅ Allowed
- `"create ctf challenge ssh"` → ✅ Allowed

## Why This Approach?

1. **Early Rejection**: Windows vulnerabilities are detected **before** any AI processing, saving API calls and time
2. **Pattern Matching**: Uses multiple detection methods to catch variations
3. **User-Friendly**: Provides clear rejection messages with alternative suggestions
4. **Explicit**: Only rejects known Windows vulnerabilities, not ambiguous requests

## Code Location

- **Detection Logic**: `packages/ctf-automation/src/core/request-validator.js`
  - Method: `checkWindowsVulnerability(message)`
  - Called in: `validate(message, conversationHistory)`

- **Error Handling**: `packages/ctf-automation/src/core/error-handler.js`
  - Method: `handleValidationError(validationResult)`
  - Handles `type: 'windows_not_supported'`

## Testing

To test the classification:

```bash
# Should be rejected (Windows)
"create ctf challenge bluekeep"
"create blue keep ctf challenge"
"create ctf challenge printnightmare"
"create ctf challenge CVE-2019-0708"

# Should be allowed (Linux)
"create ctf challenge eternal blue"
"create ctf challenge samba"
"create ctf challenge ftp"
```

## Important Notes

- **No AI Classification**: Windows detection happens **before** AI classification, so it's purely pattern-based
- **Normalization**: Handles spaces, hyphens, and underscores in vulnerability names
- **Case Insensitive**: All matching is case-insensitive
- **Explicit Only**: Only rejects known Windows vulnerabilities, not generic "windows" mentions (unless in specific context)

