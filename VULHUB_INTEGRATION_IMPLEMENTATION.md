# Vulhub Integration Implementation

## Overview

This implementation integrates Vulhub (https://github.com/vulhub/vulhub) as actual templates for CTF challenge creation, rather than just references. The system now:

1. **Fetches actual Vulhub configurations** from GitHub during challenge creation
2. **Caches Vulhub examples locally** for faster access
3. **Uses Vulhub as actual templates** with AI-powered adaptation
4. **Automatically adjusts flags and specifications** based on user requirements
5. **Ensures Guacamole connectivity** for all challenges

## Architecture

### Components Created

#### 1. Vulhub Fetcher Service (`vulhub-fetcher.js`)
- **Purpose**: Fetches and caches Vulhub repository from GitHub
- **Location**: `packages/ctf-automation/src/services/vulhub-fetcher.js`
- **Features**:
  - Clones/updates Vulhub repository to `.vulhub-cache/`
  - Searches for examples matching service types (FTP, Samba, Apache, etc.)
  - Parses Dockerfiles, docker-compose.yml, and config files
  - Returns best matching examples based on service type and vulnerability

#### 2. Vulhub Template Manager (`vulhub-template-manager.js`)
- **Purpose**: Adapts Vulhub templates for CTF challenges
- **Location**: `packages/ctf-automation/src/services/vulhub-template-manager.js`
- **Features**:
  - Uses AI (Claude) to adapt Vulhub templates
  - Adjusts flags, configurations, and ensures compatibility
  - Maintains working Vulhub configurations while adding CTF elements
  - Ensures Guacamole SSH access is configured

### Integration Points

#### 1. Challenge Designer (`designer.js`)
- **Modified**: `packages/ctf-automation/src/challenge/designer.js`
- **Changes**:
  - Extracts service type from requirements/conversation
  - Fetches Vulhub template before AI generation
  - Includes Vulhub template in design prompt
  - Merges Vulhub template data into design

#### 2. Dockerfile Generator (`dockerfile-generator.js`)
- **Modified**: `packages/ctf-automation/src/challenge/dockerfile-generator.js`
- **Changes**:
  - Checks for Vulhub template in structure
  - Uses Vulhub Dockerfile as base for victim machines
  - Adapts Vulhub Dockerfile to add flags and ensure Guacamole compatibility
  - Falls back to regular generation if Vulhub template unavailable

#### 3. Structure Builder (`structure-builder.js`)
- **Modified**: `packages/ctf-automation/src/challenge/structure-builder.js`
- **Changes**:
  - Preserves Vulhub template in structure data
  - Passes template to dockerfile generator

## Workflow

### Challenge Creation Flow

1. **User Request**: "Create FTP challenge" or "Create EternalBlue challenge"
2. **Service Detection**: System extracts service type (FTP, Samba, etc.)
3. **Vulhub Fetch**: 
   - Fetches matching Vulhub example from cache or GitHub
   - Parses Dockerfile, docker-compose.yml, and config files
4. **Template Adaptation**:
   - AI adapts Vulhub template for CTF
   - Adds unique flag: `CTF{descriptive_flag_name}`
   - Places flag in appropriate location
   - Ensures Guacamole SSH access (attacker container)
5. **Challenge Generation**:
   - Uses adapted Vulhub Dockerfile as base
   - Generates docker-compose.yml with proper networking
   - Creates config files from Vulhub templates
6. **Deployment**:
   - Deploys challenge with working Vulhub configuration
   - Automatically sets up Guacamole connection (already implemented)

## Key Features

### 1. Automatic Flag Generation
- AI generates descriptive flags: `CTF{ftp_anonymous_login_exploit_2024}`
- Flags placed in service-appropriate locations:
  - FTP: `/var/ftp/data/flag.txt`
  - Samba: `/tmp/share/flag.txt`
  - Web: `/var/www/html/flag.txt`
  - SSH: `/root/flag.txt`

### 2. Guacamole Integration
- **Attacker containers** automatically configured with SSH:
  - User: `kali`
  - Password: `kali`
  - Port: `22`
- **Guacamole connections** created during deployment (existing feature)
- **Session-based access** ensures user isolation

### 3. Template Caching
- Vulhub repository cached in `.vulhub-cache/`
- First fetch clones repository (may take a few minutes)
- Subsequent fetches update existing cache
- Reduces GitHub API calls and improves speed

### 4. AI-Powered Adaptation
- AI adapts Vulhub templates while preserving working configurations
- Adjusts flags, user requirements, and CTF-specific elements
- Maintains service startup commands and configurations
- Ensures Linux-only compatibility

## Example Usage

### User Request
```
"Create an FTP challenge with anonymous access"
```

### System Response
1. Detects service type: `ftp`
2. Fetches Vulhub FTP example (e.g., `vulhub/ftp/vsftpd/`)
3. Adapts template:
   - Keeps working `vsftpd.conf` configuration
   - Adds flag: `CTF{ftp_anonymous_access_exploit_2024}`
   - Places flag in `/var/ftp/data/flag.txt`
   - Ensures anonymous access is enabled
4. Generates challenge with working Vulhub configuration
5. Deploys and creates Guacamole connection

## Benefits

1. **Reliability**: Uses tested, working Vulhub configurations
2. **Speed**: Cached templates reduce generation time
3. **Accuracy**: Real-world vulnerability configurations
4. **Flexibility**: AI adapts templates for CTF requirements
5. **Compatibility**: Ensures Guacamole connectivity automatically

## Configuration

### Environment Variables
No new environment variables required. Uses existing:
- `ANTHROPIC_API_KEY`: For AI template adaptation
- `GUACAMOLE_URL`: For Guacamole connection setup

### Cache Location
- Default: `.vulhub-cache/` in project root
- Can be customized by modifying `VulhubFetcher.cacheDir`

## Error Handling

- **Vulhub fetch fails**: Falls back to AI-only generation
- **Template parse fails**: Uses minimal adaptation
- **AI adaptation fails**: Uses fallback with original Vulhub config
- **Service not found**: Logs warning and continues with AI generation

## Future Enhancements

1. **Template Scoring**: Rank Vulhub examples by relevance
2. **Multi-Vulnerability**: Support challenges with multiple Vulhub examples
3. **Template Updates**: Periodic cache refresh mechanism
4. **Custom Templates**: Allow users to add custom Vulhub-style templates
5. **Template Validation**: Pre-validate templates before use

## Files Modified

1. `packages/ctf-automation/src/services/vulhub-fetcher.js` (NEW)
2. `packages/ctf-automation/src/services/vulhub-template-manager.js` (NEW)
3. `packages/ctf-automation/src/challenge/designer.js` (MODIFIED)
4. `packages/ctf-automation/src/challenge/dockerfile-generator.js` (MODIFIED)
5. `packages/ctf-automation/src/challenge/structure-builder.js` (MODIFIED)

## Testing

To test the implementation:

1. **Create FTP Challenge**:
   ```
   "Create an FTP challenge with anonymous access"
   ```
   - Should fetch Vulhub FTP example
   - Should generate working vsftpd configuration
   - Should create flag in `/var/ftp/data/flag.txt`

2. **Create Samba Challenge**:
   ```
   "Create a Samba challenge with EternalBlue"
   ```
   - Should fetch Vulhub Samba example
   - Should generate working smb.conf
   - Should create flag in `/tmp/share/flag.txt`

3. **Verify Guacamole**:
   - Deploy any challenge
   - Verify Guacamole connection is created
   - Verify SSH access works (kali:kali)

## Notes

- First run will clone Vulhub repository (may take 2-5 minutes)
- Subsequent runs use cached repository (much faster)
- Vulhub repository is updated on each fetch (git pull)
- All challenges maintain Linux-only compatibility
- Guacamole connections are automatically created during deployment (existing feature)

