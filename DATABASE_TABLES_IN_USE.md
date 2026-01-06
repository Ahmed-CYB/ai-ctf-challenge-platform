# Database Tables Actually in Use

## Overview

This document lists **only the database tables that are actively used in the codebase**, based on actual code analysis.

**Note:** You mentioned you're **not using publishes or streaks**, so tables related to those features are marked as **NOT IN USE**.

---

## ✅ **PostgreSQL Database - Tables IN USE**

### **Core Application Tables**

#### 1. **users**
- ✅ **Status**: **IN USE**
- **Used in**: `packages/backend/server.js`
- **Operations**: 
  - User registration, login, authentication
  - Profile management
  - User statistics (`challenges_solved`, `challenges_created`)
- **Note**: Contains streak fields (`current_streak`, `longest_streak`) but you mentioned you're not using streaks

#### 2. **sessions**
- ✅ **Status**: **IN USE**
- **Used in**: 
  - `packages/backend/server.js`
  - `packages/backend/secure-session-manager.js`
  - `packages/ctf-automation/src/db-manager.js`
- **Operations**: 
  - Session creation, validation, expiration
  - Session tracking for chat interface

#### 3. **challenges**
- ✅ **Status**: **IN USE**
- **Used in**: `packages/backend/server.js`
- **Operations**: 
  - Save challenges (`POST /api/challenges`)
  - Get challenges (`GET /api/challenges` - filtered by `user_id`)
  - Get challenge by ID (`GET /api/challenges/:challengeId`)
  - Flag verification (`POST /api/challenges/:challengeId/submit`)
- **Key**: `user_id` ensures challenges are private

#### 4. **chat_messages**
- ✅ **Status**: **IN USE**
- **Used in**: 
  - `packages/backend/server.js`
  - `packages/ctf-automation/src/db-manager.js`
- **Operations**: 
  - Save chat messages
  - Retrieve conversation history
  - Link messages to challenges

#### 5. **challenge_submissions**
- ✅ **Status**: **IN USE**
- **Used in**: `packages/backend/server.js`
- **Operations**: 
  - Flag submission and verification
  - Track solves (`is_correct`, `solve_date`)
  - Prevent duplicate submissions

#### 6. **pending_deployments**
- ✅ **Status**: **IN USE**
- **Used in**: `packages/ctf-automation/src/db-manager.js`
- **Operations**: 
  - Store pending deployment confirmations
  - Handle deployment confirmation flow

#### 7. **session_guacamole_users**
- ✅ **Status**: **IN USE**
- **Used in**: `packages/ctf-automation/src/session-guacamole-manager.js`
- **Operations**: 
  - Map sessions to Guacamole users
  - Store Guacamole credentials per session
  - Persist Guacamole access across restarts

#### 8. **session_activity**
- ✅ **Status**: **IN USE**
- **Used in**: `packages/ctf-automation/src/db-manager.js`
- **Operations**: 
  - Track session activity for analytics
  - Monitor and debug session behavior

#### 9. **user_activity_log**
- ✅ **Status**: **IN USE**
- **Used in**: `packages/backend/server.js`
- **Operations**: 
  - Log user activities (login, registration, etc.)
  - Track IP addresses and user agents

---

### **CTF Automation Tables (IN USE)**

#### 10. **validated_os_images**
- ✅ **Status**: **IN USE**
- **Used in**: `packages/ctf-automation/src/os-image-db-manager.js`
- **Operations**: 
  - Store validated Docker OS images
  - Check if OS images are valid
  - Track OS image usage

#### 11. **os_image_validation_queue**
- ✅ **Status**: **IN USE**
- **Used in**: `packages/ctf-automation/src/os-image-db-manager.js`
- **Operations**: 
  - Queue OS images for validation
  - Track validation status

#### 12. **os_image_usage_history**
- ✅ **Status**: **IN USE**
- **Used in**: `packages/ctf-automation/src/os-image-db-manager.js`
- **Operations**: 
  - Track which challenges use which OS images
  - Analytics on OS image usage

#### 13. **ctf_tools**
- ✅ **Status**: **IN USE**
- **Used in**: `packages/ctf-automation/src/tool-learning-service.js`
- **Operations**: 
  - Store tool definitions
  - Tool catalog for CTF automation

#### 14. **tool_installation_methods**
- ✅ **Status**: **IN USE**
- **Used in**: `packages/ctf-automation/src/tool-learning-service.js`
- **Operations**: 
  - Store verified installation methods
  - Cache successful installation commands

#### 15. **tool_learning_queue**
- ✅ **Status**: **IN USE**
- **Used in**: `packages/ctf-automation/src/tool-learning-service.js`
- **Operations**: 
  - Queue tools for learning installation methods
  - Track learning status

#### 16. **service_package_mappings**
- ✅ **Status**: **IN USE**
- **Used in**: `packages/ctf-automation/src/package-mapping-db-manager.js`
- **Operations**: 
  - Map service names to package names
  - OS-specific package mappings

#### 17. **tool_package_mappings**
- ✅ **Status**: **IN USE**
- **Used in**: `packages/ctf-automation/src/package-mapping-db-manager.js`
- **Operations**: 
  - Map tool names to package names
  - Used for attacker machine tool installation

#### 18. **subnet_allocations**
- ✅ **Status**: **IN USE**
- **Used in**: `packages/ctf-automation/src/subnet-allocator.js`
- **Operations**: 
  - Track network subnet allocations
  - Prevent subnet conflicts
  - Manage challenge network isolation

---

## ❌ **PostgreSQL Database - Tables NOT IN USE**

### **Tables That Exist But Are Not Used in Code**

#### 1. **challenge_ratings**
- ❌ **Status**: **NOT IN USE**
- **Reason**: No code references found
- **Note**: You mentioned you're not using publishes/ratings

#### 2. **daily_solves**
- ⚠️ **Status**: **EXISTS IN CODE BUT NOT USED** (You said no streaks)
- **Found in**: `packages/backend/server.js` (line 1128-1131)
- **Reason**: Part of streak system, but you're not using streaks
- **Note**: Code exists but feature is disabled/not used

#### 3. **streak_history**
- ❌ **Status**: **NOT IN USE**
- **Reason**: No code references found
- **Note**: You mentioned you're not using streaks

#### 4. **password_reset_tokens**
- ❌ **Status**: **NOT IN USE**
- **Reason**: No code references found
- **Note**: Password reset functionality not implemented

#### 5. **email_verification_tokens**
- ❌ **Status**: **NOT IN USE**
- **Reason**: No code references found
- **Note**: Email verification not implemented

#### 6. **tool_aliases**
- ❌ **Status**: **NOT IN USE** (or minimal use)
- **Reason**: No direct code references found
- **Note**: May be used indirectly through tool learning system

#### 7. **tool_installation_logs**
- ❌ **Status**: **NOT IN USE** (or minimal use)
- **Reason**: No direct code references found
- **Note**: May be used for debugging/analytics

#### 8. **tool_dependencies**
- ❌ **Status**: **NOT IN USE** (or minimal use)
- **Reason**: No direct code references found

#### 9. **tool_documentation_cache**
- ❌ **Status**: **NOT IN USE** (or minimal use)
- **Reason**: No direct code references found

#### 10. **package_aliases**
- ❌ **Status**: **NOT IN USE** (or minimal use)
- **Reason**: No direct code references found

#### 11. **attack_tools**
- ❌ **Status**: **NOT IN USE** (or minimal use)
- **Reason**: No direct code references found

#### 12. **invalid_service_names**
- ❌ **Status**: **NOT IN USE** (or minimal use)
- **Reason**: No direct code references found

#### 13. **base_tools_by_os**
- ❌ **Status**: **NOT IN USE** (or minimal use)
- **Reason**: No direct code references found

#### 14. **tool_categories**
- ❌ **Status**: **NOT IN USE** (or minimal use)
- **Reason**: No direct code references found

#### 15. **database_audit_log**
- ❌ **Status**: **NOT IN USE**
- **Reason**: No code references found

---

## 📊 **MySQL Database (Guacamole) - Tables IN USE**

### **All Guacamole Tables Are Standard**

All 23 tables in the Guacamole MySQL database are **standard Guacamole tables** and are **actively used** by the Guacamole service:

1. ✅ `guacamole_connection_group`
2. ✅ `guacamole_connection`
3. ✅ `guacamole_entity`
4. ✅ `guacamole_user`
5. ✅ `guacamole_user_group`
6. ✅ `guacamole_user_group_member`
7. ✅ `guacamole_sharing_profile`
8. ✅ `guacamole_connection_parameter`
9. ✅ `guacamole_sharing_profile_parameter`
10. ✅ `guacamole_user_attribute`
11. ✅ `guacamole_user_group_attribute`
12. ✅ `guacamole_connection_attribute`
13. ✅ `guacamole_connection_group_attribute`
14. ✅ `guacamole_sharing_profile_attribute`
15. ✅ `guacamole_connection_permission`
16. ✅ `guacamole_connection_group_permission`
17. ✅ `guacamole_sharing_profile_permission`
18. ✅ `guacamole_system_permission`
19. ✅ `guacamole_user_permission`
20. ✅ `guacamole_user_group_permission`
21. ✅ `guacamole_connection_history`
22. ✅ `guacamole_user_history`
23. ✅ `guacamole_user_password_history`

**Status**: ✅ All are standard Guacamole tables, managed by Guacamole service

---

## 📋 **Summary**

### **PostgreSQL - Tables IN USE: 18**

**Core Application (9):**
1. `users`
2. `sessions`
3. `challenges`
4. `chat_messages`
5. `challenge_submissions`
6. `pending_deployments`
7. `session_guacamole_users`
8. `session_activity`
9. `user_activity_log`

**CTF Automation (9):**
10. `validated_os_images`
11. `os_image_validation_queue`
12. `os_image_usage_history`
13. `ctf_tools`
14. `tool_installation_methods`
15. `tool_learning_queue`
16. `service_package_mappings`
17. `tool_package_mappings`
18. `subnet_allocations`

### **PostgreSQL - Tables NOT IN USE: 15**

1. `challenge_ratings` ❌
2. `daily_solves` ⚠️ (exists in code but you're not using streaks)
3. `streak_history` ❌
4. `password_reset_tokens` ❌
5. `email_verification_tokens` ❌
6. `tool_aliases` ❌
7. `tool_installation_logs` ❌
8. `tool_dependencies` ❌
9. `tool_documentation_cache` ❌
10. `package_aliases` ❌
11. `attack_tools` ❌
12. `invalid_service_names` ❌
13. `base_tools_by_os` ❌
14. `tool_categories` ❌
15. `database_audit_log` ❌

### **MySQL (Guacamole) - Tables IN USE: 23**

All 23 tables are standard Guacamole tables and are actively used.

---

## ⚠️ **Important Notes**

1. **Streak System**: Code exists for streaks (`daily_solves`, `update_user_streak` function) but you mentioned you're **not using streaks**. These can be considered **NOT IN USE** for your workflow.

2. **Challenge Ratings**: Table exists but **no code uses it** - you're not using publishes/ratings.

3. **Password Reset / Email Verification**: Tables exist but **no code uses them** - features not implemented.

4. **Tool Learning Tables**: Some tables like `tool_aliases`, `tool_dependencies` exist but may have minimal or indirect use.

---

**Last Updated**: 2025-01-27  
**Status**: Based on actual codebase analysis  
**Note**: Only tables with actual code references are marked as "IN USE"

