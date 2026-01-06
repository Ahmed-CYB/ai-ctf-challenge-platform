# ERD - PostgreSQL Database (CTF Platform)

## Entity Relationship Diagram

This ERD shows all tables in use in the PostgreSQL database and their relationships.

```mermaid
erDiagram
    users ||--o{ sessions : "has"
    users ||--o{ challenges : "creates"
    users ||--o{ chat_messages : "sends"
    users ||--o{ challenge_submissions : "submits"
    users ||--o{ user_activity_log : "generates"
    
    sessions ||--o{ chat_messages : "contains"
    sessions ||--o| session_guacamole_users : "maps to"
    sessions ||--o{ session_activity : "tracks"
    sessions ||--o| pending_deployments : "has"
    
    challenges ||--o{ chat_messages : "referenced in"
    challenges ||--o{ challenge_submissions : "receives"
    
    %% CTF Automation Tables
    validated_os_images ||--o{ os_image_usage_history : "used in"
    ctf_tools ||--o{ tool_installation_methods : "has"
    ctf_tools ||--o{ tool_learning_queue : "queued for"
    
    users {
        SERIAL user_id PK
        VARCHAR username UK
        VARCHAR email UK
        VARCHAR password_hash
        VARCHAR name
        TEXT bio
        VARCHAR profile_avatar
        VARCHAR role
        BOOLEAN is_verified
        BOOLEAN is_active
        INTEGER challenges_solved
        INTEGER challenges_created
        INTEGER solve_rank
        VARCHAR avatar_animal_id
        TIMESTAMP created_at
        TIMESTAMP updated_at
        TIMESTAMP last_active
        TIMESTAMP deleted_at
    }
    
    sessions {
        VARCHAR session_id PK
        INTEGER user_id FK
        TIMESTAMP created_at
        TIMESTAMP last_activity
        TIMESTAMP expires_at
        VARCHAR ip_address
        TEXT user_agent
        BOOLEAN is_active
    }
    
    challenges {
        SERIAL challenge_id PK
        VARCHAR challenge_name
        VARCHAR slug UK
        INTEGER user_id FK
        VARCHAR category
        VARCHAR difficulty
        TEXT description
        TEXT_ARRAY hints
        VARCHAR flag
        VARCHAR github_link
        VARCHAR docker_image
        VARCHAR dockerfile_path
        TEXT build_command
        TEXT deploy_command
        TEXT run_command
        VARCHAR container_name
        VARCHAR target_url
        INTEGER_ARRAY expected_ports
        TEXT deployment_notes
        BOOLEAN is_active
        BOOLEAN is_deployed
        TIMESTAMP created_at
        TIMESTAMP updated_at
    }
    
    chat_messages {
        SERIAL message_id PK
        VARCHAR session_id
        INTEGER user_id FK
        VARCHAR role
        TEXT message_text
        INTEGER challenge_id FK
        JSON metadata
        TIMESTAMP timestamp
    }
    
    challenge_submissions {
        SERIAL submission_id PK
        INTEGER challenge_id FK
        INTEGER user_id FK
        VARCHAR submitted_flag
        BOOLEAN is_correct
        DATE solve_date
        TIMESTAMP submitted_at
    }
    
    pending_deployments {
        VARCHAR session_id PK_FK
        VARCHAR challenge_name
        VARCHAR existing_challenge_name
        TIMESTAMP created_at
    }
    
    session_guacamole_users {
        VARCHAR session_id PK_FK
        VARCHAR guacamole_username
        INTEGER guacamole_entity_id
        TIMESTAMP created_at
        TIMESTAMP expires_at
        TIMESTAMP last_activity
    }
    
    session_activity {
        SERIAL id PK
        VARCHAR session_id FK
        VARCHAR activity_type
        JSONB activity_data
        TIMESTAMP timestamp
    }
    
    user_activity_log {
        SERIAL log_id PK
        INTEGER user_id FK
        VARCHAR activity_type
        VARCHAR ip_address
        TEXT user_agent
        JSON metadata
        TIMESTAMP created_at
    }
    
    validated_os_images {
        SERIAL id PK
        VARCHAR image_name UK
        VARCHAR package_manager
        TEXT description
        VARCHAR os_type
        VARCHAR os_family
        BOOLEAN is_valid
        BOOLEAN is_pullable
        BOOLEAN is_runnable
        BOOLEAN ports_configurable
        BOOLEAN services_configurable
        DECIMAL image_size_mb
        TEXT os_info
        INTEGER usage_count
        TIMESTAMP last_used_at
        DECIMAL success_rate
        TIMESTAMP validated_at
        VARCHAR validated_by
        VARCHAR validation_method
        TEXT validation_notes
        TIMESTAMP created_at
        TIMESTAMP updated_at
    }
    
    os_image_validation_queue {
        SERIAL id PK
        VARCHAR image_name UK
        VARCHAR requested_by
        INTEGER priority
        VARCHAR status
        TEXT error_message
        INTEGER attempts
        TIMESTAMP created_at
        TIMESTAMP updated_at
    }
    
    os_image_usage_history {
        SERIAL id PK
        INTEGER image_id FK
        VARCHAR image_name
        VARCHAR challenge_name
        VARCHAR machine_name
        VARCHAR usage_type
        BOOLEAN success
        TEXT error_message
        TIMESTAMP used_at
    }
    
    ctf_tools {
        SERIAL id PK
        VARCHAR tool_name UK
        VARCHAR display_name
        TEXT description
        VARCHAR category
        VARCHAR official_docs_url
        TIMESTAMP created_at
        TIMESTAMP updated_at
        VARCHAR learned_from
    }
    
    tool_installation_methods {
        SERIAL id PK
        INTEGER tool_id FK
        VARCHAR method
        VARCHAR package_name
        TEXT install_command
        VARCHAR post_install_verify_command
        BOOLEAN requires_breakage
        BOOLEAN requires_sudo
        INTEGER priority
        INTEGER success_count
        INTEGER failure_count
        INTEGER avg_install_time_ms
        VARCHAR kali_version
        TIMESTAMP last_successful_at
        TIMESTAMP created_at
    }
    
    tool_learning_queue {
        SERIAL id PK
        VARCHAR tool_name
        VARCHAR category
        INTEGER priority
        INTEGER attempts
        TEXT last_error
        VARCHAR status
        TIMESTAMP created_at
        TIMESTAMP updated_at
    }
    
    service_package_mappings {
        SERIAL id PK
        VARCHAR service_name UK
        VARCHAR package_name
        VARCHAR alpine_package
        VARCHAR rhel_package
        BOOLEAN is_valid
        TEXT description
        VARCHAR service_type
        TIMESTAMP created_at
        TIMESTAMP updated_at
    }
    
    tool_package_mappings {
        SERIAL id PK
        INTEGER tool_id FK
        VARCHAR tool_name
        VARCHAR package_name
        VARCHAR os_type
        VARCHAR category
        BOOLEAN is_active
        TIMESTAMP created_at
        TIMESTAMP updated_at
    }
    
    subnet_allocations {
        SERIAL id PK
        VARCHAR challenge_name
        VARCHAR user_id
        CIDR subnet UK
        INET gateway_ip
        INET attacker_ip
        INET victim_ip
        JSONB additional_ips
        TIMESTAMP allocated_at
        TIMESTAMP released_at
        BOOLEAN is_active
        TIMESTAMP created_at
        TIMESTAMP updated_at
    }
```

---

## Relationship Details

### **Core Relationships:**

1. **users → sessions** (1:N)
   - One user can have many sessions
   - `sessions.user_id` → `users.user_id` (ON DELETE CASCADE)

2. **users → challenges** (1:N)
   - One user can create many challenges
   - `challenges.user_id` → `users.user_id` (ON DELETE CASCADE)
   - **Critical**: Challenges are private to users

3. **users → challenge_submissions** (1:N)
   - One user can submit flags for many challenges
   - `challenge_submissions.user_id` → `users.user_id` (ON DELETE CASCADE)

4. **sessions → chat_messages** (1:N)
   - One session can have many chat messages
   - `chat_messages.session_id` → `sessions.session_id`

5. **sessions → session_guacamole_users** (1:1)
   - One session maps to one Guacamole user
   - `session_guacamole_users.session_id` → `sessions.session_id` (ON DELETE CASCADE)

6. **sessions → session_activity** (1:N)
   - One session can have many activity records
   - `session_activity.session_id` → `sessions.session_id` (ON DELETE CASCADE)

7. **sessions → pending_deployments** (1:1)
   - One session can have one pending deployment
   - `pending_deployments.session_id` → `sessions.session_id` (ON DELETE CASCADE)

8. **challenges → challenge_submissions** (1:N)
   - One challenge can receive many submissions
   - `challenge_submissions.challenge_id` → `challenges.challenge_id` (ON DELETE CASCADE)

9. **challenges → chat_messages** (1:N)
   - One challenge can be referenced in many chat messages
   - `chat_messages.challenge_id` → `challenges.challenge_id` (ON DELETE SET NULL)

### **CTF Automation Relationships:**

10. **validated_os_images → os_image_usage_history** (1:N)
    - One OS image can be used in many challenges
    - `os_image_usage_history.image_id` → `validated_os_images.id` (ON DELETE SET NULL)

11. **ctf_tools → tool_installation_methods** (1:N)
    - One tool can have many installation methods
    - `tool_installation_methods.tool_id` → `ctf_tools.id` (ON DELETE CASCADE)

12. **ctf_tools → tool_package_mappings** (1:N)
    - One tool can have many package mappings
    - `tool_package_mappings.tool_id` → `ctf_tools.id` (ON DELETE CASCADE)

---

## Key Constraints

### **Unique Constraints:**
- `users.username` - UNIQUE
- `users.email` - UNIQUE
- `challenges.slug` - UNIQUE
- `challenge_submissions(challenge_id, user_id)` - UNIQUE (one submission per user per challenge)
- `validated_os_images.image_name` - UNIQUE
- `os_image_validation_queue.image_name` - UNIQUE
- `ctf_tools.tool_name` - UNIQUE
- `service_package_mappings.service_name` - UNIQUE
- `subnet_allocations.subnet` - UNIQUE
- `subnet_allocations(challenge_name, user_id)` - UNIQUE

### **Foreign Key Constraints:**
- All foreign keys use `ON DELETE CASCADE` except:
  - `chat_messages.challenge_id` → `ON DELETE SET NULL`
  - `os_image_usage_history.image_id` → `ON DELETE SET NULL`

---

## Table Count Summary

**Total Tables: 18**

**Core Application (9):**
1. users
2. sessions
3. challenges
4. chat_messages
5. challenge_submissions
6. pending_deployments
7. session_guacamole_users
8. session_activity
9. user_activity_log

**CTF Automation (9):**
10. validated_os_images
11. os_image_usage_history
12. os_image_validation_queue
13. ctf_tools
14. tool_installation_methods
15. tool_learning_queue
16. service_package_mappings
17. tool_package_mappings
18. subnet_allocations

---

**Last Updated**: 2025-01-27  
**Database**: PostgreSQL  
**Status**: All tables in use

