# AI CTF Challenge Platform - Use Case Specifications (Table Format)

## Document Information

| **Field** | **Value** |
|-----------|-----------|
| **Project** | AI CTF Challenge Platform |
| **Document Version** | 2.0 |
| **Date** | 2025-01-27 |
| **Author** | System Analysis Team |
| **Status** | Final |
| **Format** | Table-Based Specifications |

---

## Table of Contents

1. [Introduction](#introduction)
2. [System Overview](#system-overview)
3. [Actors](#actors)
4. [Use Case Specifications](#use-case-specifications)
   - [UC1: Register Account](#uc1-register-account)
   - [UC2: Login to Platform](#uc2-login-to-platform)
   - [UC3: Logout from Platform](#uc3-logout-from-platform)
   - [UC4: View Dashboard](#uc4-view-dashboard)
   - [UC5: Create CTF Challenge](#uc5-create-ctf-challenge)
   - [UC6: Deploy CTF Challenge](#uc6-deploy-ctf-challenge)
   - [UC7: Access Challenge](#uc7-access-challenge)
   - [UC8: Chat with AI Assistant](#uc8-chat-with-ai-assistant)
   - [UC9: View Challenge Details](#uc9-view-challenge-details)
   - [UC10: Manage User Profile](#uc10-manage-user-profile)
   - [UC11: Browse Challenges](#uc11-browse-challenges)
5. [Use Case Relationships](#use-case-relationships)
6. [Glossary](#glossary)

---

## Introduction

This document provides detailed use case specifications for the AI CTF Challenge Platform in a professional table format. The platform enables users to create, deploy, and manage Capture The Flag (CTF) cybersecurity challenges using AI-powered automation.

### Purpose

| **Purpose** | **Description** |
|-------------|----------------|
| **Define Requirements** | Define all functional requirements from a user's perspective |
| **Specify Interactions** | Specify the interactions between actors and the system |
| **Document Flows** | Document the main flows, alternative flows, and exception handling |
| **Foundation for Design** | Provide a foundation for system design and testing |

### Scope

| **Scope Area** | **Coverage** |
|----------------|--------------|
| **User Authentication** | Account registration, login, logout, session management |
| **Challenge Management** | Challenge creation, deployment, access, and browsing |
| **AI Assistant** | Natural language interaction for all platform operations |
| **User Profile** | Profile management and user preferences |

---

## System Overview

| **Aspect** | **Description** |
|------------|-----------------|
| **Platform Type** | Web-based application |
| **Primary Function** | Automated creation and deployment of CTF challenges |
| **AI Services** | OpenAI GPT-4o and Anthropic Claude Sonnet 4 |
| **Containerization** | Docker for challenge environments |
| **Version Control** | GitHub for challenge file storage |
| **Remote Access** | Apache Guacamole for browser-based SSH/RDP access |

### Key Features

| **Feature** | **Description** |
|-------------|-----------------|
| **AI-Powered Challenge Creation** | Uses OpenAI GPT-4o and Anthropic Claude to generate complete CTF challenges |
| **Automated Deployment** | Builds and deploys Docker containers automatically |
| **Browser-Based Access** | Provides SSH/RDP access via Guacamole |
| **Chat Interface** | Natural language interaction for all operations |
| **User Management** | Secure authentication and profile management |

---

## Actors

| **Actor** | **Description** |
|-----------|-----------------|
| **User** | The main user of the AI CTF Challenge Platform who creates, deploys, and accesses CTF challenges. The user has a registered account with username, email, and password, uses a web browser to access the platform, interacts with AI assistant via chat interface, and accesses challenge environments via Guacamole. |

---

## Use Case Specifications

### UC1: Register Account

| **Field** | **Value/Description** |
|----------|----------------------|
| **Use Case ID** | UC1 |
| **Use Case** | Register Account |
| **Brief Description** | This use case allows a new user to create an account in the AI CTF Challenge Platform by providing personal information including username, email address, password, and full name. The system automatically assigns a random avatar to the user account. |
| **Actors** | User |
| **Preconditions** | User is not currently logged in; User has access to a valid email address; Platform registration is enabled; User has access to web browser |
| **Postconditions** | New user account is created in the system; User credentials are stored securely in database; User receives confirmation of successful registration; Authentication token is generated (but user is not automatically logged in); User is redirected to login page; User activity is logged |
| **Main Flow** | 1. User navigates to registration page<br>2. System displays registration form with fields: username, email, password, confirm password, full name (all required). Avatar is automatically generated randomly (not user-selectable)<br>3. User enters all required information and submits form<br>4. System validates input on client side: all fields required, username format (3-20 chars, alphanumeric/underscore), password strength (min 8 chars, uppercase, lowercase, number, special char), password match<br>5. System sends registration request to backend with user data and randomly generated avatar identifier<br>6. Backend validates: all fields required, email format, password strength, username/email uniqueness (case-insensitive)<br>7. System hashes password and stores user in database (verified status, lowercase username/email, random avatar)<br>8. System generates authentication token (7-day expiration) and logs registration activity<br>9. Backend returns success response with token and user information<br>10. Frontend stores token and user info in browser storage, displays success message, and redirects to login page after 1 second<br>11. User must manually log in to access platform |
| **Alternative Flows** | **A1: Input Validation Errors** - At step 4, if email format invalid, password weak, username/email already exists, or required fields missing, system displays error and highlights field(s). Flow returns to step 3.<br><br>**A2: Database/System Error** - At step 6-7, if database connection fails or system error occurs, system logs error and displays appropriate error message. Use case terminates. |

---

### UC2: Login to Platform

| **Field** | **Value/Description** |
|----------|----------------------|
| **Use Case ID** | UC2 |
| **Use Case** | Login to Platform |
| **Brief Description** | This use case allows an existing user to authenticate to the platform by providing their email address and password. Upon successful authentication, the system creates a session and provides access to platform features. |
| **Actors** | User |
| **Preconditions** | User has a registered account; User is not currently logged in; User has valid email and password credentials |
| **Postconditions** | User is authenticated; User session is created and stored; Authentication token is generated and provided to user; User has access to platform features; User activity is logged; Failed login attempts are reset; Last login and last active timestamps are updated |
| **Main Flow** | 1. User navigates to login page and enters email and password<br>2. System validates credentials are provided (client-side)<br>3. System sends login request to backend<br>4. Backend queries database for user account using email (lowercased)<br>5. If user not found, system returns error: "Invalid email or password"<br>6. Backend checks account status: if locked (locked until > current time), returns "Account is locked"; if inactive, returns "Account is inactive"<br>7. Backend compares password with stored hash<br>8. If password invalid, backend increments failed attempts. If attempts ≥ 4, locks account for 15 minutes. Returns error: "Invalid email or password"<br>9. If password valid, backend resets failed attempts, updates last login/active timestamps, generates authentication token (7-day expiration), creates secure session, sets session cookie, and logs activity<br>10. Backend returns success response with token, session ID, and user information<br>11. Frontend stores token and user info in browser storage, displays welcome message, and dashboard is automatically displayed |
| **Alternative Flows** | **A1: Missing/Invalid Credentials** - At step 2-3 or 5, if credentials missing, user not found, or password invalid, system displays error. Backend increments failed attempts (locks account if ≥ 4 attempts). Flow returns to step 1.<br><br>**A2: Account Issues** - At step 6, if account locked or inactive, backend returns appropriate error. Use case terminates.<br><br>**A3: Database/Network Error** - At step 4 or any database operation, if connection fails, system displays "Network error. Please try again." Use case terminates. |

---

### UC3: Logout from Platform

| **Field** | **Value/Description** |
|----------|----------------------|
| **Use Case ID** | UC3 |
| **Use Case** | Logout from Platform |
| **Brief Description** | This use case allows an authenticated user to end their session and log out from the platform, invalidating their current session and authentication token. |
| **Actors** | User |
| **Preconditions** | User is currently logged in; User has an active session; User has valid authentication token |
| **Postconditions** | User session is destroyed; Authentication token is invalidated; User is logged out; User is redirected to login page; User activity is logged |
| **Main Flow** | 1. User clicks logout button (no confirmation)<br>2. Frontend sends logout request to backend with authentication token<br>3. Backend validates token, destroys session record (if exists), clears session cookie, and logs activity<br>4. Backend returns success response<br>5. Frontend removes token and user info from browser storage, updates state to logged out, and displays login page |
| **Alternative Flows** | **A1: Session/Network Error** - At step 3 or 2, if session not found, database connection fails, or network error occurs, backend logs error but continues logout. Frontend continues with client-side logout (clears token). Flow continues to step 5. |

---

### UC4: View Dashboard

| **Field** | **Value/Description** |
|----------|----------------------|
| **Use Case ID** | UC4 |
| **Use Case** | View Dashboard |
| **Brief Description** | This use case allows a user to view the main dashboard which provides a welcome message and quick action buttons to navigate to different platform features. |
| **Actors** | User |
| **Preconditions** | User is logged in; User has valid session; User has valid authentication token |
| **Postconditions** | Dashboard is displayed with welcome message and quick actions; User can navigate to other platform features |
| **Main Flow** | 1. User navigates to dashboard (or is redirected after login)<br>2. System validates authentication token<br>3. System retrieves user information from database<br>4. System displays dashboard with: welcome message showing username ("Welcome back, [username]!"), description text ("Manage your AI-generated CTF challenges"), quick actions card containing three buttons: "Generate Challenge" (navigates to chat interface), "View All Challenges" (navigates to chat interface to browse challenges), "View Profile" (navigates to profile page)<br>5. User can click on quick action buttons to navigate to different sections |
| **Alternative Flows** | **A1: Authentication/Database Error** - At step 2-3, if authentication token invalid/expired or database connection fails, system redirects to login or displays error message. Use case terminates. |

---

### UC5: Create CTF Challenge

| **Field** | **Value/Description** |
|----------|----------------------|
| **Use Case ID** | UC5 |
| **Use Case** | Create CTF Challenge |
| **Brief Description** | This use case allows a user to request the AI system to create a new CTF challenge by describing their requirements through a chat interface. The system uses AI agents to generate challenge structure, content, Dockerfiles, and stores the challenge in a GitHub repository. |
| **Actors** | User |
| **Preconditions** | User is logged in; User has valid session; OpenAI and Anthropic API keys are configured; GitHub repository access is configured; User has access to chat interface |
| **Postconditions** | New CTF challenge is created; Challenge files are stored in GitHub repository; Challenge metadata.json file is stored in GitHub repository; User receives confirmation of challenge creation; Challenge is available for deployment |
| **Main Flow** | 1. User navigates to chat interface and enters challenge request (e.g., "Create an FTP challenge with weak credentials")<br>2. System saves message to chat history and forwards to CTF Automation Service<br>3. Classifier Agent identifies intent as challenge creation and routes to Create Agent<br>4. Create Agent uses AI services to design challenge: name, description, category, difficulty, vulnerability details, flag format<br>5. Create Agent generates Dockerfiles (victim and attacker/Kali machines), docker-compose file, README, setup scripts, and metadata.json file<br>6. Create Agent creates challenge directory structure, adds files to local Git repository, commits, and pushes to GitHub<br>7. System returns success message with challenge details and deployment suggestion<br>8. **Note**: Challenge stored in GitHub only. Database saving requires separate manual action |
| **Alternative Flows** | **A1: AI/API Service Issues** - At step 4, if AI API fails (retries max 3 attempts), validation fails (regeneration max 2 attempts), or rate limit exceeded, system displays error. Flow returns to step 1 or terminates.<br><br>**A2: GitHub/Request Issues** - At step 6 or 3-4, if GitHub push fails, intent unclear, or request too vague, system displays error/saves locally or asks for clarification. Flow returns to step 1. |

---

### UC6: Deploy CTF Challenge

| **Field** | **Value/Description** |
|----------|----------------------|
| **Use Case ID** | UC6 |
| **Use Case** | Deploy CTF Challenge |
| **Brief Description** | This use case allows a user to request deployment of an existing CTF challenge. The system clones the challenge from GitHub, validates the configuration, creates Docker containers, sets up network isolation, configures Guacamole access, and provides the user with access URL. |
| **Actors** | User |
| **Preconditions** | User is logged in; Challenge exists in GitHub repository; Docker Engine is running; Guacamole service is available; Challenge has valid docker-compose.yml file; User has valid session |
| **Postconditions** | Challenge containers are running; Challenge network is created and isolated; Guacamole connection is configured; User receives access URL and credentials; Challenge deployment status is updated in database; User can access challenge environment |
| **Main Flow** | 1. User requests deployment via chat (e.g., "Deploy challenge-name")<br>2. System saves message and forwards to CTF Automation Service<br>3. Classifier identifies intent as deployment and routes to Deploy Agent<br>4. Deploy Agent extracts challenge name from message or conversation history. If not found, lists available challenges and asks user to specify<br>5. Deploy Agent synchronizes GitHub repository and retrieves challenge metadata<br>6. If challenge not found, Deploy Agent returns error with available challenges list<br>7. Deploy Agent checks if already deployed. If yes and no force redeploy requested, suggests force redeploy option<br>8. If force redeploy, Deploy Agent cleans up existing containers<br>9. Deploy Agent validates challenge files and configuration<br>10. Deploy Agent allocates subnet (172.23.x.x/24), creates Docker network, builds and starts containers<br>11. Deploy Agent waits for containers to be healthy, retrieves IP addresses. If deployment fails, attempts automatic error fixing<br>12. Deploy Agent creates/retrieves session-based Guacamole user account, creates connection (container IP, SSH port 22, kali/kali credentials), grants permissions, and generates access URL<br>13. System displays deployment success with access URL, credentials, and connection instructions<br>14. **Note**: Deployment status not automatically updated in database |
| **Alternative Flows** | **A1: Challenge/Validation Issues** - At step 5-6 or 9, if challenge not found or validation fails, system displays error with available challenges list or detailed report. Pre-Deploy Validator attempts automatic fixes. Use case terminates.<br><br>**A2: Container/Deployment Issues** - At step 10-11, if build/startup fails or services not accessible, Deploy Agent analyzes logs, requests AI fixes, and retries (max 3 attempts). If fails, system displays error with logs. Use case terminates.<br><br>**A3: Network/Guacamole Failure** - At step 10 or 12, if network allocation fails or Guacamole connection creation fails (max 2 retries), system displays error. For Guacamole failure, provides container IPs for manual access. Use case terminates. |

---

### UC7: Access Challenge

| **Field** | **Value/Description** |
|----------|----------------------|
| **Use Case ID** | UC7 |
| **Use Case** | Access Challenge |
| **Brief Description** | This use case allows a user to access a deployed CTF challenge environment through browser-based SSH/RDP terminal provided by Guacamole. User can interact with attacker and victim containers to solve the challenge. |
| **Actors** | User |
| **Preconditions** | User is logged in; Challenge is deployed and running; Guacamole connection is configured; User has valid Guacamole access credentials; Containers are healthy and accessible |
| **Postconditions** | User has active terminal session; User can interact with challenge containers; Session is logged for security; User can perform challenge activities |
| **Main Flow** | 1. User clicks Guacamole access link from deployment message<br>2. Browser navigates to Guacamole web interface<br>3. User enters session-specific Guacamole credentials (username and password from deployment message)<br>4. Guacamole authenticates user and establishes SSH connection to attacker container (container IP, port 22, kali/kali credentials)<br>5. Guacamole displays terminal interface in browser (Kali Linux)<br>6. User interacts with terminal: executes commands, runs tools (nmap, metasploit), exploits vulnerabilities, accesses victim containers via network IPs<br>7. User performs challenge activities (scanning, exploitation, flag discovery) and completes or exits session<br>8. Guacamole logs connection activity<br>9. **Note**: Each session has unique Guacamole user account with access only to connections created during that session |
| **Alternative Flows** | **A1: Connection/Container Issues** - At step 4, if connection times out or container not running/accessible, system displays error. User can retry or redeploy. Flow returns to step 1 or terminates.<br><br>**A2: Credentials/Service Issues** - At step 3 or 2, if credentials invalid/expired or Guacamole service down, system displays error suggesting redeployment. Use case terminates.<br><br>**A3: Multiple Containers** - At step 5, if multiple containers exist, user can switch between them via Guacamole connection list. Flow continues normally. |

---

### UC8: Chat with AI Assistant

| **Field** | **Value/Description** |
|----------|----------------------|
| **Use Case ID** | UC8 |
| **Use Case** | Chat with AI Assistant |
| **Brief Description** | This use case allows a user to interact with AI assistant through a chat interface to create challenges, deploy challenges, ask questions about CTF concepts, or get assistance with challenge-related tasks. |
| **Actors** | User |
| **Preconditions** | User is logged in; OpenAI and Anthropic API keys are configured; Chat interface is available; User has valid session |
| **Postconditions** | Chat message is saved to database; AI response is generated and displayed; Chat history is updated; User receives assistance or action is performed |
| **Main Flow** | 1. User opens chat interface and types message<br>2. System loads previous chat history (if any) and saves user message to database<br>3. System forwards message to CTF Automation Service<br>4. Classifier Agent analyzes intent (Create, Deploy, Question, Challenge Info) and routes to appropriate agent<br>5. Agent processes request using AI services and formats response<br>6. System saves AI response to database and displays in chat interface<br>7. User can continue conversation. System maintains context for follow-up messages |
| **Alternative Flows** | **A1: Intent/API Issues** - At step 4-5, if intent unclear, rate limit exceeded, or API service down, Questions Agent asks for clarification or system displays error and queues for retry. Flow returns to step 1.<br><br>**A2: Context/Database Handling** - At step 3 or 2, if conversation history very long, system includes only last 10-15 messages. If database connection fails, system logs and continues (history saved later). Flow continues normally.<br><br>**A3: Challenge-Specific Questions** - At step 4, if user asks about specific challenge, Info Agent retrieves details from GitHub. Flow continues to step 5. |

---

### UC9: View Challenge Details

| **Field** | **Value/Description** |
|----------|----------------------|
| **Use Case ID** | UC9 |
| **Use Case** | View Challenge Details |
| **Brief Description** | This use case allows a user to view detailed information about a specific challenge by asking the AI assistant through the chat interface. The AI retrieves challenge details from the database and displays them in the chat. |
| **Actors** | User |
| **Preconditions** | User is logged in; Challenge exists in system (database or GitHub); User has access to challenge (owns the challenge); User has access to chat interface |
| **Postconditions** | Challenge details are displayed in chat interface; User can see challenge information; User can request actions on challenge (deploy, etc.) |
| **Main Flow** | 1. User navigates to chat interface and asks about specific challenge (e.g., "Show me details of [challenge name]")<br>2. System saves message and forwards to CTF Automation Service<br>3. Classifier identifies intent as challenge information and routes to Info Agent<br>4. Info Agent extracts challenge name from message or conversation history. If not found, lists available challenges and asks user to specify<br>5. Info Agent synchronizes GitHub repository and retrieves challenge metadata<br>6. If challenge not found, Info Agent returns error with available challenges list<br>7. Info Agent prepares safe metadata (hides flag value, shows flag format), uses AI to generate explanation, and formats challenge information<br>8. System displays challenge details in chat: challenge info, AI-generated explanation, deploy suggestion<br>9. User can view information and request actions (deploy, access, etc.)<br>10. **Note**: Challenge info retrieved from GitHub (metadata.json), not database. Only GitHub-stored challenges accessible |
| **Alternative Flows** | **A1: Challenge Not Found/Not Deployed** - At step 6, if challenge doesn't exist, Info Agent responds with error and suggests browsing. If challenge not deployed, system displays "Not Deployed" status and suggests deployment. Use case terminates or flow continues to step 8.<br><br>**A2: Ambiguous Name/GitHub Issues** - At step 4 or 5, if challenge name ambiguous/multiple matches or GitHub cannot be accessed, Info Agent asks for clarification or system displays error. Flow returns to step 1 or terminates. |

---

### UC10: Manage User Profile

| **Field** | **Value/Description** |
|----------|----------------------|
| **Use Case ID** | UC10 |
| **Use Case** | Manage User Profile |
| **Brief Description** | This use case allows a user to view and update their profile information including name, avatar, email, and password. |
| **Actors** | User |
| **Preconditions** | User is logged in; User has valid session; User has access to profile page |
| **Postconditions** | Profile information is updated (if changes made); Changes are saved to database; User sees updated profile information |
| **Main Flow** | 1. User navigates to profile page<br>2. System retrieves and displays current profile: username, email, name, bio (all editable), avatar (permanent), password change option<br>3. User clicks "Edit Profile" and edits fields (username, email, name, bio). Optionally enters passwords if changing password<br>4. User clicks save<br>5. System validates input: name and username required (min 3 chars), email format. If password change, validates current password, new password strength, and password match<br>6. System sends update request to backend with updated fields<br>7. Backend validates authorization, checks username/email conflicts (case-insensitive), and if password change requested: verifies current password, validates/hashes new password, updates password, invalidates other sessions<br>8. Backend updates profile fields in database (lowercased/trimmed username/email) and returns updated data<br>9. Frontend displays success message, refreshes data, and navigates back to profile page showing updated information |
| **Alternative Flows** | **A1: Password/Email Changes** - At step 3, if password changed, system verifies current password, validates/hashes new password, updates database, invalidates other sessions, and redirects to login. If email changed, validates format and checks conflicts. Flow ends or continues to step 7.<br><br>**A2: Validation Errors** - At step 5 or 3, if current password incorrect, new password weak, passwords don't match, or no changes made, system displays error or "No changes to save". Flow returns to step 3 or continues to step 7.<br><br>**A3: Database Error** - At step 2 or 7, if database connection fails, system displays error. Use case terminates. |

---

### UC11: Browse Challenges

| **Field** | **Value/Description** |
|----------|----------------------|
| **Use Case ID** | UC11 |
| **Use Case** | Browse Challenges |
| **Brief Description** | This use case allows a user to browse through available CTF challenges by asking the AI assistant through the chat interface. The user can request to see their challenges, and the AI will retrieve and display the list of challenges from the database. |
| **Actors** | User |
| **Preconditions** | User is logged in; User has valid session; User has access to chat interface |
| **Postconditions** | Challenge list is displayed in chat interface; User can see their challenges; User can request to view details or deploy specific challenges |
| **Main Flow** | 1. User navigates to chat interface and requests to browse challenges (e.g., "Show my challenges", "List challenges")<br>2. System saves message and forwards to CTF Automation Service<br>3. Classifier identifies intent as challenge information/browse and routes to Info/Questions Agent<br>4. Agent synchronizes GitHub repository and lists all challenges from repository<br>5. For each challenge, Agent optionally retrieves metadata (name, category, difficulty, description)<br>6. Agent formats challenge list information<br>7. System displays challenge list in chat: challenge names, count, suggestions to view details or deploy<br>8. User can view list and request specific actions<br>9. **Note**: Challenges listed from GitHub (not database). All repository challenges shown (not user-filtered since GitHub is shared) |
| **Alternative Flows** | **A1: No Challenges/GitHub Issues** - At step 4, if no challenges exist or GitHub cannot be accessed, Info Agent responds suggesting to create one or system displays error. Flow continues to step 7 or terminates.<br><br>**A2: Ambiguous Request** - At step 3, if intent unclear, Questions Agent asks for clarification. Flow returns to step 1. |

---

## Use Case Relationships

### Include Relationships (<<include>>)

| **Base Use Case** | **Included Use Case** | **Description** |
|-------------------|----------------------|-----------------|
| UC5: Create CTF Challenge | UC8: Chat with AI Assistant | Creating a challenge requires AI chat interaction |
| UC6: Deploy CTF Challenge | UC8: Chat with AI Assistant | Deploying a challenge requires AI chat interaction |
| UC6: Deploy CTF Challenge | UC7: Access Challenge | Deployment must provide access capability |

### Extend Relationships (<<extend>>)

| **Extending Use Case** | **Base Use Case** | **Description** |
|------------------------|-------------------|-----------------|
| UC9: View Challenge Details | UC5: Create CTF Challenge | After creating, user may view challenge details |
| UC9: View Challenge Details | UC6: Deploy CTF Challenge | After deploying, user may view challenge details |
| UC11: Browse Challenges | UC5: Create CTF Challenge | After creating, user may browse challenges |
| UC11: Browse Challenges | UC6: Deploy CTF Challenge | After deploying, user may browse challenges |
| UC8: Chat with AI Assistant | UC4: View Dashboard | Chat with AI Assistant can extend View Dashboard |
| UC8: Chat with AI Assistant | UC9: View Challenge Details | Chat with AI Assistant can extend View Challenge Details |
| UC8: Chat with AI Assistant | UC11: Browse Challenges | Chat with AI Assistant can extend Browse Challenges |

---

## Glossary

| **Term** | **Definition** |
|----------|---------------|
| **CTF (Capture The Flag)** | A cybersecurity competition where participants solve challenges to find hidden flags. |
| **Docker** | A platform for containerization that packages applications and dependencies into containers. |
| **Docker Compose** | A tool for defining and running multi-container Docker applications. |
| **Guacamole** | Apache Guacamole, a browser-based remote access gateway supporting SSH, RDP, and VNC. |
| **JWT (JSON Web Token)** | A compact, URL-safe token used for authentication and authorization. |
| **PostgreSQL** | An open-source relational database management system. |
| **GitHub Repository** | External version control service for storing challenge files. |
| **Challenge** | A CTF challenge consisting of vulnerable systems, flags, and solution instructions. |
| **Deployment** | The process of building and running challenge containers in an isolated environment. |
| **Session** | A user's active login session with associated JWT token and activity tracking. |
| **Flag** | A secret string (typically in format CTF{...}) that participants must find to solve a challenge. |
| **Victim Machine** | A containerized system with vulnerabilities for participants to exploit. |
| **Attacker Machine** | A containerized system (typically Kali Linux) with tools for participants to use. |
| **Network Isolation** | Docker networks that separate challenge environments from each other. |
| **Pre-Deployment Validation** | Validation of challenge files before container deployment. |
| **Post-Deployment Validation** | Validation of running containers and services after deployment. |

---

**Document End**

| **Field** | **Value** |
|-----------|-----------|
| **Last Updated** | 2025-01-27 |
| **Version** | 2.0 |
| **Status** | Final |
| **Format** | Table-Based Specifications |
