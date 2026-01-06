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
| **Main Flow** | 1. User navigates to the registration page<br>2. System displays registration form with fields: username (required), email (required), password (required), name/full name (required), confirm password (required). Avatar is automatically generated randomly by the system (not displayed in form, not user-selectable)<br>3. User enters username, email, password, confirm password, and full name<br>4. User submits registration form<br>5. System validates input on client side: all fields are required (username, email, password, confirm password, name); username format (3-20 characters, letters, numbers, underscores only); password strength (minimum 8 characters, uppercase, lowercase, number, special character); password match validation<br>6. System sends registration request to backend server with username, email, password, name, and randomly generated avatar identifier<br>7. Backend server validates input data: username, email, password, name are required; email format validation; password strength validation (minimum 8 characters, uppercase, lowercase, number, special character); username uniqueness check (case-insensitive, trimmed); email uniqueness check<br>8. System hashes password using secure password hashing algorithm with 10 rounds<br>9. System stores user information in database with account verified status set to true, username stored in lowercase, email stored in lowercase, name stored as provided, avatar identifier set to randomly generated value<br>10. System generates authentication token with user information (expires in 7 days)<br>11. System creates user activity log entry for registration event<br>12. Backend server returns response indicating success, registration message, authentication token, and user information<br>13. Frontend receives response and stores authentication token in browser storage<br>14. Frontend stores user information in browser storage<br>15. Frontend displays success message: "🎉 Account created successfully! Please log in."<br>16. After 1 second delay, frontend automatically redirects user to login page<br>17. User must manually log in to access the platform |
| **Alternative Flows** | **A1: Invalid Email Format** - At step 5, if email format is invalid, system displays error message: "Please enter a valid email address" and highlights email field. Flow returns to step 3.<br><br>**A2: Weak Password** - At step 5, if password does not meet strength requirements, system displays detailed error message listing all password requirements. Flow returns to step 3.<br><br>**A3: Username Already Exists** - At step 5 or 7, if username is already taken (case-insensitive comparison), system displays error message: "Username '[username]' already exists" and highlights username field. Flow returns to step 3.<br><br>**A4: Email Already Registered** - At step 5 or 7, if email is already registered, system displays error message: "Email already exists" and highlights email field. Flow returns to step 3.<br><br>**A5: Missing Required Fields** - At step 4 or 5, if username, email, password, confirm password, or name is missing, system displays error message: "Please fill in all fields" and highlights missing fields. Flow returns to step 3.<br><br>**A6: Database Connection Failure** - At step 7, if database connection fails, system logs error and displays error message: "Registration temporarily unavailable. Please try again later." Use case terminates.<br><br>**A7: System Error** - At any step, if unexpected system error occurs, system logs error with details and displays generic error message: "An error occurred. Please try again." Use case terminates. |

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
| **Main Flow** | 1. User navigates to login page<br>2. System displays login form with fields: email, password<br>3. User enters email address and password<br>4. User submits login form<br>5. System validates that both email and password are provided (client-side validation)<br>6. System sends login request to backend server with email and password<br>7. Backend server validates that both email and password are provided<br>8. Backend server queries database for user account using email (email is lowercased for lookup)<br>9. If user not found, system returns error: "Invalid email or password"<br>10. Backend server retrieves user record including: user identifier, username, email, password hash, name, avatar identifier, role, account active status, account locked until timestamp, failed login attempts count<br>11. Backend server checks if account is locked (locked until timestamp is greater than current time). If locked, returns error: "Account is locked. Please try again later."<br>12. Backend server checks if account is active. If inactive, returns error: "Account is inactive"<br>13. Backend server compares provided password with stored password hash using secure password comparison<br>14. If password is invalid, backend server increments failed login attempts counter. If failed login attempts is 4 or more, sets account locked until timestamp to 15 minutes from now. Returns error: "Invalid email or password"<br>15. If password is valid, backend server resets failed login attempts to zero, updates last login timestamp to current time, and updates last active timestamp to current time<br>16. Backend server generates authentication token with user information (user identifier, username, email, role) with expiration of 7 days<br>17. Backend server creates secure session record in database with user identifier, IP address, and browser information<br>18. Backend server sets secure session cookie in response<br>19. Backend server logs user activity (login event with IP address) in activity log<br>20. Backend server returns response indicating success, authentication token, session identifier, and user information (user identifier, username, email, name, avatar, role)<br>21. Frontend receives response and stores authentication token in browser storage<br>22. Frontend stores user information in browser storage<br>23. Frontend displays success message: "Welcome back, [user name]!"<br>24. Frontend updates application state to indicate user is logged in<br>25. Application automatically displays dashboard (no explicit redirect needed) |
| **Alternative Flows** | **A1: Missing Credentials (Client-side)** - At step 5, if email or password is missing, system displays error message: "Please enter both email and password". Flow returns to step 3.<br><br>**A2: Missing Credentials (Server-side)** - At step 7, if email or password is missing in request, backend server returns error: "Email and password are required" with bad request status. System displays error. Flow returns to step 3.<br><br>**A3: User Not Found** - At step 9, if no user found with provided email, backend server returns error: "Invalid email or password" with unauthorized status (for security, same message as wrong password). System displays error message. Flow returns to step 3.<br><br>**A4: Account Locked** - At step 11, if account is locked (locked until timestamp is greater than current time), backend server returns error: "Account is locked. Please try again later." with forbidden status. System displays error message. Use case terminates.<br><br>**A5: Account Inactive** - At step 12, if account is inactive, backend server returns error: "Account is inactive" with forbidden status. System displays error message. Use case terminates.<br><br>**A6: Invalid Password** - At step 14, if password does not match stored hash, backend server increments failed login attempts counter. If failed login attempts is 4 or more, backend server sets account locked until timestamp to 15 minutes from now. Backend server returns error: "Invalid email or password" with unauthorized status. System displays error message. Flow returns to step 3.<br><br>**A7: Database Connection Failure** - At step 8 or any database operation, if database connection fails, backend server logs error and returns error message with server error status. System displays error message: "Network error. Please try again." Use case terminates. |

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
| **Main Flow** | 1. User clicks logout button in sidebar (no confirmation dialog)<br>2. Frontend initiates logout process<br>3. Frontend retrieves authentication token from browser storage<br>4. Frontend sends logout request to backend server with authentication token in request header<br>5. Backend server validates authentication token<br>6. Backend server retrieves session identifier from cookies or request body<br>7. If session identifier exists, backend server destroys session record in database<br>8. Backend server clears session cookie in response<br>9. Backend server logs user activity (logout event with IP address) in activity log<br>10. Backend server returns response indicating success and logout message<br>11. Frontend receives response (or handles error if request fails)<br>12. Frontend removes authentication token from browser storage (clears both authentication token and user information)<br>13. Frontend updates application state to indicate user is logged out<br>14. Frontend updates application state to show login page<br>15. Application automatically displays login page (no explicit redirect message shown) |
| **Alternative Flows** | **A1: No Session Identifier** - At step 6, if session identifier is not found in cookies or request body, backend server continues with logout process (non-critical). Flow continues to step 9.<br><br>**A2: Session Not Found** - At step 7, if session record not found in database, backend server continues with logout process (non-critical). Flow continues to step 9.<br><br>**A3: Database Connection Failure** - At step 7 or 9, if database connection fails, backend server logs error but still returns success response. Frontend continues with client-side logout (clear token). Flow continues to step 12.<br><br>**A4: Network Error** - At step 4, if network request fails, frontend still removes token from browser storage and updates application state to indicate user is logged out. User is logged out on client side. Flow continues to step 12. |

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
| **Alternative Flows** | **A1: Database Connection Failure** - At step 3, if database connection fails, system displays error message: "Unable to load dashboard. Please refresh the page." Use case terminates.<br><br>**A2: Invalid Authentication Token** - At step 2, if authentication token is invalid or expired, system redirects user to login page and displays message: "Your session has expired. Please login again." Use case terminates. |

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
| **Main Flow** | 1. User navigates to challenge creation interface (chat interface)<br>2. User enters challenge request in chat (e.g., "Create an FTP challenge with weak credentials" or "I want a web exploitation challenge")<br>3. User submits message<br>4. System saves user message to chat history in database<br>5. System forwards request to CTF Automation Service<br>6. Classifier Agent analyzes request and identifies intent as challenge creation<br>7. System routes request to Create Agent<br>8. Create Agent uses AI services to design challenge structure: challenge name and description, category (Web, Crypto, Forensics, etc.), difficulty level, vulnerability details, flag format<br>9. Create Agent generates Dockerfiles for all machines: victim machine Dockerfile, attacker machine Dockerfile (Kali Linux with tools)<br>10. Create Agent creates challenge directory structure in local repository: challenge root directory, subdirectories for each machine, configuration files<br>11. Create Agent generates docker-compose configuration file with network configuration<br>12. Create Agent generates README file with complete challenge description<br>13. Create Agent generates setup scripts and configuration files<br>14. Create Agent generates metadata file containing challenge metadata (name, description, category, difficulty, flag format, hints)<br>15. Create Agent adds all files to local Git repository<br>16. Create Agent commits files to local Git repository<br>17. Create Agent pushes challenge files to GitHub repository<br>18. GitHub confirms successful push<br>19. System returns success message to user: "Challenge [name] has been created successfully!"<br>20. System displays challenge creation confirmation with details: challenge name, category, difficulty, next steps (deploy command suggestion)<br>21. **Note**: Challenge is stored in GitHub repository only. To save challenge metadata to database, user must perform a separate manual action (not part of this use case) |
| **Alternative Flows** | **A1: AI Generation Failure** - At step 8-9, if OpenAI API fails or returns error, system retries API call (max 3 attempts with exponential backoff). If all retries fail, system displays error message: "AI service temporarily unavailable. Please try again." Flow returns to step 2.<br><br>**A2: Validation Failure** - At step 10-11, if Anthropic validation fails or suggests major changes, Create Agent requests OpenAI to regenerate content based on validation feedback. Flow returns to step 8. If regeneration fails after 2 attempts, system displays error message. Use case terminates.<br><br>**A3: GitHub Push Failure** - At step 18-19, if GitHub push fails (network error, authentication error), system displays error message: "Failed to store challenge in repository. Please check your GitHub configuration." System saves challenge locally. Flow returns to step 2.<br><br>**A4: Ambiguous Request** - At step 6, if Classifier Agent cannot determine clear intent, Questions Agent asks user for clarification. System displays: "Could you provide more details about the challenge you want to create? (e.g., category, difficulty, type of vulnerability)" Flow returns to step 2.<br><br>**A5: Invalid Challenge Requirements** - At step 8, if user request is too vague or impossible, system asks clarifying questions via chat. Flow returns to step 2.<br><br>**A6: API Rate Limit Exceeded** - At step 8 or 10, if API rate limit is exceeded, system displays error message: "AI service rate limit exceeded. Please try again in a few minutes." Use case terminates. |

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
| **Main Flow** | 1. User requests challenge deployment via chat (e.g., "Deploy challenge-name" or "Deploy my FTP challenge")<br>2. System saves user message to chat history<br>3. System forwards request to CTF Automation Service<br>4. Classifier Agent identifies intent as challenge deployment<br>5. System routes request to Deploy Agent<br>6. Deploy Agent extracts challenge name from user message or searches recent conversation history<br>7. If challenge name not found, Deploy Agent lists available challenges from GitHub and asks user to specify<br>8. Deploy Agent ensures GitHub repository is synchronized (pulls latest changes)<br>9. Deploy Agent retrieves challenge metadata from GitHub repository (reads metadata file from challenge directory)<br>10. If challenge not found in GitHub, Deploy Agent returns error with list of available challenges<br>11. Deploy Agent checks if challenge is already deployed<br>12. If already deployed and user didn't request force redeploy, Deploy Agent suggests force redeploy option<br>13. If force redeploy requested, Deploy Agent cleans up existing containers<br>14. Deploy Agent validates challenge files and configuration<br>15. If validation passes, Deploy Agent allocates subnet and IP addresses for challenge network (172.23.x.x/24)<br>16. Deploy Agent creates Docker network with allocated subnet<br>17. Docker Engine creates isolated network<br>18. Deploy Agent executes docker compose build and start commands<br>19. Docker Engine builds container images<br>20. Docker Engine starts containers and attaches to network<br>21. Deploy Agent waits for containers to be healthy and retrieves container IP addresses<br>22. If deployment fails, Deploy Agent attempts automatic error fixing with retry logic<br>23. Deploy Agent creates or retrieves session-based Guacamole user account (unique per user session)<br>24. Deploy Agent creates Guacamole connection in database with connection parameters: hostname (container IP), port (SSH: 22), protocol (SSH), username (kali), password (kali)<br>25. Deploy Agent grants connection permissions to session user<br>26. Deploy Agent generates Guacamole access URL (session-specific)<br>27. System returns Guacamole access URL to user<br>28. System displays deployment success message with: access URL (clickable link), username, password, connection instructions, challenge details<br>29. **Note**: Challenge deployment status is not automatically updated in database. If challenge was previously saved to database, deployment status update would require separate manual action |
| **Alternative Flows** | **A1: Challenge Not Found** - At step 9-10, if challenge doesn't exist in GitHub repository, system displays error message: "Challenge not found. Please create the challenge first." System provides list of available challenges. Use case terminates.<br><br>**A2: Pre-Deployment Validation Failure** - At step 10-11, if validation fails, Pre-Deploy Validator Agent attempts to fix errors automatically using AI. If fixes successful, flow continues to step 12. If fixes fail, system displays error message: "Challenge validation failed. Please fix the errors and try again." System provides detailed error report. Use case terminates.<br><br>**A3: Container Build Failure** - At step 16, if container build fails, Deploy Agent analyzes error logs, requests OpenAI for error fix suggestions, and attempts to fix and rebuild (max 3 attempts). If all attempts fail, system displays error message: "Container build failed. Please check the Dockerfiles." System provides error logs. Use case terminates.<br><br>**A4: Container Startup Failure** - At step 17-18, if containers fail to start or become unhealthy, Deploy Agent checks container logs and restarts containers. If still fails, system displays error message: "Containers failed to start. Please check the configuration." System provides container logs. Use case terminates.<br><br>**A5: Post-Deployment Validation Failure** - At step 19-21, if services are not accessible or validation fails, Post-Deploy Validator Agent identifies issues. Deploy Agent fixes startup scripts and restarts containers. Flow returns to step 19. If fixes fail after 3 attempts, system displays error message: "Challenge deployment validation failed." Use case terminates.<br><br>**A6: Network Allocation Failure** - At step 12, if no available subnet can be allocated, system displays error message: "No available network space. Please contact administrator." Use case terminates.<br><br>**A7: Guacamole Connection Failure** - At step 22-25, if Guacamole connection creation fails, system retries connection creation (max 2 attempts). If still fails, system displays error message: "Failed to create access connection. Containers are running but access is unavailable." System provides container IP addresses for manual access. Use case terminates. |

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
| **Main Flow** | 1. User clicks on challenge access link (Guacamole URL) from deployment confirmation message in chat interface<br>2. Browser navigates to Guacamole web interface URL<br>3. Guacamole web interface loads and displays login page<br>4. User enters Guacamole credentials: username (session-specific, format based on session identifier) and password (provided in deployment message)<br>5. User submits login form<br>6. Guacamole authenticates user against database<br>7. If authentication successful, Guacamole establishes SSH connection to attacker container using connection parameters: hostname (container IP on challenge network), port (22 for SSH), protocol (SSH), username (kali), password (kali)<br>8. Guacamole displays terminal interface in browser (Kali Linux desktop or SSH terminal)<br>9. User interacts with terminal: executes commands, performs file operations, runs scanning tools (nmap, metasploit, etc.), exploits vulnerabilities<br>10. User can access victim containers from attacker container using their IP addresses on the challenge network<br>11. User performs challenge activities: network scanning, vulnerability exploitation, flag discovery, solution verification<br>12. User completes challenge or exits terminal session<br>13. Guacamole logs connection activity (stored in database)<br>14. **Note**: Each user session has a unique Guacamole user account with access only to connections created during that session |
| **Alternative Flows** | **A1: Connection Timeout** - At step 5, if connection times out, system displays error message: "Connection timeout. Please try again." User can retry connection. Flow returns to step 1.<br><br>**A2: Container Unavailable** - At step 5, if container is not running or not accessible, system displays error message: "Challenge environment unavailable. The containers may have stopped. Please redeploy the challenge." Use case terminates.<br><br>**A3: Invalid Credentials** - At step 4, if Guacamole credentials are invalid or expired, system displays error message: "Access credentials expired. Please redeploy the challenge." Use case terminates.<br><br>**A4: Multiple Container Access** - At step 8, if challenge has multiple containers (attacker + victims), user can switch between containers using Guacamole connection list. Each container has separate connection. Flow continues normally.<br><br>**A5: Guacamole Service Unavailable** - At step 3, if Guacamole service is down, system displays error message: "Access service unavailable. Please try again later." Use case terminates. |

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
| **Main Flow** | 1. User opens chat interface (from dashboard or challenge page)<br>2. System loads previous chat history (if any)<br>3. User types message in chat input<br>4. User submits message<br>5. System saves user message to database in chat history<br>6. System forwards message to CTF Automation Service<br>7. Classifier Agent analyzes message intent: Create challenge request, Deploy challenge request, General question about CTF, Information about existing challenge<br>8. System routes to appropriate agent: Create Agent (for challenge creation), Deploy Agent (for challenge deployment), Questions Agent (for general questions), Info Agent (for challenge information)<br>9. Agent processes request using AI services<br>10. AI service returns response<br>11. Agent formats response appropriately<br>12. System saves AI response to database<br>13. System displays response in chat interface<br>14. User can continue conversation<br>15. System maintains conversation context for follow-up messages |
| **Alternative Flows** | **A1: Ambiguous Intent** - At step 7, if intent is unclear or ambiguous, Questions Agent asks user for clarification. System displays: "Could you clarify what you'd like to do? (e.g., create a challenge, deploy a challenge, ask a question)" Flow returns to step 3.<br><br>**A2: API Rate Limit** - At step 9-10, if API rate limit exceeded, system displays message: "AI service busy. Please try again in a moment." System queues request for retry. Flow returns to step 3.<br><br>**A3: Long Conversation Context** - At step 6, if conversation history is very long, system includes only last 10-15 messages in context. Older messages are excluded to stay within token limits. Flow continues normally.<br><br>**A4: Challenge-Specific Questions** - At step 7, if user asks about specific challenge, Info Agent retrieves challenge details from GitHub repository and provides context-aware response. Flow continues to step 9.<br><br>**A5: API Service Unavailable** - At step 9, if API service is down, system displays error message: "AI service temporarily unavailable. Please try again later." Use case terminates.<br><br>**A6: Database Connection Failure** - At step 5 or 12, if database connection fails, system logs error and continues with chat (history can be saved later). Flow continues to step 13. |

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
| **Main Flow** | 1. User navigates to chat interface<br>2. User asks about a specific challenge (e.g., "Show me details of [challenge name]", "What is the status of my FTP challenge?", "Tell me about challenge-name")<br>3. User submits message<br>4. System saves user message to chat history in database<br>5. System forwards request to CTF Automation Service<br>6. Classifier Agent analyzes message and identifies intent as challenge information request<br>7. System routes request to Info Agent<br>8. Info Agent extracts challenge name from user message or searches conversation history for recently created/deployed challenges<br>9. If challenge name not found, Info Agent lists available challenges from GitHub and asks user to specify<br>10. Info Agent ensures GitHub repository is synchronized<br>11. Info Agent retrieves challenge metadata from GitHub repository (reads metadata file from challenge directory)<br>12. If challenge not found in GitHub, Info Agent returns error with list of available challenges<br>13. Info Agent prepares safe metadata (hides flag value, only shows flag format)<br>14. Info Agent uses AI service to generate helpful explanation about the challenge<br>15. AI service returns formatted explanation<br>16. Info Agent formats challenge information with explanation<br>17. System displays challenge details in chat interface: challenge information, formatted explanation, deploy command suggestion<br>18. User can view information and request actions (deploy, access, etc.)<br>19. **Note**: Challenge information is retrieved from GitHub repository (metadata file), not from database. Only challenges stored in GitHub are accessible |
| **Alternative Flows** | **A1: Challenge Not Found** - At step 12, if challenge doesn't exist in GitHub repository, Info Agent responds: "Challenge not found. Would you like to see all available challenges?" System suggests browsing challenges. Use case terminates.<br><br>**A2: Challenge Not Deployed** - If challenge is not deployed, system displays "Not Deployed" status. Access URL and credentials are not shown. System suggests deploying the challenge. Flow continues to step 17.<br><br>**A3: Ambiguous Challenge Name** - At step 8, if challenge name is ambiguous or multiple matches found, Info Agent asks user to clarify: "I found multiple challenges. Which one did you mean? [list options]" Flow returns to step 2.<br><br>**A4: GitHub Repository Connection Failure** - At step 10, if GitHub repository cannot be accessed, system displays error message: "Unable to load challenge details. Please try again later." Use case terminates. |

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
| **Main Flow** | 1. User navigates to profile page (from navigation menu)<br>2. System retrieves user profile from backend server<br>3. System displays current profile information: username (editable), email (editable), name (editable), bio (editable), avatar (permanent, cannot be changed), password change option<br>4. User clicks "Edit Profile" button to navigate to edit profile page<br>5. User edits profile fields: username, email, name, bio (avatar cannot be changed)<br>6. User optionally enters current password, new password, and confirm password if changing password<br>7. User clicks save button<br>8. System validates input on client side: full name is required, username is required (minimum 3 characters), email format validation<br>9. If password change is requested, system validates on client side: current password is required, new password strength (same requirements as registration), passwords match<br>10. System sends update request to backend server with updated fields and user identifier<br>11. Backend server validates authorization (user can only update own profile unless administrator)<br>12. If username is being updated, backend server checks for conflicts (case-insensitive, excluding current user)<br>13. If email is being updated, backend server checks for conflicts (case-insensitive, excluding current user)<br>14. If password change is requested, backend server verifies current password, validates new password strength, hashes new password, updates password in database, and invalidates all other user sessions<br>15. Backend server updates profile fields in database: name, username (lowercased, trimmed), email (lowercased, trimmed), bio, avatar identifier (if provided), GitHub username, Twitter handle, website URL<br>16. Backend server returns updated user data<br>17. Frontend displays success message: "Profile updated successfully!"<br>18. Frontend refreshes user data from server<br>19. After brief delay, frontend navigates back to profile page<br>20. Profile page refreshes and displays updated information |
| **Alternative Flows** | **A1: Change Password** - At step 4, if user chooses to change password, system displays password change form: current password field, new password field, confirm new password field. User enters current password and new password. User submits password change. System verifies current password. System validates new password strength (same requirements as registration). System hashes new password using secure password hashing algorithm. System updates password in database. System invalidates all other sessions (security measure). System displays success message: "Password changed successfully. Please login again." System redirects user to login page. Flow ends.<br><br>**A2: Change Email** - At step 4, if user changes email, system validates email format and checks if email is already registered. If email exists, system displays error: "Email already registered". If email is new, system updates email in database and displays success message. Flow continues to step 8.<br><br>**A3: Invalid Current Password** - At step A1.5, if current password is incorrect, system displays error: "Current password is incorrect" and password change form remains open. Flow returns to step A1.4.<br><br>**A4: Weak New Password** - At step A1.6, if new password doesn't meet requirements, system displays detailed password requirements. Flow returns to step A1.4.<br><br>**A5: Password Mismatch** - At step A1.4, if new password and confirm password don't match, system displays error: "Passwords do not match". Flow returns to step A1.4.<br><br>**A6: No Changes Made** - At step 5, if user clicks save without making changes, system displays message: "No changes to save". Flow continues to step 8.<br><br>**A7: Database Connection Failure** - At step 2 or 7, if database connection fails, system displays error message: "Unable to update profile. Please try again later." Use case terminates. |

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
| **Main Flow** | 1. User navigates to chat interface (from dashboard "View All Challenges" button or sidebar "Generate Challenge" menu)<br>2. User types message requesting to browse challenges (e.g., "Show my challenges", "List all my challenges", "What challenges do I have?", "List challenges")<br>3. User submits message<br>4. System saves user message to chat history in database<br>5. System forwards request to CTF Automation Service<br>6. Classifier Agent analyzes message and identifies intent as challenge information or browse request<br>7. System routes request to Info Agent or Questions Agent depending on classifier output<br>8. Agent ensures GitHub repository is synchronized<br>9. Agent lists all challenges from GitHub repository (reads challenges directory)<br>10. System retrieves challenge list from GitHub repository (all challenges in the repository)<br>11. For each challenge, Agent optionally retrieves metadata to get additional information: challenge name, category, difficulty, description<br>12. Agent formats challenge list information<br>13. System displays challenge list in chat interface showing: challenge names, available challenges count, suggestion to view details or deploy specific challenges<br>14. User can view the list and request specific actions (view details, deploy, etc.)<br>15. **Note**: Challenges are listed from GitHub repository, not from database. All challenges in the GitHub repository are shown (not filtered by user since GitHub is a shared repository) |
| **Alternative Flows** | **A1: No Challenges Available** - At step 10, if no challenges exist in GitHub repository, Info Agent responds: "No challenges found. Would you like to create one?" System suggests creating a new challenge. Flow continues to step 13.<br><br>**A2: GitHub Repository Connection Failure** - At step 8, if GitHub repository cannot be accessed, system displays error message: "Unable to retrieve challenges. Please try again later." Use case terminates.<br><br>**A3: Ambiguous Request** - At step 6, if intent is unclear, Questions Agent asks user for clarification: "Would you like to see all available challenges, or are you looking for a specific challenge?" Flow returns to step 2. |

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
