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
| **Brief Description** | This use case allows a new user to create an account in the AI CTF Challenge Platform by providing personal information including username, email address, password, and optional profile details such as name and avatar selection. |
| **Actors** | User |
| **Preconditions** | User is not currently logged in; User has access to a valid email address; Platform registration is enabled; User has access to web browser |
| **Postconditions** | New user account is created in the system; User credentials are stored securely in PostgreSQL database; User receives confirmation of successful registration; JWT token is generated and stored; User is automatically logged in and redirected to dashboard; User activity is logged |
| **Main Flow** | 1. User navigates to the registration page<br>2. System displays registration form with fields: username, email, password, name (optional), avatar (optional)<br>3. User enters username, email, password, and optional profile information<br>4. User submits registration form<br>5. System validates input data: email format, password strength (minimum 8 characters, uppercase, lowercase, number, special character), username uniqueness (case-insensitive), email uniqueness<br>6. System hashes password using bcryptjs (10 rounds)<br>7. System stores user information in PostgreSQL database (`users` table)<br>8. System generates JWT token with user information (expires in 7 days)<br>9. System creates user activity log entry<br>10. System displays success message: "Registration successful"<br>11. System returns JWT token to client<br>12. User is automatically logged in and redirected to dashboard |
| **Alternative Flows** | **A1: Invalid Email Format** - At step 5, if email format is invalid, system displays error message: "Please enter a valid email address" and highlights email field. Flow returns to step 3.<br><br>**A2: Weak Password** - At step 5, if password does not meet strength requirements, system displays detailed error message listing all password requirements. Flow returns to step 3.<br><br>**A3: Username Already Exists** - At step 5, if username is already taken (case-insensitive comparison), system displays error message: "Username '[username]' already exists" and highlights username field. Flow returns to step 3.<br><br>**A4: Email Already Registered** - At step 5, if email is already registered, system displays error message: "Email already exists" and highlights email field. Flow returns to step 3.<br><br>**A5: Missing Required Fields** - At step 4, if username, email, or password is missing, system displays error message: "Username, email, and password are required" and highlights missing fields. Flow returns to step 3.<br><br>**A6: Database Connection Failure** - At step 7, if database connection fails, system logs error and displays error message: "Registration temporarily unavailable. Please try again later." Use case terminates.<br><br>**A7: System Error** - At any step, if unexpected system error occurs, system logs error with details and displays generic error message: "An error occurred. Please try again." Use case terminates. |

---

### UC2: Login to Platform

| **Field** | **Value/Description** |
|----------|----------------------|
| **Use Case ID** | UC2 |
| **Use Case** | Login to Platform |
| **Brief Description** | This use case allows an existing user to authenticate to the platform by providing their email address and password. Upon successful authentication, the system creates a session and provides access to platform features. |
| **Actors** | User |
| **Preconditions** | User has a registered account; User is not currently logged in; User has valid email and password credentials |
| **Postconditions** | User is authenticated; User session is created and stored; JWT token is generated and provided to user; User has access to platform features; User activity is logged; Guacamole user account is created (if doesn't exist) |
| **Main Flow** | 1. User navigates to login page<br>2. System displays login form with fields: email, password<br>3. User enters email address and password<br>4. User submits login form<br>5. System validates input format (email format, non-empty password)<br>6. System queries PostgreSQL database for user account using email<br>7. System retrieves user record including password_hash<br>8. System compares provided password with stored hash using bcryptjs<br>9. System verifies account is active and not locked<br>10. System generates JWT token with user information (user_id, username, email, role)<br>11. System creates session record in database<br>12. System creates Guacamole user if it doesn't exist<br>13. System stores JWT token in user's browser (localStorage or cookie)<br>14. System logs user activity (login event with IP address)<br>15. System redirects user to dashboard<br>16. System displays welcome message |
| **Alternative Flows** | **A1: Invalid Credentials** - At step 8, if password does not match stored hash, system increments failed login attempts counter and displays error message: "Invalid email or password". If failed attempts >= 5, system locks account for 15 minutes. Flow returns to step 3.<br><br>**A2: Account Locked** - At step 9, if account is locked due to too many failed login attempts, system displays error message: "Account is locked due to multiple failed login attempts. Please try again in 15 minutes." Use case terminates.<br><br>**A3: Account Inactive** - At step 9, if account is inactive (is_verified = false), system displays error message: "Account is inactive. Please contact administrator." Use case terminates.<br><br>**A4: User Not Found** - At step 6, if no user found with provided email, system displays error message: "Invalid email or password" (for security, same message as wrong password). Flow returns to step 3.<br><br>**A5: Missing Credentials** - At step 4, if email or password is missing, system displays error message: "Email and password are required" and highlights missing fields. Flow returns to step 3.<br><br>**A6: Database Connection Failure** - At step 6, if database connection fails, system logs error and displays error message: "Login temporarily unavailable. Please try again later." Use case terminates. |

---

### UC3: Logout from Platform

| **Field** | **Value/Description** |
|----------|----------------------|
| **Use Case ID** | UC3 |
| **Use Case** | Logout from Platform |
| **Brief Description** | This use case allows an authenticated user to end their session and log out from the platform, invalidating their current session and JWT token. |
| **Actors** | User |
| **Preconditions** | User is currently logged in; User has an active session; User has valid JWT token |
| **Postconditions** | User session is destroyed; JWT token is invalidated; User is logged out; User is redirected to login page; User activity is logged |
| **Main Flow** | 1. User clicks logout button (in navigation menu or profile dropdown)<br>2. System prompts user for confirmation (optional, can be automatic)<br>3. User confirms logout (or automatic if no confirmation required)<br>4. System invalidates JWT token<br>5. System destroys session record in database<br>6. System clears session cookie/localStorage<br>7. System logs user activity (logout event with IP address)<br>8. System redirects user to login page<br>9. System displays logout confirmation message: "You have been logged out successfully" |
| **Alternative Flows** | **A1: User Cancels Logout** - At step 3, if user cancels logout confirmation, system returns user to previous page. Use case terminates.<br><br>**A2: Session Not Found** - At step 5, if session record not found in database, system logs warning (non-critical) and continues with logout process. Flow continues to step 6.<br><br>**A3: Database Connection Failure** - At step 5, if database connection fails, system logs error and continues with client-side logout (clear token). Flow continues to step 6. |

---

### UC4: View Dashboard

| **Field** | **Value/Description** |
|----------|----------------------|
| **Use Case ID** | UC4 |
| **Use Case** | View Dashboard |
| **Brief Description** | This use case allows a user to view the main dashboard which provides a welcome message and quick action buttons to navigate to different platform features. |
| **Actors** | User |
| **Preconditions** | User is logged in; User has valid session; User has valid JWT token |
| **Postconditions** | Dashboard is displayed with welcome message and quick actions; User can navigate to other platform features |
| **Main Flow** | 1. User navigates to dashboard (or is redirected after login)<br>2. System validates JWT token<br>3. System retrieves user information from database<br>4. System displays dashboard with: welcome message showing username ("Welcome back, [username]!"), description text ("Manage your AI-generated CTF challenges"), quick actions card containing three buttons: "Generate Challenge" (navigates to chat interface), "View All Challenges" (navigates to chat interface to browse challenges), "View Profile" (navigates to profile page)<br>5. User can click on quick action buttons to navigate to different sections |
| **Alternative Flows** | **A1: Database Connection Failure** - At step 3, if database connection fails, system displays error message: "Unable to load dashboard. Please refresh the page." Use case terminates.<br><br>**A2: Invalid JWT Token** - At step 2, if JWT token is invalid or expired, system redirects user to login page and displays message: "Your session has expired. Please login again." Use case terminates. |

---

### UC5: Create CTF Challenge

| **Field** | **Value/Description** |
|----------|----------------------|
| **Use Case ID** | UC5 |
| **Use Case** | Create CTF Challenge |
| **Brief Description** | This use case allows a user to request the AI system to create a new CTF challenge by describing their requirements through a chat interface. The system uses AI agents to generate challenge structure, content, Dockerfiles, and stores the challenge in a GitHub repository. |
| **Actors** | User |
| **Preconditions** | User is logged in; User has valid session; OpenAI and Anthropic API keys are configured; GitHub repository access is configured; User has access to chat interface |
| **Postconditions** | New CTF challenge is created; Challenge files are stored in GitHub repository; Challenge metadata is stored in PostgreSQL database (if user saves); Challenge is associated with user_id; User receives confirmation of challenge creation |
| **Main Flow** | 1. User navigates to challenge creation interface (chat interface)<br>2. User enters challenge request in chat (e.g., "Create an FTP challenge with weak credentials" or "I want a web exploitation challenge")<br>3. User submits message<br>4. System saves user message to chat history in database<br>5. System forwards request to CTF Automation Service<br>6. Classifier Agent analyzes request and identifies intent as "CREATE"<br>7. System routes request to Create Agent<br>8. Create Agent sends request to OpenAI API (GPT-4o) to generate challenge structure: challenge name and description, category (Web, Crypto, Forensics, etc.), difficulty level, vulnerability details, flag format<br>9. OpenAI API returns challenge structure and content<br>10. Create Agent sends structure to Anthropic API (Claude Sonnet 4) for validation<br>11. Anthropic API validates challenge design and returns validation results<br>12. If validation passes, Create Agent generates Dockerfiles for all machines: victim machine Dockerfile, attacker machine Dockerfile (if needed)<br>13. Create Agent creates challenge directory structure: challenge root directory, subdirectories for each machine, configuration files<br>14. Create Agent generates docker-compose.yml file<br>15. Create Agent generates README.md with challenge description<br>16. Create Agent generates setup scripts<br>17. Create Agent commits files to local Git repository<br>18. Create Agent pushes challenge files to GitHub repository<br>19. GitHub confirms successful push<br>20. Create Agent stores challenge metadata in PostgreSQL (if user chooses to save)<br>21. System returns success message to user: "Challenge [name] has been created successfully!"<br>22. System displays challenge creation confirmation with details: challenge name, category, difficulty, repository URL, next steps (deploy or save) |
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
| **Main Flow** | 1. User requests challenge deployment via chat (e.g., "Deploy challenge-name" or "Deploy my FTP challenge")<br>2. System saves user message to chat history<br>3. System forwards request to CTF Automation Service<br>4. Classifier Agent identifies intent as "DEPLOY"<br>5. System routes request to Deploy Agent<br>6. Deploy Agent retrieves challenge metadata from PostgreSQL (if saved) or identifies challenge from GitHub<br>7. Deploy Agent clones challenge repository from GitHub<br>8. GitHub returns challenge files including docker-compose.yml, Dockerfiles, and configuration files<br>9. Deploy Agent calls Pre-Deploy Validator Agent for validation<br>10. Pre-Deploy Validator Agent validates Dockerfiles and docker-compose.yml: syntax validation, structure validation, dependency checking, uses Anthropic API for intelligent validation<br>11. Pre-Deploy Validator Agent returns validation results<br>12. If validation passes, Deploy Agent allocates subnet and IP addresses for challenge network (172.23.x.x/24)<br>13. Deploy Agent creates Docker network using Docker API with allocated subnet<br>14. Docker Engine creates isolated network<br>15. Deploy Agent executes `docker compose up --build` command<br>16. Docker Engine builds container images<br>17. Docker Engine starts containers and attaches to network<br>18. Deploy Agent waits for containers to be healthy (health check)<br>19. Deploy Agent calls Post-Deploy Validator Agent for validation<br>20. Post-Deploy Validator Agent tests container services and connectivity<br>21. Post-Deploy Validator Agent returns validation results<br>22. If validation passes, Deploy Agent creates Guacamole user if needed<br>23. Deploy Agent creates Guacamole connection in MySQL database<br>24. Deploy Agent configures Guacamole connection parameters: hostname (container IP), port (SSH: 22, RDP: 3389), protocol (SSH or RDP), username and password<br>25. Guacamole service creates connection<br>26. Deploy Agent updates challenge deployment status in PostgreSQL (is_deployed = true)<br>27. System returns Guacamole access URL to user<br>28. System displays deployment success message with: access URL, username, password, connection instructions, challenge details |
| **Alternative Flows** | **A1: Challenge Not Found** - At step 6-7, if challenge doesn't exist in database or GitHub, system displays error message: "Challenge not found. Please create the challenge first." Use case terminates.<br><br>**A2: Pre-Deployment Validation Failure** - At step 10-11, if validation fails, Pre-Deploy Validator Agent attempts to fix errors automatically using AI. If fixes successful, flow continues to step 12. If fixes fail, system displays error message: "Challenge validation failed. Please fix the errors and try again." System provides detailed error report. Use case terminates.<br><br>**A3: Container Build Failure** - At step 16, if container build fails, Deploy Agent analyzes error logs, requests OpenAI for error fix suggestions, and attempts to fix and rebuild (max 3 attempts). If all attempts fail, system displays error message: "Container build failed. Please check the Dockerfiles." System provides error logs. Use case terminates.<br><br>**A4: Container Startup Failure** - At step 17-18, if containers fail to start or become unhealthy, Deploy Agent checks container logs and restarts containers. If still fails, system displays error message: "Containers failed to start. Please check the configuration." System provides container logs. Use case terminates.<br><br>**A5: Post-Deployment Validation Failure** - At step 19-21, if services are not accessible or validation fails, Post-Deploy Validator Agent identifies issues. Deploy Agent fixes startup scripts and restarts containers. Flow returns to step 19. If fixes fail after 3 attempts, system displays error message: "Challenge deployment validation failed." Use case terminates.<br><br>**A6: Network Allocation Failure** - At step 12, if no available subnet can be allocated, system displays error message: "No available network space. Please contact administrator." Use case terminates.<br><br>**A7: Guacamole Connection Failure** - At step 22-25, if Guacamole connection creation fails, system retries connection creation (max 2 attempts). If still fails, system displays error message: "Failed to create access connection. Containers are running but access is unavailable." System provides container IP addresses for manual access. Use case terminates. |

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
| **Main Flow** | 1. User clicks on challenge access link (Guacamole URL) from deployment confirmation<br>2. System retrieves Guacamole connection URL from database<br>3. System redirects user to Guacamole web interface<br>4. Guacamole authenticates user session (uses session credentials)<br>5. Guacamole establishes SSH connection to attacker container (or victim container)<br>6. Guacamole displays terminal interface in browser<br>7. User interacts with terminal: executes commands, performs file operations, runs scanning tools, exploits vulnerabilities<br>8. User can switch between attacker and victim containers (if multiple connections available)<br>9. User performs challenge activities: network scanning, vulnerability exploitation, flag discovery, solution verification<br>10. User completes challenge or exits terminal<br>11. System logs session activity (optional, for security auditing) |
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
| **Main Flow** | 1. User opens chat interface (from dashboard or challenge page)<br>2. System loads previous chat history (if any)<br>3. User types message in chat input<br>4. User submits message<br>5. System saves user message to PostgreSQL database (chat_history table)<br>6. System forwards message to CTF Automation Service<br>7. Classifier Agent analyzes message intent: CREATE (Create challenge request), DEPLOY (Deploy challenge request), QUESTION (General question about CTF), CHALLENGE_INFO (Information about existing challenge)<br>8. System routes to appropriate agent: Create Agent (for CREATE), Deploy Agent (for DEPLOY), Questions Agent (for QUESTION), ChallengeInfo Agent (for CHALLENGE_INFO)<br>9. Agent processes request using OpenAI or Anthropic API<br>10. AI API returns response<br>11. Agent formats response appropriately<br>12. System saves AI response to database<br>13. System displays response in chat interface<br>14. User can continue conversation<br>15. System maintains conversation context for follow-up messages |
| **Alternative Flows** | **A1: Ambiguous Intent** - At step 7, if intent is unclear or ambiguous, Questions Agent asks user for clarification. System displays: "Could you clarify what you'd like to do? (e.g., create a challenge, deploy a challenge, ask a question)" Flow returns to step 3.<br><br>**A2: API Rate Limit** - At step 9-10, if API rate limit exceeded, system displays message: "AI service busy. Please try again in a moment." System queues request for retry. Flow returns to step 3.<br><br>**A3: Long Conversation Context** - At step 6, if conversation history is very long, system includes only last 10-15 messages in context. Older messages are excluded to stay within token limits. Flow continues normally.<br><br>**A4: Challenge-Specific Questions** - At step 7, if user asks about specific challenge, ChallengeInfo Agent retrieves challenge details from database and provides context-aware response. Flow continues to step 9.<br><br>**A5: API Service Unavailable** - At step 9, if API service is down, system displays error message: "AI service temporarily unavailable. Please try again later." Use case terminates.<br><br>**A6: Database Connection Failure** - At step 5 or 12, if database connection fails, system logs error and continues with chat (history can be saved later). Flow continues to step 13. |

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
| **Main Flow** | 1. User navigates to chat interface<br>2. User asks about a specific challenge (e.g., "Show me details of [challenge name]", "What is the status of my FTP challenge?")<br>3. User submits message<br>4. System saves user message to chat history in database<br>5. System forwards request to CTF Automation Service<br>6. Classifier Agent analyzes message and identifies intent as "CHALLENGE_INFO"<br>7. System routes request to ChallengeInfo Agent<br>8. ChallengeInfo Agent queries PostgreSQL database for challenge metadata using challenge name or ID<br>9. System retrieves challenge details from database: challenge name, description, category, difficulty, creation date, deployment status<br>10. If challenge is deployed, system retrieves access URL and Guacamole credentials<br>11. ChallengeInfo Agent formats challenge information<br>12. System displays challenge details in chat interface<br>13. User can view information and request actions (deploy, access, etc.) |
| **Alternative Flows** | **A1: Challenge Not Found** - At step 9, if challenge doesn't exist, ChallengeInfo Agent responds: "Challenge not found. Would you like to see all your challenges?" System suggests browsing challenges. Use case terminates.<br><br>**A2: Challenge Not Deployed** - At step 10, if challenge is not deployed, system displays "Not Deployed" status. Access URL and credentials are not shown. System suggests deploying the challenge. Flow continues to step 12.<br><br>**A3: Ambiguous Challenge Name** - At step 8, if challenge name is ambiguous or multiple matches found, ChallengeInfo Agent asks user to clarify: "I found multiple challenges. Which one did you mean? [list options]" Flow returns to step 2.<br><br>**A4: Database Connection Failure** - At step 8, if database connection fails, system displays error message: "Unable to load challenge details. Please try again later." Use case terminates. |

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
| **Main Flow** | 1. User navigates to profile page (from navigation menu)<br>2. System retrieves user profile from PostgreSQL<br>3. System displays current profile information: username (read-only), email, name, avatar selection, password change option<br>4. User edits profile fields (name, avatar, email)<br>5. User saves changes<br>6. System validates input: email format validation, name length validation<br>7. System updates profile in database<br>8. System displays success message: "Profile updated successfully"<br>9. Profile page refreshes with updated information |
| **Alternative Flows** | **A1: Change Password** - At step 4, if user chooses to change password, system displays password change form: current password field, new password field, confirm new password field. User enters current password and new password. User submits password change. System verifies current password. System validates new password strength (same requirements as registration). System hashes new password using bcryptjs. System updates password in database. System invalidates all other sessions (security measure). System displays success message: "Password changed successfully. Please login again." System redirects user to login page. Flow ends.<br><br>**A2: Change Email** - At step 4, if user changes email, system validates email format and checks if email is already registered. If email exists, system displays error: "Email already registered". If email is new, system updates email in database and displays success message. Flow continues to step 8.<br><br>**A3: Invalid Current Password** - At step A1.5, if current password is incorrect, system displays error: "Current password is incorrect" and password change form remains open. Flow returns to step A1.4.<br><br>**A4: Weak New Password** - At step A1.6, if new password doesn't meet requirements, system displays detailed password requirements. Flow returns to step A1.4.<br><br>**A5: Password Mismatch** - At step A1.4, if new password and confirm password don't match, system displays error: "Passwords do not match". Flow returns to step A1.4.<br><br>**A6: No Changes Made** - At step 5, if user clicks save without making changes, system displays message: "No changes to save". Flow continues to step 8.<br><br>**A7: Database Connection Failure** - At step 2 or 7, if database connection fails, system displays error message: "Unable to update profile. Please try again later." Use case terminates. |

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
| **Main Flow** | 1. User navigates to chat interface (from dashboard "View All Challenges" button or sidebar "Generate Challenge" menu)<br>2. User types message requesting to browse challenges (e.g., "Show my challenges", "List all my challenges", "What challenges do I have?")<br>3. User submits message<br>4. System saves user message to chat history in database<br>5. System forwards request to CTF Automation Service<br>6. Classifier Agent analyzes message and identifies intent as "CHALLENGE_INFO" or "BROWSE"<br>7. System routes request to ChallengeInfo Agent<br>8. ChallengeInfo Agent queries PostgreSQL database for challenges filtered by user_id<br>9. System retrieves challenge list from database<br>10. ChallengeInfo Agent formats challenge information<br>11. System displays challenge list in chat interface showing: challenge name, category, difficulty, creation date, deployment status<br>12. User can view the list and request specific actions (view details, deploy, etc.) |
| **Alternative Flows** | **A1: No Challenges Available** - At step 9, if user has no challenges, ChallengeInfo Agent responds: "You don't have any challenges yet. Would you like to create one?" System suggests creating a new challenge. Flow continues to step 11.<br><br>**A2: Database Connection Failure** - At step 8, if database connection fails, system displays error message: "Unable to retrieve challenges. Please try again later." Use case terminates.<br><br>**A3: Ambiguous Request** - At step 6, if intent is unclear, Questions Agent asks user for clarification: "Would you like to see all your challenges, or are you looking for a specific challenge?" Flow returns to step 2. |

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
