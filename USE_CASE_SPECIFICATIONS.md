# AI CTF Challenge Platform - Use Case Specifications

## Document Information

**Project**: AI CTF Challenge Platform  
**Document Version**: 1.0  
**Date**: 2025-01-27  
**Author**: System Analysis Team  
**Status**: Final

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
   - [UC7: Access Challenge Environment](#uc7-access-challenge-environment)
   - [UC8: Chat with AI Assistant](#uc8-chat-with-ai-assistant)
   - [UC9: View Challenge Details](#uc9-view-challenge-details)
   - [UC10: Manage User Profile](#uc10-manage-user-profile)
   - [UC11: Browse Challenges](#uc11-browse-challenges)
5. [Use Case Relationships](#use-case-relationships)
6. [Glossary](#glossary)

---

## Introduction

This document provides detailed use case specifications for the AI CTF Challenge Platform. The platform enables users to create, deploy, and manage Capture The Flag (CTF) cybersecurity challenges using AI-powered automation.

### Purpose

The purpose of this document is to:
- Define all functional requirements from a user's perspective
- Specify the interactions between actors and the system
- Document the main flows, alternative flows, and exception handling
- Provide a foundation for system design and testing

### Scope

This document covers all primary use cases for the AI CTF Challenge Platform, including:
- User authentication and account management
- Challenge creation and deployment
- AI assistant interactions
- Challenge access and management

### Document Conventions

- **Use Case ID**: UC1, UC2, UC3, etc.
- **Actors**: Primary actors (User) and Secondary actors (External systems)
- **Flows**: Main Success Scenario, Alternative Flows, Exception Flows
- **Relationships**: Include (<<include>>) and Extend (<<extend>>)

---

## System Overview

The AI CTF Challenge Platform is a web-based application that automates the creation and deployment of CTF challenges. The system uses AI (OpenAI and Anthropic APIs) to generate challenge content, Docker for containerization, GitHub for version control, and Guacamole for browser-based terminal access.

### Key Features

- **AI-Powered Challenge Creation**: Uses OpenAI GPT-4o and Anthropic Claude to generate complete CTF challenges
- **Automated Deployment**: Builds and deploys Docker containers automatically
- **Browser-Based Access**: Provides SSH/RDP access via Guacamole
- **Chat Interface**: Natural language interaction for all operations
- **User Management**: Secure authentication and profile management

---

## Actors

### Primary Actor

**User**
- **Description**: The main user of the AI CTF Challenge Platform who creates, deploys, and accesses CTF challenges
- **Characteristics**:
  - Has registered account with username, email, and password
  - Uses web browser to access platform
  - Interacts with AI assistant via chat interface
  - Accesses challenge environments via Guacamole
  - Can create, deploy, and manage challenges

### Secondary Actors

**OpenAI API**
- **Description**: External AI service providing GPT-4o for challenge content generation, request classification, and error analysis
- **Role**: Provides AI-powered content generation and assistance
- **Interactions**: Used by Create CTF Challenge and Chat with AI Assistant use cases

**Anthropic API**
- **Description**: External AI service providing Claude Sonnet 4 for challenge validation, design, and error resolution
- **Role**: Provides AI-powered validation and analysis
- **Interactions**: Used by Create CTF Challenge and Chat with AI Assistant use cases

**GitHub Repository**
- **Description**: External version control service storing challenge files and configurations
- **Role**: Stores and manages challenge repositories
- **Interactions**: Used by Create CTF Challenge and Deploy CTF Challenge use cases

**Guacamole Service**
- **Description**: Browser-based remote access service providing SSH/RDP access to challenge containers
- **Role**: Enables secure browser-based terminal access
- **Interactions**: Used by Deploy CTF Challenge and Access Challenge Environment use cases

---

## Use Case Specifications

### UC1: Register Account

**Use Case ID**: UC1  
**Use Case Name**: Register Account  
**Actors**: User  
**Priority**: High  
**Type**: Primary Use Case  
**Status**: Implemented

#### Description

A new user creates an account in the AI CTF Challenge Platform by providing personal information including username, email address, password, and optional profile details such as name and avatar selection.

#### Goal

Allow a new user to create an account on the platform to access CTF challenge creation and deployment features.

#### Preconditions

- User is not currently logged in
- User has access to a valid email address
- Platform registration is enabled
- User has access to web browser

#### Postconditions

- New user account is created in the system
- User credentials are stored securely in PostgreSQL database
- User receives confirmation of successful registration
- JWT token is generated and stored
- User can proceed to login
- User activity is logged

#### Main Success Scenario

1. User navigates to the registration page
2. System displays registration form with fields: username, email, password, name (optional), avatar (optional)
3. User enters username, email, password, and optional profile information
4. User submits registration form
5. System validates input data:
   - Email format validation
   - Password strength validation (minimum 8 characters, uppercase, lowercase, number, special character)
   - Username uniqueness check (case-insensitive)
   - Email uniqueness check
6. System hashes password using bcryptjs (10 rounds)
7. System stores user information in PostgreSQL database (`users` table)
8. System generates JWT token with user information (expires in 7 days)
9. System creates user activity log entry
10. System displays success message: "Registration successful"
11. System returns JWT token to client
12. User is automatically logged in and redirected to dashboard

#### Alternative Flows

**A1: Invalid Email Format**
- At step 5, if email format is invalid
- System displays error message: "Please enter a valid email address"
- System highlights email field
- Flow returns to step 3

**A2: Weak Password**
- At step 5, if password does not meet strength requirements
- System displays detailed error message listing all password requirements:
  - "Password must be at least 8 characters long"
  - "Password must contain at least one uppercase letter"
  - "Password must contain at least one lowercase letter"
  - "Password must contain at least one number"
  - "Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)"
- System highlights password field
- Flow returns to step 3

**A3: Username Already Exists**
- At step 5, if username is already taken (case-insensitive comparison)
- System displays error message: "Username '[username]' already exists"
- System highlights username field
- Flow returns to step 3

**A4: Email Already Registered**
- At step 5, if email is already registered
- System displays error message: "Email already exists"
- System highlights email field
- Flow returns to step 3

**A5: Missing Required Fields**
- At step 4, if username, email, or password is missing
- System displays error message: "Username, email, and password are required"
- System highlights missing fields
- Flow returns to step 3

#### Exception Flows

**E1: Database Connection Failure**
- At step 7, if database connection fails
- System logs error
- System displays error message: "Registration temporarily unavailable. Please try again later."
- Use case terminates

**E2: System Error**
- At any step, if unexpected system error occurs
- System logs error with details
- System displays generic error message: "An error occurred. Please try again."
- Use case terminates

**E3: JWT Token Generation Failure**
- At step 8, if JWT token generation fails
- System logs error
- System displays error message: "Registration successful, but login failed. Please login manually."
- Use case continues to step 10 (user must login manually)

#### Special Requirements

- Password must be hashed using bcryptjs with 10 salt rounds
- Username and email must be normalized (lowercase, trimmed) before storage
- JWT token must include: user_id, username, email, role
- JWT token expiration: 7 days
- User activity must be logged with IP address

#### Related Use Cases

- **UC2: Login to Platform** - User must register before logging in

---

### UC2: Login to Platform

**Use Case ID**: UC2  
**Use Case Name**: Login to Platform  
**Actors**: User  
**Priority**: High  
**Type**: Primary Use Case  
**Status**: Implemented

#### Description

An existing user authenticates to the platform by providing their email address and password. Upon successful authentication, the system creates a session and provides access to platform features.

#### Goal

Allow a registered user to authenticate and gain access to the platform's features.

#### Preconditions

- User has a registered account
- User is not currently logged in
- User has valid email and password credentials

#### Postconditions

- User is authenticated
- User session is created and stored
- JWT token is generated and provided to user
- User has access to platform features
- User activity is logged
- Guacamole user account is created (if doesn't exist)

#### Main Success Scenario

1. User navigates to login page
2. System displays login form with fields: email, password
3. User enters email address and password
4. User submits login form
5. System validates input format (email format, non-empty password)
6. System queries PostgreSQL database for user account using email
7. System retrieves user record including password_hash
8. System compares provided password with stored hash using bcryptjs
9. System verifies account is active and not locked
10. System generates JWT token with user information (user_id, username, email, role)
11. System creates session record in database
12. System creates Guacamole user if it doesn't exist
13. System stores JWT token in user's browser (localStorage or cookie)
14. System logs user activity (login event with IP address)
15. System redirects user to dashboard
16. System displays welcome message

#### Alternative Flows

**A1: Invalid Credentials**
- At step 8, if password does not match stored hash
- System increments failed login attempts counter
- System displays error message: "Invalid email or password"
- If failed attempts >= 5, system locks account for 15 minutes
- Flow returns to step 3

**A2: Account Locked**
- At step 9, if account is locked due to too many failed login attempts
- System displays error message: "Account is locked due to multiple failed login attempts. Please try again in 15 minutes."
- Use case terminates

**A3: Account Inactive**
- At step 9, if account is inactive (is_verified = false)
- System displays error message: "Account is inactive. Please contact administrator."
- Use case terminates

**A4: User Not Found**
- At step 6, if no user found with provided email
- System displays error message: "Invalid email or password" (for security, same message as wrong password)
- Flow returns to step 3

**A5: Missing Credentials**
- At step 4, if email or password is missing
- System displays error message: "Email and password are required"
- System highlights missing fields
- Flow returns to step 3

#### Exception Flows

**E1: Database Connection Failure**
- At step 6, if database connection fails
- System logs error
- System displays error message: "Login temporarily unavailable. Please try again later."
- Use case terminates

**E2: JWT Token Generation Failure**
- At step 10, if JWT token generation fails
- System logs error
- System displays error message: "Authentication failed. Please try again."
- Use case terminates

**E3: Guacamole Service Unavailable**
- At step 12, if Guacamole service is unavailable
- System logs warning (non-critical)
- System continues with login (Guacamole user creation can be deferred)
- Flow continues to step 13

#### Special Requirements

- Password comparison must use bcryptjs.compare()
- Failed login attempts must be tracked and limited (max 5 attempts, 15-minute lockout)
- JWT token must include: user_id, username, email, role
- JWT token expiration: 7 days
- Session must be stored in database for tracking
- User activity must be logged with IP address

#### Related Use Cases

- **UC1: Register Account** - User must have registered account to login (include relationship)
- **UC4: View Dashboard** - User is redirected to dashboard after login

---

### UC3: Logout from Platform

**Use Case ID**: UC3  
**Use Case Name**: Logout from Platform  
**Actors**: User  
**Priority**: Medium  
**Type**: Primary Use Case  
**Status**: Implemented

#### Description

An authenticated user ends their session and logs out from the platform, invalidating their current session and JWT token.

#### Goal

Allow an authenticated user to securely end their session and log out from the platform.

#### Preconditions

- User is currently logged in
- User has an active session
- User has valid JWT token

#### Postconditions

- User session is destroyed
- JWT token is invalidated
- User is logged out
- User is redirected to login page
- User activity is logged

#### Main Success Scenario

1. User clicks logout button (in navigation menu or profile dropdown)
2. System prompts user for confirmation (optional, can be automatic)
3. User confirms logout (or automatic if no confirmation required)
4. System invalidates JWT token
5. System destroys session record in database
6. System clears session cookie/localStorage
7. System logs user activity (logout event with IP address)
8. System redirects user to login page
9. System displays logout confirmation message: "You have been logged out successfully"

#### Alternative Flows

**A1: User Cancels Logout**
- At step 3, if user cancels logout confirmation
- System returns user to previous page
- Use case terminates

#### Exception Flows

**E1: Session Not Found**
- At step 5, if session record not found in database
- System logs warning (non-critical)
- System continues with logout process
- Flow continues to step 6

**E2: Database Connection Failure**
- At step 5, if database connection fails
- System logs error
- System continues with client-side logout (clear token)
- Flow continues to step 6

#### Special Requirements

- JWT token must be removed from client storage
- Session record should be deleted from database
- User activity must be logged

---

### UC4: View Dashboard

**Use Case ID**: UC4  
**Use Case Name**: View Dashboard  
**Actors**: User  
**Priority**: High  
**Type**: Primary Use Case  
**Status**: Implemented

#### Description

User views the main dashboard which provides an overview of the platform including recent challenges, statistics, quick actions, and navigation to different sections.

#### Goal

Provide user with an overview of their platform activity and quick access to main features.

#### Preconditions

- User is logged in
- User has valid session
- User has valid JWT token

#### Postconditions

- Dashboard is displayed with current information
- User can navigate to other platform features
- User sees their challenge statistics

#### Main Success Scenario

1. User navigates to dashboard (or is redirected after login)
2. System validates JWT token
3. System retrieves user information from database
4. System retrieves user's challenge statistics:
   - Total challenges created
   - Total challenges deployed
   - Recent challenges
5. System retrieves recent chat history (last 5-10 messages)
6. System retrieves list of user's available challenges (filtered by user_id)
7. System displays dashboard with:
   - User profile summary
   - Challenge statistics
   - Recent challenges list
   - Quick action buttons (Create Challenge, Browse Challenges)
   - Navigation menu
8. User can interact with dashboard elements

#### Alternative Flows

**A1: No Challenges Available**
- At step 6, if user has no challenges
- System displays empty state with message: "No challenges yet. Create your first challenge!"
- System displays "Create Challenge" button prominently
- Flow continues to step 7

**A2: No Chat History**
- At step 5, if user has no chat history
- System displays empty chat history section
- Flow continues to step 7

#### Exception Flows

**E1: Database Connection Failure**
- At step 3, if database connection fails
- System displays error message: "Unable to load dashboard. Please refresh the page."
- Use case terminates

**E2: Invalid JWT Token**
- At step 2, if JWT token is invalid or expired
- System redirects user to login page
- System displays message: "Your session has expired. Please login again."
- Use case terminates

#### Special Requirements

- Dashboard must load within 2 seconds
- Challenge statistics must be accurate and up-to-date
- Recent challenges should be sorted by creation date (newest first)

---

### UC5: Create CTF Challenge

**Use Case ID**: UC5  
**Use Case Name**: Create CTF Challenge  
**Actors**: User, OpenAI API, Anthropic API, GitHub Repository  
**Priority**: High  
**Type**: Primary Use Case  
**Status**: Implemented

#### Description

User requests the AI system to create a new CTF challenge by describing their requirements through a chat interface. The system uses AI agents to generate challenge structure, content, Dockerfiles, and stores the challenge in a GitHub repository.

#### Goal

Enable user to create a complete CTF challenge using AI-powered automation through natural language interaction.

#### Preconditions

- User is logged in
- User has valid session
- OpenAI and Anthropic API keys are configured
- GitHub repository access is configured
- User has access to chat interface

#### Postconditions

- New CTF challenge is created
- Challenge files are stored in GitHub repository
- Challenge metadata is stored in PostgreSQL database (if user saves)
- Challenge is associated with user_id
- User receives confirmation of challenge creation

#### Main Success Scenario

1. User navigates to challenge creation interface (chat interface)
2. User enters challenge request in chat (e.g., "Create an FTP challenge with weak credentials" or "I want a web exploitation challenge")
3. User submits message
4. System saves user message to chat history in database
5. System forwards request to CTF Automation Service
6. Classifier Agent analyzes request and identifies intent as "CREATE"
7. System routes request to Create Agent
8. Create Agent sends request to OpenAI API (GPT-4o) to generate challenge structure:
   - Challenge name and description
   - Category (Web, Crypto, Forensics, etc.)
   - Difficulty level
   - Vulnerability details
   - Flag format
9. OpenAI API returns challenge structure and content
10. Create Agent sends structure to Anthropic API (Claude Sonnet 4) for validation
11. Anthropic API validates challenge design and returns validation results
12. If validation passes, Create Agent generates Dockerfiles for all machines:
    - Victim machine Dockerfile
    - Attacker machine Dockerfile (if needed)
13. Create Agent creates challenge directory structure:
    - Challenge root directory
    - Subdirectories for each machine
    - Configuration files
14. Create Agent generates docker-compose.yml file
15. Create Agent generates README.md with challenge description
16. Create Agent generates setup scripts
17. Create Agent commits files to local Git repository
18. Create Agent pushes challenge files to GitHub repository
19. GitHub confirms successful push
20. Create Agent stores challenge metadata in PostgreSQL (if user chooses to save)
21. System returns success message to user: "Challenge [name] has been created successfully!"
22. System displays challenge creation confirmation with details:
    - Challenge name
    - Category
    - Difficulty
    - Repository URL
    - Next steps (deploy or save)

#### Include Relationships

- **UC8: Chat with AI Assistant** - Challenge creation requires AI chat interaction (mandatory)
- Challenge creation process includes:
  - AI content generation (via OpenAI)
  - Challenge validation (via Anthropic)
  - File storage (via GitHub)

#### Extend Relationships

- **UC11: Browse Challenges** - User may browse challenges after creation (optional)
- **UC9: View Challenge Details** - User may view challenge details after creation (optional)

#### Alternative Flows

**A1: AI Generation Failure**
- At step 8-9, if OpenAI API fails or returns error
- System retries API call (max 3 attempts with exponential backoff)
- If all retries fail, system displays error message: "AI service temporarily unavailable. Please try again."
- Flow returns to step 2

**A2: Validation Failure**
- At step 10-11, if Anthropic validation fails or suggests major changes
- Create Agent requests OpenAI to regenerate content based on validation feedback
- Flow returns to step 8
- If regeneration fails after 2 attempts, system displays error message
- Use case terminates

**A3: GitHub Push Failure**
- At step 18-19, if GitHub push fails (network error, authentication error)
- System displays error message: "Failed to store challenge in repository. Please check your GitHub configuration."
- System saves challenge locally
- Flow returns to step 2

**A4: Ambiguous Request**
- At step 6, if Classifier Agent cannot determine clear intent
- Questions Agent asks user for clarification
- System displays: "Could you provide more details about the challenge you want to create? (e.g., category, difficulty, type of vulnerability)"
- Flow returns to step 2

**A5: Invalid Challenge Requirements**
- At step 8, if user request is too vague or impossible
- System asks clarifying questions via chat
- Flow returns to step 2

#### Exception Flows

**E1: API Rate Limit Exceeded**
- At step 8 or 10, if API rate limit is exceeded
- System displays error message: "AI service rate limit exceeded. Please try again in a few minutes."
- Use case terminates

**E2: Network Error**
- At any step involving external services, if network error occurs
- System displays error message: "Network error. Please check your connection and try again."
- Use case terminates

**E3: Database Connection Failure**
- At step 4 or 20, if database connection fails
- System logs error
- System continues with challenge creation (chat history can be saved later)
- Flow continues to step 21

**E4: Insufficient API Credits**
- At step 8 or 10, if API credits are insufficient
- System displays error message: "Insufficient API credits. Please contact administrator."
- Use case terminates

#### Special Requirements

- Challenge name must be unique (slug-based)
- Challenge must be associated with user_id when saved
- All challenge files must be version controlled in GitHub
- Dockerfiles must be valid and buildable
- Challenge structure must follow platform conventions
- AI responses must be logged for debugging

#### Related Use Cases

- **UC8: Chat with AI Assistant** - Required for challenge creation (include)
- **UC6: Deploy CTF Challenge** - User may deploy challenge after creation
- **UC9: View Challenge Details** - User may view challenge details (extend)

---

### UC6: Deploy CTF Challenge

**Use Case ID**: UC6  
**Use Case Name**: Deploy CTF Challenge  
**Actors**: User, GitHub Repository, Docker Engine, Guacamole Service, OpenAI API, Anthropic API  
**Priority**: High  
**Type**: Primary Use Case  
**Status**: Implemented

#### Description

User requests to deploy an existing CTF challenge. The system clones the challenge from GitHub, validates the configuration, creates Docker containers, sets up network isolation, configures Guacamole access, and provides the user with access URL.

#### Goal

Enable user to deploy a CTF challenge and make it accessible via browser-based terminal.

#### Preconditions

- User is logged in
- Challenge exists in GitHub repository
- Docker Engine is running
- Guacamole service is available
- Challenge has valid docker-compose.yml file
- User has valid session

#### Postconditions

- Challenge containers are running
- Challenge network is created and isolated
- Guacamole connection is configured
- User receives access URL and credentials
- Challenge deployment status is updated in database
- User can access challenge environment

#### Main Success Scenario

1. User requests challenge deployment via chat (e.g., "Deploy challenge-name" or "Deploy my FTP challenge")
2. System saves user message to chat history
3. System forwards request to CTF Automation Service
4. Classifier Agent identifies intent as "DEPLOY"
5. System routes request to Deploy Agent
6. Deploy Agent retrieves challenge metadata from PostgreSQL (if saved) or identifies challenge from GitHub
7. Deploy Agent clones challenge repository from GitHub
8. GitHub returns challenge files including docker-compose.yml, Dockerfiles, and configuration files
9. Deploy Agent calls Pre-Deploy Validator Agent for validation
10. Pre-Deploy Validator Agent validates Dockerfiles and docker-compose.yml:
    - Syntax validation
    - Structure validation
    - Dependency checking
    - Uses Anthropic API for intelligent validation
11. Pre-Deploy Validator Agent returns validation results
12. If validation passes, Deploy Agent allocates subnet and IP addresses for challenge network (172.23.x.x/24)
13. Deploy Agent creates Docker network using Docker API with allocated subnet
14. Docker Engine creates isolated network
15. Deploy Agent executes `docker compose up --build` command
16. Docker Engine builds container images
17. Docker Engine starts containers and attaches to network
18. Deploy Agent waits for containers to be healthy (health check)
19. Deploy Agent calls Post-Deploy Validator Agent for validation
20. Post-Deploy Validator Agent tests container services and connectivity
21. Post-Deploy Validator Agent returns validation results
22. If validation passes, Deploy Agent creates Guacamole user if needed
23. Deploy Agent creates Guacamole connection in MySQL database
24. Deploy Agent configures Guacamole connection parameters:
    - Hostname (container IP)
    - Port (SSH: 22, RDP: 3389)
    - Protocol (SSH or RDP)
    - Username and password
25. Guacamole service creates connection
26. Deploy Agent updates challenge deployment status in PostgreSQL (is_deployed = true)
27. System returns Guacamole access URL to user
28. System displays deployment success message with:
    - Access URL
    - Username
    - Password
    - Connection instructions
    - Challenge details

#### Include Relationships

- **UC8: Chat with AI Assistant** - Deployment requires AI chat interaction (mandatory)
- **UC7: Access Challenge Environment** - Deployment must provide access capability (mandatory)
- Deployment process includes:
  - Pre-deployment validation
  - Network creation
  - Container deployment
  - Guacamole setup

#### Extend Relationships

- **UC11: Browse Challenges** - User may browse challenges after deployment (optional)
- **UC9: View Challenge Details** - User may view challenge details after deployment (optional)

#### Alternative Flows

**A1: Challenge Not Found**
- At step 6-7, if challenge doesn't exist in database or GitHub
- System displays error message: "Challenge not found. Please create the challenge first."
- Use case terminates

**A2: Pre-Deployment Validation Failure**
- At step 10-11, if validation fails
- Pre-Deploy Validator Agent attempts to fix errors automatically using AI
- If fixes successful, flow continues to step 12
- If fixes fail, system displays error message: "Challenge validation failed. Please fix the errors and try again."
- System provides detailed error report
- Use case terminates

**A3: Container Build Failure**
- At step 16, if container build fails
- Deploy Agent analyzes error logs
- Deploy Agent requests OpenAI for error fix suggestions
- Deploy Agent attempts to fix and rebuild (max 3 attempts)
- If all attempts fail, system displays error message: "Container build failed. Please check the Dockerfiles."
- System provides error logs
- Use case terminates

**A4: Container Startup Failure**
- At step 17-18, if containers fail to start or become unhealthy
- Deploy Agent checks container logs
- Deploy Agent restarts containers
- If still fails, system displays error message: "Containers failed to start. Please check the configuration."
- System provides container logs
- Use case terminates

**A5: Post-Deployment Validation Failure**
- At step 19-21, if services are not accessible or validation fails
- Post-Deploy Validator Agent identifies issues
- Deploy Agent fixes startup scripts and restarts containers
- Flow returns to step 19
- If fixes fail after 3 attempts, system displays error message: "Challenge deployment validation failed."
- Use case terminates

**A6: Network Allocation Failure**
- At step 12, if no available subnet can be allocated
- System displays error message: "No available network space. Please contact administrator."
- Use case terminates

**A7: Guacamole Connection Failure**
- At step 22-25, if Guacamole connection creation fails
- System retries connection creation (max 2 attempts)
- If still fails, system displays error message: "Failed to create access connection. Containers are running but access is unavailable."
- System provides container IP addresses for manual access
- Use case terminates

#### Exception Flows

**E1: Docker Engine Unavailable**
- At step 13 or 15, if Docker Engine is unavailable or not running
- System displays error message: "Container service unavailable. Please ensure Docker is running."
- Use case terminates

**E2: GitHub Access Failure**
- At step 7-8, if GitHub repository is inaccessible
- System displays error message: "Failed to access challenge repository. Please check GitHub configuration."
- Use case terminates

**E3: Database Connection Failure**
- At step 6 or 26, if database connection fails
- System logs error
- System continues with deployment (metadata update can be deferred)
- Flow continues to step 27

**E4: Guacamole Service Unavailable**
- At step 22, if Guacamole service is unavailable
- System displays error message: "Guacamole service unavailable. Containers are running but access is unavailable."
- System provides container IP addresses for manual access
- Use case terminates

#### Special Requirements

- Each deployment must use an isolated Docker network
- Network subnets must not overlap (172.23.x.x/24)
- Containers must pass health checks before deployment is considered successful
- Guacamole credentials must be unique per deployment session
- Deployment status must be tracked in database
- Container logs must be accessible for debugging

#### Related Use Cases

- **UC8: Chat with AI Assistant** - Required for deployment request (include)
- **UC7: Access Challenge Environment** - Required outcome of deployment (include)
- **UC5: Create CTF Challenge** - Challenge must be created before deployment

---

### UC7: Access Challenge Environment

**Use Case ID**: UC7  
**Use Case Name**: Access Challenge Environment  
**Actors**: User, Guacamole Service  
**Priority**: High  
**Type**: Primary Use Case  
**Status**: Implemented

#### Description

User accesses a deployed CTF challenge environment through browser-based SSH/RDP terminal provided by Guacamole. User can interact with attacker and victim containers to solve the challenge.

#### Goal

Enable user to access and interact with deployed CTF challenge containers via browser-based terminal.

#### Preconditions

- User is logged in
- Challenge is deployed and running
- Guacamole connection is configured
- User has valid Guacamole access credentials
- Containers are healthy and accessible

#### Postconditions

- User has active terminal session
- User can interact with challenge containers
- Session is logged for security
- User can perform challenge activities

#### Main Success Scenario

1. User clicks on challenge access link (Guacamole URL) from deployment confirmation
2. System retrieves Guacamole connection URL from database
3. System redirects user to Guacamole web interface
4. Guacamole authenticates user session (uses session credentials)
5. Guacamole establishes SSH connection to attacker container (or victim container)
6. Guacamole displays terminal interface in browser
7. User interacts with terminal:
   - Executes commands
   - Performs file operations
   - Runs scanning tools
   - Exploits vulnerabilities
8. User can switch between attacker and victim containers (if multiple connections available)
9. User performs challenge activities:
   - Network scanning
   - Vulnerability exploitation
   - Flag discovery
   - Solution verification
10. User completes challenge or exits terminal
11. System logs session activity (optional, for security auditing)

#### Extend Relationships

- User may view chat history related to challenge access (optional)
- User may ask AI assistant for hints during challenge solving (optional)

#### Alternative Flows

**A1: Connection Timeout**
- At step 5, if connection times out
- System displays error message: "Connection timeout. Please try again."
- User can retry connection
- Flow returns to step 1

**A2: Container Unavailable**
- At step 5, if container is not running or not accessible
- System displays error message: "Challenge environment unavailable. The containers may have stopped. Please redeploy the challenge."
- Use case terminates

**A3: Invalid Credentials**
- At step 4, if Guacamole credentials are invalid or expired
- System displays error message: "Access credentials expired. Please redeploy the challenge."
- Use case terminates

**A4: Multiple Container Access**
- At step 8, if challenge has multiple containers (attacker + victims)
- User can switch between containers using Guacamole connection list
- Each container has separate connection
- Flow continues normally

#### Exception Flows

**E1: Guacamole Service Unavailable**
- At step 3, if Guacamole service is down
- System displays error message: "Access service unavailable. Please try again later."
- Use case terminates

**E2: Network Connectivity Issues**
- At step 5, if network connectivity to containers fails
- System displays error message: "Network connectivity issue. Please check container status."
- Use case terminates

#### Special Requirements

- Terminal session should support full SSH/RDP functionality
- Session should timeout after inactivity (30 minutes default)
- User should be able to reconnect if session drops
- Container access should be logged for security
- Multiple users should not interfere with each other's sessions

#### Related Use Cases

- **UC6: Deploy CTF Challenge** - Challenge must be deployed before access (include relationship)
- **UC8: Chat with AI Assistant** - User may ask for hints during challenge solving

---

### UC8: Chat with AI Assistant

**Use Case ID**: UC8  
**Use Case Name**: Chat with AI Assistant  
**Actors**: User, OpenAI API, Anthropic API  
**Priority**: High  
**Type**: Primary Use Case  
**Status**: Implemented

#### Description

User interacts with AI assistant through a chat interface to create challenges, deploy challenges, ask questions about CTF concepts, or get assistance with challenge-related tasks.

#### Goal

Provide natural language interface for all platform operations and CTF-related assistance.

#### Preconditions

- User is logged in
- OpenAI and Anthropic API keys are configured
- Chat interface is available
- User has valid session

#### Postconditions

- Chat message is saved to database
- AI response is generated and displayed
- Chat history is updated
- User receives assistance or action is performed

#### Main Success Scenario

1. User opens chat interface (from dashboard or challenge page)
2. System loads previous chat history (if any)
3. User types message in chat input
4. User submits message
5. System saves user message to PostgreSQL database (chat_history table)
6. System forwards message to CTF Automation Service
7. Classifier Agent analyzes message intent:
   - CREATE: Create challenge request
   - DEPLOY: Deploy challenge request
   - QUESTION: General question about CTF
   - CHALLENGE_INFO: Information about existing challenge
8. System routes to appropriate agent:
   - Create Agent (for CREATE)
   - Deploy Agent (for DEPLOY)
   - Questions Agent (for QUESTION)
   - ChallengeInfo Agent (for CHALLENGE_INFO)
9. Agent processes request using OpenAI or Anthropic API
10. AI API returns response
11. Agent formats response appropriately
12. System saves AI response to database
13. System displays response in chat interface
14. User can continue conversation
15. System maintains conversation context for follow-up messages

#### Extend Relationships

- User may view chat history after chatting (optional)
- Chat may extend to challenge creation or deployment flows

#### Alternative Flows

**A1: Ambiguous Intent**
- At step 7, if intent is unclear or ambiguous
- Questions Agent asks user for clarification
- System displays: "Could you clarify what you'd like to do? (e.g., create a challenge, deploy a challenge, ask a question)"
- Flow returns to step 3

**A2: API Rate Limit**
- At step 9-10, if API rate limit exceeded
- System displays message: "AI service busy. Please try again in a moment."
- System queues request for retry
- Flow returns to step 3

**A3: Long Conversation Context**
- At step 6, if conversation history is very long
- System includes only last 10-15 messages in context
- Older messages are excluded to stay within token limits
- Flow continues normally

**A4: Challenge-Specific Questions**
- At step 7, if user asks about specific challenge
- ChallengeInfo Agent retrieves challenge details from database
- Agent provides context-aware response
- Flow continues to step 9

#### Exception Flows

**E1: API Service Unavailable**
- At step 9, if API service is down
- System displays error message: "AI service temporarily unavailable. Please try again later."
- Use case terminates

**E2: Database Connection Failure**
- At step 5 or 12, if database connection fails
- System logs error
- System continues with chat (history can be saved later)
- Flow continues to step 13

**E3: Invalid API Response**
- At step 10, if API returns invalid or malformed response
- System displays error message: "Received invalid response. Please try again."
- Use case terminates

#### Special Requirements

- Chat history must be maintained per user session
- Context must be preserved across multiple messages
- Responses should be formatted for readability (markdown support)
- API calls should have timeout (30 seconds)
- Rate limiting should be handled gracefully

#### Related Use Cases

- **UC5: Create CTF Challenge** - Chat is required for challenge creation (include)
- **UC6: Deploy CTF Challenge** - Chat is required for challenge deployment (include)
- **UC9: View Challenge Details** - Chat history may be viewed (extend)

---

### UC9: View Challenge Details

**Use Case ID**: UC9  
**Use Case Name**: View Challenge Details  
**Actors**: User  
**Priority**: Medium  
**Type**: Primary Use Case  
**Status**: Implemented

#### Description

User views detailed information about a specific challenge including description, deployment status, creation date, access URL (if deployed), and related chat history.

#### Goal

Provide user with comprehensive information about a specific challenge.

#### Preconditions

- User is logged in
- Challenge exists in system (database or GitHub)
- User has access to challenge (owns the challenge)

#### Postconditions

- Challenge details are displayed
- User can perform actions on challenge (deploy, delete, etc.)
- User can see challenge status

#### Main Success Scenario

1. User selects challenge from list (dashboard or challenges page)
2. User clicks on challenge name or "View Details" button
3. System retrieves challenge metadata from PostgreSQL
4. System retrieves challenge deployment status
5. System retrieves related chat messages (if any)
6. System retrieves challenge files from GitHub (if needed for display)
7. System displays challenge details page with:
   - Challenge name and description
   - Category and difficulty
   - Creation date
   - Deployment status (deployed/not deployed)
   - Access URL (if deployed)
   - Guacamole credentials (if deployed)
   - Related chat history
   - Action buttons (Deploy, Delete, Edit)
8. User can view all information
9. User can perform actions (deploy, delete, etc.)

#### Extend Relationships

- This use case extends UC5 (Create CTF Challenge) - User may view details after creation
- This use case extends UC6 (Deploy CTF Challenge) - User may view details after deployment

#### Alternative Flows

**A1: Challenge Not Found**
- At step 3, if challenge doesn't exist
- System displays error message: "Challenge not found"
- User is redirected to challenges list
- Use case terminates

**A2: Challenge Not Deployed**
- At step 4, if challenge is not deployed
- System displays "Not Deployed" status
- Access URL and credentials are not shown
- "Deploy" button is prominently displayed
- Flow continues to step 7

**A3: No Chat History**
- At step 5, if challenge has no related chat history
- System displays empty chat history section
- Flow continues to step 7

#### Exception Flows

**E1: Database Connection Failure**
- At step 3, if database connection fails
- System displays error message: "Unable to load challenge details. Please try again."
- Use case terminates

**E2: GitHub Access Failure**
- At step 6, if GitHub repository is inaccessible
- System displays warning: "Challenge files unavailable"
- System continues with available metadata
- Flow continues to step 7

#### Special Requirements

- Challenge details must load within 2 seconds
- Only challenge owner can view challenge details
- Deployment status must be accurate and real-time

#### Related Use Cases

- **UC5: Create CTF Challenge** - User may view details after creation (extend)
- **UC6: Deploy CTF Challenge** - User may view details after deployment (extend)
- **UC11: Browse Challenges** - User navigates from challenge list to details

---

### UC10: Manage User Profile

**Use Case ID**: UC10  
**Use Case Name**: Manage User Profile  
**Actors**: User  
**Priority**: Medium  
**Type**: Primary Use Case  
**Status**: Implemented

#### Description

User views and updates their profile information including name, avatar, email, and password.

#### Goal

Allow user to manage their account information and preferences.

#### Preconditions

- User is logged in
- User has valid session
- User has access to profile page

#### Postconditions

- Profile information is updated (if changes made)
- Changes are saved to database
- User sees updated profile information

#### Main Success Scenario

1. User navigates to profile page (from navigation menu)
2. System retrieves user profile from PostgreSQL
3. System displays current profile information:
   - Username (read-only)
   - Email
   - Name
   - Avatar selection
   - Password change option
4. User edits profile fields (name, avatar, email)
5. User saves changes
6. System validates input:
   - Email format validation
   - Name length validation
7. System updates profile in database
8. System displays success message: "Profile updated successfully"
9. Profile page refreshes with updated information

#### Include Relationships

- **UC2: Login to Platform** - User must be logged in to manage profile (implicit requirement)

#### Alternative Flows

**A1: Change Password**
- At step 4, if user chooses to change password
- System displays password change form:
  - Current password field
  - New password field
  - Confirm new password field
- User enters current password and new password
- User submits password change
- System verifies current password
- System validates new password strength (same requirements as registration)
- System hashes new password using bcryptjs
- System updates password in database
- System invalidates all other sessions (security measure)
- System displays success message: "Password changed successfully. Please login again."
- System redirects user to login page
- Flow ends

**A2: Change Email**
- At step 4, if user changes email
- System validates email format
- System checks if email is already registered
- If email exists, system displays error: "Email already registered"
- If email is new, system updates email in database
- System displays success message
- Flow continues to step 8

**A3: Invalid Current Password**
- At step A1.5, if current password is incorrect
- System displays error: "Current password is incorrect"
- Password change form remains open
- Flow returns to step A1.4

**A4: Weak New Password**
- At step A1.6, if new password doesn't meet requirements
- System displays detailed password requirements
- Flow returns to step A1.4

**A5: Password Mismatch**
- At step A1.4, if new password and confirm password don't match
- System displays error: "Passwords do not match"
- Flow returns to step A1.4

**A6: No Changes Made**
- At step 5, if user clicks save without making changes
- System displays message: "No changes to save"
- Flow continues to step 8

#### Exception Flows

**E1: Database Connection Failure**
- At step 2 or 7, if database connection fails
- System displays error message: "Unable to update profile. Please try again later."
- Use case terminates

**E2: Session Expired**
- At step 1, if user session has expired
- System redirects user to login page
- System displays message: "Your session has expired. Please login again."
- Use case terminates

#### Special Requirements

- Password must be hashed using bcryptjs before storage
- Email must be normalized (lowercase, trimmed)
- All profile changes must be logged
- Password change must invalidate all other sessions
- Username cannot be changed (read-only)

#### Related Use Cases

- **UC2: Login to Platform** - User must be logged in (implicit requirement)

---

### UC11: Browse Challenges

**Use Case ID**: UC11  
**Use Case Name**: Browse Challenges  
**Actors**: User  
**Priority**: Medium  
**Type**: Primary Use Case  
**Status**: Implemented

#### Description

User browses through available CTF challenges in the system, viewing challenge list with filters and search functionality. Challenges are filtered by user_id (users only see their own challenges).

#### Goal

Enable user to view and search through their created challenges.

#### Preconditions

- User is logged in
- User has valid session

#### Postconditions

- Challenge list is displayed
- User can select challenges to view or deploy
- User can filter and search challenges

#### Main Success Scenario

1. User navigates to challenges page (from dashboard or navigation menu)
2. System retrieves challenges from PostgreSQL filtered by user_id
3. System applies filters if specified (category, difficulty, deployment status)
4. System applies search query if specified (challenge name, description)
5. System sorts challenges (by default: newest first)
6. System displays challenge list with:
   - Challenge name
   - Category
   - Difficulty
   - Creation date
   - Deployment status
   - Quick action buttons (View, Deploy, Delete)
7. User can scroll through challenge list
8. User can select challenge for details or deployment
9. User can use filters and search to find specific challenges

#### Extend Relationships

- This use case extends UC5 (Create CTF Challenge) - User may browse challenges after creation
- This use case extends UC6 (Deploy CTF Challenge) - User may browse challenges after deployment

#### Alternative Flows

**A1: No Challenges Available**
- At step 2, if user has no challenges
- System displays empty state: "No challenges yet. Create your first challenge!"
- System displays "Create Challenge" button
- Flow continues to step 6

**A2: Filter Applied**
- At step 3, if user applies filter (category, difficulty, etc.)
- System filters challenges based on criteria
- Filtered results are displayed
- Flow continues to step 6

**A3: Search Query**
- At step 4, if user enters search query
- System searches challenge names and descriptions
- Matching challenges are displayed
- Flow continues to step 6

**A4: No Search Results**
- At step 4, if search returns no results
- System displays: "No challenges found matching your search"
- System provides option to clear search
- Flow continues to step 6

#### Exception Flows

**E1: Database Connection Failure**
- At step 2, if database connection fails
- System displays error message: "Unable to load challenges. Please try again."
- Use case terminates

#### Special Requirements

- Challenges must be filtered by user_id (privacy)
- Search must be case-insensitive
- List must support pagination if many challenges exist
- Default sort: newest first (created_at DESC)

#### Related Use Cases

- **UC5: Create CTF Challenge** - User may browse after creation (extend)
- **UC6: Deploy CTF Challenge** - User may browse after deployment (extend)
- **UC9: View Challenge Details** - User navigates from list to details

---

## Use Case Relationships

### Include Relationships (<<include>>)

**Mandatory relationships where the base use case requires the included use case:**

1. **UC5 (Create CTF Challenge) includes UC8 (Chat with AI Assistant)**
   - Creating a challenge requires AI chat interaction
   - Arrow: UC5 → UC8

2. **UC6 (Deploy CTF Challenge) includes UC8 (Chat with AI Assistant)**
   - Deploying a challenge requires AI chat interaction
   - Arrow: UC6 → UC8

3. **UC6 (Deploy CTF Challenge) includes UC7 (Access Challenge Environment)**
   - Deployment must provide access capability
   - Arrow: UC6 → UC7

### Extend Relationships (<<extend>>)

**Optional relationships where the extending use case adds optional behavior:**

1. **UC9 (View Challenge Details) extends UC5 (Create CTF Challenge)**
   - After creating, user may view challenge details
   - Arrow: UC9 → UC5

2. **UC9 (View Challenge Details) extends UC6 (Deploy CTF Challenge)**
   - After deploying, user may view challenge details
   - Arrow: UC9 → UC6

3. **UC11 (Browse Challenges) extends UC5 (Create CTF Challenge)**
   - After creating, user may browse challenges
   - Arrow: UC11 → UC5

4. **UC11 (Browse Challenges) extends UC6 (Deploy CTF Challenge)**
   - After deploying, user may browse challenges
   - Arrow: UC11 → UC6

### Actor-Use Case Associations

**Primary Actor (User) associations:**
- User → UC1 (Register Account)
- User → UC2 (Login to Platform)
- User → UC3 (Logout from Platform)
- User → UC4 (View Dashboard)
- User → UC5 (Create CTF Challenge)
- User → UC6 (Deploy CTF Challenge)
- User → UC7 (Access Challenge Environment)
- User → UC8 (Chat with AI Assistant)
- User → UC9 (View Challenge Details)
- User → UC10 (Manage User Profile)
- User → UC11 (Browse Challenges)

**Secondary Actor associations:**
- OpenAI API → UC5 (Create CTF Challenge)
- OpenAI API → UC8 (Chat with AI Assistant)
- Anthropic API → UC5 (Create CTF Challenge)
- Anthropic API → UC8 (Chat with AI Assistant)
- GitHub Repository → UC5 (Create CTF Challenge)
- GitHub Repository → UC6 (Deploy CTF Challenge)
- Guacamole Service → UC6 (Deploy CTF Challenge)
- Guacamole Service → UC7 (Access Challenge Environment)

---

## Glossary

**CTF (Capture The Flag)**: A cybersecurity competition where participants solve challenges to find hidden flags.

**Docker**: A platform for containerization that packages applications and dependencies into containers.

**Docker Compose**: A tool for defining and running multi-container Docker applications.

**Guacamole**: Apache Guacamole, a browser-based remote access gateway supporting SSH, RDP, and VNC.

**JWT (JSON Web Token)**: A compact, URL-safe token used for authentication and authorization.

**PostgreSQL**: An open-source relational database management system.

**OpenAI API**: External AI service providing GPT models for content generation.

**Anthropic API**: External AI service providing Claude models for validation and analysis.

**GitHub Repository**: External version control service for storing challenge files.

**Challenge**: A CTF challenge consisting of vulnerable systems, flags, and solution instructions.

**Deployment**: The process of building and running challenge containers in an isolated environment.

**Session**: A user's active login session with associated JWT token and activity tracking.

**Flag**: A secret string (typically in format CTF{...}) that participants must find to solve a challenge.

**Victim Machine**: A containerized system with vulnerabilities for participants to exploit.

**Attacker Machine**: A containerized system (typically Kali Linux) with tools for participants to use.

**Network Isolation**: Docker networks that separate challenge environments from each other.

**Pre-Deployment Validation**: Validation of challenge files before container deployment.

**Post-Deployment Validation**: Validation of running containers and services after deployment.

---

## References

1. **UML 2.5 Specification** - Use Case Diagram Standards
2. **Visual Paradigm** - Use Case Diagram Best Practices
3. **Go UML** - Comprehensive Guide to UML Use Case Diagrams
4. **Stack Overflow** - Use Case Diagram Relationships
5. **Project Documentation**:
   - USE_CASE_DIAGRAM_CORRECT.md
   - USE_CASE_DIAGRAM_DETAILED.md
   - PROJECT_LOGIC_FLOW.md
   - SYSTEM_ARCHITECTURE.md

---

**Document End**

**Last Updated**: 2025-01-27  
**Version**: 1.0  
**Status**: Final

