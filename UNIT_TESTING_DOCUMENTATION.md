# Unit Testing Documentation
## AI-Powered CTF Challenge Platform

**Document Version:** 1.0  
**Date:** January 2025  
**Project:** AI CTF Challenge Platform

---

## 5.2 Testing Design / Plan

### 5.2.1 Unit Testing

#### General Definition of Unit Testing

Unit testing involves verifying the functionality of individual software units or components before integration. This testing approach emphasizes isolating components to quickly identify errors and ensure each unit functions correctly in isolation. A "unit" in this context refers to any method, function, or piece of logic responsible for specific tasks such as data validation, error handling, API communication, authentication, challenge creation, or deployment orchestration.

Developers design test cases to ensure units produce correct output for specific inputs, adhering to predefined specifications. Unit testing ensures proper internal logic implementation and helps maintain code quality. Skipping unit testing can lead to silent errors that are difficult to trace and may affect larger parts of the system, making debugging more challenging and time-consuming.

#### Unit Testing for AI CTF Challenge Platform System

Developers will perform the unit testing because they are responsible for implementing the code and understand the desired logic and behavior best. The process involves developers first writing specific test cases that cover all functional aspects of each unit, such as "validate user registration input," "authenticate user login," "generate challenge structure," "deploy challenge containers," and "validate Docker configurations." After writing these test cases, developers will execute them and compare the actual output with the expected results. If the outputs match, the tests succeed; otherwise, the unit test fails, and the developer must debug the code.

---

## 5.2.1.1 Frontend Component Testing

### Authentication Components

| ID | Test Case | Expected Result | Actual Result | Priority | Status |
|----|-----------|----------------|---------------|-----------|--------|
| A1 | Render login form with email and password input fields | Login form displays with all required fields visible | | High | |
| A2 | Validate email format when user enters invalid email | Error message "Please enter a valid email address" is displayed | | High | |
| A3 | Toggle password visibility when clicking eye icon | Password field switches between visible and hidden text | | Medium | |
| A4 | Submit login form with valid credentials | User is authenticated and redirected to dashboard | | High | |
| A5 | Display error message for invalid login credentials | Error message "Invalid email or password" is displayed | | High | |
| A6 | Navigate to registration page when clicking sign up link | Registration page is loaded and displayed | | Medium | |
| A7 | Display loading state during authentication request | Loading spinner or indicator is shown during API call | | Medium | |
| A8 | Render registration form with all required fields | Registration form displays username, email, password, and confirm password fields | | High | |
| A9 | Validate username format (3-20 characters, alphanumeric) | Error message appears if username doesn't meet requirements | | High | |
| A10 | Validate password strength requirements | Error message lists all missing password requirements (uppercase, lowercase, number, special char) | | High | |
| A11 | Validate password confirmation matching | Error message appears if passwords don't match | | High | |
| A12 | Submit registration form with valid data | User account is created and user is redirected to dashboard | | High | |
| A13 | Display error for duplicate username during registration | Error message "Username already exists" is displayed | | High | |
| A14 | Display error for duplicate email during registration | Error message "Email already exists" is displayed | | High | |

### Dashboard Component

| ID | Test Case | Expected Result | Actual Result | Priority | Status |
|----|-----------|----------------|---------------|-----------|--------|
| D1 | Render dashboard with user information | Dashboard displays welcome message with username | | High | |
| D2 | Display challenge statistics (total created, total deployed) | Statistics cards show correct challenge counts | | High | |
| D3 | Display empty state when user has no challenges | Empty state message "No challenges yet. Create your first challenge!" is shown | | Medium | |
| D4 | Navigate to challenge creation when clicking "Create Challenge" button | Chat interface page is loaded | | High | |
| D5 | Navigate to challenge browsing when clicking "Browse Challenges" button | Challenge list page is loaded | | High | |
| D6 | Display user profile information on dashboard | User profile section shows username, email, and avatar | | Medium | |

### Chat Interface Component

| ID | Test Case | Expected Result | Actual Result | Priority | Status |
|----|-----------|----------------|---------------|-----------|--------|
| C1 | Render chat interface with message input field | Chat interface displays with empty message history and input field | | High | |
| C2 | Submit message through chat input field | User message is displayed in chat history | | High | |
| C3 | Display assistant response in chat interface | AI assistant response is displayed in chat history | | High | |
| C4 | Generate and store session ID on component mount | Session ID is generated and stored in sessionStorage | | High | |
| C5 | Load previous chat history when component mounts | Previous messages are displayed in chat history | | Medium | |
| C6 | Display progress indicators during challenge creation | Progress steps are shown with checkmarks for completed steps | | High | |
| C7 | Display challenge information card after creation | Challenge details card shows name, category, difficulty, and repository URL | | High | |
| C8 | Display Guacamole access link after deployment | Access URL and credentials are displayed in chat interface | | High | |
| C9 | Display error message when API request fails | User-friendly error message is displayed in chat | | High | |
| C10 | Maintain conversation context across multiple messages | AI assistant remembers previous conversation context | | Medium | |

### Challenge Browsing Component

| ID | Test Case | Expected Result | Actual Result | Priority | Status |
|----|-----------|----------------|---------------|-----------|--------|
| B1 | Render challenge list with all user challenges | List displays all challenges created by the user | | High | |
| B2 | Display empty state when no challenges exist | Empty state message is shown with "Create Challenge" button | | Medium | |
| B3 | Display challenge card with name, category, difficulty, and status | Each challenge card shows all relevant metadata | | High | |
| B4 | Filter challenges by category using filter dropdown | Only challenges matching selected category are displayed | | Medium | |
| B5 | Filter challenges by difficulty using filter dropdown | Only challenges matching selected difficulty are displayed | | Medium | |
| B6 | Search challenges by name using search input | Challenges matching search query are displayed | | Medium | |
| B7 | Navigate to challenge details when clicking challenge card | Challenge details page is loaded | | High | |
| B8 | Display deployment status badge on challenge cards | Status badge shows "Deployed" or "Not Deployed" | | Medium | |

---

## 5.2.1.2 Backend API Testing

### Authentication Endpoints

| ID | Test Case | Expected Result | Actual Result | Priority | Status |
|----|-----------|----------------|---------------|-----------|--------|
| API1 | POST /api/auth/register with valid user data | User account is created, JWT token is returned | | High | |
| API2 | POST /api/auth/register with duplicate username | Error response 400 with message "Username already exists" | | High | |
| API3 | POST /api/auth/register with duplicate email | Error response 400 with message "Email already exists" | | High | |
| API4 | POST /api/auth/register with invalid email format | Error response 400 with validation error message | | High | |
| API5 | POST /api/auth/register with weak password | Error response 400 listing password requirements | | High | |
| API6 | POST /api/auth/register hashes password with bcrypt | Password stored in database is hashed, not plain text | | High | |
| API7 | POST /api/auth/login with valid credentials | JWT token is returned, user session is created | | High | |
| API8 | POST /api/auth/login with invalid password | Error response 401 with message "Invalid email or password" | | High | |
| API9 | POST /api/auth/login with non-existent user | Error response 401 with message "Invalid email or password" | | High | |
| API10 | POST /api/auth/login locks account after 5 failed attempts | Account is locked for 15 minutes after 5 failed attempts | | High | |
| API11 | GET /api/auth/me with valid JWT token | User information is returned | | High | |
| API12 | GET /api/auth/me with invalid token | Error response 401 with "Unauthorized" message | | High | |
| API13 | GET /api/auth/me with expired token | Error response 401 with "Token expired" message | | High | |
| API14 | POST /api/auth/logout destroys session | Session record is deleted from database | | Medium | |

### Session Management Endpoints

| ID | Test Case | Expected Result | Actual Result | Priority | Status |
|----|-----------|----------------|---------------|-----------|--------|
| S1 | POST /api/sessions/create generates unique session ID | Unique session ID is returned and stored in database | | High | |
| S2 | POST /api/sessions/validate with valid session ID | Validation returns success response | | High | |
| S3 | POST /api/sessions/validate with expired session ID | Validation returns error response | | High | |
| S4 | GET /api/sessions/user/:userId returns user sessions | List of user's active sessions is returned | | Medium | |
| S5 | DELETE /api/sessions/:sessionId deletes session | Session record is removed from database | | Medium | |

### Chat Endpoints

| ID | Test Case | Expected Result | Actual Result | Priority | Status |
|----|-----------|----------------|---------------|-----------|--------|
| CH1 | POST /api/chat/messages saves message to database | Message is stored with correct session_id and role | | High | |
| CH2 | GET /api/chat/history/:sessionId returns messages | Chat history is returned in chronological order | | High | |
| CH3 | GET /api/chat/history/:sessionId with invalid session | Error response 404 with "Session not found" message | | Medium | |

### Challenge Endpoints

| ID | Test Case | Expected Result | Actual Result | Priority | Status |
|----|-----------|----------------|---------------|-----------|--------|
| CHL1 | GET /api/challenges returns user's challenges | List of challenges filtered by user_id is returned | | High | |
| CHL2 | GET /api/challenges/:challengeId returns challenge details | Challenge metadata is returned | | High | |
| CHL3 | GET /api/challenges/:challengeId with invalid ID | Error response 404 with "Challenge not found" message | | Medium | |
| CHL4 | POST /api/challenges saves challenge metadata | Challenge record is created in database | | High | |
| CHL5 | POST /api/challenges with duplicate challenge name | Error response 400 with "Challenge name already exists" | | Medium | |

---

## 5.2.1.3 CTF Automation Service Testing

### Classifier Agent

| ID | Test Case | Expected Result | Actual Result | Priority | Status |
|----|-----------|----------------|---------------|-----------|--------|
| CL1 | Classify "Create an FTP challenge" request | Intent is classified as "CREATE" with confidence > 0.8 | | High | |
| CL2 | Classify "Deploy my challenge" request | Intent is classified as "DEPLOY" with confidence > 0.8 | | High | |
| CL3 | Classify "What is SQL injection?" question | Intent is classified as "QUESTION" with confidence > 0.8 | | Medium | |
| CL4 | Classify "Show me my challenges" request | Intent is classified as "CHALLENGE_INFO" with confidence > 0.8 | | Medium | |
| CL5 | Handle ambiguous intent with low confidence | Questions agent asks user for clarification | | Medium | |

### Create Agent

| ID | Test Case | Expected Result | Actual Result | Priority | Status |
|----|-----------|----------------|---------------|-----------|--------|
| CR1 | Generate challenge name from user request | Unique challenge name is generated and returned | | High | |
| CR2 | Create challenge structure with attacker and victim machines | Challenge structure with correct machine roles is created | | High | |
| CR3 | Generate docker-compose.yml file | Valid docker-compose.yml file is generated | | High | |
| CR4 | Generate Dockerfiles for all machines | Dockerfiles are created with correct base images | | High | |
| CR5 | Commit challenge files to GitHub repository | Files are committed and pushed to GitHub successfully | | High | |
| CR6 | Save challenge metadata to database | Challenge record is created in PostgreSQL | | High | |
| CR7 | Handle GitHub push failure gracefully | Error message is returned, challenge is saved locally | | High | |

### Deploy Agent

| ID | Test Case | Expected Result | Actual Result | Priority | Status |
|----|-----------|----------------|---------------|-----------|--------|
| DP1 | Clone challenge repository from GitHub | Challenge files are cloned to local directory | | High | |
| DP2 | Create Docker network with allocated subnet | Network is created with IP range 172.23.x.x/24 | | High | |
| DP3 | Build Docker containers from docker-compose.yml | Containers are built successfully without errors | | High | |
| DP4 | Start containers and attach to network | All containers start and are connected to network | | High | |
| DP5 | Create Guacamole user for session | Guacamole user is created in MySQL database | | High | |
| DP6 | Create Guacamole connection for attacker machine | Connection is created with correct parameters | | High | |
| DP7 | Generate Guacamole access URL | Valid access URL is returned with connection ID | | High | |
| DP8 | Handle container build failure | Error message is returned with container logs | | High | |
| DP9 | Handle container startup failure | Error message is returned, containers are stopped | | High | |

### Universal Structure Agent

| ID | Test Case | Expected Result | Actual Result | Priority | Status |
|----|-----------|----------------|---------------|-----------|--------|
| US1 | Generate multi-machine challenge structure | Structure includes attacker and victim machines | | High | |
| US2 | Allocate IP addresses for machines | IP addresses are allocated from 172.23.x.x/24 range | | High | |
| US3 | Generate docker-compose.yml with network configuration | docker-compose.yml includes network and IP settings | | High | |
| US4 | Assign correct roles to machines (attacker/victim) | Machine roles are correctly assigned | | High | |

### Content Agents

| ID | Test Case | Expected Result | Actual Result | Priority | Status |
|----|-----------|----------------|---------------|-----------|--------|
| CN1 | Network Content Agent generates FTP challenge | FTP service configuration and vulnerability are created | | High | |
| CN2 | Network Content Agent generates SSH challenge | SSH service with weak credentials is configured | | High | |
| CN3 | Web Content Agent generates web application | Web application with vulnerability is created | | High | |
| CN4 | Crypto Content Agent generates cryptography challenge | Encryption/decryption logic and flag are created | | High | |
| CN5 | Content agents place flags correctly | Flags are placed in correct locations for discovery | | High | |

### Validator Agents

| ID | Test Case | Expected Result | Actual Result | Priority | Status |
|----|-----------|----------------|---------------|-----------|--------|
| V1 | Pre-Deploy Validator validates Dockerfile syntax | Validation passes for valid Dockerfile | | High | |
| V2 | Pre-Deploy Validator detects Dockerfile errors | Validation fails and errors are reported | | High | |
| V3 | Pre-Deploy Validator validates docker-compose.yml | Validation passes for valid docker-compose.yml | | High | |
| V4 | Post-Deploy Validator checks container health | Health check passes for running containers | | High | |
| V5 | Post-Deploy Validator tests service accessibility | Services are accessible on configured ports | | High | |
| V6 | Post-Deploy Validator detects service failures | Validation fails when services are not accessible | | High | |

### Manager Components

| ID | Test Case | Expected Result | Actual Result | Priority | Status |
|----|-----------|----------------|---------------|-----------|--------|
| M1 | Docker Manager creates container successfully | Container is created and returns container ID | | High | |
| M2 | Docker Manager starts container | Container status changes to "running" | | High | |
| M3 | Docker Manager creates network | Network is created with specified subnet | | High | |
| M4 | Git Manager clones repository | Repository files are cloned to local directory | | High | |
| M5 | Git Manager commits and pushes files | Files are committed and pushed to GitHub | | High | |
| M6 | Subnet Allocator allocates unique subnet | Subnet is allocated from available range | | High | |
| M7 | Subnet Allocator detects IP conflicts | Error is returned if subnet is already in use | | Medium | |
| M8 | Guacamole Manager creates user | User is created in Guacamole MySQL database | | High | |
| M9 | Guacamole Manager creates connection | Connection is created with correct parameters | | High | |

---

## Test Coverage Requirements

### Minimum Coverage Targets

- **Overall Code Coverage**: 80%
- **Critical Functions**: 95%
- **API Endpoints**: 90%
- **Authentication Logic**: 100%
- **Security Functions**: 100%
- **Error Handling**: 85%

### Critical Areas Requiring High Coverage

1. **Authentication and Authorization**
   - Login/logout flows
   - Session management
   - Password hashing
   - JWT token handling

2. **Security Functions**
   - Input validation
   - SQL injection prevention
   - XSS prevention
   - CSRF protection

3. **Challenge Creation and Deployment**
   - Challenge generation
   - Docker operations
   - Network configuration
   - Guacamole integration

4. **Error Handling**
   - API error responses
   - Database error handling
   - External service failures
   - User-friendly error messages

---

## Test Execution

### Running Tests

#### Frontend Tests
```bash
cd packages/frontend
npm test
```

#### Backend Tests
```bash
cd packages/backend
npm test
```

#### CTF Automation Tests
```bash
cd packages/ctf-automation
npm test
```

#### All Tests
```bash
npm run test:all
```

### Test Environment Setup

1. **Test Database**: Use separate test database instances
2. **Mock External Services**: Mock OpenAI, Anthropic, GitHub APIs
3. **Docker Test Environment**: Use test Docker networks
4. **Test Data**: Use fixtures and factories for test data

### Continuous Integration

- Run tests on every commit
- Run tests on pull requests
- Generate coverage reports
- Fail builds on coverage drop below threshold

---

**Document End**

**Last Updated**: January 2025  
**Version**: 1.0  
**Status**: Active
