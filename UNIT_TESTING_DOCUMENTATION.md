# Unit Testing Documentation
## AI-Powered CTF Challenge Platform

**Document Version:** 1.0  
**Date:** January 2025  
**Project:** AI CTF Challenge Platform

---

## Table of Contents

1. [Introduction](#introduction)
2. [Testing Strategy](#testing-strategy)
3. [Frontend Unit Tests](#frontend-unit-tests)
4. [Backend Unit Tests](#backend-unit-tests)
5. [CTF Automation Service Unit Tests](#ctf-automation-service-unit-tests)
6. [Test Coverage Requirements](#test-coverage-requirements)
7. [Test Execution](#test-execution)

---

## Introduction

This document outlines the unit testing requirements for the AI-Powered CTF Challenge Platform. Unit tests verify that individual components and functions work correctly in isolation, ensuring code reliability and maintainability.

### Purpose

- Verify individual functions and components work as expected
- Catch bugs early in the development cycle
- Ensure code quality and maintainability
- Provide documentation through test cases
- Enable safe refactoring

### Testing Framework

- **Frontend**: Jest + React Testing Library
- **Backend**: Jest + Supertest
- **CTF Automation**: Jest

---

## Testing Strategy

### Test Categories

1. **Unit Tests**: Test individual functions and components in isolation
2. **Integration Tests**: Test interactions between components
3. **API Tests**: Test API endpoints and responses
4. **Utility Tests**: Test helper functions and utilities

### Test Structure

Each test file should follow this structure:
- Setup/Teardown
- Test cases grouped by functionality
- Clear test descriptions
- Assertions for expected behavior

---

## Frontend Unit Tests

### Component Tests

#### 1. Authentication Components

**Login Component (`Login.tsx`)**
- Test form rendering with all fields
- Test email format validation
- Test password field visibility toggle
- Test form submission with valid credentials
- Test error message display for invalid credentials
- Test navigation to registration page
- Test loading state during authentication

**Registration Component (`Register.tsx`)**
- Test form rendering with all required fields
- Test username validation (3-20 characters, alphanumeric)
- Test email format validation
- Test password strength validation (8+ chars, uppercase, lowercase, number, special char)
- Test password confirmation matching
- Test form submission with valid data
- Test error handling for duplicate username/email
- Test success message and redirect after registration

#### 2. Dashboard Component (`Dashboard.tsx`)
- Test dashboard rendering with user data
- Test statistics display (challenge count, deployment count)
- Test empty state when no challenges exist
- Test navigation to challenge creation
- Test navigation to challenge browsing
- Test user profile display

#### 3. Chat Interface Component (`CTFChatInterface.tsx`)
- Test chat interface rendering
- Test message input field
- Test message submission
- Test message display (user and assistant messages)
- Test session ID generation and storage
- Test chat history loading
- Test progress indicators during challenge creation
- Test challenge information display
- Test Guacamole link display
- Test error message display

#### 4. Challenge Browsing Component (`ChallengeList.tsx`)
- Test challenge list rendering
- Test empty state when no challenges
- Test challenge card display (name, category, difficulty, status)
- Test search functionality
- Test filter functionality (category, difficulty, status)
- Test pagination (if implemented)
- Test challenge selection and navigation

#### 5. Challenge Details Component (`ChallengeDetails.tsx`)
- Test challenge details rendering
- Test challenge metadata display
- Test deployment status display
- Test access URL display (when deployed)
- Test action buttons (Deploy, Delete, Edit)
- Test chat history display
- Test error handling for missing challenge

### Utility Function Tests

#### 1. Session Management (`sessionUtils.ts`)
- Test session ID generation (cryptographically secure)
- Test session ID storage in sessionStorage
- Test session ID retrieval
- Test session ID validation
- Test session expiration handling

#### 2. API Communication (`apiClient.ts`)
- Test API request construction
- Test authentication header injection
- Test error handling for network failures
- Test error handling for API errors
- Test response parsing
- Test timeout handling

#### 3. Form Validation (`validationUtils.ts`)
- Test email validation
- Test password strength validation
- Test username validation
- Test required field validation

---

## Backend Unit Tests

### API Endpoint Tests

#### 1. Authentication Endpoints

**POST `/api/auth/register`**
- Test successful user registration
- Test duplicate username rejection
- Test duplicate email rejection
- Test invalid email format rejection
- Test weak password rejection
- Test password hashing with bcrypt
- Test JWT token generation
- Test database transaction rollback on error

**POST `/api/auth/login`**
- Test successful login with valid credentials
- Test login failure with invalid password
- Test login failure with non-existent user
- Test account lockout after 5 failed attempts
- Test lockout duration (15 minutes)
- Test JWT token generation on successful login
- Test failed attempt counter increment
- Test failed attempt counter reset on success

**GET `/api/auth/me`**
- Test authenticated user info retrieval
- Test unauthenticated request rejection
- Test invalid token rejection
- Test expired token rejection

**POST `/api/auth/logout`**
- Test session destruction
- Test token invalidation
- Test database session deletion

#### 2. Session Management Endpoints

**POST `/api/sessions/create`**
- Test session creation
- Test session ID generation
- Test session expiration setting
- Test user association

**POST `/api/sessions/validate`**
- Test valid session validation
- Test expired session rejection
- Test non-existent session rejection

**GET `/api/sessions/user/:userId`**
- Test user session retrieval
- Test filtering by user ID
- Test empty result for user with no sessions

**DELETE `/api/sessions/:sessionId`**
- Test session deletion
- Test non-existent session handling

#### 3. Chat Endpoints

**POST `/api/chat/messages`**
- Test message saving
- Test session association
- Test message metadata storage
- Test invalid session rejection

**GET `/api/chat/history/:sessionId`**
- Test chat history retrieval
- Test message ordering (chronological)
- Test empty history handling
- Test invalid session handling

#### 4. Challenge Endpoints

**GET `/api/challenges`**
- Test challenge list retrieval
- Test user filtering (only user's challenges)
- Test authentication requirement
- Test empty list handling

**GET `/api/challenges/:challengeId`**
- Test challenge details retrieval
- Test challenge ownership verification
- Test non-existent challenge handling
- Test unauthorized access rejection

**POST `/api/challenges`**
- Test challenge creation
- Test challenge metadata storage
- Test user association
- Test duplicate challenge name rejection

**POST `/api/challenges/:challengeId/submit`**
- Test solution submission
- Test flag validation
- Test submission recording

### Database Operation Tests

#### 1. User Operations (`userService.js`)
- Test user creation
- Test user retrieval by ID
- Test user retrieval by email
- Test user retrieval by username
- Test user update
- Test password update
- Test account lockout
- Test account unlock

#### 2. Session Operations (`sessionService.js`)
- Test session creation
- Test session retrieval
- Test session validation
- Test session expiration check
- Test session deletion
- Test session cleanup (expired sessions)

#### 3. Challenge Operations (`challengeService.js`)
- Test challenge creation
- Test challenge retrieval
- Test challenge update
- Test challenge deletion
- Test challenge filtering by user

### Security Tests

#### 1. Password Security
- Test password hashing (bcrypt)
- Test password comparison (bcrypt.compare)
- Test password not stored in plain text
- Test password strength requirements

#### 2. JWT Token Security
- Test token generation with correct payload
- Test token expiration (7 days)
- Test token signature verification
- Test token tampering detection

#### 3. SQL Injection Prevention
- Test parameterized queries
- Test input sanitization
- Test prepared statements usage

#### 4. Authentication Middleware
- Test token extraction from headers
- Test token validation
- Test unauthorized request rejection
- Test expired token handling

---

## CTF Automation Service Unit Tests

### Agent Tests

#### 1. Classifier Agent (`classifier.js`)
- Test CREATE intent classification
- Test DEPLOY intent classification
- Test QUESTION intent classification
- Test CHALLENGE_INFO intent classification
- Test ambiguous intent handling
- Test confidence score calculation

#### 2. Create Agent (`agents/create-agent.js`)
- Test challenge name generation
- Test challenge structure creation
- Test GitHub repository creation
- Test file commit and push
- Test challenge metadata storage
- Test error handling for GitHub failures

#### 3. Deploy Agent (`agents/deploy-agent.js`)
- Test challenge repository cloning
- Test Docker network creation
- Test container building
- Test container startup
- Test Guacamole connection creation
- Test deployment status update
- Test error handling for deployment failures

#### 4. Universal Structure Agent (`agents/universal-structure-agent.js`)
- Test multi-machine structure generation
- Test docker-compose.yml generation
- Test network configuration
- Test IP allocation
- Test machine role assignment (attacker/victim)

#### 5. Content Agents

**Network Content Agent (`agents/content/network-content-agent.js`)**
- Test network service challenge generation
- Test service configuration
- Test vulnerability implementation
- Test flag placement

**Web Content Agent (`agents/content/web-content-agent.js`)**
- Test web application generation
- Test vulnerability implementation
- Test database setup
- Test flag placement

**Crypto Content Agent (`agents/content/crypto-content-agent.js`)**
- Test cryptography challenge generation
- Test encryption/decryption logic
- Test flag encoding

#### 6. Tool Installation Agent (`agents/tool-installation-agent.js`)
- Test Dockerfile generation
- Test package installation method selection
- Test OS-specific package manager detection
- Test tool installation script generation

#### 7. Validator Agents

**Pre-Deploy Validator (`agents/pre-deploy-validator-agent.js`)**
- Test Dockerfile syntax validation
- Test docker-compose.yml validation
- Test file structure validation
- Test error detection
- Test auto-fix suggestions

**Post-Deploy Validator (`agents/post-deploy-validator.js`)**
- Test container health checks
- Test service accessibility
- Test network connectivity
- Test validation result reporting

### Manager Tests

#### 1. Docker Manager (`docker-manager.js`)
- Test container creation
- Test container start/stop
- Test network creation
- Test network deletion
- Test container status retrieval
- Test IP address allocation
- Test error handling for Docker failures

#### 2. Git Manager (`git-manager.js`)
- Test repository cloning
- Test file commit
- Test file push
- Test branch operations
- Test error handling for Git failures

#### 3. Database Manager (`db-manager.js`)
- Test session validation
- Test chat message storage
- Test challenge metadata operations
- Test connection pooling
- Test transaction handling

#### 4. Subnet Allocator (`subnet-allocator.js`)
- Test subnet allocation
- Test IP conflict detection
- Test subnet range management (172.23.x.x/24)
- Test subnet release

#### 5. Guacamole Managers

**Session Guacamole Manager (`session-guacamole-manager.js`)**
- Test Guacamole user creation
- Test connection creation
- Test permission assignment
- Test URL generation
- Test session isolation

**Guacamole PostgreSQL Manager (`guacamole-postgresql-manager.js`)**
- Test database connection
- Test user operations
- Test connection operations
- Test permission operations

### Utility Function Tests

#### 1. Logger (`core/logger.js`)
- Test log level filtering
- Test log formatting
- Test error logging
- Test info logging
- Test warning logging

#### 2. Error Handler (`core/error-handler.js`)
- Test error classification
- Test error formatting
- Test error response generation
- Test error logging

#### 3. Request Validator (`core/request-validator.js`)
- Test request validation
- Test session validation
- Test input sanitization
- Test error response generation

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

### Test Maintenance

- Update tests when functionality changes
- Remove obsolete tests
- Refactor tests for maintainability
- Document test cases and scenarios

---

## Test Examples

### Example: Frontend Component Test

```javascript
// Login.test.tsx
import { render, screen, fireEvent } from '@testing-library/react';
import { Login } from './Login';

describe('Login Component', () => {
  test('renders login form with all fields', () => {
    render(<Login />);
    expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument();
  });

  test('validates email format', () => {
    render(<Login />);
    const emailInput = screen.getByLabelText(/email/i);
    fireEvent.change(emailInput, { target: { value: 'invalid-email' } });
    fireEvent.submit(screen.getByRole('form'));
    expect(screen.getByText(/invalid email/i)).toBeInTheDocument();
  });
});
```

### Example: Backend API Test

```javascript
// auth.test.js
const request = require('supertest');
const app = require('../server');

describe('POST /api/auth/register', () => {
  test('creates new user with valid data', async () => {
    const response = await request(app)
      .post('/api/auth/register')
      .send({
        username: 'testuser',
        email: 'test@example.com',
        password: 'Test123!@#'
      });
    
    expect(response.status).toBe(201);
    expect(response.body).toHaveProperty('token');
    expect(response.body.user).toHaveProperty('username', 'testuser');
  });

  test('rejects duplicate username', async () => {
    // First registration
    await request(app)
      .post('/api/auth/register')
      .send({
        username: 'testuser',
        email: 'test1@example.com',
        password: 'Test123!@#'
      });

    // Duplicate attempt
    const response = await request(app)
      .post('/api/auth/register')
      .send({
        username: 'testuser',
        email: 'test2@example.com',
        password: 'Test123!@#'
      });

    expect(response.status).toBe(400);
    expect(response.body.error).toContain('username already exists');
  });
});
```

### Example: CTF Automation Service Test

```javascript
// classifier.test.js
const Classifier = require('./classifier');

describe('Classifier Agent', () => {
  test('classifies CREATE intent correctly', async () => {
    const result = await Classifier.classify('Create an FTP challenge');
    expect(result.intent).toBe('CREATE');
    expect(result.confidence).toBeGreaterThan(0.8);
  });

  test('classifies DEPLOY intent correctly', async () => {
    const result = await Classifier.classify('Deploy my challenge');
    expect(result.intent).toBe('DEPLOY');
    expect(result.confidence).toBeGreaterThan(0.8);
  });
});
```

---

## Conclusion

Unit testing is essential for maintaining code quality and ensuring the reliability of the AI-Powered CTF Challenge Platform. This document provides a comprehensive guide for implementing unit tests across all components of the system.

**Key Principles:**
- Test individual functions and components in isolation
- Aim for high coverage of critical functionality
- Maintain tests alongside code changes
- Use mocks for external dependencies
- Write clear, descriptive test cases

---

**Document End**

**Last Updated**: January 2025  
**Version**: 1.0  
**Status**: Active

