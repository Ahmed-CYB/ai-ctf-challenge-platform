# AI CTF Challenge Platform - Storyboard

## Overview

This storyboard illustrates the complete user journey through the AI CTF Challenge Platform, from initial registration to creating, deploying, and accessing CTF challenges. Each scene represents a key interaction point in the system.

---

## Scene 1: Landing Page / Login

**Screen Description:**
- Dark-themed login page with platform branding
- Centered login form with:
  - Email/Username input field
  - Password input field
  - "Login" button
  - "Don't have an account? Sign Up" link
- Platform logo and tagline: "AI-Powered CTF Challenge Platform"

**User Action:**
- User enters credentials
- Clicks "Login" button

**System Response:**
- Validates credentials
- Creates session
- Redirects to Dashboard

**Transition:** → Scene 3 (Dashboard)

---

## Scene 2: Registration / Sign Up

**Screen Description:**
- Similar dark-themed design
- Registration form with:
  - Username input
  - Email input
  - Password input
  - Confirm Password input
  - "Create Account" button
  - "Already have an account? Login" link

**User Action:**
- User fills in registration details
- Clicks "Create Account"

**System Response:**
- Validates input
- Hashes password (bcryptjs)
- Creates user account in PostgreSQL
- Shows success message
- Redirects to Login page

**Transition:** → Scene 1 (Login)

---

## Scene 3: Dashboard (First View)

**Screen Description:**
- Sidebar navigation on left:
  - Dashboard (active)
  - Generate Challenge
  - Profile
  - Logout
- Main content area showing:
  - Welcome message: "Welcome back, [Username]!"
  - Statistics cards:
    - Total Challenges Created: 0
    - Challenges Deployed: 0
    - Active Sessions: 0
  - Recent Activity section (empty)
  - Quick Actions:
    - "Create New Challenge" button
    - "Browse Challenges" button

**User Action:**
- User clicks "Create New Challenge" button

**System Response:**
- Navigates to Generate Challenge page

**Transition:** → Scene 4 (Generate Challenge)

---

## Scene 4: Generate Challenge Page (AI Chat Interface)

**Screen Description:**
- Full-screen chat interface
- Left side: Chat history panel (initially empty)
- Right side: Main chat area with:
  - Chat header: "AI Challenge Creator"
  - Message history area (empty for new user)
  - Input field at bottom with:
    - Text input for user message
    - "Send" button
  - System message: "Hi! I can help you create CTF challenges. What would you like to create?"

**User Action:**
- User types: "Create a SQL injection challenge"
- Clicks "Send"

**System Response:**
- Message appears in chat
- Shows "AI is thinking..." indicator
- Classifier Agent analyzes request
- Routes to Create Agent
- AI generates challenge structure

**Transition:** → Scene 5 (Challenge Creation Process)

---

## Scene 5: Challenge Creation Process (AI Working)

**Screen Description:**
- Same chat interface
- User message visible: "Create a SQL injection challenge"
- AI response streaming in:
  - "I'll create a SQL injection challenge for you..."
  - "Generating challenge structure..."
  - "Creating Dockerfile..."
  - "Setting up vulnerable web application..."
  - Progress indicators showing:
    - ✓ Challenge structure created
    - ✓ Content generated
    - ⏳ Dockerfile being created
    - ⏳ Files being stored in GitHub

**User Action:**
- User waits for AI to complete

**System Response:**
- Create Agent generates:
  - Challenge description
  - Vulnerable code
  - Dockerfile
  - Flag configuration
- Files stored in GitHub repository
- Challenge metadata saved to PostgreSQL

**Transition:** → Scene 6 (Challenge Created Success)

---

## Scene 6: Challenge Created Success

**Screen Description:**
- Chat interface showing:
  - User request
  - AI response: "✅ Challenge created successfully!"
  - Challenge details card:
    - Challenge Name: "SQL Injection Challenge"
    - Category: Web Exploitation
    - Difficulty: Intermediate
    - Status: Created (Not Deployed)
    - Repository: github.com/ctf-platform/sql-injection-challenge
  - Action buttons:
    - "Deploy Challenge" button
    - "View Details" button
    - "Create Another" button

**User Action:**
- User clicks "Deploy Challenge"

**System Response:**
- Navigates to deployment process

**Transition:** → Scene 7 (Deploy Challenge)

---

## Scene 7: Deploy Challenge (AI Chat)

**Screen Description:**
- Chat interface continues
- User message: "Deploy SQL injection challenge"
- AI response:
  - "Deploying SQL injection challenge..."
  - "Creating Docker container..."
  - "Setting up network..."
  - "Configuring Guacamole access..."
  - Progress indicators:
    - ✓ Container created
    - ✓ Network configured
    - ⏳ Guacamole connection being set up
    - ⏳ Challenge environment starting

**User Action:**
- User waits for deployment

**System Response:**
- Deploy Agent:
  - Pulls challenge from GitHub
  - Creates Docker container
  - Sets up Docker network
  - Configures Guacamole connection in MySQL
  - Starts challenge environment
  - Generates access credentials

**Transition:** → Scene 8 (Deployment Success)

---

## Scene 8: Deployment Success

**Screen Description:**
- Chat interface showing:
  - Deployment confirmation
  - Success message: "✅ Challenge deployed successfully!"
  - Access information card:
    - Challenge Name: "SQL Injection Challenge"
    - Status: Deployed & Running
    - Container IP: 172.23.1.5
    - Guacamole Access URL: [Link]
    - SSH Credentials:
      - Username: ctf_user
      - Password: [hidden]
    - Web Interface: http://172.23.1.5:8080
  - Action buttons:
    - "Access Challenge" button (primary)
    - "View Details" button
    - "Deploy Another" button

**User Action:**
- User clicks "Access Challenge"

**System Response:**
- Opens Guacamole connection in new tab/window

**Transition:** → Scene 9 (Access Challenge Environment)

---

## Scene 9: Access Challenge Environment (Guacamole)

**Screen Description:**
- New browser tab/window
- Guacamole interface showing:
  - Terminal/SSH connection to challenge container
  - Terminal prompt: `ctf_user@sql-injection-challenge:~$`
  - File system visible
  - Challenge files accessible:
    - `vulnerable_app.py`
    - `database.sql`
    - `README.md`
  - User can interact with terminal
  - User can browse files
  - User can test the vulnerable application

**User Action:**
- User explores the challenge environment
- User tests SQL injection vulnerability
- User finds and extracts the flag

**System Response:**
- Terminal responds to commands
- Application runs and responds
- User can solve the challenge

**Transition:** → Scene 10 (View Challenge Details)

---

## Scene 10: View Challenge Details

**Screen Description:**
- Dashboard or dedicated challenge details page
- Challenge information card showing:
  - Challenge Name: "SQL Injection Challenge"
  - Category: Web Exploitation
  - Difficulty: Intermediate
  - Created: [Date/Time]
  - Deployed: [Date/Time]
  - Status: Active
  - Description: Full challenge description
  - Hints: Progressive hints (if available)
  - Files: List of challenge files
  - Access Information:
    - Guacamole URL
    - Container IP
    - SSH Credentials
  - Chat History: Link to related chat conversation
  - Action buttons:
    - "Access Challenge" button
    - "Redeploy" button
    - "Delete Challenge" button

**User Action:**
- User reviews challenge details
- User clicks "Back to Dashboard"

**System Response:**
- Returns to dashboard

**Transition:** → Scene 11 (Dashboard with Challenges)

---

## Scene 11: Dashboard (With Challenges)

**Screen Description:**
- Updated dashboard showing:
  - Statistics cards:
    - Total Challenges Created: 1
    - Challenges Deployed: 1
    - Active Sessions: 1
  - Recent Challenges section:
    - Card showing "SQL Injection Challenge"
      - Status: Deployed
      - Created: [Date]
      - Quick actions: View | Access | Delete
  - Recent Activity:
    - "Created SQL Injection Challenge" - [Time]
    - "Deployed SQL Injection Challenge" - [Time]
  - Quick Actions still available

**User Action:**
- User clicks "Browse Challenges" or navigates to challenges list

**System Response:**
- Shows list of all challenges

**Transition:** → Scene 12 (Browse Challenges)

---

## Scene 12: Browse Challenges

**Screen Description:**
- Challenges list page
- Filter/Search bar at top:
  - Search input
  - Category filter dropdown
  - Difficulty filter
  - Status filter (All | Created | Deployed)
- Grid/List view toggle
- Challenge cards showing:
  - Challenge 1: "SQL Injection Challenge"
    - Category: Web
    - Difficulty: Intermediate
    - Status: Deployed
    - Created: [Date]
    - Actions: View | Access | Delete
  - Challenge 2: (if more exist)
- Pagination at bottom

**User Action:**
- User clicks on a challenge card or "View" button

**System Response:**
- Shows challenge details

**Transition:** → Scene 10 (View Challenge Details)

---

## Scene 13: Profile Management

**Screen Description:**
- Profile page showing:
  - User information section:
    - Profile picture/avatar
    - Username: [Username]
    - Email: [Email]
    - Member since: [Date]
  - Statistics:
    - Challenges created: 1
    - Challenges deployed: 1
    - Total chat messages: 15
  - Account settings:
    - "Edit Profile" button
    - "Change Password" button
    - "Delete Account" button (danger zone)

**User Action:**
- User clicks "Edit Profile"

**System Response:**
- Navigates to edit profile page

**Transition:** → Scene 14 (Edit Profile)

---

## Scene 14: Edit Profile

**Screen Description:**
- Edit profile form:
  - Username input (editable)
  - Email input (editable)
  - Profile picture upload
  - Bio/Description textarea
  - "Save Changes" button
  - "Cancel" button

**User Action:**
- User updates information
- Clicks "Save Changes"

**System Response:**
- Validates input
- Updates user information in PostgreSQL
- Shows success message
- Returns to profile page

**Transition:** → Scene 13 (Profile)

---

## Scene 15: Logout

**Screen Description:**
- User clicks "Logout" from sidebar
- Confirmation dialog appears:
  - "Are you sure you want to logout?"
  - "Yes, Logout" button
  - "Cancel" button

**User Action:**
- User confirms logout

**System Response:**
- Invalidates JWT token
- Destroys session
- Clears session data
- Redirects to login page

**Transition:** → Scene 1 (Login)

---

## Alternative Flows

### Flow A: User Creates Multiple Challenges

**Scene 4 → Scene 5 → Scene 6 → Scene 4 (Loop)**
- User creates first challenge
- After success, clicks "Create Another"
- Returns to chat interface
- Process repeats

### Flow B: User Deploys Existing Challenge

**Scene 11 → Scene 12 → Scene 10 → Scene 7**
- User browses challenges
- Selects an existing challenge
- Views details
- Clicks "Deploy" button
- Goes through deployment process

### Flow C: User Accesses Challenge Directly

**Scene 11 → Scene 10 → Scene 9**
- From dashboard, user clicks on challenge
- Views details
- Clicks "Access Challenge"
- Opens Guacamole interface

### Flow D: User Asks Questions via Chat

**Scene 4 → Chat Interface**
- User types general questions:
  - "What is SQL injection?"
  - "How do I create a web challenge?"
  - "Explain XSS vulnerabilities"
- AI responds with educational content
- No challenge creation/deployment

---

## Key User Interactions Summary

1. **Authentication Flow:**
   - Register → Login → Dashboard

2. **Challenge Creation Flow:**
   - Dashboard → Generate Challenge → Chat with AI → Challenge Created → Deploy → Access

3. **Challenge Management Flow:**
   - Dashboard → Browse Challenges → View Details → Access/Deploy/Delete

4. **Profile Management Flow:**
   - Dashboard → Profile → Edit Profile → Save

5. **Session Management:**
   - Any page → Logout → Login

---

## Technical Components Involved

### Frontend (React + TypeScript)
- Login/SignUp pages
- Dashboard component
- GenerateChallenge component (Chat interface)
- Profile/EditProfile components
- Navigation sidebar

### Backend (Express.js)
- Authentication endpoints
- User management
- Session management (JWT)
- API routing

### CTF Automation Service
- Chat endpoint
- Classifier Agent
- Create Agent
- Deploy Agent
- AI integration (OpenAI/Anthropic)

### External Services
- PostgreSQL (user data, challenges, chat history)
- MySQL (Guacamole configuration)
- GitHub (challenge storage)
- Docker (container management)
- Guacamole (remote access)

---

## Visual Design Notes

- **Theme:** Dark mode throughout
- **Color Scheme:**
  - Primary: Blue/Teal accents
  - Background: Dark gray/black
  - Text: Light gray/white
  - Success: Green
  - Warning: Yellow/Orange
  - Error: Red

- **UI Components:**
  - Cards for information display
  - Chat bubbles for messages
  - Progress indicators for async operations
  - Buttons with clear hierarchy
  - Sidebar navigation
  - Modal dialogs for confirmations

- **Responsive Design:**
  - Desktop-first approach
  - Mobile-friendly navigation
  - Adaptive layouts

---

## User Experience Highlights

1. **Seamless AI Interaction:** Natural chat interface for challenge creation
2. **Real-time Feedback:** Progress indicators during creation/deployment
3. **Quick Access:** One-click access to deployed challenges
4. **Comprehensive Dashboard:** Overview of all activities
5. **Easy Navigation:** Clear sidebar and breadcrumbs
6. **Educational Focus:** AI provides explanations and guidance

---

**Last Updated:** 2025-01-27  
**Version:** 1.0  
**Platform:** AI CTF Challenge Platform

