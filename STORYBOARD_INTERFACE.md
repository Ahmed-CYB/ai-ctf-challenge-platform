# AI CTF Challenge Platform - Interface Storyboard

## Overview

This storyboard presents wireframe-style layouts for each interface page in the AI CTF Challenge Platform. Each storyboard shows the structural layout, UI components, and user interface elements for a specific screen.

---

## Storyboard 1: Login Page

**Description:** The login screen where users authenticate to access the platform.

**Wireframe Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│                    [Platform Logo]                           │
│              AI CTF Challenge Platform                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│                    ┌─────────────────┐                      │
│                    │   Login Form    │                      │
│                    │                 │                      │
│                    │  Username/Email │                      │
│                    │  ┌───────────┐  │                      │
│                    │  │           │  │                      │
│                    │  └───────────┘  │                      │
│                    │                 │                      │
│                    │  Password       │                      │
│                    │  ┌───────────┐  │                      │
│                    │  │           │  │                      │
│                    │  └───────────┘  │                      │
│                    │                 │                      │
│                    │  [Login Button] │                      │
│                    │                 │                      │
│                    │  Don't have an  │                      │
│                    │  account?       │                      │
│                    │  [Sign Up Link] │                      │
│                    └─────────────────┘                      │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**UI Elements:**
- Platform logo at top center
- Centered login form
- Username/Email input field
- Password input field
- Login button (primary action)
- "Sign Up" link below form
- Dark theme background

---

## Storyboard 2: Registration / Sign Up Page

**Description:** The registration screen where new users create an account.

**Wireframe Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│                    [Platform Logo]                           │
│              AI CTF Challenge Platform                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│                    ┌─────────────────┐                      │
│                    │  Sign Up Form   │                      │
│                    │                 │                      │
│                    │  Username       │                      │
│                    │  ┌───────────┐  │                      │
│                    │  │           │  │                      │
│                    │  └───────────┘  │                      │
│                    │                 │                      │
│                    │  Email          │                      │
│                    │  ┌───────────┐  │                      │
│                    │  │           │  │                      │
│                    │  └───────────┘  │                      │
│                    │                 │                      │
│                    │  Password       │                      │
│                    │  ┌───────────┐  │                      │
│                    │  │           │  │                      │
│                    │  └───────────┘  │                      │
│                    │                 │                      │
│                    │  Confirm Pass   │                      │
│                    │  ┌───────────┐  │                      │
│                    │  │           │  │                      │
│                    │  └───────────┘  │                      │
│                    │                 │                      │
│                    │  [Create Account]│                     │
│                    │                 │                      │
│                    │  Already have   │                      │
│                    │  account?       │                      │
│                    │  [Login Link]  │                      │
│                    └─────────────────┘                      │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**UI Elements:**
- Platform logo at top center
- Centered registration form
- Username input field
- Email input field
- Password input field
- Confirm Password input field
- Create Account button (primary action)
- "Login" link below form
- Dark theme background

---

## Storyboard 3: Dashboard (Main Screen)

**Description:** The main dashboard screen showing platform overview and statistics.

**Wireframe Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│ ┌──────┐  ┌──────────────────────────────────────────────┐ │
│ │      │  │  Welcome back, [Username]!                    │ │
│ │ Side │  │                                                │ │
│ │ bar  │  │  ┌──────────┐  ┌──────────┐  ┌──────────┐    │ │
│ │      │  │  │ Total    │  │ Deployed │  │ Active   │    │ │
│ │ Dash │  │  │ Created │  │          │  │ Sessions │    │ │
│ │ Gen  │  │  │    0    │  │    0     │  │    0     │    │ │
│ │ Prof │  │  └──────────┘  └──────────┘  └──────────┘    │ │
│ │ Log  │  │                                                │ │
│ │ out  │  │  Recent Challenges                              │ │
│ │      │  │  ┌──────────────────────────────────────────┐ │ │
│ │      │  │  │  No challenges yet.                        │ │ │
│ │      │  │  │  Create your first challenge!            │ │ │
│ │      │  │  └──────────────────────────────────────────┘ │ │
│ │      │  │                                                │ │
│ │      │  │  Quick Actions                                 │ │
│ │      │  │  [Create New Challenge]  [Browse Challenges]  │ │
│ │      │  │                                                │ │
│ └──────┘  └──────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

**UI Elements:**
- Left sidebar navigation (Dashboard, Generate, Profile, Logout)
- Welcome message at top
- Three statistics cards (Total Created, Deployed, Active Sessions)
- Recent Challenges section (empty state initially)
- Quick action buttons
- Dark theme throughout

---

## Storyboard 4: Generate Challenge Page (Chat Interface - Initial State)

**Description:** The AI chat interface for creating challenges, shown in initial empty state.

**Wireframe Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│ ┌──────┐  ┌──────────────────────────────────────────────┐ │
│ │ Side │  │  AI Challenge Creator                        │ │
│ │ bar  │  ├──────────────────────────────────────────────┤ │
│ │      │  │                                               │ │
│ │ Dash │  │  ┌─────────────────────────────────────┐   │ │
│ │ Gen  │  │  │  Chat History Panel (Left)           │   │ │
│ │ Prof │  │  │                                       │   │ │
│ │      │  │  │  [Empty - No messages yet]           │   │ │
│ │      │  │  │                                       │   │ │
│ │      │  │  └─────────────────────────────────────┘   │ │
│ │      │  │                                               │ │
│ │      │  │  ┌─────────────────────────────────────┐   │ │
│ │      │  │  │  Main Chat Area (Right)              │   │ │
│ │      │  │  │                                       │   │ │
│ │      │  │  │  System: Hi! I can help you create   │   │ │
│ │      │  │  │  CTF challenges. What would you     │   │ │
│ │      │  │  │  like to create?                     │   │ │
│ │      │  │  │                                       │   │ │
│ │      │  │  │                                       │   │ │
│ │      │  │  │  ┌───────────────────────────────┐ │   │ │
│ │      │  │  │  │ Type your message...           │ │   │ │
│ │      │  │  │  │ [Send Button]                  │ │   │ │
│ │      │  │  │  └───────────────────────────────┘ │   │ │
│ │      │  │  └─────────────────────────────────────┘   │ │
│ └──────┘  └──────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

**UI Elements:**
- Left sidebar navigation
- Chat header: "AI Challenge Creator"
- Left panel: Chat history (empty initially)
- Right panel: Main chat area
- System welcome message
- Message input field at bottom
- Send button
- Dark theme

---

## Storyboard 5: Generate Challenge Page (User Typing Message)

**Description:** User is typing a message to create a challenge.

**Wireframe Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│ ┌──────┐  ┌──────────────────────────────────────────────┐ │
│ │ Side │  │  AI Challenge Creator                        │ │
│ │ bar  │  ├──────────────────────────────────────────────┤ │
│ │      │  │                                               │ │
│ │ Dash │  │  ┌─────────────────────────────────────┐   │ │
│ │ Gen  │  │  │  Chat History                        │   │ │
│ │ Prof │  │  │                                       │   │ │
│ │      │  │  │  System: Hi! I can help you...       │   │ │
│ │      │  │  │                                       │   │ │
│ │      │  │  └─────────────────────────────────────┘   │ │
│ │      │  │                                               │ │
│ │      │  │  ┌─────────────────────────────────────┐   │ │
│ │      │  │  │  Main Chat Area                     │   │ │
│ │      │  │  │                                       │   │ │
│ │      │  │  │  System: Hi! I can help you create   │   │ │
│ │      │  │  │  CTF challenges. What would you     │   │ │
│ │      │  │  │  like to create?                     │   │ │
│ │      │  │  │                                       │   │ │
│ │      │  │  │  ┌───────────────────────────────┐ │   │ │
│ │      │  │  │  │ Create a SQL injection         │ │   │ │
│ │      │  │  │  │ [Send Button]                  │ │   │ │
│ │      │  │  │  └───────────────────────────────┘ │   │ │
│ │      │  │  └─────────────────────────────────────┘   │ │
│ └──────┘  └──────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

**UI Elements:**
- User message visible in input field
- "Create a SQL injection challenge" text entered
- Send button ready
- Chat history shows previous system message

---

## Storyboard 6: Generate Challenge Page (AI Processing)

**Description:** AI is processing the user's request and generating the challenge.

**Wireframe Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│ ┌──────┐  ┌──────────────────────────────────────────────┐ │
│ │ Side │  │  AI Challenge Creator                        │ │
│ │ bar  │  ├──────────────────────────────────────────────┤ │
│ │      │  │                                               │ │
│ │ Dash │  │  ┌─────────────────────────────────────┐   │ │
│ │ Gen  │  │  │  Chat History                        │   │ │
│ │ Prof │  │  │                                       │   │ │
│ │      │  │  │  System: Hi! I can help you...       │   │ │
│ │      │  │  │  User: Create a SQL injection        │   │ │
│ │      │  │  │                                       │   │ │
│ │      │  │  └─────────────────────────────────────┘   │ │
│ │      │  │                                               │ │
│ │      │  │  ┌─────────────────────────────────────┐   │ │
│ │      │  │  │  Main Chat Area                     │   │ │
│ │      │  │  │                                       │   │ │
│ │      │  │  │  User: Create a SQL injection        │   │ │
│ │      │  │  │  challenge                            │   │ │
│ │      │  │  │                                       │   │ │
│ │      │  │  │  AI: I'll create a SQL injection      │   │ │
│ │      │  │  │  challenge for you...                 │   │ │
│ │      │  │  │                                       │   │ │
│ │      │  │  │  [Progress Indicators]                │   │ │
│ │      │  │  │  ✓ Challenge structure created         │   │ │
│ │      │  │  │  ✓ Content generated                  │   │ │
│ │      │  │  │  ⏳ Dockerfile being created...        │   │ │
│ │      │  │  │  ⏳ Storing files in GitHub...         │   │ │
│ │      │  │  │                                       │   │ │
│ │      │  │  │  ┌───────────────────────────────┐ │   │ │
│ │      │  │  │  │ Type your message...           │ │   │ │
│ │      │  │  │  │ [Send Button]                  │ │   │ │
│ │      │  │  │  └───────────────────────────────┘ │   │ │
│ │      │  │  └─────────────────────────────────────┘   │ │
│ └──────┘  └──────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

**UI Elements:**
- User message displayed
- AI response streaming in
- Progress indicators showing steps:
  - ✓ Completed steps
  - ⏳ In-progress steps
- Input field disabled during processing
- Loading animation

---

## Storyboard 7: Generate Challenge Page (Challenge Created Success)

**Description:** Challenge has been successfully created, showing success message and challenge details.

**Wireframe Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│ ┌──────┐  ┌──────────────────────────────────────────────┐ │
│ │ Side │  │  AI Challenge Creator                        │ │
│ │ bar  │  ├──────────────────────────────────────────────┤ │
│ │      │  │                                               │ │
│ │ Dash │  │  ┌─────────────────────────────────────┐   │ │
│ │ Gen  │  │  │  Chat History                        │   │ │
│ │ Prof │  │  │                                       │   │ │
│ │      │  │  │  System: Hi! I can help you...       │   │ │
│ │      │  │  │  User: Create a SQL injection        │   │ │
│ │      │  │  │  AI: Challenge created!              │   │ │
│ │      │  │  │                                       │   │ │
│ │      │  │  └─────────────────────────────────────┘   │ │
│ │      │  │                                               │ │
│ │      │  │  ┌─────────────────────────────────────┐   │ │
│ │      │  │  │  Main Chat Area                     │   │ │
│ │      │  │  │                                       │   │ │
│ │      │  │  │  AI: ✅ Challenge created            │   │ │
│ │      │  │  │  successfully!                       │   │ │
│ │      │  │  │                                       │   │ │
│ │      │  │  │  ┌───────────────────────────────┐   │ │
│ │      │  │  │  Challenge Details Card          │   │ │
│ │      │  │  │  ┌─────────────────────────────┐ │   │ │
│ │      │  │  │  │ Name: SQL Injection Challenge│ │   │ │
│ │      │  │  │  │ Category: Web Exploitation   │ │   │ │
│ │      │  │  │  │ Difficulty: Intermediate      │ │   │ │
│ │      │  │  │  │ Status: Created (Not Deployed)│ │   │ │
│ │      │  │  │  │ Repository: github.com/...   │ │   │ │
│ │      │  │  │  └─────────────────────────────┘ │   │ │
│ │      │  │  │                                   │   │ │
│ │      │  │  │  [Deploy Challenge] [View Details]│   │ │
│ │      │  │  │  [Create Another]                 │   │ │
│ │      │  │  │                                   │   │ │
│ │      │  │  │  ┌───────────────────────────────┐ │   │ │
│ │      │  │  │  │ Type your message...           │ │   │ │
│ │      │  │  │  │ [Send Button]                  │ │   │ │
│ │      │  │  │  └───────────────────────────────┘ │   │ │
│ │      │  │  └─────────────────────────────────────┘   │ │
│ └──────┘  └──────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

**UI Elements:**
- Success message from AI
- Challenge details card with:
  - Challenge name
  - Category
  - Difficulty
  - Status
  - Repository link
- Action buttons:
  - Deploy Challenge (primary)
  - View Details
  - Create Another
- Chat input field available for next message

---

## Storyboard 8: Generate Challenge Page (Deployment Process)

**Description:** User requested deployment, AI is processing the deployment.

**Wireframe Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│ ┌──────┐  ┌──────────────────────────────────────────────┐ │
│ │ Side │  │  AI Challenge Creator                        │ │
│ │ bar  │  ├──────────────────────────────────────────────┤ │
│ │      │  │                                               │ │
│ │ Dash │  │  ┌─────────────────────────────────────┐   │ │
│ │ Gen  │  │  │  Chat History                        │   │ │
│ │ Prof │  │  │                                       │   │ │
│ │      │  │  │  [Previous messages...]               │   │ │
│ │      │  │  │  User: Deploy SQL injection challenge │   │ │
│ │      │  │  │                                       │   │ │
│ │      │  │  └─────────────────────────────────────┘   │ │
│ │      │  │                                               │ │
│ │      │  │  ┌─────────────────────────────────────┐   │ │
│ │      │  │  │  Main Chat Area                     │   │ │
│ │      │  │  │                                       │   │ │
│ │      │  │  │  User: Deploy SQL injection challenge│   │ │
│ │      │  │  │                                       │   │ │
│ │      │  │  │  AI: Deploying SQL injection          │   │ │
│ │      │  │  │  challenge...                         │   │ │
│ │      │  │  │                                       │   │ │
│ │      │  │  │  [Progress Indicators]                │   │ │
│ │      │  │  │  ✓ Container created                  │   │ │
│ │      │  │  │  ✓ Network configured                  │   │ │
│ │      │  │  │  ⏳ Guacamole connection...            │   │ │
│ │      │  │  │  ⏳ Challenge environment starting...   │   │ │
│ │      │  │  │                                       │   │ │
│ │      │  │  │  ┌───────────────────────────────┐ │   │ │
│ │      │  │  │  │ Type your message...           │ │   │ │
│ │      │  │  │  │ [Send Button]                  │ │   │ │
│ │      │  │  │  └───────────────────────────────┘ │   │ │
│ │      │  │  └─────────────────────────────────────┘   │ │
│ └──────┘  └──────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

**UI Elements:**
- User deployment request visible
- AI deployment response
- Progress indicators:
  - ✓ Completed steps
  - ⏳ In-progress steps
- Loading state

---

## Storyboard 9: Generate Challenge Page (Deployment Success)

**Description:** Challenge has been successfully deployed, showing access information.

**Wireframe Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│ ┌──────┐  ┌──────────────────────────────────────────────┐ │
│ │ Side │  │  AI Challenge Creator                        │ │
│ │ bar  │  ├──────────────────────────────────────────────┤ │
│ │      │  │                                               │ │
│ │ Dash │  │  ┌─────────────────────────────────────┐   │ │
│ │ Gen  │  │  │  Chat History                        │   │ │
│ │ Prof │  │  │                                       │   │ │
│ │      │  │  │  [Previous messages...]               │   │ │
│ │      │  │  │                                       │   │ │
│ │      │  │  └─────────────────────────────────────┘   │ │
│ │      │  │                                               │ │
│ │      │  │  ┌─────────────────────────────────────┐   │ │
│ │      │  │  │  Main Chat Area                     │   │ │
│ │      │  │  │                                       │   │ │
│ │      │  │  │  AI: ✅ Challenge deployed            │   │ │
│ │      │  │  │  successfully!                         │   │ │
│ │      │  │  │                                       │   │ │
│ │      │  │  │  ┌───────────────────────────────┐   │ │
│ │      │  │  │  Access Information Card         │   │ │
│ │      │  │  │  ┌─────────────────────────────┐ │   │ │
│ │      │  │  │  │ Challenge: SQL Injection    │ │   │ │
│ │      │  │  │  │ Status: Deployed & Running  │ │   │ │
│ │      │  │  │  │ Container IP: 172.23.1.5    │ │   │ │
│ │      │  │  │  │ Guacamole URL: [Link]       │ │   │ │
│ │      │  │  │  │ SSH User: ctf_user          │ │   │ │
│ │      │  │  │  │ SSH Pass: [hidden]          │ │   │ │
│ │      │  │  │  │ Web: http://172.23.1.5:8080  │ │   │ │
│ │      │  │  │  └─────────────────────────────┘ │   │ │
│ │      │  │  │                                   │   │ │
│ │      │  │  │  [Access Challenge] [View Details]│   │ │
│ │      │  │  │  [Deploy Another]                 │   │ │
│ │      │  │  │                                   │   │ │
│ │      │  │  │  ┌───────────────────────────────┐ │   │ │
│ │      │  │  │  │ Type your message...           │ │   │ │
│ │      │  │  │  │ [Send Button]                  │ │   │ │
│ │      │  │  │  └───────────────────────────────┘ │   │ │
│ │      │  │  └─────────────────────────────────────┘   │ │
│ └──────┘  └──────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

**UI Elements:**
- Success message from AI
- Access information card with:
  - Challenge name
  - Deployment status
  - Container IP address
  - Guacamole access URL (clickable link)
  - SSH credentials
  - Web interface URL
- Action buttons:
  - Access Challenge (primary, opens Guacamole)
  - View Details
  - Deploy Another

---

## Storyboard 10: Dashboard (With Challenges)

**Description:** Dashboard showing user's created and deployed challenges.

**Wireframe Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│ ┌──────┐  ┌──────────────────────────────────────────────┐ │
│ │ Side │  │  Welcome back, [Username]!                    │ │
│ │ bar  │  │                                                │ │
│ │      │  │  ┌──────────┐  ┌──────────┐  ┌──────────┐   │ │
│ │ Dash │  │  │ Total    │  │ Deployed │  │ Active   │   │ │
│ │ Gen  │  │  │ Created │  │          │  │ Sessions │   │ │
│ │ Prof │  │  │    1    │  │    1     │  │    1     │   │ │
│ │      │  │  └──────────┘  └──────────┘  └──────────┘   │ │
│ │      │  │                                                │ │
│ │      │  │  Recent Challenges                             │ │
│ │      │  │  ┌──────────────────────────────────────────┐ │ │
│ │      │  │  │  SQL Injection Challenge                  │ │ │
│ │      │  │  │  Category: Web | Difficulty: Intermediate│ │ │
│ │      │  │  │  Status: Deployed                         │ │ │
│ │      │  │  │  Created: [Date]                          │ │ │
│ │      │  │  │  [View] [Access] [Delete]                 │ │ │
│ │      │  │  └──────────────────────────────────────────┘ │ │
│ │      │  │                                                │ │
│ │      │  │  Recent Activity                               │ │
│ │      │  │  • Created SQL Injection Challenge - [Time]   │ │
│ │      │  │  • Deployed SQL Injection Challenge - [Time]  │ │
│ │      │  │                                                │ │
│ │      │  │  Quick Actions                                 │ │
│ │      │  │  [Create New Challenge]  [Browse Challenges]  │ │
│ │      │  │                                                │ │
│ └──────┘  └──────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

**UI Elements:**
- Updated statistics (1 created, 1 deployed, 1 active)
- Recent Challenges section with challenge card:
  - Challenge name
  - Category and difficulty
  - Status badge
  - Creation date
  - Action buttons (View, Access, Delete)
- Recent Activity timeline
- Quick action buttons

---

## Storyboard 11: Browse Challenges Page

**Description:** Page showing all user's challenges in a list/grid view.

**Wireframe Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│ ┌──────┐  ┌──────────────────────────────────────────────┐ │
│ │ Side │  │  Browse Challenges                            │ │
│ │ bar  │  ├──────────────────────────────────────────────┤ │
│ │      │  │                                                │ │
│ │ Dash │  │  ┌──────────────────────────────────────┐   │ │
│ │ Gen  │  │  │  Search: [________]  Filter: [All ▼] │   │ │
│ │ Prof │  │  └──────────────────────────────────────┘   │ │
│ │      │  │                                                │ │
│ │      │  │  ┌──────────────┐  ┌──────────────┐          │ │
│ │      │  │  │ SQL Injection│  │ Challenge 2  │          │ │
│ │      │  │  │ Web | Inter  │  │ Network | Adv│          │ │
│ │      │  │  │ Deployed     │  │ Created      │          │ │
│ │      │  │  │ [View][Access]│ │ [View][Deploy]│         │ │
│ │      │  │  └──────────────┘  └──────────────┘          │ │
│ │      │  │                                                │ │
│ │      │  │  ┌──────────────┐  ┌──────────────┐          │ │
│ │      │  │  │ Challenge 3  │  │ Challenge 4  │          │ │
│ │      │  │  │ Crypto | Beg │  │ Web | Inter  │          │ │
│ │      │  │  │ Created      │  │ Deployed     │          │ │
│ │      │  │  │ [View][Deploy]│ │ [View][Access]│         │ │
│ │      │  │  └──────────────┘  └──────────────┘          │ │
│ │      │  │                                                │ │
│ │      │  │  [< Previous]  [1] [2] [3] [Next >]         │ │
│ │      │  │                                                │ │
│ └──────┘  └──────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

**UI Elements:**
- Page title: "Browse Challenges"
- Search bar at top
- Filter dropdown (All, Created, Deployed, by Category)
- Grid layout of challenge cards (2-3 columns)
- Each card shows:
  - Challenge name
  - Category and difficulty
  - Status
  - Action buttons
- Pagination controls at bottom

---

## Storyboard 12: Challenge Details Page

**Description:** Detailed view of a specific challenge with all information.

**Wireframe Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│ ┌──────┐  ┌──────────────────────────────────────────────┐ │
│ │ Side │  │  Challenge Details                            │ │
│ │ bar  │  ├──────────────────────────────────────────────┤ │
│ │      │  │                                                │ │
│ │ Dash │  │  ┌────────────────────────────────────────┐ │ │
│ │ Gen  │  │  │  SQL Injection Challenge                 │ │ │
│ │ Prof │  │  │  Category: Web Exploitation              │ │ │
│ │      │  │  │  Difficulty: Intermediate                │ │ │
│ │      │  │  │  Status: Deployed                        │ │ │
│ │      │  │  │  Created: [Date/Time]                     │ │ │
│ │      │  │  │  Deployed: [Date/Time]                   │ │ │
│ │      │  │  └────────────────────────────────────────┘ │ │
│ │      │  │                                                │ │
│ │      │  │  Description                                  │ │
│ │      │  │  ┌────────────────────────────────────────┐ │ │
│ │      │  │  │  [Challenge description text...]         │ │ │
│ │      │  │  └────────────────────────────────────────┘ │ │
│ │      │  │                                                │ │
│ │      │  │  Access Information                          │ │
│ │      │  │  ┌────────────────────────────────────────┐ │ │
│ │      │  │  │  Container IP: 172.23.1.5                │ │ │
│ │      │  │  │  Guacamole URL: [Clickable Link]         │ │ │
│ │      │  │  │  SSH User: ctf_user                      │ │ │
│ │      │  │  │  SSH Pass: [Show/Hide]                   │ │ │
│ │      │  │  │  Web Interface: http://172.23.1.5:8080   │ │ │
│ │      │  │  └────────────────────────────────────────┘ │ │
│ │      │  │                                                │ │
│ │      │  │  Files                                        │ │
│ │      │  │  ┌────────────────────────────────────────┐ │ │
│ │      │  │  │  • vulnerable_app.py                   │ │ │
│ │      │  │  │  • database.sql                        │ │ │
│ │      │  │  │  • README.md                           │ │ │
│ │      │  │  └────────────────────────────────────────┘ │ │
│ │      │  │                                                │ │
│ │      │  │  [Access Challenge] [Redeploy] [Delete]      │ │
│ │      │  │  [Back to Dashboard]                        │ │
│ │      │  │                                                │ │
│ └──────┘  └──────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

**UI Elements:**
- Challenge header with name, category, difficulty, status
- Creation and deployment timestamps
- Description section
- Access information section with:
  - Container IP
  - Guacamole URL (clickable)
  - SSH credentials
  - Web interface URL
- Files list
- Action buttons:
  - Access Challenge (primary)
  - Redeploy
  - Delete (danger)
  - Back to Dashboard

---

## Storyboard 13: Profile Page

**Description:** User profile page showing account information and statistics.

**Wireframe Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│ ┌──────┐  ┌──────────────────────────────────────────────┐ │
│ │ Side │  │  Profile                                      │ │
│ │ bar  │  ├──────────────────────────────────────────────┤ │
│ │      │  │                                                │ │
│ │ Dash │  │  ┌────────────────────────────────────────┐ │ │
│ │ Gen  │  │  │  [Profile Picture/Avatar]               │ │ │
│ │ Prof │  │  │                                        │ │ │
│ │      │  │  │  Username: [Username]                   │ │ │
│ │      │  │  │  Email: [Email Address]                 │ │ │
│ │      │  │  │  Member since: [Date]                   │ │ │
│ │      │  │  └────────────────────────────────────────┘ │ │
│ │      │  │                                                │ │
│ │      │  │  Statistics                                   │ │
│ │      │  │  ┌────────────────────────────────────────┐ │ │
│ │      │  │  │  Challenges Created: 1                  │ │ │
│ │      │  │  │  Challenges Deployed: 1                 │ │ │
│ │      │  │  │  Total Chat Messages: 15                │ │ │
│ │      │  │  └────────────────────────────────────────┘ │ │
│ │      │  │                                                │ │
│ │      │  │  Account Settings                             │ │
│ │      │  │  ┌────────────────────────────────────────┐ │ │
│ │      │  │  │  [Edit Profile]                        │ │ │
│ │      │  │  │  [Change Password]                     │ │ │
│ │      │  │  │                                        │ │ │
│ │      │  │  │  Danger Zone                            │ │ │
│ │      │  │  │  [Delete Account] (red button)         │ │ │
│ │      │  │  └────────────────────────────────────────┘ │ │
│ │      │  │                                                │ │
│ └──────┘  └──────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

**UI Elements:**
- Profile picture/avatar (circular)
- User information:
  - Username
  - Email address
  - Member since date
- Statistics section:
  - Challenges created count
  - Challenges deployed count
  - Total chat messages
- Account settings:
  - Edit Profile button
  - Change Password button
- Danger zone:
  - Delete Account button (red/warning style)

---

## Storyboard 14: Edit Profile Page

**Description:** Form for editing user profile information.

**Wireframe Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│ ┌──────┐  ┌──────────────────────────────────────────────┐ │
│ │ Side │  │  Edit Profile                                  │ │
│ │ bar  │  ├──────────────────────────────────────────────┤ │
│ │      │  │                                                │ │
│ │ Dash │  │  ┌────────────────────────────────────────┐ │ │
│ │ Gen  │  │  │  Profile Picture                         │ │ │
│ │ Prof │  │  │  [Current Avatar]  [Upload New]         │ │ │
│ │      │  │  │                                        │ │ │
│ │      │  │  │  Username                                │ │ │
│ │      │  │  │  ┌────────────────────────────────────┐ │ │ │
│ │      │  │  │  │ [Current Username]                │ │ │ │
│ │      │  │  │  └────────────────────────────────────┘ │ │ │
│ │      │  │  │                                        │ │ │
│ │      │  │  │  Email                                  │ │ │
│ │      │  │  │  ┌────────────────────────────────────┐ │ │ │
│ │      │  │  │  │ [Current Email]                     │ │ │ │
│ │      │  │  │  └────────────────────────────────────┘ │ │ │
│ │      │  │  │                                        │ │ │
│ │      │  │  │  Bio/Description                        │ │ │
│ │      │  │  │  ┌────────────────────────────────────┐ │ │ │
│ │      │  │  │  │                                    │ │ │ │
│ │      │  │  │  │  [Multi-line text area]            │ │ │ │
│ │      │  │  │  │                                    │ │ │ │
│ │      │  │  │  └────────────────────────────────────┘ │ │ │
│ │      │  │  │                                        │ │ │
│ │      │  │  │  [Save Changes]  [Cancel]              │ │ │
│ │      │  │  └────────────────────────────────────────┘ │ │
│ │      │  │                                                │ │
│ └──────┘  └──────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

**UI Elements:**
- Profile picture upload section
- Username input field (editable)
- Email input field (editable)
- Bio/Description textarea (multi-line)
- Save Changes button (primary)
- Cancel button (secondary, returns to profile)

---

## Storyboard 15: Guacamole Access (Challenge Environment)

**Description:** Guacamole interface showing terminal access to deployed challenge.

**Wireframe Layout:**
```
┌─────────────────────────────────────────────────────────────┐
│  Guacamole - SQL Injection Challenge                       │
│  [Connection Info] [Settings] [Disconnect]                  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Terminal Window                                      │  │
│  │  ┌────────────────────────────────────────────────┐ │  │
│  │  │ ctf_user@sql-injection-challenge:~$            │ │  │
│  │  │                                                 │ │  │
│  │  │ [Terminal output and commands]                  │ │  │
│  │  │                                                 │ │  │
│  │  │ $ ls                                            │ │  │
│  │  │ vulnerable_app.py  database.sql  README.md     │ │  │
│  │  │                                                 │ │  │
│  │  │ $ cat README.md                                 │ │  │
│  │  │ [File contents displayed]                      │ │  │
│  │  │                                                 │ │  │
│  │  │ $ python3 vulnerable_app.py                    │ │  │
│  │  │ [Application output]                           │ │  │
│  │  │                                                 │ │  │
│  │  │ ctf_user@sql-injection-challenge:~$ _          │ │  │
│  │  └────────────────────────────────────────────────┘ │  │
│  │                                                       │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
│  [File Browser] [Clipboard] [Keyboard]                      │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**UI Elements:**
- Guacamole header with connection name
- Connection info, settings, disconnect buttons
- Terminal window showing:
  - Command prompt
  - File system navigation
  - Application execution
  - User can type commands
- File browser panel (optional)
- Clipboard and keyboard controls

---

## Summary

This storyboard presents 15 distinct interface screens for the AI CTF Challenge Platform:

1. **Login Page** - User authentication
2. **Registration Page** - Account creation
3. **Dashboard (Empty)** - Initial platform view
4. **Generate Challenge (Initial)** - Chat interface start
5. **Generate Challenge (Typing)** - User input
6. **Generate Challenge (Processing)** - AI working
7. **Generate Challenge (Success)** - Challenge created
8. **Generate Challenge (Deploying)** - Deployment process
9. **Generate Challenge (Deployed)** - Deployment success
10. **Dashboard (With Data)** - Updated dashboard
11. **Browse Challenges** - Challenge listing
12. **Challenge Details** - Challenge information
13. **Profile** - User profile view
14. **Edit Profile** - Profile editing form
15. **Guacamole Access** - Terminal interface

Each storyboard shows the structural layout using ASCII wireframes, making it easy to visualize the interface design and user flow.

---

**Last Updated:** 2025-01-27  
**Version:** 1.0  
**Platform:** AI CTF Challenge Platform

