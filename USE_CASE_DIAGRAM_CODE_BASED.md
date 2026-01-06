# AI CTF Challenge Platform - Use Case Diagram (Based on Actual Code Logic)

## Overview

This use case diagram is based on the **actual code implementation** and reflects how the system truly works, not theoretical design.

---

## Use Case Diagram (Code-Based Logic)

```mermaid
graph TB
    subgraph System["AI CTF Challenge Platform"]
        UC1[Register Account]
        UC2[Login to Platform]
        UC3[Logout from Platform]
        UC4[View Dashboard]
        UC5[Create CTF Challenge]
        UC6[Deploy CTF Challenge]
        UC7[Access Challenge Environment]
        UC8[Chat with AI Assistant]
        UC9[View Challenge Details]
        UC10[Manage User Profile]
        UC11[Browse Challenges]
    end

    User((User))
    OpenAI((OpenAI API))
    Anthropic((Anthropic API))
    GitHub((GitHub Repository))
    Guacamole((Guacamole Service))

    %% Actor-Use Case Associations (Solid lines, NO arrowheads - UML Standard)
    User --- UC1
    User --- UC2
    User --- UC3
    User --- UC4
    User --- UC5
    User --- UC6
    User --- UC7
    User --- UC8
    User --- UC9
    User --- UC10
    User --- UC11

    %% Include Relationships (MANDATORY - Dashed arrow FROM base TO included)
    %% Based on code: Create/Deploy MUST go through chat interface
    UC5 -.->|<<include>>| UC8
    UC6 -.->|<<include>>| UC8
    UC6 -.->|<<include>>| UC7

    %% Extend Relationships (OPTIONAL - Dashed arrow FROM extending TO base)
    %% Based on code: These are optional actions that may happen after Create/Deploy
    UC9 -.->|<<extend>>| UC5
    UC9 -.->|<<extend>>| UC6
    UC11 -.->|<<extend>>| UC5
    UC11 -.->|<<extend>>| UC6

    %% External Actor Associations (Solid lines, NO arrowheads)
    %% Based on code: Which APIs are actually used by which use cases
    
    %% Create CTF Challenge uses:
    UC5 --- OpenAI      %% For challenge generation (create-agent.js uses OpenAI GPT-4o)
    UC5 --- Anthropic   %% For validation (designer.js uses Claude Sonnet 4)
    UC5 --- GitHub      %% For storing challenge files (git-manager.js)
    
    %% Deploy CTF Challenge uses:
    UC6 --- OpenAI      %% For classification (classifier.js uses OpenAI GPT-4)
    UC6 --- Anthropic   %% For pre-deployment validation (pre-deploy-validator-agent.js uses Claude)
    UC6 --- GitHub      %% For pulling challenge files (deployer.js pulls from GitHub)
    UC6 --- Guacamole   %% For creating browser-based SSH access (guacamole-agent.js)
    
    %% Chat with AI Assistant uses:
    UC8 --- OpenAI      %% For classification and questions (classifier.js, questions-agent.js)
    UC8 --- Anthropic   %% For content generation and error fixing (various agents)
    
    %% Access Challenge Environment uses:
    UC7 --- Guacamole   %% For browser-based SSH access

    style System fill:#e1f5ff,stroke:#01579b,stroke-width:3px
    style User fill:#fff9c4,stroke:#f57f17,stroke-width:3px
    style OpenAI fill:#ffccbc,stroke:#bf360c,stroke-width:2px
    style Anthropic fill:#ffccbc,stroke:#bf360c,stroke-width:2px
    style GitHub fill:#ffccbc,stroke:#bf360c,stroke-width:2px
    style Guacamole fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
```

---

## Code-Based Relationship Explanations

### Include Relationships (MANDATORY)

**Arrow Direction**: FROM base use case TO included use case  
**Visual Pattern**: `[Base] --<<include>>--> [Included]`

#### 1. **UC5 (Create Challenge) includes UC8 (Chat with AI Assistant)**
- **Code Evidence**: 
  - `GenerateChallenge.tsx` only renders `CTFChatInterface`
  - All creation requests go through `/api/chat` endpoint
  - `orchestrator.js` processes all requests through chat interface
- **Why Include?**: You **CANNOT** create a challenge without using the chat interface
- **Implementation**: User types "create ftp challenge" in chat → System processes through chat → Creates challenge

#### 2. **UC6 (Deploy Challenge) includes UC8 (Chat with AI Assistant)**
- **Code Evidence**:
  - All deployment requests go through `/api/chat` endpoint
  - `orchestrator.js` routes deployment through chat interface
  - Classifier uses AI (OpenAI) to understand "deploy challenge-name"
- **Why Include?**: You **CANNOT** deploy a challenge without using the chat interface
- **Implementation**: User types "deploy challenge-name" in chat → System processes through chat → Deploys challenge

#### 3. **UC6 (Deploy Challenge) includes UC7 (Access Challenge Environment)**
- **Code Evidence**:
  - `deployer.js` automatically creates Guacamole connection after deployment
  - `guacamole-agent.js` sets up browser-based SSH access
  - Deployment always provides access URL
- **Why Include?**: Deployment **ALWAYS** creates access (Guacamole connection is mandatory)
- **Implementation**: After containers start → Guacamole connection created → Access URL provided

### Extend Relationships (OPTIONAL)

**Arrow Direction**: FROM extending use case TO base use case  
**Visual Pattern**: `[Extending] --<<extend>>--> [Base]`

#### 1. **UC9 (View Challenge Details) extends UC5 (Create Challenge)**
- **Code Evidence**: Dashboard shows challenge cards, but viewing details is optional
- **Why Extend?**: After creating, you **MAY** view details (but don't have to)
- **Implementation**: User creates challenge → Optionally views details on dashboard or asks in chat

#### 2. **UC9 (View Challenge Details) extends UC6 (Deploy Challenge)**
- **Code Evidence**: Dashboard shows challenge cards, but viewing details is optional
- **Why Extend?**: After deploying, you **MAY** view details (but don't have to)
- **Implementation**: User deploys challenge → Optionally views details on dashboard or asks in chat

#### 3. **UC11 (Browse Challenges) extends UC5 (Create Challenge)**
- **Code Evidence**: Dashboard shows challenges, but browsing is optional
- **Why Extend?**: Before/after creating, you **MAY** browse challenges (but don't have to)
- **Implementation**: User creates challenge → Optionally browses other challenges

#### 4. **UC11 (Browse Challenges) extends UC6 (Deploy Challenge)**
- **Code Evidence**: Dashboard shows challenges, but browsing is optional
- **Why Extend?**: Before/after deploying, you **MAY** browse challenges (but don't have to)
- **Implementation**: User deploys challenge → Optionally browses other challenges

---

## External API Connections (Based on Code)

### OpenAI API Connections

**Connected to:**
1. **UC5 (Create CTF Challenge)**
   - **File**: `packages/ctf-automation/src/agents/create-agent.js`
   - **Usage**: Uses OpenAI GPT-4o to generate challenge structure and content
   - **Line**: `const completion = await openai.chat.completions.create({ model: 'gpt-4o' })`

2. **UC6 (Deploy CTF Challenge)**
   - **File**: `packages/ctf-automation/src/classifier.js`
   - **Usage**: Uses OpenAI GPT-4 to classify deployment requests
   - **Line**: `const completion = await openai.chat.completions.create({ model: 'gpt-4' })`

3. **UC8 (Chat with AI Assistant)**
   - **File**: `packages/ctf-automation/src/classifier.js`, `questions-agent.js`
   - **Usage**: Uses OpenAI for request classification and answering questions
   - **Line**: Multiple files use OpenAI for chat interactions

### Anthropic API Connections

**Connected to:**
1. **UC5 (Create CTF Challenge)**
   - **File**: `packages/ctf-automation/src/challenge/designer.js`
   - **Usage**: Uses Claude Sonnet 4 for challenge design and validation
   - **Line**: `const response = await anthropic.messages.create({ model: 'claude-sonnet-4-20250514' })`

2. **UC6 (Deploy CTF Challenge)**
   - **File**: `packages/ctf-automation/src/agents/pre-deploy-validator-agent.js`
   - **Usage**: Uses Claude Sonnet 4 for pre-deployment validation of Dockerfiles
   - **Line**: `const message = await anthropic.messages.create({ model: 'claude-sonnet-4-20250514' })`

3. **UC8 (Chat with AI Assistant)**
   - **File**: Multiple content agents (network-content-agent.js, web-content-agent.js, etc.)
   - **Usage**: Uses Claude for content generation and error fixing
   - **Line**: Multiple files use Anthropic for various chat-related tasks

### GitHub Repository Connections

**Connected to:**
1. **UC5 (Create CTF Challenge)**
   - **File**: `packages/ctf-automation/src/git-manager.js`
   - **Usage**: Stores challenge files in GitHub repository
   - **Function**: `gitManager.pushToGitHub()` commits and pushes challenge files

2. **UC6 (Deploy CTF Challenge)**
   - **File**: `packages/ctf-automation/src/deployment/deployer.js`
   - **Usage**: Pulls challenge files from GitHub before deployment
   - **Line**: `await gitManager.ensureRepository()` pulls latest changes

### Guacamole Service Connections

**Connected to:**
1. **UC6 (Deploy CTF Challenge)**
   - **File**: `packages/ctf-automation/src/agents/guacamole-agent.js`
   - **Usage**: Creates Guacamole user and connection during deployment
   - **Function**: `guacamoleAgent.createConnection()` sets up browser-based SSH access

2. **UC7 (Access Challenge Environment)**
   - **File**: `packages/ctf-automation/src/agents/guacamole-agent.js`
   - **Usage**: Provides browser-based SSH access to deployed challenges
   - **Implementation**: User accesses challenge via Guacamole web interface

---

## Key Differences from Theoretical Diagrams

### What the Code Actually Does:

1. **Chat is MANDATORY for Create/Deploy**
   - ❌ **Wrong**: "Chat includes Create/Deploy" (suggests chat is the main use case)
   - ✅ **Correct**: "Create/Deploy include Chat" (chat is a required component)

2. **Deployment ALWAYS provides Access**
   - ❌ **Wrong**: "Access includes Deploy" (suggests access is the main use case)
   - ✅ **Correct**: "Deploy includes Access" (access is automatically created)

3. **AI APIs are used in Deployment**
   - ❌ **Wrong**: Only Create uses AI APIs
   - ✅ **Correct**: Both Create AND Deploy use AI APIs (for classification and validation)

4. **Browse/View Details are OPTIONAL**
   - ✅ **Correct**: These extend Create/Deploy (optional actions)

---

## PlantUML Format (Code-Based)

```plantuml
@startuml AI_CTF_Challenge_Platform_Use_Case_Diagram_Code_Based

left to right direction

actor User
actor "OpenAI API" as OpenAI
actor "Anthropic API" as Anthropic
actor "GitHub Repository" as GitHub
actor "Guacamole Service" as Guacamole

rectangle "AI CTF Challenge Platform" {
    usecase "Register Account" as UC1
    usecase "Login to Platform" as UC2
    usecase "Logout from Platform" as UC3
    usecase "View Dashboard" as UC4
    usecase "Create CTF Challenge" as UC5
    usecase "Deploy CTF Challenge" as UC6
    usecase "Access Challenge Environment" as UC7
    usecase "Chat with AI Assistant" as UC8
    usecase "View Challenge Details" as UC9
    usecase "Manage User Profile" as UC10
    usecase "Browse Challenges" as UC11
}

' Actor-Use Case Associations (Solid lines, no arrowheads)
User -- UC1
User -- UC2
User -- UC3
User -- UC4
User -- UC5
User -- UC6
User -- UC7
User -- UC8
User -- UC9
User -- UC10
User -- UC11

' Include Relationships (Dashed arrow FROM base TO included)
' Based on code: Create/Deploy MUST go through chat
UC5 ..> UC8 : <<include>>
UC6 ..> UC8 : <<include>>
UC6 ..> UC7 : <<include>>

' Extend Relationships (Dashed arrow FROM extending TO base)
' Based on code: These are optional actions
UC9 ..> UC5 : <<extend>>
UC9 ..> UC6 : <<extend>>
UC11 ..> UC5 : <<extend>>
UC11 ..> UC6 : <<extend>>

' External Actor Associations (Solid lines, no arrowheads)
' Based on actual code usage

' Create CTF Challenge uses:
UC5 -- OpenAI      ' create-agent.js uses OpenAI GPT-4o
UC5 -- Anthropic   ' designer.js uses Claude Sonnet 4
UC5 -- GitHub      ' git-manager.js stores files

' Deploy CTF Challenge uses:
UC6 -- OpenAI      ' classifier.js uses OpenAI GPT-4
UC6 -- Anthropic   ' pre-deploy-validator-agent.js uses Claude
UC6 -- GitHub      ' deployer.js pulls from GitHub
UC6 -- Guacamole   ' guacamole-agent.js creates access

' Chat with AI Assistant uses:
UC8 -- OpenAI      ' classifier.js, questions-agent.js
UC8 -- Anthropic   ' content agents use Claude

' Access Challenge Environment uses:
UC7 -- Guacamole   ' Browser-based SSH access

@enduml
```

---

## Summary

**Total Use Cases**: 11 (All user-initiated)  
**Primary Actor**: 1 (User)  
**Secondary Actors**: 4 (OpenAI API, Anthropic API, GitHub Repository, Guacamole Service)  
**Actor-Use Case Associations**: 11 (solid lines, no arrowheads)  
**Include Relationships**: 3 (mandatory dependencies)  
**Extend Relationships**: 4 (optional behaviors)  

**Key Principle**: This diagram reflects **what the code actually does**, not what it theoretically could do.

---

**Last Updated**: 2025-01-27  
**Version**: 4.0 (Code-Based Logic)  
**UML Standard**: UML 2.5  
**Validation**: Based on actual codebase analysis

