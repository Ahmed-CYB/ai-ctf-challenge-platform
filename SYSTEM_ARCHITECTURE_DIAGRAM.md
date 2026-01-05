# AI CTF Challenge Platform - System Architecture Diagrams

This document provides visual system architecture diagrams for the AI CTF Challenge Platform.

---

## 🏗️ High-Level System Architecture

```mermaid
graph TB
    subgraph "User Layer"
        User[👤 User]
    end

    subgraph "Frontend Layer - Port 4000"
        Frontend[React + TypeScript Frontend<br/>Dashboard, Chat Interface, Profile]
    end

    subgraph "API Layer - Port 4002"
        Backend[Express.js Backend API<br/>Authentication, Sessions, Chat History]
    end

    subgraph "CTF Automation Layer - Port 4003"
        CTFAuto[CTF Automation Service<br/>AI-Powered Challenge Management]
        Classifier[Classifier Agent]
        CreateAgent[Create Agent]
        DeployAgent[Deploy Agent]
        QuestionsAgent[Questions Agent]
        ValidatorAgent[Pre-Deploy Validator]
        ErrorFixer[Auto Error Fixer]
    end

    subgraph "Infrastructure Services"
        PostgreSQL[(PostgreSQL<br/>Port 5433<br/>Main Database)]
        MySQL[(MySQL<br/>Port 3307<br/>Guacamole DB)]
        Docker[Docker Engine<br/>Container Management]
        Guacamole[Apache Guacamole<br/>Port 8081<br/>Browser SSH Access]
    end

    subgraph "External Services"
        GitHub[GitHub Repository<br/>Challenge Storage]
        OpenAI[OpenAI API<br/>GPT-4]
        Anthropic[Anthropic API<br/>Claude]
    end

    User -->|HTTP/WebSocket| Frontend
    Frontend -->|REST API| Backend
    Backend -->|REST API| CTFAuto
    Backend -->|Read/Write| PostgreSQL
    
    CTFAuto -->|Route| Classifier
    Classifier -->|Create| CreateAgent
    Classifier -->|Deploy| DeployAgent
    Classifier -->|Question| QuestionsAgent
    
    CreateAgent -->|Validate| ValidatorAgent
    DeployAgent -->|Fix Errors| ErrorFixer
    DeployAgent -->|Deploy| Docker
    
    CTFAuto -->|Read/Write| PostgreSQL
    CTFAuto -->|Manage| Guacamole
    Guacamole -->|Read/Write| MySQL
    CTFAuto -->|Push/Pull| GitHub
    CTFAuto -->|AI Calls| OpenAI
    CTFAuto -->|AI Calls| Anthropic
    
    Docker -->|Network| Guacamole
    Docker -->|Containers| ChallengeNetworks[Challenge Networks<br/>172.23.x.x/24]

    style User fill:#e1f5ff
    style Frontend fill:#c8e6c9
    style Backend fill:#fff9c4
    style CTFAuto fill:#f8bbd0
    style PostgreSQL fill:#b39ddb
    style MySQL fill:#b39ddb
    style Docker fill:#90caf9
    style Guacamole fill:#a5d6a7
    style GitHub fill:#ffccbc
    style OpenAI fill:#ffccbc
    style Anthropic fill:#ffccbc
```

---

## 🔄 Request Flow Architecture

```mermaid
sequenceDiagram
    participant U as User
    participant F as Frontend<br/>(Port 4000)
    participant B as Backend API<br/>(Port 4002)
    participant C as CTF Automation<br/>(Port 4003)
    participant CL as Classifier Agent
    participant CA as Create Agent
    participant DA as Deploy Agent
    participant G as Git Manager
    participant D as Docker Engine
    participant GU as Guacamole
    participant DB as PostgreSQL

    U->>F: 1. User Request<br/>"Create FTP challenge"
    F->>B: 2. POST /api/chat<br/>{message, sessionId}
    B->>DB: 3. Save message to chat_history
    B->>C: 4. POST /api/chat<br/>{message, sessionId}
    
    C->>CL: 5. Classify request
    CL-->>C: 6. Intent: CREATE
    
    C->>CA: 7. Route to Create Agent
    CA->>CA: 8. Generate challenge structure
    CA->>G: 9. Create challenge files
    G->>G: 10. Commit & push to GitHub
    G-->>CA: 11. Challenge created
    CA-->>C: 12. Challenge ready
    
    C-->>B: 13. Response: Challenge created
    B->>DB: 14. Save challenge metadata
    B-->>F: 15. Return response
    F-->>U: 16. Display success message

    Note over U,DB: Deployment Flow
    U->>F: 17. "Deploy challenge-name"
    F->>B: 18. POST /api/chat
    B->>C: 19. Forward request
    C->>CL: 20. Classify: DEPLOY
    C->>DA: 21. Route to Deploy Agent
    DA->>G: 22. Clone challenge from GitHub
    DA->>D: 23. docker compose up --build
    D-->>DA: 24. Containers running
    DA->>GU: 25. Create Guacamole connection
    GU-->>DA: 26. Connection URL
    DA-->>C: 27. Deployment complete
    C-->>B: 28. Return deployment info
    B-->>F: 29. Return to frontend
    F-->>U: 30. Display Guacamole link
```

---

## 🤖 Agent System Architecture

```mermaid
graph LR
    subgraph "CTF Automation Service"
        Main[Main API Endpoint<br/>/api/chat]
        Classifier[Classifier Agent<br/>Request Routing]
    end

    subgraph "Creation Agents"
        Create[Create Agent<br/>Challenge Creation]
        Universal[Universal Structure Agent<br/>Multi-machine Setup]
        NetworkContent[Network Content Agent<br/>Network Challenges]
        WebContent[Web Content Agent<br/>Web Challenges]
        CryptoContent[Crypto Content Agent<br/>Crypto Challenges]
        ToolInstall[Tool Installation Agent<br/>Dockerfile Generation]
    end

    subgraph "Deployment Agents"
        Deploy[Deploy Agent<br/>Deployment Orchestration]
        PreValidator[Pre-Deploy Validator<br/>File Validation]
        PostValidator[Post-Deploy Validator<br/>Runtime Validation]
        VictimValidator[Victim Validation Agent<br/>Container Health]
        ErrorFixer[Auto Error Fixer<br/>Error Resolution]
    end

    subgraph "Support Agents"
        Questions[Questions Agent<br/>Q&A Handler]
        Retriever[Retriever Agent<br/>Challenge Info]
        GuacamoleAgent[Guacamole Agent<br/>Connection Management]
    end

    Main --> Classifier
    Classifier -->|CREATE| Create
    Classifier -->|DEPLOY| Deploy
    Classifier -->|QUESTION| Questions
    Classifier -->|INFO| Retriever

    Create --> Universal
    Universal --> NetworkContent
    Universal --> WebContent
    Universal --> CryptoContent
    Universal --> ToolInstall

    Deploy --> PreValidator
    Deploy --> PostValidator
    Deploy --> VictimValidator
    Deploy --> ErrorFixer
    Deploy --> GuacamoleAgent

    style Main fill:#ff9800
    style Classifier fill:#2196f3
    style Create fill:#4caf50
    style Deploy fill:#f44336
    style Questions fill:#9c27b0
```

---

## 🐳 Docker Network Architecture

```mermaid
graph TB
    subgraph "Host Machine"
        subgraph "Docker Networks"
            subgraph "Challenge Network 1<br/>172.23.156.0/24"
                Attacker1[Attacker Container<br/>172.23.156.3<br/>Kali Linux]
                Victim1A[Victim 1<br/>172.23.156.4<br/>FTP Server]
                Victim1B[Victim 2<br/>172.23.156.5<br/>Web Server]
            end

            subgraph "Challenge Network 2<br/>172.23.157.0/24"
                Attacker2[Attacker Container<br/>172.23.157.3<br/>Kali Linux]
                Victim2A[Victim 1<br/>172.23.157.4<br/>SMB Server]
            end

            subgraph "Shared Network<br/>ctf-instances-network"
                Guacd[Guacamole Daemon<br/>ctf-guacd-new]
            end

            subgraph "Application Network<br/>ctf-network"
                FrontendContainer[Frontend Container<br/>Port 4000]
                BackendContainer[Backend Container<br/>Port 4002]
                CTFContainer[CTF Automation<br/>Port 4003]
                PostgresContainer[PostgreSQL<br/>Port 5433]
                GuacamoleWeb[Guacamole Web UI<br/>Port 8081]
                MySQLContainer[MySQL<br/>Port 3307]
            end
        end
    end

    Attacker1 -.->|Dual-homed| Guacd
    Attacker2 -.->|Dual-homed| Guacd
    Guacd -->|SSH Connection| Attacker1
    Guacd -->|SSH Connection| Attacker2
    GuacamoleWeb -->|Web Interface| Guacd
    GuacamoleWeb -->|Database| MySQLContainer

    FrontendContainer -->|API Calls| BackendContainer
    BackendContainer -->|API Calls| CTFContainer
    BackendContainer -->|Database| PostgresContainer
    CTFContainer -->|Docker API| Attacker1
    CTFContainer -->|Docker API| Attacker2

    style Attacker1 fill:#ff9800
    style Attacker2 fill:#ff9800
    style Victim1A fill:#f44336
    style Victim1B fill:#f44336
    style Victim2A fill:#f44336
    style Guacd fill:#4caf50
    style GuacamoleWeb fill:#4caf50
```

---

## 📊 Data Flow Architecture

```mermaid
flowchart TD
    subgraph "User Input"
        UserMsg[User Message]
    end

    subgraph "Frontend Processing"
        Frontend[Frontend Service<br/>React + TypeScript]
        ChatUI[Chat Interface Component]
    end

    subgraph "Backend Processing"
        Backend[Backend API<br/>Express.js]
        Auth[Authentication Middleware]
        Session[Session Manager]
        ChatStorage[Chat History Storage]
    end

    subgraph "CTF Automation Processing"
        CTFService[CTF Automation Service]
        Classifier[Request Classifier]
        AgentRouter[Agent Router]
        ResponseFormatter[Response Formatter]
    end

    subgraph "Data Storage"
        PostgresDB[(PostgreSQL<br/>Users, Sessions,<br/>Challenges, Chat)]
        MySQLDB[(MySQL<br/>Guacamole Config)]
        GitRepo[GitHub Repository<br/>Challenge Files]
    end

    subgraph "External Services"
        DockerAPI[Docker API<br/>Container Management]
        GuacamoleAPI[Guacamole API<br/>Connection Management]
        AIAPI[AI APIs<br/>OpenAI/Anthropic]
    end

    UserMsg --> Frontend
    Frontend --> ChatUI
    ChatUI -->|HTTP POST| Backend
    Backend --> Auth
    Auth --> Session
    Session --> ChatStorage
    ChatStorage -->|Save| PostgresDB
    Backend -->|Forward| CTFService
    CTFService --> Classifier
    Classifier --> AgentRouter
    AgentRouter -->|Create| GitRepo
    AgentRouter -->|Deploy| DockerAPI
    AgentRouter -->|Connect| GuacamoleAPI
    AgentRouter -->|Generate| AIAPI
    AgentRouter --> ResponseFormatter
    ResponseFormatter -->|Return| Backend
    Backend -->|Save Response| PostgresDB
    Backend -->|Return| Frontend
    Frontend -->|Display| UserMsg

    style UserMsg fill:#e1f5ff
    style Frontend fill:#c8e6c9
    style Backend fill:#fff9c4
    style CTFService fill:#f8bbd0
    style PostgresDB fill:#b39ddb
    style MySQLDB fill:#b39ddb
    style GitRepo fill:#ffccbc
```

---

## 🔐 Authentication & Session Flow

```mermaid
sequenceDiagram
    participant U as User
    participant F as Frontend
    participant B as Backend API
    participant DB as PostgreSQL
    participant C as CTF Automation
    participant G as Guacamole

    Note over U,G: Login Flow
    U->>F: 1. Enter credentials
    F->>B: 2. POST /api/auth/login
    B->>DB: 3. Validate credentials
    DB-->>B: 4. User data
    B->>B: 5. Generate JWT token
    B->>DB: 6. Create session
    B-->>F: 7. Return token + sessionId
    F->>F: 8. Store in localStorage

    Note over U,G: Challenge Request Flow
    U->>F: 9. Send message
    F->>B: 10. POST /api/chat<br/>{message, sessionId, token}
    B->>B: 11. Verify JWT token
    B->>DB: 12. Validate session
    B->>C: 13. Forward request<br/>{message, sessionId}
    
    Note over U,G: Guacamole User Creation
    C->>DB: 14. Check session_guacamole_users
    alt User doesn't exist
        C->>G: 15. Create Guacamole user<br/>ctf_{sessionId}
        G->>DB: 16. Store in MySQL
        G-->>C: 17. User created
    else User exists
        C->>DB: 18. Retrieve existing user
    end
    
    C->>G: 19. Create connection<br/>{challengeName}_{sessionId}
    G-->>C: 20. Connection URL
    C-->>B: 21. Return response
    B->>DB: 22. Save chat message
    B-->>F: 23. Return response
    F-->>U: 24. Display result
```

---

## 🚀 Challenge Deployment Flow

```mermaid
flowchart TD
    Start([User: Deploy Challenge]) --> Validate{Challenge<br/>Exists?}
    Validate -->|No| Error1[Return Error]
    Validate -->|Yes| Allocate[Allocate Subnet & IPs<br/>172.23.x.x/24]
    
    Allocate --> PreValidate[Pre-Deploy Validator<br/>Fix Dockerfiles]
    PreValidate --> DisconnectGuacd[Disconnect Guacd from<br/>Old Networks]
    
    DisconnectGuacd --> DockerCompose[docker compose up<br/>--build -d]
    DockerCompose --> BuildContainers[Build Containers]
    BuildContainers --> StartContainers[Start Containers]
    
    StartContainers --> CheckStatus{Containers<br/>Running?}
    CheckStatus -->|No| ErrorFixer[Auto Error Fixer<br/>Analyze & Fix]
    ErrorFixer --> Retry[Retry Deployment<br/>Max 3 attempts]
    Retry --> CheckStatus
    
    CheckStatus -->|Yes| ConnectGuacd[Connect Guacd to<br/>Challenge Network]
    ConnectGuacd --> GetIPs[Get Container IPs]
    GetIPs --> VictimValidation[Victim Validation Agent<br/>Verify Services]
    
    VictimValidation --> ServicesOK{Services<br/>Accessible?}
    ServicesOK -->|No| FixVictim[Fix Startup Scripts<br/>Restart Containers]
    FixVictim --> ServicesOK
    
    ServicesOK -->|Yes| CreateGuacUser[Create Guacamole User<br/>ctf_{sessionId}]
    CreateGuacUser --> CreateConnection[Create Guacamole Connection<br/>{challenge}_{sessionId}]
    CreateConnection --> GrantAccess[Grant User Access]
    GrantAccess --> ReturnURL[Return Guacamole URL]
    ReturnURL --> End([Deployment Complete])
    
    Error1 --> End

    style Start fill:#e1f5ff
    style End fill:#c8e6c9
    style Error1 fill:#ffcdd2
    style ErrorFixer fill:#fff9c4
    style VictimValidation fill:#f8bbd0
```

---

## 📦 Component Interaction Diagram

```mermaid
graph TB
    subgraph "Frontend Components"
        Dashboard[Dashboard Component]
        ChatInterface[CTF Chat Interface]
        Profile[Profile Component]
        Generate[Generate Challenge Component]
    end

    subgraph "Backend Services"
        AuthService[Authentication Service]
        ChatService[Chat Service]
        ChallengeService[Challenge Service]
    end

    subgraph "CTF Automation Services"
        DockerManager[Docker Manager<br/>Container Operations]
        GitManager[Git Manager<br/>Repository Management]
        SubnetAllocator[Subnet Allocator<br/>IP Management]
        GuacamoleManager[Guacamole Manager<br/>Connection Setup]
        SessionGuacManager[Session Guacamole Manager<br/>User Management]
    end

    subgraph "Infrastructure"
        DockerEngine[Docker Engine]
        GitRepo[GitHub Repository]
        GuacamoleService[Guacamole Service]
        Databases[(Databases)]
    end

    Dashboard --> AuthService
    ChatInterface --> ChatService
    Generate --> ChallengeService
    
    ChatService --> DockerManager
    ChallengeService --> GitManager
    ChallengeService --> SubnetAllocator
    ChallengeService --> GuacamoleManager
    ChallengeService --> SessionGuacManager
    
    DockerManager --> DockerEngine
    GitManager --> GitRepo
    GuacamoleManager --> GuacamoleService
    SessionGuacManager --> Databases
    AuthService --> Databases
    ChatService --> Databases

    style Dashboard fill:#c8e6c9
    style ChatInterface fill:#c8e6c9
    style DockerManager fill:#f8bbd0
    style GitManager fill:#f8bbd0
    style GuacamoleManager fill:#f8bbd0
```

---

## 🌐 Network Topology

```mermaid
graph TB
    subgraph "Internet"
        UserBrowser[User Browser]
    end

    subgraph "Host Machine - Docker Host"
        subgraph "Bridge Network: ctf-network"
            Frontend[Frontend:4000]
            Backend[Backend:4002]
            CTFAuto[CTF Automation:4003]
            Postgres[PostgreSQL:5433]
            GuacamoleWeb[Guacamole Web:8081]
            MySQL[MySQL:3307]
        end

        subgraph "Bridge Network: ctf-instances-network"
            Guacd[Guacamole Daemon<br/>guacd]
        end

        subgraph "Challenge Network 1: 172.23.156.0/24"
            Attacker1[Attacker: 172.23.156.3]
            Victim1A[Victim 1: 172.23.156.4]
            Victim1B[Victim 2: 172.23.156.5]
        end

        subgraph "Challenge Network 2: 172.23.157.0/24"
            Attacker2[Attacker: 172.23.157.3]
            Victim2A[Victim 1: 172.23.157.4]
        end
    end

    UserBrowser -->|HTTP:4000| Frontend
    UserBrowser -->|HTTP:8081| GuacamoleWeb
    Frontend -->|HTTP:4002| Backend
    Backend -->|HTTP:4003| CTFAuto
    Backend -->|PostgreSQL| Postgres
    CTFAuto -->|Docker API| Attacker1
    CTFAuto -->|Docker API| Attacker2
    CTFAuto -->|MySQL| MySQL
    GuacamoleWeb -->|WebSocket| Guacd
    Guacd -.->|SSH:22| Attacker1
    Guacd -.->|SSH:22| Attacker2
    Attacker1 -->|Network Scan| Victim1A
    Attacker1 -->|Network Scan| Victim1B
    Attacker2 -->|Network Scan| Victim2A

    style UserBrowser fill:#e1f5ff
    style Frontend fill:#c8e6c9
    style Backend fill:#fff9c4
    style CTFAuto fill:#f8bbd0
    style Attacker1 fill:#ff9800
    style Attacker2 fill:#ff9800
    style Victim1A fill:#f44336
    style Victim1B fill:#f44336
    style Victim2A fill:#f44336
    style Guacd fill:#4caf50
    style GuacamoleWeb fill:#4caf50
```

---

## 📝 Notes

### Port Configuration
- **Frontend**: 4000
- **Backend API**: 4002
- **CTF Automation**: 4003
- **PostgreSQL**: 5433
- **MySQL (Guacamole)**: 3307
- **Guacamole Web**: 8081

### Network Ranges
- Challenge networks: `172.23.{20-30}.{userId}.0/24`
- Attacker IP: Always `.3`
- Victim IPs: `.4` to `.253` (randomized)

### Key Features
- **Session-based isolation**: Each user session gets isolated Guacamole access
- **Auto-error fixing**: Automatic detection and resolution of deployment errors
- **Victim validation**: Ensures all containers are running and accessible
- **AI-powered generation**: Uses OpenAI GPT-4 and Anthropic Claude for challenge creation

---

**Last Updated**: 2025-01-03  
**Version**: 2.0

