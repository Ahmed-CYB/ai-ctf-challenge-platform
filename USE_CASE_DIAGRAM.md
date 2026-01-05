# AI CTF Challenge Platform - Use Case Diagram

## Use Case Diagram

```mermaid
graph TB
    subgraph System["AI CTF Challenge Platform"]
        UC1[Register User]
        UC2[Login User]
        UC3[Logout User]
        UC4[View Dashboard]
        UC5[Create Challenge]
        UC6[Deploy Challenge]
        UC7[Chat with AI]
        UC8[View Chat History]
        UC9[Access Challenge]
        UC10[View Profile]
        UC11[Edit Profile]
        UC12[View Challenges List]
        UC13[Manage Session]
    end

    User((User))
    OpenAI((OpenAI API))
    Anthropic((Anthropic API))
    GitHub((GitHub))
    Guacamole((Guacamole))

    %% User Associations
    User -->|uses| UC1
    User -->|uses| UC2
    User -->|uses| UC3
    User -->|uses| UC4
    User -->|uses| UC5
    User -->|uses| UC6
    User -->|uses| UC7
    User -->|uses| UC8
    User -->|uses| UC9
    User -->|uses| UC10
    User -->|uses| UC11
    User -->|uses| UC12

    %% Include Relationships
    UC2 -.->|<<include>>| UC13
    UC5 -.->|<<include>>| UC7
    UC6 -.->|<<include>>| UC7
    UC6 -.->|<<include>>| UC9
    UC10 -.->|<<include>>| UC11

    %% Extend Relationships
    UC7 -.->|<<extend>>| UC8
    UC5 -.->|<<extend>>| UC12
    UC6 -.->|<<extend>>| UC12
    UC9 -.->|<<extend>>| UC8

    %% External Actor Associations
    UC5 -->|uses| OpenAI
    UC5 -->|uses| Anthropic
    UC5 -->|uses| GitHub
    UC6 -->|uses| GitHub
    UC6 -->|uses| Guacamole
    UC7 -->|uses| OpenAI
    UC7 -->|uses| Anthropic

    style System fill:#e1f5ff,stroke:#01579b,stroke-width:2px
    style User fill:#fff9c4,stroke:#f57f17,stroke-width:2px
    style OpenAI fill:#ffccbc,stroke:#bf360c,stroke-width:2px
    style Anthropic fill:#ffccbc,stroke:#bf360c,stroke-width:2px
    style GitHub fill:#ffccbc,stroke:#bf360c,stroke-width:2px
    style Guacamole fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
```

---

## Use Case Descriptions

### Primary Use Cases

#### 1. **Register User**
- **Actor**: User
- **Description**: New user creates an account with email, username, and password
- **Preconditions**: User is not logged in
- **Postconditions**: User account created, user can login

#### 2. **Login User**
- **Actor**: User
- **Description**: User authenticates with credentials to access the platform
- **Preconditions**: User has an account
- **Postconditions**: User is authenticated, session created
- **Includes**: Manage Session

#### 3. **Logout User**
- **Actor**: User
- **Description**: User ends their session and logs out
- **Preconditions**: User is logged in
- **Postconditions**: Session destroyed, user logged out

#### 4. **View Dashboard**
- **Actor**: User
- **Description**: User views the main dashboard with platform overview
- **Preconditions**: User is logged in
- **Postconditions**: Dashboard displayed

#### 5. **Create Challenge**
- **Actor**: User, OpenAI API, Anthropic API, GitHub
- **Description**: User requests AI to create a new CTF challenge via chat
- **Preconditions**: User is logged in
- **Postconditions**: Challenge created and stored in GitHub repository
- **Includes**: Chat with AI
- **Extends**: View Challenges List

#### 6. **Deploy Challenge**
- **Actor**: User, GitHub, Guacamole
- **Description**: User requests to deploy an existing challenge, creating containers and access
- **Preconditions**: Challenge exists, user is logged in
- **Postconditions**: Challenge deployed, containers running, Guacamole access created
- **Includes**: Chat with AI, Access Challenge
- **Extends**: View Challenges List

#### 7. **Chat with AI**
- **Actor**: User, OpenAI API, Anthropic API
- **Description**: User interacts with AI assistant for challenge creation, deployment, or questions
- **Preconditions**: User is logged in
- **Postconditions**: Chat message sent, AI response received
- **Extends**: View Chat History

#### 8. **View Chat History**
- **Actor**: User
- **Description**: User views previous chat conversations
- **Preconditions**: User is logged in, has chat history
- **Postconditions**: Chat history displayed

#### 9. **Access Challenge**
- **Actor**: User, Guacamole
- **Description**: User accesses deployed challenge via browser-based SSH/RDP through Guacamole
- **Preconditions**: Challenge is deployed, user is logged in
- **Postconditions**: User has terminal access to challenge containers
- **Extends**: View Chat History

#### 10. **View Profile**
- **Actor**: User
- **Description**: User views their profile information
- **Preconditions**: User is logged in
- **Postconditions**: Profile information displayed
- **Includes**: Edit Profile

#### 11. **Edit Profile**
- **Actor**: User
- **Description**: User updates their profile information (name, avatar, password)
- **Preconditions**: User is logged in
- **Postconditions**: Profile updated

#### 12. **View Challenges List**
- **Actor**: User
- **Description**: User views list of available challenges
- **Preconditions**: User is logged in
- **Postconditions**: Challenges list displayed

#### 13. **Manage Session**
- **Actor**: System
- **Description**: System manages user session (create, validate, regenerate, destroy)
- **Preconditions**: User is authenticating or authenticated
- **Postconditions**: Session managed appropriately

---

## Relationships

### Include Relationships (<<include>>)
- **Login User** includes **Manage Session** (mandatory)
- **Create Challenge** includes **Chat with AI** (mandatory)
- **Deploy Challenge** includes **Chat with AI** (mandatory)
- **Deploy Challenge** includes **Access Challenge** (mandatory)
- **View Profile** includes **Edit Profile** (mandatory)

### Extend Relationships (<<extend>>)
- **Chat with AI** extends **View Chat History** (optional)
- **Create Challenge** extends **View Challenges List** (optional)
- **Deploy Challenge** extends **View Challenges List** (optional)
- **Access Challenge** extends **View Chat History** (optional)

---

## Actors

### Primary Actor
- **User**: The main user of the system who creates, deploys, and accesses CTF challenges

### External Actors
- **OpenAI API**: Provides AI-powered challenge generation and assistance
- **Anthropic API**: Provides AI validation and error analysis
- **GitHub**: Stores challenge repositories and files
- **Guacamole**: Provides browser-based SSH/RDP access to challenge containers

---

## Use Case Diagram in PlantUML Format

```plantuml
@startuml AI_CTF_Challenge_Platform_Use_Case_Diagram

left to right direction

actor User
actor "OpenAI API" as OpenAI
actor "Anthropic API" as Anthropic
actor GitHub
actor Guacamole

rectangle "AI CTF Challenge Platform" {
    usecase "Register User" as UC1
    usecase "Login User" as UC2
    usecase "Logout User" as UC3
    usecase "View Dashboard" as UC4
    usecase "Create Challenge" as UC5
    usecase "Deploy Challenge" as UC6
    usecase "Chat with AI" as UC7
    usecase "View Chat History" as UC8
    usecase "Access Challenge" as UC9
    usecase "View Profile" as UC10
    usecase "Edit Profile" as UC11
    usecase "View Challenges List" as UC12
    usecase "Manage Session" as UC13
}

User --> UC1
User --> UC2
User --> UC3
User --> UC4
User --> UC5
User --> UC6
User --> UC7
User --> UC8
User --> UC9
User --> UC10
User --> UC11
User --> UC12

UC2 ..> UC13 : <<include>>
UC5 ..> UC7 : <<include>>
UC6 ..> UC7 : <<include>>
UC6 ..> UC9 : <<include>>
UC10 ..> UC11 : <<include>>

UC7 ..> UC8 : <<extend>>
UC5 ..> UC12 : <<extend>>
UC6 ..> UC12 : <<extend>>
UC9 ..> UC8 : <<extend>>

UC5 --> OpenAI
UC5 --> Anthropic
UC5 --> GitHub
UC6 --> GitHub
UC6 --> Guacamole
UC7 --> OpenAI
UC7 --> Anthropic

@enduml
```

---

## Summary

**Total Use Cases**: 13
**Primary Actor**: User
**External Actors**: 4 (OpenAI API, Anthropic API, GitHub, Guacamole)
**Include Relationships**: 5
**Extend Relationships**: 4

---

**Last Updated**: 2025-01-27  
**Version**: 1.0

