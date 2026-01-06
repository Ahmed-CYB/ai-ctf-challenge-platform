# AI CTF Challenge Platform - Activity Diagram

## Overview

This document contains the comprehensive activity diagram for the AI-Powered Platform for Automated CTF Challenge Generation and Deployment. The activity diagram illustrates the dynamic behavior and workflow of the system, showing the sequence of activities, decision points, and parallel processes.

---

## Main Activity Diagram

The main activity diagram covers the complete user journey from registration to challenge creation, deployment, and access.

```mermaid
flowchart TD
    Start([Start])
    End([End])
    
    %% Registration and Authentication Flow
    Start --> CheckAccount{User has account?}
    CheckAccount -->|No| Register[Register Account]
    CheckAccount -->|Yes| Login[Login to Platform]
    
    Register --> ValidateReg{Validate Registration Data}
    ValidateReg -->|Invalid| Register
    ValidateReg -->|Valid| SaveUser[Save User to Database]
    SaveUser --> GenerateToken[Generate JWT Token]
    GenerateToken --> CreateSession[Create User Session]
    CreateSession --> Dashboard
    
    Login --> ValidateCred{Validate Credentials}
    ValidateCred -->|Invalid| Login
    ValidateCred -->|Valid| VerifyAccount{Account Active?}
    VerifyAccount -->|No| End
    VerifyAccount -->|Yes| GenerateToken
    
    %% Dashboard and Main Menu
    Dashboard[View Dashboard]
    Dashboard --> MainMenu{Select Action}
    
    %% Profile Management Flow
    MainMenu -->|Manage Profile| ViewProfile[View Profile]
    ViewProfile --> EditProfile{Edit Profile?}
    EditProfile -->|Yes| UpdateProfile[Update Profile Information]
    UpdateProfile --> ValidateProfile{Validate Changes}
    ValidateProfile -->|Invalid| UpdateProfile
    ValidateProfile -->|Valid| SaveProfile[Save Profile to Database]
    SaveProfile --> Dashboard
    EditProfile -->|No| Dashboard
    
    %% Browse Challenges Flow
    MainMenu -->|Browse Challenges| BrowseChallenges[Browse Challenges]
    BrowseChallenges --> FilterChallenges{Apply Filters?}
    FilterChallenges -->|Yes| ApplyFilters[Apply Search/Filter]
    ApplyFilters --> DisplayChallenges[Display Challenge List]
    FilterChallenges -->|No| DisplayChallenges
    DisplayChallenges --> SelectChallenge{Select Challenge?}
    SelectChallenge -->|Yes| ViewDetails[View Challenge Details]
    SelectChallenge -->|No| Dashboard
    ViewDetails --> ChallengeActions{Action on Challenge?}
    ChallengeActions -->|Deploy| DeployFlow
    ChallengeActions -->|Access| AccessFlow
    ChallengeActions -->|Back| BrowseChallenges
    
    %% Challenge Creation Flow
    MainMenu -->|Create Challenge| OpenChat[Open Chat Interface]
    OpenChat --> EnterRequest[Enter Challenge Request]
    EnterRequest --> SaveMessage[Save User Message to Database]
    SaveMessage --> ForwardRequest[Forward to CTF Automation Service]
    ForwardRequest --> ClassifyIntent[Classifier Agent: Analyze Intent]
    ClassifyIntent --> IntentType{Intent Type?}
    
    IntentType -->|CREATE| CreateFlow
    IntentType -->|DEPLOY| DeployFlow
    IntentType -->|QUESTION| QuestionFlow
    IntentType -->|CHALLENGE_INFO| InfoFlow
    
    %% Create Challenge Flow
    CreateFlow[Route to Create Agent]
    CreateFlow --> GenerateContent[Send Request to OpenAI API]
    GenerateContent --> ReceiveContent[Receive Challenge Structure]
    ReceiveContent --> ValidateContent[Send to Anthropic for Validation]
    ValidateContent --> ValidationResult{Validation Passed?}
    ValidationResult -->|No| RegenerateContent[Request Regeneration]
    RegenerateContent --> GenerateContent
    ValidationResult -->|Yes| GenerateDockerfiles[Generate Dockerfiles]
    GenerateDockerfiles --> CreateStructure[Create Directory Structure]
    CreateStructure --> CommitFiles[Commit Files to Git]
    CommitFiles --> PushGitHub[Push to GitHub Repository]
    PushGitHub --> PushResult{GitHub Push Success?}
    PushResult -->|No| ErrorGitHub[Display Error Message]
    ErrorGitHub --> EnterRequest
    PushResult -->|Yes| StoreMetadata[Store Challenge Metadata in Database]
    StoreMetadata --> ConfirmCreation[Display Creation Confirmation]
    ConfirmCreation --> PostCreation{Post-Creation Action?}
    PostCreation -->|Save| SaveChallenge[Save Challenge to Database]
    PostCreation -->|Deploy| DeployFlow
    PostCreation -->|Browse| BrowseChallenges
    PostCreation -->|Continue| OpenChat
    SaveChallenge --> Dashboard
    
    %% Deployment Flow
    DeployFlow[Route to Deploy Agent]
    DeployFlow --> RetrieveMetadata[Retrieve Challenge Metadata]
    RetrieveMetadata --> ChallengeExists{Challenge Exists?}
    ChallengeExists -->|No| ErrorNotFound[Display Error: Challenge Not Found]
    ErrorNotFound --> Dashboard
    ChallengeExists -->|Yes| CloneRepo[Clone Challenge from GitHub]
    CloneRepo --> PreValidate[Pre-Deployment Validation]
    PreValidate --> PreValResult{Validation Passed?}
    PreValResult -->|No| AutoFix[Attempt Auto-Fix]
    AutoFix --> FixResult{Auto-Fix Success?}
    FixResult -->|No| ErrorValidation[Display Validation Error]
    ErrorValidation --> Dashboard
    FixResult -->|Yes| PreValidate
    PreValResult -->|Yes| AllocateNetwork[Allocate Subnet and IP Addresses]
    AllocateNetwork --> CreateNetwork[Create Docker Network]
    CreateNetwork --> BuildContainers[Execute docker compose up --build]
    BuildContainers --> BuildResult{Build Success?}
    BuildResult -->|No| AnalyzeError[Analyze Build Error]
    AnalyzeError --> RequestFix[Request AI Fix Suggestions]
    RequestFix --> ApplyFix[Apply Fixes]
    ApplyFix --> RetryCount{Retry Count < 3?}
    RetryCount -->|Yes| BuildContainers
    RetryCount -->|No| ErrorBuild[Display Build Error]
    ErrorBuild --> Dashboard
    BuildResult -->|Yes| WaitHealth[Wait for Containers to be Healthy]
    WaitHealth --> PostValidate[Post-Deployment Validation]
    PostValidate --> PostValResult{Validation Passed?}
    PostValResult -->|No| FixStartup[Fix Startup Scripts]
    FixStartup --> RestartContainers[Restart Containers]
    RestartContainers --> PostValidate
    PostValResult -->|Yes| CreateGuacamoleUser[Create Guacamole User]
    CreateGuacamoleUser --> ConfigGuacamole[Configure Guacamole Connection]
    ConfigGuacamole --> UpdateStatus[Update Deployment Status in Database]
    UpdateStatus --> ReturnURL[Return Guacamole Access URL]
    ReturnURL --> DisplayDeploySuccess[Display Deployment Success]
    DisplayDeploySuccess --> AccessFlow
    
    %% Access Challenge Flow
    AccessFlow[Access Challenge Environment]
    AccessFlow --> GetGuacamoleURL[Retrieve Guacamole Connection URL]
    GetGuacamoleURL --> RedirectGuacamole[Redirect to Guacamole Web Interface]
    RedirectGuacamole --> AuthenticateGuacamole[Guacamole Authenticates Session]
    AuthenticateGuacamole --> EstablishSSH[Establish SSH Connection to Container]
    EstablishSSH --> ConnectionResult{Connection Success?}
    ConnectionResult -->|No| ErrorConnection[Display Connection Error]
    ErrorConnection --> Dashboard
    ConnectionResult -->|Yes| DisplayTerminal[Display Terminal Interface]
    DisplayTerminal --> InteractChallenge[User Interacts with Challenge]
    InteractChallenge --> ChallengeAction{User Action?}
    ChallengeAction -->|Ask Question| QuestionFlow
    ChallengeAction -->|Request Hint| HintFlow
    ChallengeAction -->|Submit Flag| FlagFlow
    ChallengeAction -->|Continue| InteractChallenge
    ChallengeAction -->|Exit| LogSession[Log Session Activity]
    LogSession --> Dashboard
    
    %% Question Flow
    QuestionFlow[Route to Questions Agent]
    QuestionFlow --> ProcessQuestion[Process Question via AI]
    ProcessQuestion --> ReturnAnswer[Return AI Answer]
    ReturnAnswer --> SaveResponse[Save Response to Chat History]
    SaveResponse --> DisplayAnswer[Display Answer in Chat]
    DisplayAnswer --> OpenChat
    
    %% Hint Flow
    HintFlow[Request Hint from AI]
    HintFlow --> GenerateHint[AI Generates Hint]
    GenerateHint --> ReturnHint[Return Hint to User]
    ReturnHint --> SaveHint[Save Hint to Chat History]
    SaveHint --> DisplayHint[Display Hint]
    DisplayHint --> InteractChallenge
    
    %% Flag Submission Flow
    FlagFlow[Submit Flag for Verification]
    FlagFlow --> VerifyFlag[Verify Flag Against Database]
    VerifyFlag --> FlagCorrect{Flag Correct?}
    FlagCorrect -->|Yes| MarkSolved[Mark Challenge as Solved]
    MarkSolved --> UpdateStats[Update User Statistics]
    UpdateStats --> DisplaySuccess[Display Success Message]
    DisplaySuccess --> SaveIfNeeded{Challenge Saved?}
    SaveIfNeeded -->|No| SaveChallenge
    SaveIfNeeded -->|Yes| Dashboard
    FlagCorrect -->|No| DisplayFailure[Display Failure Message]
    DisplayFailure --> InteractChallenge
    
    %% Info Flow
    InfoFlow[Route to Challenge Info Agent]
    InfoFlow --> RetrieveInfo[Retrieve Challenge Information]
    RetrieveInfo --> ReturnInfo[Return Challenge Details]
    ReturnInfo --> SaveInfo[Save to Chat History]
    SaveInfo --> DisplayInfo[Display Information]
    DisplayInfo --> OpenChat
    
    %% Logout Flow
    MainMenu -->|Logout| ConfirmLogout{Confirm Logout?}
    ConfirmLogout -->|No| Dashboard
    ConfirmLogout -->|Yes| InvalidateToken[Invalidate JWT Token]
    InvalidateToken --> DestroySession[Destroy Session Record]
    DestroySession --> ClearCookie[Clear Session Cookie]
    ClearCookie --> RedirectLogin[Redirect to Login Page]
    RedirectLogin --> End
    
    style Start fill:#90EE90
    style End fill:#FFB6C1
    style Dashboard fill:#87CEEB
    style CreateFlow fill:#FFD700
    style DeployFlow fill:#FFA500
    style AccessFlow fill:#98FB98
    style QuestionFlow fill:#DDA0DD
    style FlagFlow fill:#F0E68C
```

---

## Detailed Activity Diagrams

### 1. Challenge Creation Activity Diagram

This diagram focuses specifically on the challenge creation workflow with detailed AI interactions.

```mermaid
flowchart TD
    Start([Start: User Initiates Challenge Creation])
    End([End: Challenge Created])
    
    Start --> OpenChat[Open Chat Interface]
    OpenChat --> EnterRequest[User Enters Challenge Request]
    EnterRequest --> SaveMessage[Save User Message to Database]
    SaveMessage --> ForwardService[Forward to CTF Automation Service]
    
    ForwardService --> Classify[Classifier Agent: Analyze Intent]
    Classify --> CheckIntent{Intent = CREATE?}
    CheckIntent -->|No| RouteOther[Route to Other Agent]
    CheckIntent -->|Yes| CreateAgent[Route to Create Agent]
    
    CreateAgent --> FormatPrompt[Format Prompt for OpenAI]
    FormatPrompt --> CallOpenAI[Call OpenAI API]
    CallOpenAI --> APICheck1{API Call Success?}
    APICheck1 -->|No| Retry1{Retry Count < 3?}
    Retry1 -->|Yes| CallOpenAI
    Retry1 -->|No| ErrorAI[Display Error: AI Service Unavailable]
    ErrorAI --> End
    
    APICheck1 -->|Yes| ReceiveStructure[Receive Challenge Structure]
    ReceiveStructure --> ValidateAnthropic[Send to Anthropic for Validation]
    ValidateAnthropic --> APICheck2{Anthropic API Success?}
    APICheck2 -->|No| Retry2{Retry Count < 3?}
    Retry2 -->|Yes| ValidateAnthropic
    Retry2 -->|No| ErrorAI
    
    APICheck2 -->|Yes| ValidationResult{Validation Passed?}
    ValidationResult -->|No| RequestImprovements[Request Improvements from Anthropic]
    RequestImprovements --> Regenerate[Request OpenAI to Regenerate]
    Regenerate --> CallOpenAI
    ValidationResult -->|Yes| GenerateDocker[Generate Dockerfiles for All Machines]
    
    GenerateDocker --> CreateDir[Create Challenge Directory Structure]
    CreateDir --> InitGit[Initialize Git Repository]
    InitGit --> AddFiles[Add All Challenge Files]
    AddFiles --> Commit[Commit Files with Message]
    Commit --> PushGitHub[Push to GitHub Repository]
    PushGitHub --> GitHubResult{GitHub Push Success?}
    GitHubResult -->|No| ErrorGitHub[Display Error: GitHub Push Failed]
    ErrorGitHub --> End
    GitHubResult -->|Yes| StoreDB[Store Challenge Metadata in PostgreSQL]
    StoreDB --> ReturnSuccess[Return Success Message to User]
    ReturnSuccess --> DisplayConfirm[Display Challenge Creation Confirmation]
    DisplayConfirm --> End
    
    style Start fill:#90EE90
    style End fill:#FFB6C1
    style CreateAgent fill:#FFD700
    style CallOpenAI fill:#87CEEB
    style ValidateAnthropic fill:#DDA0DD
    style PushGitHub fill:#98FB98
```

### 2. Challenge Deployment Activity Diagram

This diagram details the deployment process including validation, Docker operations, and Guacamole setup.

```mermaid
flowchart TD
    Start([Start: User Requests Deployment])
    End([End: Challenge Deployed])
    
    Start --> ReceiveRequest[Receive Deploy Request via Chat]
    ReceiveRequest --> SaveDeployMsg[Save Deployment Message]
    SaveDeployMsg --> ClassifyDeploy[Classifier Agent: Identify Intent as DEPLOY]
    ClassifyDeploy --> RouteDeploy[Route to Deploy Agent]
    
    RouteDeploy --> RetrieveMeta[Retrieve Challenge Metadata from Database]
    RetrieveMeta --> CheckExists{Challenge Exists?}
    CheckExists -->|No| ErrorNotFound[Display Error: Challenge Not Found]
    ErrorNotFound --> End
    
    CheckExists -->|Yes| CloneGitHub[Clone Challenge Repository from GitHub]
    CloneGitHub --> PreValidate[Pre-Deployment Validation]
    PreValidate --> ReadDockerfiles[Read Dockerfiles and docker-compose.yml]
    ReadDockerfiles --> CheckSyntax[Check Syntax and Structure]
    CheckSyntax --> ValidateConfig[Validate Container Configurations]
    ValidateConfig --> PreValResult{Pre-Validation Passed?}
    
    PreValResult -->|No| AutoFix[Auto-Fix Agent Attempts Fixes]
    AutoFix --> FixSuccess{Fix Successful?}
    FixSuccess -->|No| ErrorValidation[Display Validation Error]
    ErrorValidation --> End
    FixSuccess -->|Yes| PreValidate
    
    PreValResult -->|Yes| AllocateSubnet[Allocate Subnet 172.23.x.x/24]
    AllocateSubnet --> AllocateIPs[Allocate IP Addresses for Containers]
    AllocateIPs --> CreateDockerNet[Create Docker Network via Docker API]
    CreateDockerNet --> NetResult{Network Created?}
    NetResult -->|No| ErrorNetwork[Display Error: Network Creation Failed]
    ErrorNetwork --> End
    
    NetResult -->|Yes| ExecuteCompose[Execute docker compose up --build]
    ExecuteCompose --> BuildImages[Docker Engine Builds Container Images]
    BuildImages --> BuildResult{Build Success?}
    BuildResult -->|No| AnalyzeError[Analyze Build Error Logs]
    AnalyzeError --> RequestAIFix[Request OpenAI for Fix Suggestions]
    RequestAIFix --> ApplyFixes[Apply Suggested Fixes]
    ApplyFixes --> RetryCount{Retry Count < 3?}
    RetryCount -->|Yes| ExecuteCompose
    RetryCount -->|No| ErrorBuild[Display Build Error]
    ErrorBuild --> End
    
    BuildResult -->|Yes| StartContainers[Docker Engine Starts Containers]
    StartContainers --> AttachNetwork[Attach Containers to Network]
    AttachNetwork --> WaitHealth[Wait for Containers to be Healthy]
    WaitHealth --> HealthCheck{Containers Healthy?}
    HealthCheck -->|No| CheckLogs[Check Container Logs]
    CheckLogs --> RestartContainers[Restart Containers]
    RestartContainers --> WaitHealth
    
    HealthCheck -->|Yes| PostValidate[Post-Deployment Validation]
    PostValidate --> TestServices[Test Container Services and Connectivity]
    TestServices --> PostValResult{Post-Validation Passed?}
    PostValResult -->|No| FixStartup[Fix Startup Scripts]
    FixStartup --> RestartContainers
    PostValResult -->|Yes| CreateGuacUser[Create Guacamole User if Needed]
    CreateGuacUser --> CreateGuacConn[Create Guacamole Connection in MySQL]
    CreateGuacConn --> SetParams[Set Connection Parameters]
    SetParams --> GrantPerms[Grant User Permissions]
    GrantPerms --> GuacResult{Guacamole Connection Created?}
    GuacResult -->|No| ErrorGuacamole[Display Error: Guacamole Setup Failed]
    ErrorGuacamole --> End
    
    GuacResult -->|Yes| UpdateDeployStatus[Update Deployment Status in Database]
    UpdateDeployStatus --> GenerateURL[Generate Guacamole Access URL]
    GenerateURL --> ReturnCredentials[Return Access URL and Credentials]
    ReturnCredentials --> DisplaySuccess[Display Deployment Success Message]
    DisplaySuccess --> End
    
    style Start fill:#90EE90
    style End fill:#FFB6C1
    style RouteDeploy fill:#FFD700
    style PreValidate fill:#87CEEB
    style ExecuteCompose fill:#FFA500
    style PostValidate fill:#98FB98
    style CreateGuacConn fill:#DDA0DD
```

### 3. User Authentication Activity Diagram

This diagram shows the complete authentication flow including registration and login.

```mermaid
flowchart TD
    Start([Start: User Accesses Platform])
    End([End: User Authenticated])
    EndLogout([End: User Logged Out])
    
    Start --> CheckAccount{User Has Account?}
    CheckAccount -->|No| ShowRegister[Display Registration Form]
    CheckAccount -->|Yes| ShowLogin[Display Login Form]
    
    %% Registration Flow
    ShowRegister --> EnterRegData[User Enters Registration Data]
    EnterRegData --> ValidateEmail{Email Format Valid?}
    ValidateEmail -->|No| ErrorEmail[Display Error: Invalid Email]
    ErrorEmail --> EnterRegData
    ValidateEmail -->|Yes| ValidatePassword{Password Strength Valid?}
    ValidatePassword -->|No| ErrorPassword[Display Error: Weak Password]
    ErrorPassword --> EnterRegData
    ValidatePassword -->|Yes| CheckUsername{Username Unique?}
    CheckUsername -->|No| ErrorUsername[Display Error: Username Exists]
    ErrorUsername --> EnterRegData
    CheckUsername -->|Yes| CheckEmail{Email Unique?}
    CheckEmail -->|No| ErrorEmailExists[Display Error: Email Registered]
    ErrorEmailExists --> EnterRegData
    CheckEmail -->|Yes| HashPassword[Hash Password with bcryptjs]
    HashPassword --> SaveUser[Save User to PostgreSQL]
    SaveUser --> DBResult{Database Save Success?}
    DBResult -->|No| ErrorDB[Display Error: Registration Failed]
    ErrorDB --> End
    DBResult -->|Yes| GenerateJWT[Generate JWT Token]
    GenerateJWT --> CreateSession[Create User Session]
    CreateSession --> RedirectDash[Redirect to Dashboard]
    RedirectDash --> End
    
    %% Login Flow
    ShowLogin --> EnterCredentials[User Enters Email and Password]
    EnterCredentials --> ValidateFormat{Input Format Valid?}
    ValidateFormat -->|No| ErrorFormat[Display Error: Invalid Format]
    ErrorFormat --> EnterCredentials
    ValidateFormat -->|Yes| QueryUser[Query User from Database]
    QueryUser --> UserFound{User Found?}
    UserFound -->|No| ErrorCred[Display Error: Invalid Credentials]
    ErrorCred --> IncrementAttempts[Increment Failed Login Attempts]
    IncrementAttempts --> CheckAttempts{Failed Attempts >= 5?}
    CheckAttempts -->|Yes| LockAccount[Lock Account for 15 Minutes]
    LockAccount --> EnterCredentials
    CheckAttempts -->|No| EnterCredentials
    
    UserFound -->|Yes| ComparePassword[Compare Password with Hash]
    ComparePassword --> PasswordMatch{Password Matches?}
    PasswordMatch -->|No| ErrorCred
    PasswordMatch -->|Yes| CheckActive{Account Active?}
    CheckActive -->|No| ErrorInactive[Display Error: Account Inactive]
    ErrorInactive --> End
    CheckActive -->|Yes| CheckLocked{Account Locked?}
    CheckLocked -->|Yes| ErrorLocked[Display Error: Account Locked]
    ErrorLocked --> End
    CheckLocked -->|No| GenerateJWT
    GenerateJWT --> CreateGuacUser[Create Guacamole User if Needed]
    CreateGuacUser --> StoreToken[Store JWT Token in Browser]
    StoreToken --> RedirectDash
    
    %% Logout Flow
    End --> UserAction{User Action}
    UserAction -->|Logout| ConfirmLogout{Confirm Logout?}
    ConfirmLogout -->|No| UserAction
    ConfirmLogout -->|Yes| InvalidateJWT[Invalidate JWT Token]
    InvalidateJWT --> DestroySession[Destroy Session Record]
    DestroySession --> ClearCookie[Clear Session Cookie]
    ClearCookie --> RedirectLogin[Redirect to Login Page]
    RedirectLogin --> EndLogout
    
    style Start fill:#90EE90
    style End fill:#FFB6C1
    style EndLogout fill:#FFB6C1
    style ShowRegister fill:#87CEEB
    style ShowLogin fill:#87CEEB
    style HashPassword fill:#FFD700
    style GenerateJWT fill:#FFA500
```

---

## Activity Diagram Elements

### Symbols Used

1. **Start Node** (Filled Circle): Represents the beginning of the activity flow
2. **End Node** (Filled Circle with Border): Represents the end of the activity flow
3. **Activity** (Rounded Rectangle): Represents an action or task performed
4. **Decision Node** (Diamond): Represents a decision point with multiple possible outcomes
5. **Fork Node** (Horizontal Bar): Represents the start of parallel activities
6. **Join Node** (Horizontal Bar): Represents the synchronization of parallel activities
7. **Flow** (Arrow): Represents the transition from one activity to another

### Swimlanes (Implicit)

While the main diagram doesn't explicitly show swimlanes, the activities can be conceptually organized into:

1. **User Swimlane**: User-initiated actions (entering data, clicking buttons)
2. **Frontend Swimlane**: UI rendering and user interaction handling
3. **Backend API Swimlane**: Request processing and routing
4. **CTF Automation Service Swimlane**: AI agent orchestration
5. **External Services Swimlane**: OpenAI, Anthropic, GitHub, Docker, Guacamole

---

## Key Workflows Covered

### 1. User Registration and Authentication
- Account registration with validation
- Login with credential verification
- Session management
- Logout process

### 2. Challenge Creation
- AI-powered challenge generation
- Content validation
- File storage in GitHub
- Database metadata storage

### 3. Challenge Deployment
- Pre-deployment validation
- Docker container orchestration
- Network isolation
- Guacamole access setup

### 4. Challenge Access
- Guacamole connection establishment
- Terminal interaction
- Hint and question handling
- Flag submission and verification

### 5. Profile Management
- View and edit profile
- Password change
- Data validation

### 6. Challenge Browsing
- List challenges
- Filter and search
- View details
- Select actions

---

## Decision Points

The activity diagram includes several critical decision points:

1. **Account Existence**: Determines registration vs. login flow
2. **Validation Results**: Determines if operations can proceed or need correction
3. **API Success**: Determines if external service calls succeeded
4. **Intent Classification**: Routes requests to appropriate AI agents
5. **User Actions**: Determines next steps based on user choices
6. **Flag Verification**: Determines challenge completion status

---

## Parallel Activities

While the current implementation is primarily sequential, potential parallel activities include:

1. **AI API Calls**: OpenAI and Anthropic could theoretically be called in parallel (though current flow uses them sequentially for validation)
2. **Container Health Checks**: Multiple containers can be checked simultaneously
3. **File Operations**: Multiple challenge files can be processed concurrently

---

## Error Handling

The activity diagram includes error handling paths for:

1. **Validation Errors**: Input validation failures with retry options
2. **API Failures**: External service unavailability with retry mechanisms
3. **Build Errors**: Docker build failures with auto-fix attempts
4. **Connection Errors**: Network and service connection failures
5. **Database Errors**: Data persistence failures

---

## Best Practices Applied

1. **Clear Start and End Points**: Each workflow has explicit start and end nodes
2. **Decision Points**: All conditional flows use proper decision nodes
3. **Error Handling**: Alternative paths for error scenarios
4. **Modularity**: Separate diagrams for complex workflows
5. **Consistent Notation**: Standard UML activity diagram symbols
6. **Readability**: Logical flow from top to bottom, left to right
7. **Completeness**: Covers all major use cases from the use case diagram

---

## References

- UML 2.5 Activity Diagram Specification
- Use Case Diagram: `USE_CASE_DIAGRAM_DETAILED.md`
- Project Logic Flow: `PROJECT_LOGIC_FLOW.md`
- System Architecture: `SYSTEM_ARCHITECTURE.md`

---

**Last Updated**: 2025-01-27  
**Version**: 1.0  
**Author**: Based on AI CTF Challenge Platform Requirements

