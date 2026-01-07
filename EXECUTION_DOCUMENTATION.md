# 4.5 Execution

## 4.5.1 Introduction

This section presents the comprehensive implementation details of the AI-Powered CTF Challenge Platform, documenting the technical execution phase of the project. The implementation encompasses the selection and integration of various technologies, the development of core system components, API implementations, and the systematic procedures followed throughout the development lifecycle.

The platform was architected using a microservices-based approach, comprising three primary service components: a Node.js-based backend API server, a React frontend application, and an AI-powered CTF automation service. This architectural decision enables scalability, maintainability, and independent deployment of system components. The implementation follows industry best practices for security, code organization, and system reliability, incorporating automated testing, error handling, and comprehensive logging mechanisms.

The development process adhered to the Kanban-DevOps methodology, enabling continuous integration and deployment while maintaining flexibility in feature development. All system components were developed with a focus on modularity, allowing for future extensibility and maintenance.

---

## 4.5.2 Technology Selection and Implementation Rationale

### 4.5.2.1 Backend Framework: Node.js with Express.js

**Technology Choice**: Node.js (v18+) with Express.js framework was selected as the backend runtime environment and web application framework. Node.js provides an asynchronous, event-driven architecture that is ideal for handling concurrent API requests, making it well-suited for the platform's requirement to process multiple user requests simultaneously. Express.js was chosen for its minimal, flexible design that provides essential web application features without unnecessary complexity, enabling rapid development while maintaining code clarity.

**Implementation Details**: The backend server is implemented in `packages/backend/server.js`, utilizing Express.js middleware architecture to handle request processing, authentication, and database operations. The server configuration includes Helmet.js middleware for security headers, CORS middleware for cross-origin resource sharing, and body-parser middleware for JSON request parsing. The server listens on port 4002 and implements RESTful API endpoints for user authentication, session management, challenge metadata operations, and chat history persistence.

**Key Implementation Features**:
- **Connection Pooling**: PostgreSQL connections are managed through the `pg` library's Pool class, maintaining a pool of reusable database connections to optimize performance and prevent connection exhaustion.
- **Security Headers**: Helmet.js middleware configures HTTP security headers including HSTS (HTTP Strict Transport Security), XSS protection, frame guard, and content security policy.
- **JWT Authentication**: JSON Web Token authentication is implemented using the `jsonwebtoken` library, enabling stateless authentication that supports horizontal scaling across multiple server instances.
- **Password Hashing**: The `bcryptjs` library is used for password hashing, implementing one-way cryptographic hashing with automatic salt generation to protect user credentials.

### 4.5.2.2 Frontend Framework: React 18 with TypeScript

**Technology Choice**: React 18 with TypeScript was selected for the frontend application development. React provides a component-based architecture that enables code reusability and maintainability, while TypeScript adds static type checking that reduces runtime errors and improves code quality. The combination enables rapid UI development with strong type safety guarantees.

**Implementation Details**: The frontend application is built using Vite as the build tool, which provides fast development server startup and hot module replacement. The application uses React 18's concurrent features for improved performance and user experience. Tailwind CSS v4 is utilized for styling, providing utility-first CSS classes that enable rapid UI development while maintaining design consistency.

**Key Implementation Features**:
- **Component Architecture**: The application is organized into reusable components including `CTFChatInterface.tsx` for chat functionality, authentication components for login and registration, and challenge management components for browsing and viewing challenges.
- **State Management**: React hooks (useState, useEffect) are used for component-level state management, with sessionStorage for persistent session data storage.
- **API Communication**: Axios library is used for HTTP requests to the backend API, providing promise-based asynchronous request handling with automatic JSON parsing.
- **Type Safety**: TypeScript interfaces define data structures for API responses, user objects, challenge metadata, and chat messages, ensuring type safety throughout the application.

### 4.5.2.3 Database Systems: PostgreSQL and MySQL

**Technology Choice**: PostgreSQL 15 was selected as the primary database system for application data storage, while MySQL 8.0 is used exclusively for Apache Guacamole's database requirements. PostgreSQL was chosen for its ACID compliance, robust foreign key support, JSON data type capabilities, and excellent performance for concurrent read and write operations. MySQL is used for Guacamole because it is required by the Guacamole architecture and is optimized for connection management.

**Implementation Details**: The PostgreSQL database schema is defined in `database/schema.sql`, implementing normalized relational tables for users, challenges, sessions, and chat messages. The database connection is established using the `pg` library with connection pooling enabled. The MySQL database for Guacamole is managed through the `mysql2` library, with schema initialization handled by Guacamole's built-in database initialization scripts.

**Key Implementation Features**:
- **Schema Design**: The database schema implements proper normalization with foreign key constraints, ensuring data integrity and referential consistency.
- **Connection Pooling**: Both PostgreSQL and MySQL connections use connection pooling to optimize resource utilization and improve performance.
- **Transaction Support**: Critical operations such as user registration and challenge creation use database transactions to ensure atomicity and data consistency.
- **JSON Support**: PostgreSQL's native JSON data type is utilized for storing flexible metadata in chat messages and challenge configurations.

### 4.5.2.4 AI Services Integration: OpenAI and Anthropic APIs

**Technology Choice**: OpenAI GPT-4o and Anthropic Claude Sonnet 4 were selected as the AI models for challenge generation and validation. GPT-4o was chosen for its advanced language understanding and code generation capabilities, making it ideal for generating complete challenge implementations. Claude Sonnet 4 was selected for its complementary reasoning capabilities and alternative validation perspective.

**Implementation Details**: The AI integration is implemented in the CTF automation service (`packages/ctf-automation`), utilizing the official OpenAI SDK (`openai`) and Anthropic SDK (`@anthropic-ai/sdk`) for API communication. The classifier agent uses GPT-4o for request classification, while the create agent uses GPT-4o for challenge generation. The validator agents use Claude Sonnet 4 for challenge validation and error analysis.

**Key Implementation Features**:
- **Structured Output**: AI responses are configured to return structured JSON format, enabling programmatic processing of AI-generated content.
- **Retry Logic**: Exponential backoff retry logic handles transient API failures, ensuring system reliability.
- **Token Management**: Conversation history is limited to recent messages to balance context awareness with API token efficiency.
- **Error Handling**: Comprehensive error handling captures API failures and provides user-friendly error messages.

### 4.5.2.5 Containerization: Docker and Docker Compose

**Technology Choice**: Docker was selected for containerization of challenge environments, providing consistent execution environments, resource isolation, and portability. Docker Compose was chosen for multi-container orchestration, enabling simplified deployment of complex challenge architectures that require multiple containers.

**Implementation Details**: Docker operations are managed through the Docker Engine API using the `dockerode` library, enabling programmatic container creation, network management, and container lifecycle operations. Docker Compose is executed through child process spawning, running `docker compose up --build -d` commands within challenge directories.

**Key Implementation Features**:
- **Network Isolation**: Each challenge operates in its own isolated Docker network with allocated IP subnets from the 172.23.0.0/16 range.
- **Multi-Container Support**: Challenges can include multiple containers (attacker and victim machines) orchestrated through docker-compose.yml files.
- **Health Monitoring**: Container health is monitored through status checks and log analysis, ensuring challenges are fully operational before being made available to users.
- **Resource Cleanup**: Automated cleanup mechanisms remove containers and networks when challenges are undeployed, preventing resource exhaustion.

### 4.5.2.6 Remote Access: Apache Guacamole

**Technology Choice**: Apache Guacamole was selected as the browser-based remote access solution, eliminating the need for users to install SSH clients or configure VPN connections. Guacamole supports SSH, RDP, and VNC protocols, providing flexible remote access capabilities through a web browser.

**Implementation Details**: Guacamole integration is implemented through direct MySQL database operations using the `mysql2` library. The system creates session-specific Guacamole users and connections, enabling isolated access to challenge containers. Guacamole connection URLs are generated with authentication tokens, providing secure access to challenge environments.

**Key Implementation Features**:
- **Session Isolation**: Each user session receives a unique Guacamole user account, ensuring security isolation between different users and sessions.
- **Connection Management**: Guacamole connections are created dynamically during challenge deployment, with connection parameters configured for SSH access to challenge containers.
- **URL Generation**: Access URLs are generated with authentication tokens, enabling direct browser access to challenge environments without additional authentication steps.

---

## 4.5.3 System Initialization and Service Startup

### 4.5.3.1 Backend Server Initialization

**Figure 1: Backend Server Startup Terminal Output**

The backend server initialization process begins with loading environment variables from the `.env` file, which contains database connection strings, JWT secret keys, and service configuration parameters. The server then establishes a connection pool to the PostgreSQL database using the `pg` library's Pool class, configured with connection parameters including host, port, database name, username, and password. The connection pool is initialized with a maximum of 20 concurrent connections, enabling efficient handling of multiple simultaneous database requests.

The Express.js application is instantiated and configured with essential middleware including Helmet.js for security headers, CORS for cross-origin resource sharing, and body-parser for JSON request parsing. The server then registers API route handlers for authentication endpoints (`/api/auth/register`, `/api/auth/login`), session management endpoints (`/api/sessions/*`), chat endpoints (`/api/chat/*`), and challenge endpoints (`/api/challenges/*`). Each route handler implements appropriate authentication middleware using JWT token verification, ensuring that protected endpoints are only accessible to authenticated users.

The server startup sequence displays in the terminal output, showing successful database connection establishment, middleware registration confirmation, and server listening status on port 4002. The terminal output confirms that all required services are properly configured and the API endpoints are ready to accept requests, demonstrating successful system initialization.

**Technology Used**: Node.js runtime, Express.js framework, PostgreSQL database, `pg` library for database connectivity, `jsonwebtoken` library for JWT authentication, `bcryptjs` library for password hashing, `helmet` middleware for security headers, `cors` middleware for cross-origin resource sharing.

### 4.5.3.2 Database Connection and Schema Initialization

**Figure 2: PostgreSQL Database Connection via pgAdmin**

The PostgreSQL database connection is established through pgAdmin, a graphical administration tool for PostgreSQL databases. The connection interface displays the database server connection parameters, including host address (localhost), port number (5433), database name (ctf_platform), and authentication credentials. Upon successful connection, pgAdmin displays the complete database schema structure, showing all tables including users, challenges, sessions, chat_messages, and related tables.

The database schema is initialized by executing SQL scripts located in the `database/` directory, which create all required tables with appropriate columns, data types, constraints, and relationships. The users table includes columns for user_id (primary key), username (unique), email (unique), password_hash (bcrypt hashed), role, failed_login_attempts, account_locked_until, and timestamps. The challenges table establishes foreign key relationships with the users table, ensuring referential integrity. The chat_messages table stores conversation history with session_id grouping, enabling conversation context preservation.

The pgAdmin interface displays the schema browser showing table structures, column definitions, indexes, and foreign key constraints. This visual representation confirms that the database schema is properly initialized with all required tables and relationships, validating the database design implementation.

**Technology Used**: PostgreSQL 15 database server, pgAdmin administration tool, SQL schema definition language, `pg` library for Node.js database connectivity.

### 4.5.3.3 Frontend Application Compilation and Startup

**Figure 3: Frontend React Application Compilation**

The frontend application compilation process begins with Vite reading the project configuration from `vite.config.ts`, which specifies the build tool settings, TypeScript compilation options, and development server configuration. Vite then processes the React components, TypeScript files, and CSS stylesheets, performing type checking through the TypeScript compiler and bundling assets for the development server.

The compilation output displays in the terminal, showing TypeScript type checking results, module resolution, and asset bundling progress. Vite's development server starts on port 4000 (or 3000 depending on configuration), providing hot module replacement that enables instant updates when source files are modified. The terminal output confirms successful compilation with no errors, indicating that all React components, TypeScript types, and dependencies are properly configured.

The frontend application is accessible through the web browser at `http://localhost:4000`, displaying the login interface as the initial entry point. The React application uses React Router for client-side routing, enabling navigation between different pages including login, registration, dashboard, chat interface, and challenge management pages.

**Technology Used**: React 18 framework, TypeScript language, Vite build tool, Tailwind CSS for styling, Axios for API communication, React Router for client-side routing.

---

## 4.5.4 User Authentication System Implementation

### 4.5.4.1 User Registration Interface and Process

**Figure 4: User Registration Interface**

The user registration interface is implemented as a React component that renders a form with input fields for username, email, password, confirm password, and optional full name. The form includes client-side validation that provides immediate feedback to users, checking email format, password strength requirements, and password confirmation matching. The validation logic is implemented using JavaScript regular expressions and conditional rendering to display error messages when validation fails.

When the user submits the registration form, the frontend sends a POST request to `/api/auth/register` endpoint with the form data. The backend server receives the request and performs server-side validation, checking for duplicate usernames and emails in the database. The password is hashed using bcryptjs with 10 salt rounds, ensuring that plaintext passwords are never stored in the database. The user record is then inserted into the PostgreSQL database with the hashed password, and a JWT token is generated containing user identification information.

Upon successful registration, the backend returns a response containing the JWT token and user information. The frontend stores the JWT token in localStorage and redirects the user to the dashboard interface. The registration success is confirmed through a success message displayed to the user, and the user is automatically logged in without requiring additional authentication.

**Technology Used**: React component architecture, HTML form elements, JavaScript validation, Axios for HTTP requests, bcryptjs for password hashing, jsonwebtoken for JWT generation, PostgreSQL for data storage.

### 4.5.4.2 User Login Process and Authentication

**Figure 5: User Login Interface and Authentication Flow**

The user login interface displays a form with email and password input fields. When the user submits the login form, the frontend sends a POST request to `/api/auth/login` with the email and password credentials. The backend server retrieves the user record from the database using the email address, normalizing it to lowercase to ensure case-insensitive matching.

The server then compares the provided password with the stored password hash using bcryptjs's `compare()` function, which performs constant-time comparison to prevent timing attacks. If the password matches, the server checks for account lockout status by examining the `account_locked_until` timestamp. If the account is not locked, the server generates a JWT token containing user_id and email, resets the failed_login_attempts counter, and updates the last_login timestamp.

If authentication fails, the server increments the failed_login_attempts counter. After five failed attempts, the account is locked for 15 minutes by setting the account_locked_until timestamp. The server returns appropriate error messages that do not distinguish between invalid email and invalid password, preventing user enumeration attacks.

Upon successful authentication, the backend returns the JWT token and user information. The frontend stores the token in localStorage and includes it in subsequent API requests through the Authorization header. The user is redirected to the dashboard, and the welcome message displays the username, confirming successful authentication.

**Technology Used**: React form components, Axios HTTP client, bcryptjs password comparison, jsonwebtoken for JWT generation, PostgreSQL for user data retrieval, sessionStorage for token storage.

### 4.5.4.3 Dashboard Interface and User Information Display

**Figure 6: Main Dashboard Interface**

The dashboard interface is implemented as a React component that fetches user information and challenge statistics from the backend API upon component mounting. The component sends a GET request to `/api/auth/me` with the JWT token in the Authorization header, and the backend verifies the token and returns user information including username, email, and challenge statistics.

The dashboard displays a welcome message with the user's username, statistics cards showing the total number of challenges created and deployed, and quick action buttons for navigating to challenge creation or challenge browsing pages. The statistics are calculated by querying the challenges table in the database, counting records where the user_id matches the authenticated user's ID.

The dashboard uses React's useEffect hook to fetch data when the component mounts, and useState hooks to manage the component's state including user information and challenge statistics. The interface employs Tailwind CSS classes for styling, creating a card-based layout that organizes information hierarchically. The empty state design for new users displays a message encouraging challenge creation, with a prominent "Create Challenge" button.

**Technology Used**: React hooks (useState, useEffect), Axios for API requests, JWT token authentication, PostgreSQL for data queries, Tailwind CSS for styling, React Router for navigation.

---

## 4.5.5 AI-Powered Challenge Creation Workflow

### 4.5.5.1 Chat Interface Initialization and Session Management

**Figure 7: AI Chat Interface Initial State**

The AI chat interface is implemented as a React component (`CTFChatInterface.tsx`) that manages conversation state and user interactions. Upon component mounting, the interface generates a cryptographically secure session ID using the Web Crypto API's `crypto.randomUUID()` function, which creates a unique identifier for the conversation session. This session ID is stored in the browser's sessionStorage, ensuring persistence across page refreshes while being cleared when the browser tab is closed.

The chat interface displays an empty conversation history panel initially, with a system welcome message that provides guidance on available functionalities. The message input field is ready for user interaction, and the send button is enabled. The interface uses React state management to track messages, with each message object containing role (user or assistant), content, timestamp, and optional metadata.

The session ID is sent with every chat message to the backend API, enabling the system to group messages into conversation sessions and maintain context across multiple interactions. The backend stores each message in the chat_messages table with the session_id, user_id, role, content, and timestamp, enabling conversation history retrieval and context preservation.

**Technology Used**: React component architecture, Web Crypto API for session ID generation, sessionStorage for session persistence, Axios for API communication, PostgreSQL for message storage.

### 4.5.5.2 Challenge Creation Request and AI Classification

**Figure 8: Challenge Creation Request in Chat Interface**

When a user types a message requesting challenge creation (e.g., "Create an FTP challenge with weak credentials"), the message is displayed in the conversation history panel, and an AI processing indicator appears, showing that the system is analyzing the request. The frontend sends a POST request to `/api/chat` endpoint with the message content and session ID.

The backend forwards the request to the CTF automation service running on port 4003, which receives the message and passes it to the classifier agent. The classifier agent uses OpenAI's GPT-4o model to analyze the user's message and determine the intent category. The classification process utilizes a system prompt that defines four intent categories: Create, Deploy, ChallengeInfo, and Question.

**Figure 9: AI Classification Process Terminal Output**

The classifier agent sends the user message to OpenAI's API with a carefully crafted system prompt that includes examples and keyword patterns for each category. The API returns a structured JSON response containing the classification result, confidence score, reasoning explanation, challenge type identification, and required tools extraction. The terminal output displays the classification result, showing that the intent is classified as "CREATE" with a high confidence score (typically > 0.8), and extracts the challenge type (e.g., "FTP") and required tools.

The classification result is then used to route the request to the appropriate agent. For CREATE intent, the request is routed to the Create Agent, which begins the challenge generation workflow. The classification process includes retry logic with exponential backoff to handle transient API failures, ensuring system reliability.

**Technology Used**: OpenAI GPT-4o API, OpenAI SDK (`openai`), JSON structured output, retry logic with exponential backoff, Node.js Express server for API routing.

### 4.5.5.3 Challenge Generation Progress and Workflow

**Figure 10: Challenge Generation Progress Indicators**

The challenge generation workflow is a multi-stage process that involves several AI agents working sequentially. The Create Agent orchestrates the workflow, coordinating with specialized agents including the Universal Structure Agent, Content Agents, Tool Installation Agent, and Validator Agents. Progress callbacks are implemented throughout the workflow, enabling real-time progress reporting to the frontend interface.

The progress indicators display in the chat interface, showing completed steps with checkmarks and in-progress steps with loading animations. The workflow stages include: (1) Challenge structure creation, where the Universal Structure Agent determines the challenge architecture including attacker and victim machines; (2) Content generation, where Content Agents create vulnerable application code, configuration files, and documentation; (3) Dockerfile creation, where the Tool Installation Agent generates Dockerfiles for containerization; (4) docker-compose.yml generation, where the Universal Structure Agent creates orchestration configuration; (5) Pre-deployment validation, where Validator Agents check file correctness; (6) GitHub repository storage, where the Git Manager commits and pushes files to the repository.

Each stage involves AI-powered generation using OpenAI's GPT-4o model, which receives detailed prompts including challenge requirements, conversation history for context, and specific instructions for each file type. The AI generates complete, functional code including vulnerable applications, Docker configurations, and documentation. The generated content is validated for completeness, checking for placeholder patterns that indicate incomplete generation.

**Technology Used**: OpenAI GPT-4o API, Node.js workflow orchestration, progress callback mechanisms, React state management for UI updates, GitHub API for repository operations.

### 4.5.5.4 Challenge File Generation and Repository Storage

**Figure 11: Generated Challenge Directory Structure**

The challenge generation process creates a complete file system structure for each challenge, organized in a standardized directory hierarchy. The challenge root directory contains a docker-compose.yml file that defines the multi-container setup, including attacker and victim machines with network configuration and IP address allocation. Each machine has its own subdirectory containing a Dockerfile that specifies the base image, tool installations, service configurations, and startup scripts.

The vulnerable application code is generated based on the challenge type. For network challenges (FTP, SSH, Samba), the code includes service configuration files and vulnerable settings. For web challenges, the code includes web application files (HTML, PHP, Python Flask, etc.) with intentional vulnerabilities. For cryptography challenges, the code includes encryption/decryption logic and flag encoding mechanisms.

The README.md file is generated with challenge description, learning objectives, vulnerability explanation, and solution hints. The metadata.json file contains structured challenge information including name, category, difficulty, description, and flag format. All files are generated by AI agents using GPT-4o, ensuring consistency and completeness.

**Figure 12: GitHub Repository Push Operation**

The Git Manager handles version control operations, staging all generated files, creating a commit with a descriptive message, and pushing the files to the GitHub repository. The terminal output displays Git commands executing, showing file additions, commit creation, and successful push confirmation. The challenge files are now stored in the GitHub repository, making them available for deployment.

The Git operations use the GitHub API through the `@octokit/rest` library, enabling programmatic repository management. The system authenticates using a GitHub personal access token stored in environment variables, ensuring secure repository access. The challenge files are organized in repository subdirectories, with each challenge having its own directory structure.

**Technology Used**: Node.js file system operations (fs module), GitHub API (`@octokit/rest`), Git command-line interface, OpenAI GPT-4o for file generation, Docker Compose YAML format.

### 4.5.5.5 Challenge Creation Success Confirmation

**Figure 13: Challenge Creation Success with Details Card**

Upon successful challenge generation and repository storage, the system returns a success message to the frontend, which displays a challenge details card in the chat interface. The card shows comprehensive challenge information including challenge name, category (e.g., Network, Web, Crypto), difficulty level (Easy, Medium, Hard), repository location (GitHub URL), and action buttons for deployment or viewing additional details.

The challenge details are extracted from the generated metadata.json file and the AI's response, formatted into a structured card component using React and Tailwind CSS. The card design employs visual hierarchy with the challenge name as the primary heading, category and difficulty as badges, and the description as body text. The action buttons enable users to immediately proceed with deployment or navigate to the challenge details page for more information.

The success confirmation provides immediate feedback to users, confirming that their challenge request has been successfully processed and the challenge is ready for deployment. The interface maintains the conversation history, allowing users to reference the challenge creation process and continue the conversation with follow-up questions or requests.

**Technology Used**: React component rendering, Tailwind CSS for card styling, JSON data parsing, GitHub URL generation, React Router for navigation.

---

## 4.5.6 Challenge Deployment Process

### 4.5.6.1 Deployment Request and Orchestration

**Figure 14: Challenge Deployment Request in Chat Interface**

When a user requests challenge deployment through the chat interface (e.g., "Deploy my FTP challenge"), the message is sent to the CTF automation service, which routes the request to the Deploy Agent. The Deploy Agent begins the deployment workflow, which involves multiple stages including repository cloning, Docker network creation, container building, service initialization, and Guacamole connection setup.

The deployment progress is tracked through progress callbacks that update the frontend interface in real-time. The progress indicators display the current deployment stage, showing steps such as "Cloning repository", "Creating Docker network", "Building containers", "Starting services", "Validating deployment", and "Setting up access". Each stage completion is confirmed before proceeding to the next stage, ensuring reliable deployment.

The Deploy Agent first retrieves challenge metadata from the PostgreSQL database or identifies the challenge from the GitHub repository. It then clones the challenge repository to a local temporary directory, enabling access to the challenge files including docker-compose.yml and Dockerfiles.

**Technology Used**: Node.js child process execution, Git operations for repository cloning, Docker Engine API for container management, progress callback mechanisms, React state updates for UI.

### 4.5.6.2 Docker Container Build and Startup Process

**Figure 15: Docker Compose Build Process Terminal Output**

The Docker deployment process begins with network resource cleanup, where the system inspects existing Docker networks and disconnects the Guacamole daemon from challenge-specific networks to prevent conflicts. The system then creates a new isolated Docker network for the challenge, allocating an IP subnet from the 172.23.0.0/16 range using the Subnet Allocator.

The Docker Compose build process is executed through a child process, running the command `docker compose up --build -d` within the challenge directory. The `--build` flag ensures that container images are rebuilt from source, incorporating any changes to Dockerfiles or application code. The `-d` flag runs containers in detached mode, allowing the deployment process to continue without blocking.

The terminal output displays Docker Compose executing build commands, showing container image creation, layer caching, dependency installation, and container startup processes. Each container's build process shows the execution of Dockerfile instructions including base image pulling, package installations, file copying, and service configurations. The build output confirms successful image creation and container startup.

**Figure 16: Docker Containers Running Status in Docker Desktop**

The Docker Desktop interface displays all running containers associated with the deployed challenge, showing container names, status indicators (running/stopped), network connections, and resource usage statistics. Each container shows its assigned IP address within the challenge network, port mappings, and resource allocation (CPU, memory). The interface confirms that all required containers are healthy and properly networked, with the attacker container and victim container(s) running and accessible.

**Technology Used**: Docker Engine API (`dockerode` library), Docker Compose command-line interface, Docker network management, container lifecycle operations, Docker Desktop for container monitoring.

### 4.5.6.3 Network Configuration and Isolation

**Figure 17: Docker Network Configuration Terminal Output**

The Docker network configuration is displayed through terminal output showing network inspection results. The network information includes the network name (e.g., `ftp-challenge_net`), subnet allocation (e.g., `172.23.1.0/24`), gateway IP address, and connected containers with their assigned IP addresses. The network isolation ensures that each challenge operates in its own isolated environment, preventing interference between different challenges.

The Subnet Allocator manages IP address allocation, tracking used subnets and preventing conflicts. When a challenge is deployed, the allocator assigns the next available subnet from the 172.23.0.0/16 range, ensuring unique network isolation for each challenge. The IP addresses are assigned to containers according to the docker-compose.yml configuration, with the attacker container typically receiving .3 and victim containers receiving .4 through .253.

The network connectivity is verified through container inspection, confirming that containers can communicate within the challenge network while remaining isolated from other challenges and the host system. This network isolation is critical for security, ensuring that vulnerabilities in one challenge cannot affect other challenges or the platform infrastructure.

**Technology Used**: Docker network management API, IP subnet allocation algorithms, network inspection commands, Docker Compose network configuration.

### 4.5.6.4 Guacamole Connection Setup and Access Configuration

**Figure 18: Guacamole Connection Setup Terminal Output**

The Guacamole connection setup process begins by checking if a Guacamole user exists for the current session. If no user exists, the Session Guacamole Manager creates a new user in the Guacamole MySQL database with a username format `ctf_{sessionId}`, ensuring unique user identification per session. The user is created with appropriate permissions and a randomly generated password.

The system then creates a Guacamole connection for the attacker container, configuring connection parameters including hostname (container IP address), port (22 for SSH), protocol (SSH), username, and password. The connection is created in the Guacamole MySQL database through direct SQL operations using the `mysql2` library, inserting records into the `guacamole_connection` and `guacamole_connection_parameter` tables.

The terminal output displays the database operations, showing SQL INSERT statements executing to create the connection and configure parameters. The connection is then granted to the session user through permission records in the `guacamole_connection_permission` table, enabling the user to access the connection through the Guacamole web interface.

**Technology Used**: MySQL database operations (`mysql2` library), Guacamole database schema, SQL INSERT operations, session management, connection parameter configuration.

### 4.5.6.5 Deployment Success and Access Information Display

**Figure 19: Deployment Success with Access Information**

Upon successful deployment completion, the system returns comprehensive access information to the frontend, which displays a detailed access information card in the chat interface. The card includes the challenge name, category, description, Guacamole login URL, session-specific username and password credentials, container IP addresses, and web interface endpoints (if applicable).

The Guacamole access URL is generated in the format `http://localhost:8081/#/client/{connectionId}?token={authToken}`, where the connectionId is the Guacamole connection identifier and the authToken is an authentication token that enables direct access without additional login steps. The URL is clickable, allowing users to open the challenge environment directly in a new browser tab.

The credentials are displayed in plain text format within the chat interface, making them easily accessible for copy-paste operations. The session-specific username format `ctf_{sessionId}` and randomly generated password ensure security isolation between different user sessions, preventing unauthorized access to other users' challenge environments.

**Technology Used**: URL generation algorithms, Guacamole authentication token generation, React component rendering, Tailwind CSS for card styling, session management.

---

## 4.5.7 Browser-Based Remote Access Implementation

### 4.5.7.1 Guacamole Login Interface and Authentication

**Figure 20: Guacamole Login Interface**

The Guacamole login interface is accessed through the generated access URL, displaying a web-based authentication form with username and password fields. The interface is served by the Apache Guacamole web application running on port 8081, providing a browser-based gateway to remote access capabilities.

When the user enters the session-specific credentials (username: `ctf_{sessionId}`, password: [generated password]), Guacamole authenticates the user against the MySQL database. Upon successful authentication, Guacamole establishes an SSH connection to the challenge container using the connection parameters configured during deployment. The connection is established through the Guacamole daemon (guacd), which acts as a proxy between the web interface and the remote SSH server.

The authentication process validates the user credentials, checks connection permissions, and establishes the remote session. The interface then transitions to the terminal view, displaying the SSH connection to the challenge container.

**Technology Used**: Apache Guacamole web application, MySQL authentication, SSH protocol, Guacamole daemon (guacd), browser-based remote access.

### 4.5.7.2 Terminal Access and Command Execution

**Figure 21: Guacamole Terminal Interface with SSH Connection**

The Guacamole terminal interface displays a browser-based terminal emulator that provides full command-line access to the challenge container. The terminal shows the command prompt (e.g., `root@attacker-machine:/#`), indicating successful SSH connection and shell access. The interface supports standard terminal operations including command execution, file system navigation, text editing, and application interaction.

The terminal connection is established through the Guacamole protocol, which translates browser-based input/output into SSH protocol communications. User keystrokes are transmitted to the remote container, and terminal output is streamed back to the browser in real-time. The interface maintains terminal state, preserving command history and session context throughout the user's interaction with the challenge environment.

The terminal provides access to all standard Linux commands and tools installed in the container, enabling users to explore the challenge environment, test vulnerabilities, and interact with vulnerable services. The browser-based approach eliminates the need for local SSH client installation, making the platform accessible to users regardless of their local system configuration.

**Technology Used**: Apache Guacamole terminal emulator, SSH protocol, WebSocket communication, browser-based terminal rendering, real-time data streaming.

### 4.5.7.3 Challenge Environment Interaction and Vulnerability Testing

**Figure 22: Challenge Environment Interaction in Terminal**

The challenge interaction screenshot demonstrates practical engagement with a deployed challenge, showing command execution and application interaction. The terminal displays user commands such as `ls` for directory listing, `cat` for file reading, `nmap` for network scanning, and application-specific commands for testing vulnerabilities.

For network challenges, users can scan for open ports, connect to services using tools like `ftp`, `ssh`, or `smbclient`, and exploit vulnerabilities such as weak credentials or misconfigurations. For web challenges, users can interact with web applications, test for SQL injection, cross-site scripting (XSS), or other web vulnerabilities. For cryptography challenges, users can analyze encrypted data, test decryption methods, and discover flags.

The terminal interaction enables complete challenge-solving workflows, from initial reconnaissance through vulnerability exploitation to flag discovery. The browser-based terminal provides the same functionality as a local SSH client, ensuring that users can perform all necessary operations to solve challenges without requiring additional tool installation.

**Technology Used**: Linux command-line tools, network scanning tools (nmap), service clients (ftp, ssh, smbclient), web testing tools (curl, wget), cryptography tools, browser-based terminal emulation.

---

## 4.5.8 Database Operations and API Integration

### 4.5.8.1 Database Query Execution and Data Retrieval

**Figure 23: Database Query Execution in pgAdmin**

The pgAdmin interface displays SQL query execution and results, showing database operations including SELECT queries for user records, challenge metadata, and chat message history. The query interface allows execution of custom SQL statements, enabling data inspection and validation of database operations.

The query results display tabular data from the PostgreSQL database, showing user information including usernames, emails, and account status. Challenge records show challenge names, categories, difficulties, and deployment status. Chat message history displays conversation records with session grouping, message content, and timestamps.

The database operations confirm that data persistence is functioning correctly, with user registrations, challenge creations, and chat messages properly stored in the database. The foreign key relationships ensure data integrity, with challenge records properly linked to user accounts and chat messages associated with sessions and users.

**Technology Used**: PostgreSQL database, pgAdmin administration tool, SQL query language, database connection pooling, foreign key constraints.

### 4.5.8.2 API Request and Response Testing

**Figure 24: API Request and Response in Postman**

The Postman interface displays API testing operations, showing HTTP requests to the backend API endpoints with request bodies, authentication headers, and JSON responses. The API testing demonstrates the chat endpoint (`POST /api/chat`), showing the request body containing message content and session ID, and the Authorization header containing the JWT token.

The response displays the AI-generated message confirming successful challenge creation, including challenge metadata and access information. The API testing validates that the authentication mechanism works correctly, with JWT tokens properly verified, and that the API integration between frontend and backend services functions as expected.

Postman enables comprehensive API testing, including testing different request scenarios, validating response formats, and debugging API issues. The testing confirms that all API endpoints are properly implemented and return expected responses with correct data structures.

**Technology Used**: Postman API testing tool, HTTP protocol, JSON data format, JWT token authentication, RESTful API design, Express.js routing.

---

## 4.5.9 Challenge Management Interface Implementation

### 4.5.9.1 Challenge Browsing and Search Functionality

**Figure 25: Challenge Browsing Interface**

The challenge browsing interface displays a grid layout of challenge cards, each showing essential metadata including challenge name, category badge, difficulty level, creation date, and deployment status. The interface includes search and filter controls at the top, enabling users to locate specific challenges by name or filter by category, difficulty, or deployment status.

The challenge list is populated by sending a GET request to `/api/challenges` endpoint with the JWT token in the Authorization header. The backend queries the PostgreSQL database, filtering challenges by user_id to ensure users only see their own challenges. The results are returned as JSON data, which the frontend component renders as challenge cards.

The search functionality implements client-side filtering, searching through challenge names and descriptions as the user types. The filter dropdowns enable filtering by category (Network, Web, Crypto) and difficulty (Easy, Medium, Hard), with the filtered results updating in real-time. The card-based design enables quick scanning of available challenges while providing sufficient information for selection decisions.

**Technology Used**: React component rendering, Axios for API requests, PostgreSQL database queries, client-side filtering algorithms, Tailwind CSS for grid layout, React state management.

### 4.5.9.2 Challenge Details View and Management

**Figure 26: Challenge Details Page**

The challenge details page consolidates all information related to a specific challenge in a single view, displaying comprehensive metadata including challenge name, category, difficulty, description, creation and deployment timestamps, access information (if deployed), file structure, and management action buttons.

The page is accessed by clicking on a challenge card in the browsing interface, which navigates to `/challenges/:challengeId` route. The React component fetches challenge details by sending a GET request to `/api/challenges/:challengeId` endpoint, which queries the database for the specific challenge record and returns detailed information.

The interface organizes information into logical sections using card-based layouts, with challenge metadata, description, access credentials, and file structure presented in a structured format. The management action buttons provide direct access to common operations such as deployment, access, and deletion, reducing the number of steps required for challenge management.

**Technology Used**: React Router for navigation, Axios for API requests, PostgreSQL for data retrieval, React component architecture, Tailwind CSS for layout styling.

---

## 4.5.10 Development Workflow and Procedures

### 4.5.10.1 Environment Setup and Configuration

The development environment setup begins with installing required software including Node.js (v18+), Docker Desktop, PostgreSQL 15, and Git. The project repository is cloned from GitHub, and dependencies are installed using `npm install` in each package directory (frontend, backend, ctf-automation).

Environment variables are configured in `.env` files for each service, containing database connection strings, API keys (OpenAI, Anthropic, GitHub), JWT secret keys, and service ports. The PostgreSQL database is initialized by executing SQL schema scripts from the `database/` directory, creating all required tables and relationships.

Docker Compose files are used to start infrastructure services including PostgreSQL, MySQL, and Apache Guacamole. The services are started using `docker-compose -f docker-compose.infrastructure.yml up -d`, which runs containers in detached mode. The backend and CTF automation services are started using `npm start` commands, and the frontend development server is started using `npm run dev`.

### 4.5.10.2 Development and Testing Procedures

During development, code changes are made using VS Code with TypeScript and ESLint extensions for code quality. The development servers provide hot module replacement, enabling instant updates when source files are modified. API endpoints are tested using Postman, and database operations are verified through pgAdmin.

The testing workflow includes unit testing for individual components, integration testing for API endpoints, and end-to-end testing for complete user workflows. Test cases are executed using Jest testing framework, with test coverage reports generated to ensure comprehensive code coverage.

Git version control is used throughout development, with feature branches created for new functionality and pull requests used for code review. The Kanban methodology is followed, with tasks tracked on a Kanban board and continuous integration ensuring that code changes are automatically tested and validated.

### 4.5.10.3 Deployment and Production Procedures

Production deployment involves building optimized production images for each service using Docker. The frontend is built using Vite's production build command, creating optimized static assets. The backend and CTF automation services are containerized using Dockerfiles that install dependencies and configure runtime environments.

Environment variables are configured for production, using secure secret management systems. The services are deployed to cloud infrastructure (AWS, Azure, or similar), with load balancers configured for high availability. Database backups are configured for data protection, and monitoring systems are set up for system health tracking.

---

## 4.5.11 Key Design Decisions and Implementation Techniques

### 4.5.11.1 Microservices Architecture

The platform implements a microservices architecture with three independent services (frontend, backend, CTF automation), enabling independent development, deployment, and scaling. This architecture allows each service to be optimized for its specific requirements, with the frontend optimized for user experience, the backend optimized for data management, and the CTF automation service optimized for AI processing and container management.

### 4.5.11.2 AI Agent System

The CTF automation service uses a multi-agent architecture where specialized agents handle specific tasks. The Classifier Agent routes requests, the Create Agent orchestrates challenge generation, the Deploy Agent manages deployment, and Validator Agents ensure quality. This modular approach enables extensibility, allowing new agents to be added for additional functionality without modifying existing code.

### 4.5.11.3 Docker Network Isolation

Each challenge operates in its own isolated Docker network with allocated IP subnets, ensuring security isolation between challenges. This network isolation prevents challenges from interfering with each other and protects the platform infrastructure from challenge vulnerabilities.

### 4.5.11.4 Session-Based Access Control

Guacamole connections are created with session-specific user accounts, ensuring that each user session has isolated access to challenge environments. This approach provides security isolation while enabling browser-based access without requiring local client installation.

---

## 4.5.12 Summary

The execution phase successfully implemented an AI-powered CTF platform with comprehensive functionality for challenge creation, deployment, and management. The implementation utilized modern web technologies including React, Node.js, PostgreSQL, Docker, and AI services, creating a scalable and maintainable system architecture. The platform demonstrates practical application of AI in cybersecurity education, reducing manual effort while maintaining educational value and security best practices.

The development process followed industry best practices for security, code organization, and system reliability, incorporating automated testing, error handling, and comprehensive logging mechanisms. The microservices architecture enables independent service development and deployment, while the AI agent system provides extensible functionality for future enhancements.

---

**Document End**

**Last Updated**: January 2025  
**Version**: 1.0  
**Status**: Complete
