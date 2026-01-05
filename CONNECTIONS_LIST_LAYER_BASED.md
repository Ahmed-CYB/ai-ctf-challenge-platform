# Architecture Connections - Layer-Based Organization

## How to Read:
**FROM → TO: "Label"**

Each connection shows one directional arrow. For bidirectional communication, there are two separate connections listed.

---

## 👤 USER LAYER

### User Browser Connections:

1. **User Browser** → **Frontend (Port 4000)**
   - Label: `"HTTP/WebSocket Requests"`

---

## 🌐 FRONTEND LAYER (Port 4000)

### Frontend → Backend Connections:

2. **Frontend** → **Backend (Port 4002)**
   - Label: `"REST API: POST /api/auth/login"`

3. **Frontend** → **Backend (Port 4002)**
   - Label: `"REST API: POST /api/auth/register"`

4. **Frontend** → **Backend (Port 4002)**
   - Label: `"REST API: GET /api/challenges"`

5. **Frontend** → **Backend (Port 4002)**
   - Label: `"REST API: POST /api/chat/messages"`

6. **Frontend** → **Backend (Port 4002)**
   - Label: `"REST API: GET /api/chat/history/:sessionId"`

7. **Frontend** → **Backend (Port 4002)**
   - Label: `"REST API: GET /api/users/:userId"`

8. **Backend (Port 4002)** → **Frontend**
   - Label: `"JSON Response, JWT Token"`

### Frontend → CTF Automation Connections:

9. **Frontend** → **CTF Automation (Port 4003)**
   - Label: `"REST API: POST /api/chat"`

10. **CTF Automation (Port 4003)** → **Frontend**
    - Label: `"JSON Response, AI Chat Output"`

---

## 🔧 BACKEND LAYER (Port 4002)

### Backend Internal Connections:

11. **Backend** → **JWT (jsonwebtoken)**
    - Label: `"jwt.sign() - Generate Token"`

12. **JWT (jsonwebtoken)** → **Backend**
    - Label: `"Token Created"`

13. **Backend** → **JWT (jsonwebtoken)**
    - Label: `"jwt.verify() - Verify Token"`

14. **JWT (jsonwebtoken)** → **Backend**
    - Label: `"Token Verified, User Data"`

15. **Backend** → **Bcrypt (bcryptjs)**
    - Label: `"bcrypt.hash() - Hash Password"`

16. **Bcrypt (bcryptjs)** → **Backend**
    - Label: `"Password Hashed"`

17. **Backend** → **Bcrypt (bcryptjs)**
    - Label: `"bcrypt.compare() - Compare Password"`

18. **Bcrypt (bcryptjs)** → **Backend**
    - Label: `"Password Valid/Invalid"`

### Backend → Database Connections:

19. **Backend** → **PostgreSQL (Port 5433)**
    - Label: `"SQL: INSERT INTO users"`

20. **Backend** → **PostgreSQL (Port 5433)**
    - Label: `"SQL: SELECT FROM users WHERE email"`

21. **Backend** → **PostgreSQL (Port 5433)**
    - Label: `"SQL: INSERT INTO sessions"`

22. **Backend** → **PostgreSQL (Port 5433)**
    - Label: `"SQL: SELECT FROM sessions WHERE session_id"`

23. **Backend** → **PostgreSQL (Port 5433)**
    - Label: `"SQL: INSERT INTO chat_messages"`

24. **Backend** → **PostgreSQL (Port 5433)**
    - Label: `"SQL: SELECT FROM chat_messages WHERE session_id"`

25. **Backend** → **PostgreSQL (Port 5433)**
    - Label: `"SQL: UPDATE users SET last_login"`

26. **PostgreSQL (Port 5433)** → **Backend**
    - Label: `"User Data, Session Info, Chat Messages"`

---

## 🤖 CTF AUTOMATION LAYER (Port 4003)

### CTF Automation Internal Connections:

27. **CTF Automation** → **Classifier Agent**
    - Label: `"Route Request, Classify Intent"`

28. **Classifier Agent** → **CTF Automation**
    - Label: `"Intent: CREATE/DEPLOY/QUESTION"`

29. **Classifier Agent** → **Create Agent**
    - Label: `"Intent: CREATE"`

30. **Classifier Agent** → **Deploy Agent**
    - Label: `"Intent: DEPLOY"`

31. **Classifier Agent** → **Questions Agent**
    - Label: `"Intent: QUESTION"`

32. **Create Agent** → **CTF Automation**
    - Label: `"Challenge Created Response"`

33. **Deploy Agent** → **CTF Automation**
    - Label: `"Deployment Complete Response"`

34. **Questions Agent** → **CTF Automation**
    - Label: `"Answer Response"`

35. **Deploy Agent** → **Validator Agent**
    - Label: `"Request Validation"`

36. **Validator Agent** → **Deploy Agent**
    - Label: `"Validation Results, Error Reports"`

### CTF Automation → Database Connections:

37. **CTF Automation** → **PostgreSQL (Port 5433)**
    - Label: `"SQL: SELECT FROM challenges"`

38. **CTF Automation** → **PostgreSQL (Port 5433)**
    - Label: `"SQL: INSERT INTO challenges"`

39. **CTF Automation** → **PostgreSQL (Port 5433)**
    - Label: `"SQL: SELECT FROM os_images"`

40. **CTF Automation** → **PostgreSQL (Port 5433)**
    - Label: `"SQL: INSERT INTO os_images"`

41. **CTF Automation** → **PostgreSQL (Port 5433)**
    - Label: `"SQL: SELECT FROM tool_installations"`

42. **CTF Automation** → **PostgreSQL (Port 5433)**
    - Label: `"SQL: INSERT INTO tool_installations"`

43. **PostgreSQL (Port 5433)** → **CTF Automation**
    - Label: `"Challenge Metadata, OS Images, Tool Data"`

44. **CTF Automation** → **MySQL (Port 3307)**
    - Label: `"SQL: INSERT INTO guacamole_user"`

45. **CTF Automation** → **MySQL (Port 3307)**
    - Label: `"SQL: SELECT FROM guacamole_user"`

46. **CTF Automation** → **MySQL (Port 3307)**
    - Label: `"SQL: INSERT INTO guacamole_connection"`

47. **CTF Automation** → **MySQL (Port 3307)**
    - Label: `"SQL: INSERT INTO guacamole_connection_parameter"`

48. **MySQL (Port 3307)** → **CTF Automation**
    - Label: `"Guacamole User Data, Connection Parameters"`

### CTF Automation → Container Infrastructure Connections:

49. **CTF Automation** → **Docker Engine**
    - Label: `"Docker API: docker compose up --build"`

50. **CTF Automation** → **Docker Engine**
    - Label: `"Docker API: docker network create"`

51. **CTF Automation** → **Docker Engine**
    - Label: `"Docker API: docker inspect container"`

52. **CTF Automation** → **Docker Engine**
    - Label: `"Docker API: docker exec container"`

53. **Docker Engine** → **CTF Automation**
    - Label: `"Container Status, Network Info, Container IPs"`

54. **CTF Automation** → **Guacamole (Port 8081)**
    - Label: `"Create Connection via MySQL Database"`

55. **Guacamole (Port 8081)** → **CTF Automation**
    - Label: `"Connection URL, Connection Status"`

### CTF Automation → External Services Connections:

56. **Create Agent** → **GitHub**
    - Label: `"Git API: git init, git add, git commit"`

57. **Create Agent** → **GitHub**
    - Label: `"Git API: git push origin main"`

58. **GitHub** → **Create Agent**
    - Label: `"Repository URL, Commit Hash, Push Status"`

59. **Deploy Agent** → **GitHub**
    - Label: `"Git API: git clone repository"`

60. **Deploy Agent** → **GitHub**
    - Label: `"Git API: git pull origin main"`

61. **GitHub** → **Deploy Agent**
    - Label: `"Challenge Files, docker-compose.yml, Dockerfiles"`

62. **Create Agent** → **OpenAI**
    - Label: `"API: POST /v1/chat/completions"`

63. **OpenAI** → **Create Agent**
    - Label: `"Generated Challenge Content, Dockerfiles"`

64. **Create Agent** → **Anthropic**
    - Label: `"API: POST /v1/messages"`

65. **Anthropic** → **Create Agent**
    - Label: `"AI Responses, Validation Results"`

66. **Deploy Agent** → **OpenAI**
    - Label: `"API: Error Analysis, Fix Suggestions"`

67. **OpenAI** → **Deploy Agent**
    - Label: `"Error Fixes, Code Suggestions"`

68. **Deploy Agent** → **Anthropic**
    - Label: `"API: Deployment Validation"`

69. **Anthropic** → **Deploy Agent**
    - Label: `"Validation Results, Fix Recommendations"`

---

## 💾 DATABASE LAYER

### PostgreSQL (Port 5433) Connections:

70. **PostgreSQL** → **Backend**
    - Label: `"Query Results: Users, Sessions, Chat"`

71. **PostgreSQL** → **CTF Automation**
    - Label: `"Query Results: Challenges, OS Images, Tools"`

### MySQL (Port 3307) Connections:

72. **MySQL** → **CTF Automation**
    - Label: `"Query Results: Guacamole Users, Connections"`

73. **MySQL** → **Guacamole**
    - Label: `"Query Results: Connection Configs, Permissions"`

---

## 🐳 CONTAINER INFRASTRUCTURE LAYER

### Docker Engine Connections:

74. **Docker Engine** → **Challenge Containers**
    - Label: `"Create Containers, Start Services"`

75. **Docker Engine** → **Challenge Containers**
    - Label: `"Attach to Network, Assign IPs"`

76. **Challenge Containers** → **Docker Engine**
    - Label: `"Container Logs, Health Status, Exit Codes"`

### Guacamole (Port 8081) Connections:

77. **Guacamole** → **MySQL (Port 3307)**
    - Label: `"SQL: SELECT FROM guacamole_connection"`

78. **Guacamole** → **MySQL (Port 3307)**
    - Label: `"SQL: SELECT FROM guacamole_connection_parameter"`

79. **Guacamole** → **MySQL (Port 3307)**
    - Label: `"SQL: INSERT INTO guacamole_connection_history"`

80. **Guacamole** → **Challenge Containers**
    - Label: `"SSH Protocol: Connect to Container"`

81. **Guacamole** → **Challenge Containers**
    - Label: `"RDP Protocol: Connect to Container (if Windows)"`

82. **Challenge Containers** → **Guacamole**
    - Label: `"Terminal Output, Connection Status"`

### Challenge Containers Connections:

83. **Attacker Container** → **Victim Container**
    - Label: `"Network Scan, Exploit Attempts"`

84. **Victim Container** → **Attacker Container**
    - Label: `"Service Responses, Network Traffic"`

---

## ☁️ EXTERNAL SERVICES LAYER

### GitHub Connections:

85. **GitHub** → **Create Agent**
    - Label: `"Repository Created, Files Pushed"`

86. **GitHub** → **Deploy Agent**
    - Label: `"Repository Cloned, Files Retrieved"`

### OpenAI Connections:

87. **OpenAI** → **Create Agent**
    - Label: `"AI Generated Content"`

88. **OpenAI** → **Deploy Agent**
    - Label: `"Error Analysis Results"`

### Anthropic Connections:

89. **Anthropic** → **Create Agent**
    - Label: `"AI Validation Results"`

90. **Anthropic** → **Deploy Agent**
    - Label: `"Deployment Validation Results"`

---

## 📊 Summary by Layer

**Total Connections: 90**

- **User Layer**: 1 connection (1 outgoing)
- **Frontend Layer**: 10 connections (2 incoming, 8 outgoing)
- **Backend Layer**: 18 connections (1 incoming, 17 outgoing)
- **CTF Automation Layer**: 43 connections (6 incoming, 37 outgoing)
- **Database Layer**: 4 connections (4 outgoing)
- **Container Infrastructure Layer**: 9 connections (3 incoming, 6 outgoing)
- **External Services Layer**: 5 connections (5 outgoing)

---

**Note:** All connections are directional arrows. Each connection represents one arrow in your diagram. Draw arrows from FROM component to TO component with the specified label.

