# Architecture Connections - Simple List

## How to Read:
**FROM → TO: "Label"**

Each line shows one connection arrow to draw in your diagram.

---

## User Layer Connections

1. **User Browser** → **Frontend (Port 4000)**
   - Label: `"HTTP/WebSocket Requests"`

---

## Frontend Layer Connections

2. **Frontend** → **Backend (Port 4002)**
   - Label: `"REST API: POST /api/auth/login, GET /api/challenges, POST /api/chat/messages"`

3. **Frontend** → **CTF Automation (Port 4003)**
   - Label: `"REST API: POST /api/chat"`

---

## Backend Layer Connections

4. **Backend** → **JWT (inside Backend)**
   - Label: `"Generate/Verify Tokens"`

5. **Backend** → **Bcrypt (inside Backend)**
   - Label: `"Hash/Compare Passwords"`

6. **Backend** → **PostgreSQL (Port 5433)**
   - Label: `"SQL: INSERT, SELECT, UPDATE"`

7. **PostgreSQL** → **Backend**
   - Label: `"User Data, Session Info, Chat Messages"`

---

## CTF Automation Layer Connections

8. **CTF Automation** → **Classifier Agent**
   - Label: `"Route Request"`

9. **Classifier Agent** → **Create Agent**
   - Label: `"Intent: CREATE"`

10. **Classifier Agent** → **Deploy Agent**
    - Label: `"Intent: DEPLOY"`

11. **Classifier Agent** → **Questions Agent**
    - Label: `"Intent: QUESTION"`

12. **Deploy Agent** → **Validator Agent**
    - Label: `"Validate Challenge"`

13. **Validator Agent** → **Deploy Agent**
    - Label: `"Validation Results"`

---

## Database Connections

14. **CTF Automation** → **PostgreSQL (Port 5433)**
    - Label: `"SQL: SELECT, INSERT, UPDATE"`

15. **PostgreSQL** → **CTF Automation**
    - Label: `"Challenge Data, OS Images, Tool Installations"`

16. **CTF Automation** → **MySQL (Port 3307)**
    - Label: `"SQL: Create Guacamole Users & Connections"`

17. **MySQL** → **CTF Automation**
    - Label: `"Guacamole User Data, Connection Parameters"`

18. **Guacamole** → **MySQL (Port 3307)**
    - Label: `"SQL: SELECT, INSERT, UPDATE"`

19. **MySQL** → **Guacamole**
    - Label: `"Connection Configs, User Permissions"`

---

## Container Infrastructure Connections

20. **CTF Automation** → **Docker Engine**
    - Label: `"Docker API: docker compose up, docker network create"`

21. **Docker Engine** → **CTF Automation**
    - Label: `"Container Status, Network Info, Container IPs"`

22. **Docker Engine** → **Challenge Containers**
    - Label: `"Create Containers, Attach Networks"`

23. **Challenge Containers** → **Docker Engine**
    - Label: `"Container Logs, Health Status"`

24. **CTF Automation** → **Guacamole (Port 8081)**
    - Label: `"Create Connections via MySQL"`

25. **Guacamole** → **CTF Automation**
    - Label: `"Connection URLs, Connection Status"`

26. **Guacamole** → **Challenge Containers**
    - Label: `"SSH/RDP Protocol via WebSocket"`

27. **Challenge Containers** → **Guacamole**
    - Label: `"Terminal Output, Connection Status"`

---

## External Services Connections

28. **Create Agent** → **GitHub**
    - Label: `"Git API: git push, git commit"`

29. **GitHub** → **Create Agent**
    - Label: `"Repository URL, Commit Hash"`

30. **Deploy Agent** → **GitHub**
    - Label: `"Git API: git clone, git pull"`

31. **GitHub** → **Deploy Agent**
    - Label: `"Challenge Files, Docker Compose Configs"`

32. **Create Agent** → **OpenAI**
    - Label: `"API: POST /v1/chat/completions"`

33. **OpenAI** → **Create Agent**
    - Label: `"Generated Content, AI Responses"`

34. **Create Agent** → **Anthropic**
    - Label: `"API: POST /v1/messages"`

35. **Anthropic** → **Create Agent**
    - Label: `"AI Responses, Validation Results"`

36. **Deploy Agent** → **OpenAI**
    - Label: `"API: Error Analysis"`

37. **OpenAI** → **Deploy Agent**
    - Label: `"Error Fixes, Code Suggestions"`

38. **Deploy Agent** → **Anthropic**
    - Label: `"API: Deployment Validation"`

39. **Anthropic** → **Deploy Agent**
    - Label: `"Validation Results, Fix Recommendations"`

---

## Summary

**Total Connections: 39**

- User → Frontend: 1
- Frontend → Services: 2
- Backend Internal: 4
- CTF Automation Internal: 6
- Database: 6
- Container Infrastructure: 8
- External Services: 12

---

**Note:** All connections are directional (one-way arrows). For bidirectional communication, draw two separate arrows (one in each direction).

