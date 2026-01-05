# Architecture Connections - Generalized (Simple)

## How to Read:
**FROM → TO: "Label"**

Simple, high-level labels without technical details.

---

## 👤 USER LAYER

1. **User Browser** → **Frontend**
   - Label: `"User Requests"`

---

## 🌐 FRONTEND LAYER

2. **Frontend** → **Backend**
   - Label: `"Authentication & Data Requests"`

3. **Backend** → **Frontend**
   - Label: `"Responses"`

4. **Frontend** → **CTF Automation**
   - Label: `"Chat Requests"`

5. **CTF Automation** → **Frontend**
   - Label: `"Chat Responses"`

---

## 🔧 BACKEND LAYER

6. **Backend** → **PostgreSQL**
   - Label: `"Store Data"`

7. **PostgreSQL** → **Backend**
   - Label: `"Return Data"`

---

## 🤖 CTF AUTOMATION LAYER

8. **CTF Automation** → **Classifier Agent**
   - Label: `"Route Request"`

9. **Classifier Agent** → **Create Agent**
   - Label: `"Create Challenge"`

10. **Classifier Agent** → **Deploy Agent**
    - Label: `"Deploy Challenge"`

11. **Classifier Agent** → **Questions Agent**
    - Label: `"Answer Question"`

12. **Deploy Agent** → **Validator Agent**
    - Label: `"Validate"`

13. **Validator Agent** → **Deploy Agent**
    - Label: `"Validation Results"`

14. **CTF Automation** → **PostgreSQL**
    - Label: `"Read/Write Data"`

15. **PostgreSQL** → **CTF Automation**
    - Label: `"Return Data"`

16. **CTF Automation** → **MySQL**
    - Label: `"Create Connections"`

17. **MySQL** → **CTF Automation**
    - Label: `"Connection Data"`

18. **CTF Automation** → **Docker Engine**
    - Label: `"Manage Containers"`

19. **Docker Engine** → **CTF Automation**
    - Label: `"Container Status"`

20. **CTF Automation** → **Guacamole**
    - Label: `"Setup Access"`

21. **Guacamole** → **CTF Automation**
    - Label: `"Access URLs"`

22. **Create Agent** → **GitHub**
    - Label: `"Push Files"`

23. **GitHub** → **Create Agent**
    - Label: `"Repository Info"`

24. **Deploy Agent** → **GitHub**
    - Label: `"Pull Files"`

25. **GitHub** → **Deploy Agent**
    - Label: `"Challenge Files"`

26. **Create Agent** → **OpenAI**
    - Label: `"Generate Content"`

27. **OpenAI** → **Create Agent**
    - Label: `"AI Response"`

28. **Create Agent** → **Anthropic**
    - Label: `"Validate Content"`

29. **Anthropic** → **Create Agent**
    - Label: `"Validation Results"`

30. **Deploy Agent** → **OpenAI**
    - Label: `"Error Analysis"`

31. **OpenAI** → **Deploy Agent**
    - Label: `"Fix Suggestions"`

32. **Deploy Agent** → **Anthropic**
    - Label: `"Deployment Check"`

33. **Anthropic** → **Deploy Agent**
    - Label: `"Check Results"`

---

## 💾 DATABASE LAYER

34. **PostgreSQL** → **Backend**
    - Label: `"Data"`

35. **PostgreSQL** → **CTF Automation**
    - Label: `"Data"`

36. **MySQL** → **CTF Automation**
    - Label: `"Connection Data"`

37. **MySQL** → **Guacamole**
    - Label: `"Config Data"`

---

## 🐳 CONTAINER INFRASTRUCTURE LAYER

38. **Docker Engine** → **Challenge Containers**
    - Label: `"Create & Start"`

39. **Challenge Containers** → **Docker Engine**
    - Label: `"Status"`

40. **Guacamole** → **MySQL**
    - Label: `"Read Config"`

41. **Guacamole** → **Challenge Containers**
    - Label: `"SSH/RDP Access"`

42. **Challenge Containers** → **Guacamole**
    - Label: `"Terminal Output"`

43. **Attacker Container** → **Victim Container**
    - Label: `"Network Traffic"`

44. **Victim Container** → **Attacker Container**
    - Label: `"Responses"`

---

## ☁️ EXTERNAL SERVICES LAYER

45. **GitHub** → **Create Agent**
    - Label: `"Confirm Push"`

46. **GitHub** → **Deploy Agent**
    - Label: `"Files"`

47. **OpenAI** → **Create Agent**
    - Label: `"Content"`

48. **OpenAI** → **Deploy Agent**
    - Label: `"Analysis"`

49. **Anthropic** → **Create Agent**
    - Label: `"Results"`

50. **Anthropic** → **Deploy Agent**
    - Label: `"Results"`

---

## 📊 Complete Layer Structure

### Your Current Layers (✅ Correct):
1. **User Browser** ✅
2. **Frontend** ✅
3. **Backend** ✅
4. **CTF Automation** ✅
5. **PostgreSQL** ✅
6. **MySQL** ✅
7. **External APIs** (OpenAI, Anthropic, GitHub) ✅
8. **Docker** ✅

### Missing Layers You Should Add:
9. **Guacamole** ⚠️ (Important - handles SSH/RDP access)
10. **Challenge Containers** ⚠️ (Attacker & Victim machines)

### Optional (Can be shown inside CTF Automation):
- **Classifier Agent**
- **Create Agent**
- **Deploy Agent**
- **Validator Agent**
- **Questions Agent**

---

## 📋 Recommended Layer Structure:

```
1. User Layer
   └── User Browser

2. Frontend Layer
   └── Frontend (React + TypeScript)

3. Backend Layer
   └── Backend (Express.js)

4. CTF Automation Layer
   ├── CTF Automation Service
   ├── Classifier Agent
   ├── Create Agent
   ├── Deploy Agent
   ├── Validator Agent
   └── Questions Agent

5. Database Layer
   ├── PostgreSQL
   └── MySQL

6. Container Infrastructure Layer
   ├── Docker Engine
   ├── Guacamole
   └── Challenge Containers

7. External Services Layer
   ├── GitHub
   ├── OpenAI
   └── Anthropic
```

---

**Total Connections: 50 (simplified from 90)**

**Note:** Use simple, general labels like "Store Data", "Manage Containers", "Generate Content" instead of technical details.

