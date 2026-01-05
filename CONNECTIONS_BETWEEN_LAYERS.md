# Architecture Connections - Between Layers Only

## Layer Order (Top to Bottom):
1. **User Layer**
2. **Frontend Layer**
3. **Backend Layer**
4. **CTF Automation Layer**
5. **PostgreSQL Layer**
6. **MySQL Layer**
7. **External API Layer**
8. **Container Infrastructure Layer**

---

## Connections Between Layers

### User Layer → Frontend Layer

1. **User Layer** → **Frontend Layer**
   - Label: `"User Requests"`

2. **Frontend Layer** → **User Layer**
   - Label: `"Display Results"`

---

### Frontend Layer → Backend Layer

3. **Frontend Layer** → **Backend Layer**
   - Label: `"Authentication & Data Requests"`

4. **Backend Layer** → **Frontend Layer**
   - Label: `"Responses"`

---

### Frontend Layer → CTF Automation Layer

5. **Frontend Layer** → **CTF Automation Layer**
   - Label: `"Chat Requests"`

6. **CTF Automation Layer** → **Frontend Layer**
   - Label: `"Chat Responses"`

---

### Backend Layer → PostgreSQL Layer

7. **Backend Layer** → **PostgreSQL Layer**
   - Label: `"Store Users, Sessions, Chat History"`

8. **PostgreSQL Layer** → **Backend Layer**
   - Label: `"User Credentials, Session Data, Chat Messages"`

---

### CTF Automation Layer → PostgreSQL Layer

9. **CTF Automation Layer** → **PostgreSQL Layer**
   - Label: `"Store Challenges, OS Images, Tool Installations"`

10. **PostgreSQL Layer** → **CTF Automation Layer**
    - Label: `"Challenge Metadata, OS Images, Tool Data"`

---

### CTF Automation Layer → MySQL Layer

11. **CTF Automation Layer** → **MySQL Layer**
    - Label: `"Create Guacamole Users & Connections"`

12. **MySQL Layer** → **CTF Automation Layer**
    - Label: `"Guacamole User Credentials, Connection Parameters"`

---

### CTF Automation Layer → External API Layer

13. **CTF Automation Layer** → **External API Layer**
    - Label: `"API Requests (Generate Content, Clone Repos)"`

14. **External API Layer** → **CTF Automation Layer**
    - Label: `"AI Responses, Repository Files"`

---

### CTF Automation Layer → Container Infrastructure Layer

15. **CTF Automation Layer** → **Container Infrastructure Layer**
    - Label: `"Deploy Containers, Create Networks"`

16. **Container Infrastructure Layer** → **CTF Automation Layer**
    - Label: `"Container IPs, Status, Logs"`

---

### Container Infrastructure Layer → MySQL Layer

17. **Container Infrastructure Layer** → **MySQL Layer**
    - Label: `"Read Connection Configs & Credentials"`

18. **MySQL Layer** → **Container Infrastructure Layer**
    - Label: `"SSH/RDP Credentials, Connection Parameters"`

---

## Summary

**Total Inter-Layer Connections: 18**

- User ↔ Frontend: 2 connections
- Frontend ↔ Backend: 2 connections
- Frontend ↔ CTF Automation: 2 connections
- Backend ↔ PostgreSQL: 2 connections (Users, Sessions, Chat)
- CTF Automation ↔ PostgreSQL: 2 connections (Challenges, OS Images, Tools)
- CTF Automation ↔ MySQL: 2 connections (Guacamole Users, Connections)
- CTF Automation ↔ External API: 2 connections (AI, GitHub)
- CTF Automation ↔ Container Infrastructure: 2 connections (Deploy, Status)
- Container Infrastructure ↔ MySQL: 2 connections (Connection Configs, Credentials)

---

## Visual Representation

```
User Layer
    ↕
Frontend Layer
    ↕          ↕
Backend Layer  CTF Automation Layer
    ↕              ↕    ↕    ↕    ↕
PostgreSQL Layer  PostgreSQL MySQL External Container
                        Layer  Layer  API     Infrastructure
                                Layer      Layer
                                      ↕
                                    MySQL
                                    Layer
```

---

## Data Flow Summary

### PostgreSQL Layer Data:
- **From Backend**: Users, Sessions, Chat History
- **From CTF Automation**: Challenges, OS Images, Tool Installations
- **To Backend**: User Credentials, Session Data, Chat Messages
- **To CTF Automation**: Challenge Metadata, OS Images, Tool Data

### MySQL Layer Data:
- **From CTF Automation**: Guacamole Users, Connection Configs
- **From Container Infrastructure**: Connection History
- **To CTF Automation**: Guacamole User Credentials, Connection Parameters
- **To Container Infrastructure**: SSH/RDP Credentials, Connection Parameters

---

**Note:** All connections are bidirectional (shown with ↕). Each layer connects to other layers, but internal components within each layer are not shown.

