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
   - Label: `"Store & Retrieve Data"`

8. **PostgreSQL Layer** → **Backend Layer**
   - Label: `"Data"`

---

### CTF Automation Layer → PostgreSQL Layer

9. **CTF Automation Layer** → **PostgreSQL Layer**
   - Label: `"Read/Write Data"`

10. **PostgreSQL Layer** → **CTF Automation Layer**
    - Label: `"Data"`

---

### CTF Automation Layer → MySQL Layer

11. **CTF Automation Layer** → **MySQL Layer**
    - Label: `"Create Connections"`

12. **MySQL Layer** → **CTF Automation Layer**
    - Label: `"Connection Data"`

---

### CTF Automation Layer → External API Layer

13. **CTF Automation Layer** → **External API Layer**
    - Label: `"API Requests"`

14. **External API Layer** → **CTF Automation Layer**
    - Label: `"API Responses"`

---

### CTF Automation Layer → Container Infrastructure Layer

15. **CTF Automation Layer** → **Container Infrastructure Layer**
    - Label: `"Manage Containers"`

16. **Container Infrastructure Layer** → **CTF Automation Layer**
    - Label: `"Container Status"`

---

### Container Infrastructure Layer → MySQL Layer

17. **Container Infrastructure Layer** → **MySQL Layer**
    - Label: `"Read Config"`

18. **MySQL Layer** → **Container Infrastructure Layer**
    - Label: `"Config Data"`

---

## Summary

**Total Inter-Layer Connections: 18**

- User ↔ Frontend: 2 connections
- Frontend ↔ Backend: 2 connections
- Frontend ↔ CTF Automation: 2 connections
- Backend ↔ PostgreSQL: 2 connections
- CTF Automation ↔ PostgreSQL: 2 connections
- CTF Automation ↔ MySQL: 2 connections
- CTF Automation ↔ External API: 2 connections
- CTF Automation ↔ Container Infrastructure: 2 connections
- Container Infrastructure ↔ MySQL: 2 connections

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

**Note:** All connections are bidirectional (shown with ↕). Each layer connects to other layers, but internal components within each layer are not shown.

