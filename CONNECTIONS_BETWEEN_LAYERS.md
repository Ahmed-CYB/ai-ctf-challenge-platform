# Architecture Connections - Between Layers Only

## Layer Order (Top to Bottom):
1. **User Layer**
2. **Frontend Layer**
3. **Backend Layer**
4. **CTF Automation Layer**
5. **Database Layer**
6. **External API Layer**
7. **Container Infrastructure Layer**

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

### Backend Layer → Database Layer

7. **Backend Layer** → **Database Layer**
   - Label: `"Store & Retrieve Data"`

8. **Database Layer** → **Backend Layer**
   - Label: `"Data"`

---

### CTF Automation Layer → Database Layer

9. **CTF Automation Layer** → **Database Layer**
   - Label: `"Read/Write Data"`

10. **Database Layer** → **CTF Automation Layer**
    - Label: `"Data"`

---

### CTF Automation Layer → External API Layer

11. **CTF Automation Layer** → **External API Layer**
    - Label: `"API Requests"`

12. **External API Layer** → **CTF Automation Layer**
    - Label: `"API Responses"`

---

### CTF Automation Layer → Container Infrastructure Layer

13. **CTF Automation Layer** → **Container Infrastructure Layer**
    - Label: `"Manage Containers"`

14. **Container Infrastructure Layer** → **CTF Automation Layer**
    - Label: `"Container Status"`

---

### Container Infrastructure Layer → Database Layer

15. **Container Infrastructure Layer** → **Database Layer**
    - Label: `"Read Config"`

16. **Database Layer** → **Container Infrastructure Layer**
    - Label: `"Config Data"`

---

## Summary

**Total Inter-Layer Connections: 16**

- User ↔ Frontend: 2 connections
- Frontend ↔ Backend: 2 connections
- Frontend ↔ CTF Automation: 2 connections
- Backend ↔ Database: 2 connections
- CTF Automation ↔ Database: 2 connections
- CTF Automation ↔ External API: 2 connections
- CTF Automation ↔ Container Infrastructure: 2 connections
- Container Infrastructure ↔ Database: 2 connections

---

## Visual Representation

```
User Layer
    ↕
Frontend Layer
    ↕          ↕
Backend Layer  CTF Automation Layer
    ↕              ↕        ↕        ↕
Database Layer     Database  External  Container
                        Layer    API     Infrastructure
                                Layer      Layer
```

---

**Note:** All connections are bidirectional (shown with ↕). Each layer connects to other layers, but internal components within each layer are not shown.

