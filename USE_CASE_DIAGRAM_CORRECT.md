# AI CTF Challenge Platform - Use Case Diagram (UML Compliant)

## Quick Reference: <<include>> vs <<extend>>

### 🎯 **Simple Rule to Remember:**

**<<include>>** = **MANDATORY** (Must happen)
- Arrow: `[Main Use Case] --<<include>>--> [Helper Use Case]`
- Example: "Create Challenge" --<<include>>--> "Chat with AI"
- Meaning: You CANNOT create a challenge without chatting

**<<extend>>** = **OPTIONAL** (May happen)
- Arrow: `[Optional Use Case] --<<extend>>--> [Main Use Case]`
- Example: "View History" --<<extend>>--> "Chat with AI"
- Meaning: After chatting, you MAY view history (but don't have to)

### 📍 **How to Tell Them Apart in the Diagram:**

1. **Look at the arrow direction:**
   - **<<include>>**: Arrow points FROM main use case TO helper use case
   - **<<extend>>**: Arrow points FROM optional use case TO main use case

2. **Look at the label:**
   - Both show `<<include>>` or `<<extend>>` in the label
   - The arrow direction tells you which is which!

3. **Ask yourself:**
   - "Is this required?" → If YES, it's <<include>>
   - "Is this optional?" → If YES, it's <<extend>>

---

## References

This use case diagram follows UML 2.5 specifications and best practices from:

1. **Stack Overflow - Use Case Diagram Connections**: [Which is the correct way to use in use case diagram?](https://stackoverflow.com/questions/65665579/which-is-the-correct-way-to-use-in-use-case-diagram)
   - Solid lines without arrowheads for actor-use case associations
   - Dashed arrows for include/extend relationships

2. **Visual Paradigm - Use Case Diagram Tips**: [10 Use Case Diagram Tips](https://knowhow.visual-paradigm.com/uml/10-use-case-diagram-tips/)
   - <<include>> for shared mandatory behavior
   - <<extend>> for optional conditional behavior
   - Concise, descriptive use case names

3. **Go UML - Comprehensive Guide**: [Comprehensive Guide to UML Use Case Diagrams](https://www.go-uml.com/comprehensive-guide-to-uml-use-case-diagrams/)
   - Focus on user goals, not system functions
   - Actors as roles, not individuals
   - Proper generalization relationships

4. **Visual Paradigm Tutorial**: [UML Use Case Diagram Tutorial](https://www.visual-paradigm.com/guide/uml-unified-modeling-language/what-is-use-case-diagram/)
   - System boundary representation
   - Actor placement and organization

---

## Use Case Diagram (UML Compliant)

```mermaid
graph TB
    subgraph System["AI CTF Challenge Platform"]
        UC1[Register Account]
        UC2[Login to Platform]
        UC3[Logout from Platform]
        UC4[View Dashboard]
        UC5[Create CTF Challenge]
        UC6[Deploy CTF Challenge]
        UC7[Access Challenge Environment]
        UC8[Chat with AI Assistant]
        UC9[View Challenge Details]
        UC10[View Chat History]
        UC11[Manage User Profile]
        UC12[Browse Challenges]
        UC13[Validate Challenge Deployment]
        UC14[Generate Challenge Content]
        UC15[Store Challenge Files]
        UC16[Create Container Network]
        UC17[Setup Guacamole Connection]
    end

    User((User))
    OpenAI((OpenAI API))
    Anthropic((Anthropic API))
    GitHub((GitHub Repository))
    Guacamole((Guacamole Service))
    Docker((Docker Engine))

    %% Actor-Use Case Associations (Solid lines, NO arrowheads - UML Standard)
    User --- UC1
    User --- UC2
    User --- UC3
    User --- UC4
    User --- UC5
    User --- UC6
    User --- UC7
    User --- UC8
    User --- UC9
    User --- UC11
    User --- UC12

    %% Include Relationships (MANDATORY - Dashed arrow FROM base TO included)
    %% Rule: Base use case MUST include these - they always happen
    %% Visual: Blue dashed arrows pointing FROM base TO included
    UC5 -.->|<<include>>| UC8
    UC5 -.->|<<include>>| UC14
    UC5 -.->|<<include>>| UC15
    UC6 -.->|<<include>>| UC8
    UC6 -.->|<<include>>| UC13
    UC6 -.->|<<include>>| UC16
    UC6 -.->|<<include>>| UC17
    UC6 -.->|<<include>>| UC7

    %% Extend Relationships (OPTIONAL - Dashed arrow FROM extending TO base)
    %% Rule: Extending use case MAY happen - it's optional behavior
    %% Visual: Green dashed arrows pointing FROM extending TO base
    UC12 -.->|<<extend>>| UC5
    UC12 -.->|<<extend>>| UC6
    UC10 -.->|<<extend>>| UC8
    UC10 -.->|<<extend>>| UC7
    UC10 -.->|<<extend>>| UC9
    UC9 -.->|<<extend>>| UC5
    UC9 -.->|<<extend>>| UC6

    %% External Actor Associations (Solid lines, NO arrowheads)
    UC14 --- OpenAI
    UC14 --- Anthropic
    UC15 --- GitHub
    UC6 --- GitHub
    UC13 --- Docker
    UC16 --- Docker
    UC17 --- Guacamole
    UC7 --- Guacamole

    style System fill:#e1f5ff,stroke:#01579b,stroke-width:3px
    style User fill:#fff9c4,stroke:#f57f17,stroke-width:2px
    style OpenAI fill:#ffccbc,stroke:#bf360c,stroke-width:2px
    style Anthropic fill:#ffccbc,stroke:#bf360c,stroke-width:2px
    style GitHub fill:#ffccbc,stroke:#bf360c,stroke-width:2px
    style Guacamole fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
    style Docker fill:#90caf9,stroke:#0d47a1,stroke-width:2px
    
    %% Color coding for relationships (if supported)
    linkStyle 11 stroke:#2196F3,stroke-width:2px,stroke-dasharray: 5 5
    linkStyle 12 stroke:#2196F3,stroke-width:2px,stroke-dasharray: 5 5
    linkStyle 13 stroke:#2196F3,stroke-width:2px,stroke-dasharray: 5 5
    linkStyle 14 stroke:#2196F3,stroke-width:2px,stroke-dasharray: 5 5
    linkStyle 15 stroke:#2196F3,stroke-width:2px,stroke-dasharray: 5 5
    linkStyle 16 stroke:#2196F3,stroke-width:2px,stroke-dasharray: 5 5
    linkStyle 17 stroke:#2196F3,stroke-width:2px,stroke-dasharray: 5 5
    linkStyle 18 stroke:#2196F3,stroke-width:2px,stroke-dasharray: 5 5
    linkStyle 19 stroke:#4CAF50,stroke-width:2px,stroke-dasharray: 5 5
    linkStyle 20 stroke:#4CAF50,stroke-width:2px,stroke-dasharray: 5 5
    linkStyle 21 stroke:#4CAF50,stroke-width:2px,stroke-dasharray: 5 5
    linkStyle 22 stroke:#4CAF50,stroke-width:2px,stroke-dasharray: 5 5
    linkStyle 23 stroke:#4CAF50,stroke-width:2px,stroke-dasharray: 5 5
    linkStyle 24 stroke:#4CAF50,stroke-width:2px,stroke-dasharray: 5 5
    linkStyle 25 stroke:#4CAF50,stroke-width:2px,stroke-dasharray: 5 5
```

---

## How to Differentiate <<include>> vs <<extend>>

### Key Differences:

| Aspect | <<include>> | <<extend>> |
|--------|-------------|------------|
| **Arrow Direction** | FROM base use case TO included use case | FROM extending use case TO base use case |
| **Meaning** | **MANDATORY** - Always happens | **OPTIONAL** - May happen |
| **When Used** | Base use case is incomplete without included | Extending use case adds optional behavior |
| **Example** | "Create Challenge" → includes → "Chat with AI" | "View History" → extends → "Chat with AI" |
| **Think of it as** | "Must do" or "Part of" | "May do" or "Can also do" |
| **Color in Diagram** | Blue dashed arrow | Green dashed arrow |

### Visual Comparison Diagram:

```mermaid
graph LR
    subgraph Include["<<include>> Example - MANDATORY"]
        A1[Create Challenge] -.->|<<include>>| A2[Chat with AI]
        A3["When you Create Challenge,<br/>you MUST Chat with AI<br/>(It's part of the process)"]
    end
    
    subgraph Extend["<<extend>> Example - OPTIONAL"]
        B1[View History] -.->|<<extend>>| B2[Chat with AI]
        B3["After Chatting,<br/>you MAY View History<br/>(It's optional)"]
    end
    
    style A1 fill:#fff9c4
    style A2 fill:#c8e6c9
    style B1 fill:#fff9c4
    style B2 fill:#c8e6c9
```

### Visual Identification:

**<<include>> (Mandatory)**:
```
[Base Use Case] --<<include>>--> [Included Use Case]
     (FROM)                            (TO)
```
- Arrow points FROM the main use case TO the required sub-use case
- Example: "Create Challenge" --<<include>>--> "Chat with AI"
- **Meaning**: When you Create Challenge, you MUST Chat with AI (it's part of the process)

**<<extend>> (Optional)**:
```
[Extending Use Case] --<<extend>>--> [Base Use Case]
         (FROM)                           (TO)
```
- Arrow points FROM the optional use case TO the base use case
- Example: "View History" --<<extend>>--> "Chat with AI"
- **Meaning**: After Chatting, you MAY optionally View History (it's not required)

### Quick Rule:
- **<<include>>**: "I need this to work" → Arrow FROM main TO helper
- **<<extend>>**: "I might do this too" → Arrow FROM optional TO main

---

## UML Notation Standards Applied

### 1. **Actor-Use Case Associations**
- **Standard**: Solid lines WITHOUT arrowheads
- **Rationale**: Associations are bidirectional; actors and use cases communicate with each other
- **Reference**: [Stack Overflow - Use Case Diagram Connections](https://stackoverflow.com/questions/65665579/which-is-the-correct-way-to-use-in-use-case-diagram)

### 2. **Include Relationship (<<include>>)**
- **Standard**: Dashed arrow FROM base use case TO included use case
- **Meaning**: The included use case is ALWAYS executed as part of the base use case (MANDATORY)
- **Arrow Direction**: Base → Included
- **Example**: "Create CTF Challenge" includes "Chat with AI Assistant" (mandatory - you must chat to create)
- **Visual**: `UC5 --<<include>>--> UC8` (Create Challenge includes Chat)
- **Reference**: [UML Diagrams - Include Relationship](https://www.uml-diagrams.org/use-case-include.html)

### 3. **Extend Relationship (<<extend>>)**
- **Standard**: Dashed arrow FROM extending use case TO base use case
- **Meaning**: The extending use case adds OPTIONAL behavior to the base use case (CONDITIONAL)
- **Arrow Direction**: Extending → Base
- **Example**: "View Chat History" extends "Chat with AI Assistant" (optional - you may view history after chatting)
- **Visual**: `UC10 --<<extend>>--> UC8` (View History extends Chat)
- **Reference**: [Visual Paradigm - Extend Relationship](https://knowhow.visual-paradigm.com/uml/10-use-case-diagram-tips/)

### 4. **Use Case Naming Convention**
- **Standard**: Verb-Noun format (e.g., "Create Challenge", "Deploy Challenge")
- **Rationale**: Use cases represent actions/goals, not system functions
- **Reference**: [Go UML - Use Case Naming](https://www.go-uml.com/mastering-use-case-diagrams-10-essential-tips-for-clarity-and-effectiveness/)

### 5. **Actor Representation**
- **Standard**: Actors represent roles, not individuals
- **Rationale**: "User" represents all users of the system, not specific people
- **Reference**: [Go UML - Actor Definition](https://www.go-uml.com/mastering-use-case-diagrams-10-essential-tips-for-clarity-and-effectiveness/)

---

## Corrected Relationships Explanation

### Include Relationships (MANDATORY - Always Happens)

**Arrow Direction**: FROM base use case TO included use case  
**Visual Pattern**: `[Base] --<<include>>--> [Included]`

1. **UC5 (Create Challenge) includes UC8, UC14, UC15**
   - **UC5 → UC8**: Creating challenge **MUST** use AI chat (mandatory)
   - **UC5 → UC14**: Creating challenge **MUST** generate content (mandatory)
   - **UC5 → UC15**: Creating challenge **MUST** store files (mandatory)
   - **Why Include?**: You cannot create a challenge without chatting, generating, and storing

2. **UC6 (Deploy Challenge) includes UC8, UC13, UC16, UC17, UC7**
   - **UC6 → UC8**: Deployment **MUST** use AI chat (mandatory)
   - **UC6 → UC13**: Deployment **MUST** validate (mandatory)
   - **UC6 → UC16**: Deployment **MUST** create network (mandatory)
   - **UC6 → UC17**: Deployment **MUST** setup Guacamole (mandatory)
   - **UC6 → UC7**: Deployment **MUST** provide access (mandatory)
   - **Why Include?**: You cannot deploy without these steps

**Key Point**: If the base use case happens, the included use case ALWAYS happens.

### Extend Relationships (OPTIONAL - May Happen)

**Arrow Direction**: FROM extending use case TO base use case  
**Visual Pattern**: `[Extending] --<<extend>>--> [Base]`

1. **UC12 (Browse Challenges) extends UC5, UC6**
   - **UC12 → UC5**: After creating, user **MAY** browse challenges (optional)
   - **UC12 → UC6**: After deploying, user **MAY** browse challenges (optional)
   - **Why Extend?**: Browsing is not required after creating/deploying

2. **UC10 (View Chat History) extends UC8, UC7, UC9**
   - **UC10 → UC8**: After chatting, user **MAY** view history (optional)
   - **UC10 → UC7**: After accessing, user **MAY** view history (optional)
   - **UC10 → UC9**: After viewing details, user **MAY** view history (optional)
   - **Why Extend?**: Viewing history is not required after these actions

3. **UC9 (View Challenge Details) extends UC5, UC6**
   - **UC9 → UC5**: After creating, user **MAY** view details (optional)
   - **UC9 → UC6**: After deploying, user **MAY** view details (optional)
   - **Why Extend?**: Viewing details is not required after creating/deploying

**Key Point**: If the base use case happens, the extending use case MAY happen (but not always).

---

## Visual Comparison Table

| Relationship | Arrow Direction | Label | Meaning | Example |
|--------------|----------------|-------|---------|---------|
| **<<include>>** | Base → Included | `<<include>>` | **MANDATORY** - Always happens | Create Challenge → Chat with AI |
| **<<extend>>** | Extending → Base | `<<extend>>` | **OPTIONAL** - May happen | View History → Chat with AI |

---

## Memory Trick

**<<include>>** = "**I NEED** this" (mandatory)
- Think: "I need to chat to create a challenge"
- Arrow: Create → Chat
- **Color**: Blue (in diagram)
- **Direction**: Base → Included

**<<extend>>** = "**I MIGHT** do this" (optional)
- Think: "I might view history after chatting"
- Arrow: View History → Chat
- **Color**: Green (in diagram)
- **Direction**: Extending → Base

---

## Step-by-Step Identification Guide

### How to Identify <<include>>:

1. **Look at the arrow direction**: FROM a main use case TO a helper use case
2. **Ask yourself**: "Can the main use case work without this?"
   - If NO → It's <<include>>
3. **Example**: 
   - "Create Challenge" → "Chat with AI"
   - Question: Can you create a challenge without chatting? NO
   - Answer: It's <<include>> (mandatory)

### How to Identify <<extend>>:

1. **Look at the arrow direction**: FROM an optional use case TO a main use case
2. **Ask yourself**: "Is this required for the main use case to work?"
   - If NO → It's <<extend>>
3. **Example**:
   - "View History" → "Chat with AI"
   - Question: Is viewing history required for chatting? NO
   - Answer: It's <<extend>> (optional)

---

## Real-World Analogy

**<<include>>** = Making Coffee
- Making Coffee **includes** Boiling Water (you MUST boil water)
- Making Coffee **includes** Adding Coffee (you MUST add coffee)
- You cannot make coffee without these steps

**<<extend>>** = Making Coffee
- Making Coffee **extends** Adding Sugar (you MAY add sugar, but it's optional)
- Making Coffee **extends** Adding Milk (you MAY add milk, but it's optional)
- Coffee works fine without sugar or milk

---

## Use Case Naming Verification

All use cases follow **Verb-Noun** format:

✅ **Correct Naming**:
- Register Account (verb: Register, noun: Account)
- Login to Platform (verb: Login, noun: Platform)
- Create CTF Challenge (verb: Create, noun: Challenge)
- Deploy CTF Challenge (verb: Deploy, noun: Challenge)
- Access Challenge Environment (verb: Access, noun: Environment)
- Chat with AI Assistant (verb: Chat, noun: Assistant)
- View Challenge Details (verb: View, noun: Details)
- Browse Challenges (verb: Browse, noun: Challenges)

❌ **Incorrect Naming** (avoided):
- Account Registration (noun-verb - wrong order)
- Challenge Creation (noun-verb - wrong order)
- User Login Process (too verbose, includes "Process")

---

## PlantUML Format (UML Standard)

```plantuml
@startuml AI_CTF_Challenge_Platform_Use_Case_Diagram

left to right direction

actor User
actor "OpenAI API" as OpenAI
actor "Anthropic API" as Anthropic
actor "GitHub Repository" as GitHub
actor "Guacamole Service" as Guacamole
actor "Docker Engine" as Docker

rectangle "AI CTF Challenge Platform" {
    usecase "Register Account" as UC1
    usecase "Login to Platform" as UC2
    usecase "Logout from Platform" as UC3
    usecase "View Dashboard" as UC4
    usecase "Create CTF Challenge" as UC5
    usecase "Deploy CTF Challenge" as UC6
    usecase "Access Challenge Environment" as UC7
    usecase "Chat with AI Assistant" as UC8
    usecase "View Challenge Details" as UC9
    usecase "View Chat History" as UC10
    usecase "Manage User Profile" as UC11
    usecase "Browse Challenges" as UC12
    usecase "Validate Challenge Deployment" as UC13
    usecase "Generate Challenge Content" as UC14
    usecase "Store Challenge Files" as UC15
    usecase "Create Container Network" as UC16
    usecase "Setup Guacamole Connection" as UC17
}

' Actor-Use Case Associations (Solid lines, no arrowheads)
User -- UC1
User -- UC2
User -- UC3
User -- UC4
User -- UC5
User -- UC6
User -- UC7
User -- UC8
User -- UC9
User -- UC11
User -- UC12

' Include Relationships (Dashed arrow FROM base TO included)
UC5 ..> UC8 : <<include>>
UC5 ..> UC14 : <<include>>
UC5 ..> UC15 : <<include>>
UC6 ..> UC8 : <<include>>
UC6 ..> UC13 : <<include>>
UC6 ..> UC16 : <<include>>
UC6 ..> UC17 : <<include>>
UC6 ..> UC7 : <<include>>

' Extend Relationships (Dashed arrow FROM extending TO base)
UC12 ..> UC5 : <<extend>>
UC12 ..> UC6 : <<extend>>
UC10 ..> UC8 : <<extend>>
UC10 ..> UC7 : <<extend>>
UC10 ..> UC9 : <<extend>>
UC9 ..> UC5 : <<extend>>
UC9 ..> UC6 : <<extend>>

' External Actor Associations (Solid lines, no arrowheads)
UC14 -- OpenAI
UC14 -- Anthropic
UC15 -- GitHub
UC6 -- GitHub
UC13 -- Docker
UC16 -- Docker
UC17 -- Guacamole
UC7 -- Guacamole

@enduml
```

---

## Summary of Corrections Made

### 1. **Arrow Types**
- ✅ **Changed**: Actor-Use Case associations from arrows to solid lines (no arrowheads)
- ✅ **Changed**: External actor associations from arrows to solid lines (no arrowheads)
- ✅ **Kept**: Dashed arrows for include/extend relationships (correct)

### 2. **Arrow Directions**
- ✅ **Include**: Arrow FROM base use case TO included use case
- ✅ **Extend**: Arrow FROM extending use case TO base use case

### 3. **Naming Conventions**
- ✅ All use cases follow Verb-Noun format
- ✅ Use case names are concise and goal-oriented
- ✅ Actors represent roles, not individuals

### 4. **Relationship Corrections**
- ✅ Fixed include relationships (mandatory dependencies) - 8 relationships
- ✅ Fixed extend relationships (optional behaviors) - 7 relationships
- ✅ Removed incorrect "initiates" and "uses" labels from associations
- ✅ Removed incorrect include relationship between Login and Register (Login doesn't include Register, it just requires registration to have occurred previously)

---

## Use Case Diagram Statistics

- **Total Use Cases**: 17
- **Primary Use Cases**: 12 (User-initiated)
- **Secondary Use Cases**: 5 (System-internal)
- **Primary Actor**: 1 (User)
- **Secondary Actors**: 5 (OpenAI API, Anthropic API, GitHub Repository, Guacamole Service, Docker Engine)
- **Actor-Use Case Associations**: 19 (solid lines, no arrowheads)
- **Include Relationships**: 8 (dashed arrows, mandatory)
- **Extend Relationships**: 7 (dashed arrows, optional)

---

## References

1. **Stack Overflow** (2021). "Which is the correct way to use in use case diagram?"  
   https://stackoverflow.com/questions/65665579/which-is-the-correct-way-to-use-in-use-case-diagram

2. **Visual Paradigm** (n.d.). "10 Use Case Diagram Tips and Best Practices"  
   https://knowhow.visual-paradigm.com/uml/10-use-case-diagram-tips/

3. **Go UML** (n.d.). "Comprehensive Guide to UML Use Case Diagrams"  
   https://www.go-uml.com/comprehensive-guide-to-uml-use-case-diagrams/

4. **Go UML** (n.d.). "Mastering Use Case Diagrams: 10 Essential Tips"  
   https://www.go-uml.com/mastering-use-case-diagrams-10-essential-tips-for-clarity-and-effectiveness/

5. **Visual Paradigm** (n.d.). "UML Use Case Diagram Tutorial"  
   https://www.visual-paradigm.com/guide/uml-unified-modeling-language/what-is-use-case-diagram/

6. **IDA, Linköping University** (n.d.). "Requirements Engineering"  
   https://www.ida.liu.se/~TDDC88/theory/03requirements.pdf

---

**Last Updated**: 2025-01-27  
**Version**: 3.0 (UML Compliant)  
**UML Standard**: UML 2.5

