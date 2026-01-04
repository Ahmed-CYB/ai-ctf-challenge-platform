# AI-Powered CTF Challenge Generator

An automated platform for generating and deploying Capture The Flag (CTF) cybersecurity challenges using AI.

## Features

- **Interactive UI Design**: Clean, modern interface for challenge generation
- **Simulated Workflow**: Demonstrates the complete deployment pipeline
- **Multiple Categories**: Supports Web Exploitation, Cryptography, Reverse Engineering, Forensics, Binary Exploitation, and OSINT
- **Difficulty Levels**: Beginner, Intermediate, and Advanced challenges
- **Real-time Progress**: Visual feedback through all deployment stages
- **Solution Writeups**: View detailed step-by-step solutions

## Setup

### Prerequisites

- Node.js 18+

### Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the development server:
   ```bash
   npm run dev
   ```

## Usage

This is a **design prototype** demonstrating the user interface and interaction flow:

1. Select a challenge category
2. Choose a difficulty level
3. Click "Generate Challenge"
4. Watch the simulated workflow progress through:
   - AI Planning
   - Docker Building
   - Cloud Deployment
   - Challenge Validation
5. View the challenge details and solution writeup

## Architecture

### Frontend
- **React + TypeScript**: Modern UI framework
- **Tailwind CSS V4**: Styling and responsive design
- **shadcn/ui**: Component library

### Workflow Simulation
1. User selects category and difficulty
2. Simulated AI planning phase
3. Simulated Docker container build
4. Simulated cloud deployment
5. Simulated validation
6. Display challenge URL and writeup

## Project Structure

```
├── App.tsx                          # Main application entry
├── components/
│   ├── CTFChatInterface.tsx         # Main chat interface component
│   └── ui/                          # shadcn/ui components
└── styles/
    └── globals.css                  # Tailwind V4 global styles
```

## Design Focus

This prototype focuses on:
- Clean, intuitive user interface
- Smooth interaction flows
- Visual feedback during operations
- Responsive design
- Accessibility considerations

## Future Implementation

To convert this design into a production system:
- Integrate real ChatGPT API for challenge generation
- Implement actual Docker containerization
- Set up AWS deployment infrastructure
- Add user authentication and authorization
- Build challenge validation system
- Create persistent storage for challenges

## Research Background

This project is based on the investigation report: "AI Powered Platform for Automated CTF Challenge Generation and Deployment" by Ahmed Mohamed Osman Ahmed Omer (TP074235), completed at Asia Pacific University of Technology and Innovation (2025).

### Key Research Findings

- 72.7% of survey respondents believe they would benefit from automated CTF generation
- 61.4% cited "lack of time" as the main barrier to CTF participation
- 54.5% preferred web-based platform access over VMs or repositories
- Platform rated highly useful for students (47.7% - very useful), lecturers (45.5%), and hobbyists (59.1%)

## Project Status

**Current Phase**: UI/UX Design Prototype

This is a design demonstration focusing on user interface and interaction flows. Backend implementation with ChatGPT integration, Docker, and AWS deployment will be added in future development phases.

## License

This project was developed as part of academic research at Asia Pacific University.

## Acknowledgements

- Supervisor: Dr. Julia Binti Juremi
- Second Marker: Assoc. Prof. Dr. Jalil Bin Md Desa
- Asia Pacific University Forensics and Security (FSeC) Department

---

**Design Prototype | Built with React & TypeScript | Designed for Cybersecurity Education**
