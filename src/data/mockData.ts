import { User, Challenge, UserStats } from '../types';

// Default user data (will be replaced with actual user data from auth)
export const currentUser: User = {
  id: 'user-1',
  name: 'User',
  username: 'user',
  email: 'user@example.com',
  avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=Default',
  bio: 'Cybersecurity enthusiast. Passionate about CTF challenges and ethical hacking.',
  level: 'Intermediate',
  points: 2450,
  challengesSolved: 34,
  challengesCreated: 8,
  rank: 12
};

export const mockUsers: User[] = [
  currentUser,
  {
    id: 'user-2',
    name: 'Sarah Chen',
    username: 'sarah_chen',
    email: 'sarah.chen@example.com',
    avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=Sarah',
    bio: 'Security researcher and CTF enthusiast',
    level: 'Advanced',
    points: 4820,
    challengesSolved: 67,
    challengesCreated: 15,
    rank: 3
  },
  {
    id: 'user-3',
    name: 'Marcus Johnson',
    username: 'marcus_j',
    email: 'marcus.j@example.com',
    avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=Marcus',
    bio: 'Penetration tester and educator',
    level: 'Advanced',
    points: 3920,
    challengesSolved: 52,
    challengesCreated: 12,
    rank: 7
  },
  {
    id: 'user-4',
    name: 'Lisa Wong',
    username: 'lisa_wong',
    email: 'lisa.wong@example.com',
    avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=Lisa',
    bio: 'Cybersecurity lecturer at APU',
    level: 'Advanced',
    points: 5200,
    challengesSolved: 89,
    challengesCreated: 24,
    rank: 1
  }
];

export const mockChallenges: Challenge[] = [
  {
    id: 'ch-1',
    title: 'SQL Injection Login Bypass',
    description: 'A vulnerable login form that is susceptible to SQL injection. Can you bypass the authentication and retrieve the flag?',
    category: 'Web Exploitation',
    difficulty: 'Beginner',
    author: currentUser,
    solves: 234,
    attempts: 456,
    points: 100,
    tags: ['SQL Injection', 'Authentication Bypass', 'Web Security'],
    createdAt: new Date('2025-01-15'),
    isPublished: true,
    targetUrl: 'http://192.168.1.100:8001',
    estimatedTime: '10-20 minutes'
  },
  {
    id: 'ch-2',
    title: 'XSS Cookie Stealer',
    description: 'Find and exploit a Cross-Site Scripting vulnerability to steal session cookies from an admin user.',
    category: 'Web Exploitation',
    difficulty: 'Intermediate',
    author: currentUser,
    solves: 156,
    attempts: 389,
    points: 200,
    tags: ['XSS', 'Cookie Theft', 'JavaScript'],
    createdAt: new Date('2025-01-10'),
    isPublished: true,
    targetUrl: 'http://192.168.1.101:8002',
    estimatedTime: '20-30 minutes'
  },
  {
    id: 'ch-3',
    title: 'Caesar Cipher Challenge',
    description: 'A message has been encrypted using a classical cipher. Can you decrypt it and find the flag?',
    category: 'Cryptography',
    difficulty: 'Beginner',
    author: mockUsers[1],
    solves: 445,
    attempts: 567,
    points: 50,
    tags: ['Caesar Cipher', 'Classical Crypto', 'ROT13'],
    createdAt: new Date('2025-01-20'),
    isPublished: true,
    targetUrl: 'http://192.168.1.102:8003',
    estimatedTime: '5-15 minutes'
  },
  {
    id: 'ch-4',
    title: 'RSA Encryption Weakness',
    description: 'Exploit a weak RSA implementation with small prime numbers to decrypt the flag.',
    category: 'Cryptography',
    difficulty: 'Advanced',
    author: mockUsers[1],
    solves: 78,
    attempts: 234,
    points: 500,
    tags: ['RSA', 'Number Theory', 'Factorization'],
    createdAt: new Date('2025-01-12'),
    isPublished: true,
    targetUrl: 'http://192.168.1.103:8004',
    estimatedTime: '45-60 minutes'
  },
  {
    id: 'ch-5',
    title: 'Simple Password Checker',
    description: 'A binary that checks if your password is correct. Can you find the right password?',
    category: 'Reverse Engineering',
    difficulty: 'Beginner',
    author: mockUsers[2],
    solves: 312,
    attempts: 445,
    points: 100,
    tags: ['Strings', 'Static Analysis', 'Binary'],
    createdAt: new Date('2025-01-18'),
    isPublished: true,
    targetUrl: 'http://192.168.1.104:8005',
    estimatedTime: '10-15 minutes'
  },
  {
    id: 'ch-6',
    title: 'Buffer Overflow Challenge',
    description: 'A vulnerable C program with a buffer overflow. Can you exploit it to get a shell?',
    category: 'Binary Exploitation',
    difficulty: 'Advanced',
    author: mockUsers[3],
    solves: 45,
    attempts: 178,
    points: 600,
    tags: ['Buffer Overflow', 'Stack', 'Shellcode'],
    createdAt: new Date('2025-01-08'),
    isPublished: true,
    targetUrl: 'http://192.168.1.105:8006',
    estimatedTime: '30-45 minutes'
  },
  {
    id: 'ch-7',
    title: 'Hidden Message in Image',
    description: 'An image file contains a hidden message. Use your forensics skills to extract the flag.',
    category: 'Forensics',
    difficulty: 'Intermediate',
    author: mockUsers[2],
    solves: 189,
    attempts: 312,
    points: 250,
    tags: ['Steganography', 'Image Analysis', 'Metadata'],
    createdAt: new Date('2025-01-14'),
    isPublished: true,
    targetUrl: 'http://192.168.1.106:8007',
    estimatedTime: '15-25 minutes'
  },
  {
    id: 'ch-8',
    title: 'Find the Location',
    description: 'Using only publicly available information, can you identify the location in the photograph?',
    category: 'OSINT',
    difficulty: 'Intermediate',
    author: mockUsers[3],
    solves: 134,
    attempts: 267,
    points: 200,
    tags: ['OSINT', 'Geolocation', 'EXIF'],
    createdAt: new Date('2025-01-16'),
    isPublished: true,
    targetUrl: 'http://192.168.1.107:8008',
    estimatedTime: '20-30 minutes'
  },
  // Unpublished/Saved challenges for current user
  {
    id: 'ch-9',
    title: 'API Rate Limiting Bypass',
    description: 'Find a way to bypass the API rate limiting mechanism and extract sensitive data.',
    category: 'Web Exploitation',
    difficulty: 'Intermediate',
    author: currentUser,
    solves: 0,
    attempts: 0,
    points: 300,
    tags: ['API', 'Rate Limiting', 'Web Security'],
    createdAt: new Date('2025-01-22'),
    isPublished: false,
    estimatedTime: '25-35 minutes'
  },
  {
    id: 'ch-10',
    title: 'JWT Token Manipulation',
    description: 'Exploit weaknesses in JSON Web Token implementation to gain admin access.',
    category: 'Web Exploitation',
    difficulty: 'Advanced',
    author: currentUser,
    solves: 0,
    attempts: 0,
    points: 450,
    tags: ['JWT', 'Authentication', 'Token Security'],
    createdAt: new Date('2025-01-21'),
    isPublished: false,
    estimatedTime: '35-50 minutes'
  }
];

export const userStats: UserStats = {
  totalSolved: 34,
  totalPoints: 2450,
  currentStreak: 7,
  longestStreak: 14,
  categoriesBreakdown: [
    { category: 'Web Exploitation', solved: 12, total: 25 },
    { category: 'Cryptography', solved: 8, total: 15 },
    { category: 'Reverse Engineering', solved: 6, total: 12 },
    { category: 'Forensics', solved: 4, total: 10 },
    { category: 'Binary Exploitation', solved: 2, total: 8 },
    { category: 'OSINT', solved: 2, total: 6 }
  ]
};

// Saved challenges (other users' challenges bookmarked by current user)
export const savedChallenges: Challenge[] = [
  { ...mockChallenges[3], isSaved: true },
  { ...mockChallenges[5], isSaved: true },
  { ...mockChallenges[6], isSaved: true }
];
