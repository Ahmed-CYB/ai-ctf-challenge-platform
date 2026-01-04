export interface User {
  id: string;
  name: string;
  username: string;
  email: string;
  avatar?: string;
  role?: string;
  bio?: string;
  level?: string;
  points?: number;
  challengesSolved?: number;
  challengesCreated?: number;
  rank?: number;
}

export interface Challenge {
  id: string;
  title: string;
  description: string;
  category: string;
  difficulty: 'Beginner' | 'Intermediate' | 'Advanced';
  author: User;
  solves: number;
  attempts: number;
  points: number;
  tags: string[];
  createdAt: Date;
  isPublished: boolean;
  isSaved?: boolean;
  targetUrl?: string;
  estimatedTime: string;
}

export interface UserStats {
  totalSolved: number;
  totalPoints: number;
  currentStreak: number;
  longestStreak: number;
  categoriesBreakdown: {
    category: string;
    solved: number;
    total: number;
  }[];
}

export interface LeaderboardEntry {
  rank: number;
  username: string;
  name: string;
  avatar?: string;
  points: number;
  challengesSolved: number;
  level: string;
}
