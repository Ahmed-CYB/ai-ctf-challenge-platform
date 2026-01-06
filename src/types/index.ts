export interface User {
  id: string;
  name: string;
  username: string;
  email: string;
  avatar?: string;
  role?: string;
  bio?: string;
  level?: string;
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
  tags: string[];
  createdAt: Date;
  isPublished: boolean;
  isSaved?: boolean;
  targetUrl?: string;
  estimatedTime: string;
}

export interface UserStats {
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
  challengesSolved: number;
  level: string;
}
