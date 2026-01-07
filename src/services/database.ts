/**
 * Database API Client
 * Communicates with backend API server for database operations
 */

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:4002/api'; // New port, original 3002 kept for backup

// ===== CHAT MESSAGES =====

export interface ChatMessage {
  message_id?: number;
  session_id: string;
  user_id?: number;
  role: 'user' | 'assistant';
  message_text: string;
  challenge_id?: number;
  timestamp?: Date;
  metadata?: any;
}

/**
 * Save a chat message to the database
 */
export async function saveChatMessage(message: ChatMessage): Promise<void> {
  try {
    const response = await fetch(`${API_BASE_URL}/chat/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(message),
    });
    
    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }
    
    console.log('💾 Chat message saved to database');
  } catch (error) {
    console.error('Error saving chat message:', error);
    throw error;
  }
}

/**
 * Get chat history for a session
 */
export async function getChatHistory(sessionId: string): Promise<ChatMessage[]> {
  try {
    const response = await fetch(`${API_BASE_URL}/chat/history/${sessionId}`);
    
    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }
    
    const data = await response.json();
    return data.data || [];
  } catch (error) {
    console.error('Error getting chat history:', error);
    return [];
  }
}

// ===== SESSIONS =====

/**
 * Create or update a session
 */
export async function createSession(sessionId: string, userId?: number): Promise<void> {
  try {
    const response = await fetch(`${API_BASE_URL}/sessions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sessionId, userId }),
    });
    
    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }
  } catch (error) {
    console.error('Error creating session:', error);
    throw error;
  }
}

// ===== USERS =====

export interface User {
  user_id: number;
  username: string;
  email: string;
  name?: string;
  bio?: string;
  profile_avatar?: string;
  avatar_animal_id?: string;
  role: string;
  challenges_solved: number;
  current_streak: number;
  longest_streak: number;
  streak_frozen: boolean;
}

/**
 * Get user by ID
 */
export async function getUserById(userId: number): Promise<User | null> {
  try {
    const response = await fetch(`${API_BASE_URL}/users/${userId}`);
    
    if (!response.ok) {
      return null;
    }
    
    const data = await response.json();
    return data.data || null;
  } catch (error) {
    console.error('Error getting user:', error);
    return null;
  }
}

/**
 * Update user profile
 */
export async function updateUserProfile(userId: number, updates: Partial<User>, token: string): Promise<User | null> {
  try {
    const response = await fetch(`${API_BASE_URL}/users/${userId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify(updates),
    });
    
    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }
    
    const data = await response.json();
    return data.data || null;
  } catch (error) {
    console.error('Error updating user:', error);
    return null;
  }
}

// ===== CHALLENGES =====

export interface Challenge {
  challenge_id?: number;
  challenge_name: string;
  slug: string;
  user_id?: number;
  category: string;
  difficulty?: string;
  description?: string;
  hints?: string[];
  flag: string;
  points?: number;
  github_link?: string;
  docker_image?: string;
  deploy_command?: string;
  container_name?: string;
  target_url?: string;
  is_active?: boolean;
}

/**
 * Save a challenge generated from the CTF automation service
 */
export async function saveChallenge(challenge: Challenge, token: string): Promise<number> {
  try {
    const response = await fetch(`${API_BASE_URL}/challenges`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify(challenge),
    });
    
    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }
    
    const data = await response.json();
    console.log('💾 Challenge saved to database');
    return data.data.challenge_id;
  } catch (error) {
    console.error('Error saving challenge:', error);
    throw error;
  }
}

/**
 * Get all active challenges
 */
export async function getAllChallenges(): Promise<Challenge[]> {
  try {
    const response = await fetch(`${API_BASE_URL}/challenges`);
    
    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }
    
    const data = await response.json();
    return data.data || [];
  } catch (error) {
    console.error('Error getting challenges:', error);
    return [];
  }
}

/**
 * Get challenge by ID
 */
export async function getChallengeById(challengeId: number): Promise<Challenge | null> {
  try {
    const response = await fetch(`${API_BASE_URL}/challenges/${challengeId}`);
    
    if (!response.ok) {
      return null;
    }
    
    const data = await response.json();
    return data.data || null;
  } catch (error) {
    console.error('Error getting challenge:', error);
    return null;
  }
}

/**
 * Submit flag for a challenge
 */
export async function submitFlag(challengeId: number, flag: string, token: string): Promise<{ correct: boolean; message: string }> {
  try {
    const response = await fetch(`${API_BASE_URL}/challenges/${challengeId}/submit`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({ submitted_flag: flag }),
    });
    
    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }
    
    const data = await response.json();
    return {
      correct: data.correct,
      message: data.message,
    };
  } catch (error) {
    console.error('Error submitting flag:', error);
    throw error;
  }
}

// ===== LEADERBOARDS =====

export interface LeaderboardEntry {
  rank: number;
  user_id: number;
  username: string;
  name?: string;
  profile_avatar?: string;
  avatar_animal_id?: string;
  score: number;
}

/**
 * Get leaderboard by challenges solved
 */
export async function getLeaderboardBySolves(limit: number = 100): Promise<LeaderboardEntry[]> {
  try {
    const response = await fetch(`${API_BASE_URL}/leaderboard/solves?limit=${limit}`);
    
    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }
    
    const data = await response.json();
    return data.data || [];
  } catch (error) {
    console.error('Error getting solves leaderboard:', error);
    return [];
  }
}

/**
 * Get leaderboard by current streak
 */
export async function getLeaderboardByStreak(limit: number = 100): Promise<LeaderboardEntry[]> {
  try {
    const response = await fetch(`${API_BASE_URL}/leaderboard/streak?limit=${limit}`);
    
    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }
    
    const data = await response.json();
    return data.data || [];
  } catch (error) {
    console.error('Error getting streak leaderboard:', error);
    return [];
  }
}

// ===== UTILITY =====

/**
 * Test API connection
 */
export async function testConnection(): Promise<boolean> {
  try {
    const response = await fetch(`${API_BASE_URL}/health`);
    
    if (!response.ok) {
      return false;
    }
    
    const data = await response.json();
    console.log('✅ Backend API connected:', data);
    return data.status === 'ok';
  } catch (error) {
    console.error('❌ Backend API connection failed:', error);
    return false;
  }
}
