/**
 * Custom Authentication Service
 * JWT-based authentication using PostgreSQL
 */

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:4002/api'; // New port, original 3002 kept for backup

export interface User {
  user_id: number;
  username: string;
  email: string;
  name: string;
  avatar: string; // avatar_animal_id
  role: string;
  bio?: string;
  challenges_solved?: number;
  current_streak?: number;
}

interface AuthResponse {
  success: boolean;
  token?: string;
  user?: User;
  error?: string;
  message?: string;
}

/**
 * Store auth token in localStorage
 */
function setAuthToken(token: string): void {
  localStorage.setItem('auth_token', token);
}

/**
 * Get auth token from localStorage
 */
function getAuthToken(): string | null {
  return localStorage.getItem('auth_token');
}

/**
 * Remove auth token from localStorage
 */
function removeAuthToken(): void {
  localStorage.removeItem('auth_token');
  localStorage.removeItem('current_user');
}

/**
 * Store current user in localStorage
 */
function setCurrentUser(user: User): void {
  localStorage.setItem('current_user', JSON.stringify(user));
}

/**
 * Get current user from localStorage
 */
function getCachedUser(): User | null {
  const userStr = localStorage.getItem('current_user');
  if (!userStr) return null;
  try {
    return JSON.parse(userStr);
  } catch {
    return null;
  }
}

/**
 * Register a new user
 */
export async function register(
  username: string,
  email: string,
  password: string,
  name?: string,
  avatar?: string
): Promise<AuthResponse> {
  try {
    const response = await fetch(`${API_BASE_URL}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        email,
        password,
        name: name || username,
        avatar_animal_id: avatar || 'lion',
      }),
    });

    const data: AuthResponse = await response.json();

    if (data.success && data.token && data.user) {
      setAuthToken(data.token);
      setCurrentUser(data.user);
    }

    return data;
  } catch (error) {
    console.error('Registration error:', error);
    return {
      success: false,
      error: 'Network error. Please try again.',
    };
  }
}

/**
 * Login with email and password
 */
export async function login(email: string, password: string): Promise<AuthResponse> {
  try {
    const response = await fetch(`${API_BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    const data: AuthResponse = await response.json();

    if (data.success && data.token && data.user) {
      setAuthToken(data.token);
      setCurrentUser(data.user);
    }

    return data;
  } catch (error) {
    console.error('Login error:', error);
    return {
      success: false,
      error: 'Network error. Please try again.',
    };
  }
}

/**
 * Logout current user
 */
export async function logout(): Promise<void> {
  try {
    const token = getAuthToken();
    if (token) {
      await fetch(`${API_BASE_URL}/auth/logout`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
    }
  } catch (error) {
    console.error('Logout error:', error);
  } finally {
    removeAuthToken();
  }
}

/**
 * Check if user is authenticated
 * Validates the token by checking with the backend
 */
export async function isAuthenticated(): Promise<boolean> {
  const token = getAuthToken();
  if (!token) {
    return false;
  }

  // Validate token by checking with backend
  try {
    const response = await fetch(`${API_BASE_URL}/auth/me`, {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      // Token is invalid, remove it
      removeAuthToken();
      return false;
    }

    const data = await response.json();
    if (data.success && data.user) {
      // Update cached user
      const user: User = {
        user_id: data.user.user_id,
        username: data.user.username,
        email: data.user.email,
        name: data.user.name,
        avatar: data.user.avatar_animal_id,
        role: data.user.role,
        bio: data.user.bio,
        challenges_solved: data.user.challenges_solved,
        current_streak: data.user.current_streak,
      };
      setCurrentUser(user);
      return true;
    }

    return false;
  } catch (error) {
    console.error('Authentication check error:', error);
    // On network error, if we have a token, assume it's valid (offline mode)
    // But if backend is down, we should still show login to avoid confusion
    return false;
  }
}

/**
 * Get current authenticated user
 */
export async function getCurrentUser(forceRefresh: boolean = false): Promise<User | null> {
  try {
    const token = getAuthToken();
    if (!token) {
      return null;
    }

    // Return cached user if not forcing refresh
    if (!forceRefresh) {
      const cachedUser = getCachedUser();
      if (cachedUser) {
        return cachedUser;
      }
    }

    // Fetch fresh user data from API
    const response = await fetch(`${API_BASE_URL}/auth/me`, {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      removeAuthToken();
      return null;
    }

    const data = await response.json();
    if (data.success && data.user) {
      const user: User = {
        user_id: data.user.user_id,
        username: data.user.username,
        email: data.user.email,
        name: data.user.name,
        avatar: data.user.avatar_animal_id,
        role: data.user.role,
        bio: data.user.bio,
        challenges_solved: data.user.challenges_solved,
        current_streak: data.user.current_streak,
      };
      setCurrentUser(user);
      return user;
    }

    return null;
  } catch (error) {
    console.error('Get user error:', error);
    return null;
  }
}

/**
 * Refresh the user session
 */
export async function refreshSession(): Promise<void> {
  await getCurrentUser(true);
}

/**
 * Get auth token for API calls
 */
export function getToken(): string | null {
  return getAuthToken();
}
