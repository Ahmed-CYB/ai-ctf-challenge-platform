/**
 * Backend API Server for CTF Platform
 * Handles database operations and authentication
 * Implements OWASP secure session management
 */

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const SecureSessionManager = require('./secure-session-manager');
require('dotenv').config({ path: '../.env' });

const app = express();
const PORT = process.env.BACKEND_PORT || 3002;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';

// Security Middleware
app.use(helmet()); // Security headers

// HSTS - HTTP Strict Transport Security (forces HTTPS)
app.use(helmet.hsts({
  maxAge: 31536000,           // 1 year in seconds
  includeSubDomains: true,    // Apply to all subdomains
  preload: true               // Submit to HSTS preload list
}));

// Additional security headers
app.use(helmet.frameguard({ action: 'deny' }));           // Prevent clickjacking
app.use(helmet.noSniff());                                 // Prevent MIME sniffing
app.use(helmet.xssFilter());                               // XSS protection
app.use(helmet.referrerPolicy({ policy: 'no-referrer' })); // Hide referrer

// HTTPS redirect middleware (for production)
if (process.env.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.header('x-forwarded-proto') !== 'https') {
      return res.redirect(`https://${req.header('host')}${req.url}`);
    }
    next();
  });
}

// CORS with credentials support
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true  // Allow cookies
}));

app.use(express.json());
app.use(cookieParser());

// PostgreSQL Connection Pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: false,
});

// Test database connection
pool.on('connect', () => {
  console.log('✅ Connected to PostgreSQL database');
});

pool.on('error', (err) => {
  console.error('❌ Unexpected database error:', err);
});

// Initialize Secure Session Manager
const sessionManager = new SecureSessionManager(pool);

// Periodic session cleanup (every 15 minutes)
setInterval(async () => {
  try {
    await sessionManager.cleanupExpiredSessions();
  } catch (error) {
    console.error('Session cleanup error:', error);
  }
}, 15 * 60 * 1000);

console.log('🔒 Secure session manager initialized');
console.log(`   Session timeout: ${sessionManager.SESSION_TIMEOUT / 60000} minutes`);
console.log(`   Inactivity timeout: ${sessionManager.INACTIVITY_TIMEOUT / 60000} minutes`);

// ===== MIDDLEWARE =====

// Session validation middleware
const validateSession = async (req, res, next) => {
  try {
    const sessionId = req.cookies.sessionId || req.body.sessionId || req.headers['x-session-id'];
    
    if (!sessionId) {
      return res.status(401).json({ success: false, error: 'No session provided' });
    }

    const ipAddress = req.ip || req.connection.remoteAddress;
    const validation = await sessionManager.validateSession(sessionId, ipAddress);

    if (!validation.valid) {
      return res.status(401).json({ 
        success: false, 
        error: 'Invalid or expired session',
        reason: validation.reason 
      });
    }

    req.session = validation.session;
    next();
  } catch (error) {
    console.error('Session validation error:', error);
    return res.status(500).json({ success: false, error: 'Session validation failed' });
  }
};

// Verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, error: 'No token provided' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// ===== HEALTH CHECK =====
app.get('/api/health', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.json({
      status: 'ok',
      database: 'connected',
      timestamp: result.rows[0].now,
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: error.message,
    });
  }
});

// ===== AUTHENTICATION API =====

// Register new user
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, name, avatar_animal_id } = req.body;

    // Validate input
    if (!username || !email || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Username, email, and password are required' 
      });
    }

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT user_id FROM users WHERE username = $1 OR email = $2',
      [username, email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'Username or email already exists' 
      });
    }

    // Hash password
    const password_hash = await bcrypt.hash(password, 10);

    // Insert user
    const result = await pool.query(
      `INSERT INTO users (username, email, password_hash, name, avatar_animal_id, is_verified)
       VALUES ($1, $2, $3, $4, $5, TRUE)
       RETURNING user_id, username, email, name, avatar_animal_id, role, created_at`,
      [username, email.toLowerCase(), password_hash, name || username, avatar_animal_id || 'lion']
    );

    const user = result.rows[0];

    // Create JWT token
    const token = jwt.sign(
      { 
        user_id: user.user_id, 
        username: user.username, 
        email: user.email,
        role: user.role 
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Log activity
    await pool.query(
      'INSERT INTO user_activity_log (user_id, activity_type, ip_address) VALUES ($1, $2, $3)',
      [user.user_id, 'register', req.ip]
    );

    res.json({
      success: true,
      message: 'Registration successful',
      token,
      user: {
        user_id: user.user_id,
        username: user.username,
        email: user.email,
        name: user.name,
        avatar: user.avatar_animal_id,
        role: user.role,
      },
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Login user
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Email and password are required' 
      });
    }

    // Find user
    const result = await pool.query(
      `SELECT user_id, username, email, password_hash, name, avatar_animal_id, role, 
              is_active, account_locked_until, failed_login_attempts
       FROM users 
       WHERE email = $1`,
      [email.toLowerCase()]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ 
        success: false, 
        error: 'Invalid email or password' 
      });
    }

    const user = result.rows[0];

    // Check if account is locked
    if (user.account_locked_until && new Date(user.account_locked_until) > new Date()) {
      return res.status(403).json({ 
        success: false, 
        error: 'Account is locked. Please try again later.' 
      });
    }

    // Check if account is active
    if (!user.is_active) {
      return res.status(403).json({ 
        success: false, 
        error: 'Account is inactive' 
      });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password_hash);

    if (!validPassword) {
      // Increment failed login attempts
      await pool.query(
        `UPDATE users 
         SET failed_login_attempts = failed_login_attempts + 1,
             account_locked_until = CASE 
               WHEN failed_login_attempts >= 4 THEN NOW() + INTERVAL '15 minutes'
               ELSE account_locked_until
             END
         WHERE user_id = $1`,
        [user.user_id]
      );

      return res.status(401).json({ 
        success: false, 
        error: 'Invalid email or password' 
      });
    }

    // Reset failed login attempts and update last login
    await pool.query(
      `UPDATE users 
       SET failed_login_attempts = 0, 
           last_login = NOW(),
           last_active = NOW()
       WHERE user_id = $1`,
      [user.user_id]
    );

    // Create JWT token
    const token = jwt.sign(
      { 
        user_id: user.user_id, 
        username: user.username, 
        email: user.email,
        role: user.role 
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Create secure session with regenerated ID (prevent session fixation)
    const ipAddress = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];
    const session = await sessionManager.createSession(user.user_id, ipAddress, userAgent);
    
    // Set secure session cookie
    sessionManager.setSessionCookie(res, session.sessionId, session.maxAge);

    // Log activity
    await pool.query(
      'INSERT INTO user_activity_log (user_id, activity_type, ip_address) VALUES ($1, $2, $3)',
      [user.user_id, 'login', req.ip]
    );

    console.log(`✅ User ${user.username} logged in with session: ${session.sessionId.substring(0, 8)}...`);

    res.json({
      success: true,
      message: 'Login successful',
      token,
      sessionId: session.sessionId,  // For non-cookie clients
      user: {
        user_id: user.user_id,
        username: user.username,
        email: user.email,
        name: user.name,
        avatar: user.avatar_animal_id,
        role: user.role,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get current user (with token)
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT user_id, username, email, name, bio, profile_avatar, avatar_animal_id, 
              role, challenges_solved, current_streak, longest_streak, created_at
       FROM users 
       WHERE user_id = $1 AND is_active = TRUE`,
      [req.user.user_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    res.json({
      success: true,
      user: result.rows[0],
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Logout (destroys session)
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    const sessionId = req.cookies.sessionId || req.body.sessionId;
    
    if (sessionId) {
      // Destroy session
      await sessionManager.destroySession(sessionId);
      
      // Clear session cookie
      sessionManager.clearSessionCookie(res);
      
      console.log(`✅ User ${req.user.username} logged out, session destroyed`);
    }
    
    // Log activity
    await pool.query(
      'INSERT INTO user_activity_log (user_id, activity_type, ip_address) VALUES ($1, $2, $3)',
      [req.user.user_id, 'logout', req.ip]
    );

    res.json({ success: true, message: 'Logout successful' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ===== SECURE SESSIONS API =====

// Create secure session (typically called on first visit)
app.post('/api/sessions/create', async (req, res) => {
  try {
    const { userId } = req.body;
    const ipAddress = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];
    
    const session = await sessionManager.createSession(userId, ipAddress, userAgent);
    
    // Set secure cookie
    sessionManager.setSessionCookie(res, session.sessionId, session.maxAge);
    
    res.json({ 
      success: true, 
      message: 'Secure session created',
      sessionId: session.sessionId,  // For non-cookie clients
      expiresAt: session.expiresAt
    });
  } catch (error) {
    console.error('Error creating session:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Validate and refresh session
app.post('/api/sessions/validate', async (req, res) => {
  try {
    const sessionId = req.cookies.sessionId || req.body.sessionId;
    const ipAddress = req.ip || req.connection.remoteAddress;
    
    const validation = await sessionManager.validateSession(sessionId, ipAddress);
    
    if (!validation.valid) {
      // Clear invalid cookie
      sessionManager.clearSessionCookie(res);
      return res.status(401).json({ 
        success: false, 
        error: 'Invalid or expired session',
        reason: validation.reason 
      });
    }
    
    res.json({ 
      success: true, 
      valid: true,
      session: validation.session
    });
  } catch (error) {
    console.error('Error validating session:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Regenerate session ID (prevent session fixation)
app.post('/api/sessions/regenerate', validateSession, async (req, res) => {
  try {
    const oldSessionId = req.session.sessionId;
    const session = await sessionManager.regenerateSessionId(oldSessionId, req.session.userId);
    
    // Set new session cookie
    sessionManager.setSessionCookie(res, session.sessionId, session.maxAge);
    
    res.json({ 
      success: true, 
      message: 'Session ID regenerated',
      sessionId: session.sessionId,
      expiresAt: session.expiresAt
    });
  } catch (error) {
    console.error('Error regenerating session:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Delete session and cleanup Guacamole user
app.delete('/api/sessions/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    
    // Destroy secure session
    await sessionManager.destroySession(sessionId);
    
    // Clear session cookie
    sessionManager.clearSessionCookie(res);
    
    res.json({ 
      success: true, 
      message: 'Session destroyed',
      sessionId 
    });
  } catch (error) {
    console.error('Error deleting session:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get user's active sessions
app.get('/api/sessions/user/:userId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Ensure user can only see their own sessions (unless admin)
    if (req.user.user_id !== parseInt(userId) && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Unauthorized' });
    }
    
    const sessions = await sessionManager.getUserSessions(userId);
    
    res.json({ 
      success: true, 
      sessions: sessions.map(s => ({
        sessionId: s.session_id.substring(0, 8) + '...',  // Partial ID for security
        createdAt: s.created_at,
        lastActivity: s.last_activity,
        ipAddress: s.ip_address,
        userAgent: s.user_agent
      }))
    });
  } catch (error) {
    console.error('Error getting user sessions:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Destroy all user sessions (e.g., on password change)
app.post('/api/sessions/user/:userId/destroy-all', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    const { exceptCurrent } = req.body;
    
    // Ensure user can only destroy their own sessions (unless admin)
    if (req.user.user_id !== parseInt(userId) && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Unauthorized' });
    }
    
    const currentSessionId = exceptCurrent ? (req.cookies.sessionId || req.body.sessionId) : null;
    const count = await sessionManager.destroyAllUserSessions(userId, currentSessionId);
    
    res.json({ 
      success: true, 
      message: `Destroyed ${count} sessions`,
      count 
    });
  } catch (error) {
    console.error('Error destroying user sessions:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ===== CHAT SESSIONS API =====

// Create or update a chat session (simple session for chat tracking)
app.post('/api/sessions', async (req, res) => {
  try {
    const { sessionId, userId } = req.body;
    
    if (!sessionId) {
      return res.status(400).json({ 
        success: false, 
        error: 'Session ID is required' 
      });
    }

    // Check if session exists
    const existingSession = await pool.query(
      'SELECT session_id FROM sessions WHERE session_id = $1',
      [sessionId]
    );

    if (existingSession.rows.length === 0) {
      // Create new session
      await pool.query(
        `INSERT INTO sessions (session_id, user_id, created_at, last_activity)
         VALUES ($1, $2, NOW(), NOW())
         ON CONFLICT (session_id) DO NOTHING`,
        [sessionId, userId || null]
      );
    } else {
      // Update last activity
      await pool.query(
        'UPDATE sessions SET last_activity = NOW() WHERE session_id = $1',
        [sessionId]
      );
    }

    res.json({
      success: true,
      message: 'Session created or updated',
      sessionId,
    });
  } catch (error) {
    console.error('Error creating chat session:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ===== CHAT MESSAGES API =====

// Save chat message
app.post('/api/chat/messages', async (req, res) => {
  try {
    const { session_id, user_id, role, message_text, challenge_id, metadata } = req.body;
    
    const result = await pool.query(
      `INSERT INTO chat_messages (session_id, user_id, role, message_text, challenge_id, metadata)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING message_id, timestamp`,
      [
        session_id,
        user_id || null,
        role,
        message_text,
        challenge_id || null,
        metadata ? JSON.stringify(metadata) : null,
      ]
    );
    
    res.json({
      success: true,
      message: 'Chat message saved',
      data: result.rows[0],
    });
  } catch (error) {
    console.error('Error saving chat message:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get chat history for a session
app.get('/api/chat/history/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    
    const result = await pool.query(
      `SELECT * FROM chat_messages 
       WHERE session_id = $1 
       ORDER BY timestamp ASC`,
      [sessionId]
    );
    
    res.json({
      success: true,
      data: result.rows,
    });
  } catch (error) {
    console.error('Error getting chat history:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ===== USERS API =====

// Get user by ID
app.get('/api/users/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    
    const result = await pool.query(
      `SELECT user_id, username, email, name, bio, profile_avatar, avatar_animal_id,
              role, challenges_solved, challenges_created, current_streak, longest_streak,
              github_username, twitter_handle, website_url, created_at
       FROM users 
       WHERE user_id = $1 AND is_active = TRUE`,
      [userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    res.json({
      success: true,
      data: result.rows[0],
    });
  } catch (error) {
    console.error('Error getting user:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Update user profile
app.put('/api/users/:userId', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Check if user is updating their own profile or is admin
    if (req.user.user_id !== parseInt(userId) && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Unauthorized' });
    }

    const { name, bio, avatar_animal_id, github_username, twitter_handle, website_url } = req.body;
    
    const result = await pool.query(
      `UPDATE users 
       SET name = COALESCE($1, name),
           bio = COALESCE($2, bio),
           avatar_animal_id = COALESCE($3, avatar_animal_id),
           github_username = COALESCE($4, github_username),
           twitter_handle = COALESCE($5, twitter_handle),
           website_url = COALESCE($6, website_url),
           updated_at = NOW()
       WHERE user_id = $7
       RETURNING user_id, username, email, name, bio, avatar_animal_id`,
      [name, bio, avatar_animal_id, github_username, twitter_handle, website_url, userId]
    );
    
    res.json({
      success: true,
      message: 'Profile updated',
      data: result.rows[0],
    });
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ===== CHALLENGES API =====

// Get all active challenges
app.get('/api/challenges', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT c.*, u.username as creator_username
       FROM challenges c
       LEFT JOIN users u ON c.user_id = u.user_id
       WHERE c.is_active = TRUE 
       ORDER BY c.created_at DESC`
    );
    
    res.json({
      success: true,
      data: result.rows,
    });
  } catch (error) {
    console.error('Error getting challenges:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get challenge by ID
app.get('/api/challenges/:challengeId', async (req, res) => {
  try {
    const { challengeId } = req.params;
    
    const result = await pool.query(
      `SELECT c.*, u.username as creator_username
       FROM challenges c
       LEFT JOIN users u ON c.user_id = u.user_id
       WHERE c.challenge_id = $1 AND c.is_active = TRUE`,
      [challengeId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Challenge not found' });
    }
    
    res.json({
      success: true,
      data: result.rows[0],
    });
  } catch (error) {
    console.error('Error getting challenge:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Save new challenge
app.post('/api/challenges', authenticateToken, async (req, res) => {
  try {
    const {
      challenge_name,
      slug,
      category,
      difficulty,
      description,
      hints,
      flag,
      github_link,
      docker_image,
      deploy_command,
      container_name,
      target_url,
    } = req.body;
    
    const result = await pool.query(
      `INSERT INTO challenges 
       (challenge_name, slug, user_id, category, difficulty, description, hints, flag, 
        github_link, docker_image, deploy_command, container_name, target_url)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
       RETURNING challenge_id`,
      [
        challenge_name,
        slug,
        req.user.user_id,
        category,
        difficulty || 'beginner',
        description || '',
        hints || [],
        flag,
        github_link || null,
        docker_image || null,
        deploy_command || null,
        container_name || null,
        target_url || null,
      ]
    );
    
    // Update user's challenges_created count
    await pool.query(
      'UPDATE users SET challenges_created = challenges_created + 1 WHERE user_id = $1',
      [req.user.user_id]
    );
    
    res.json({
      success: true,
      message: 'Challenge saved',
      data: { challenge_id: result.rows[0].challenge_id },
    });
  } catch (error) {
    console.error('Error saving challenge:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Submit flag for challenge
app.post('/api/challenges/:challengeId/submit', authenticateToken, async (req, res) => {
  try {
    const { challengeId } = req.params;
    const { submitted_flag } = req.body;
    
    // Get challenge
    const challengeResult = await pool.query(
      'SELECT flag FROM challenges WHERE challenge_id = $1 AND is_active = TRUE',
      [challengeId]
    );
    
    if (challengeResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Challenge not found' });
    }
    
    const correctFlag = challengeResult.rows[0].flag;
    const isCorrect = submitted_flag === correctFlag;
    
    // Check if already solved
    const existingSubmission = await pool.query(
      'SELECT submission_id, is_correct FROM challenge_submissions WHERE challenge_id = $1 AND user_id = $2',
      [challengeId, req.user.user_id]
    );
    
    if (existingSubmission.rows.length > 0) {
      if (existingSubmission.rows[0].is_correct) {
        return res.json({
          success: true,
          correct: false,
          message: 'You have already solved this challenge',
        });
      }
    }
    
    // Save submission
    await pool.query(
      `INSERT INTO challenge_submissions (challenge_id, user_id, submitted_flag, is_correct, solve_date)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (challenge_id, user_id) 
       DO UPDATE SET submitted_flag = $3, is_correct = $4, submitted_at = NOW()`,
      [challengeId, req.user.user_id, submitted_flag, isCorrect, isCorrect ? new Date().toISOString().split('T')[0] : null]
    );
    
    if (isCorrect) {
      // Update user stats
      await pool.query(
        'UPDATE users SET challenges_solved = challenges_solved + 1 WHERE user_id = $1',
        [req.user.user_id]
      );
      
      // Update streak
      await pool.query('SELECT update_user_streak($1)', [req.user.user_id]);
      
      // Record daily solve
      await pool.query(
        `INSERT INTO daily_solves (user_id, solve_date, challenges_solved_today)
         VALUES ($1, CURRENT_DATE, 1)
         ON CONFLICT (user_id, solve_date)
         DO UPDATE SET challenges_solved_today = daily_solves.challenges_solved_today + 1`,
        [req.user.user_id]
      );
    }
    
    res.json({
      success: true,
      correct: isCorrect,
      message: isCorrect ? 'Correct! Challenge solved!' : 'Incorrect flag. Try again!',
    });
  } catch (error) {
    console.error('Error submitting flag:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ===== LEADERBOARDS API =====

// Get leaderboard by challenges solved
app.get('/api/leaderboard/solves', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    
    const result = await pool.query(
      `SELECT 
         ROW_NUMBER() OVER (ORDER BY challenges_solved DESC, created_at ASC) as rank,
         user_id,
         username,
         name,
         profile_avatar,
         avatar_animal_id,
         challenges_solved as score
       FROM users
       WHERE is_active = TRUE AND deleted_at IS NULL
       ORDER BY challenges_solved DESC
       LIMIT $1`,
      [limit]
    );
    
    res.json({
      success: true,
      data: result.rows,
    });
  } catch (error) {
    console.error('Error getting solves leaderboard:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get leaderboard by current streak
app.get('/api/leaderboard/streak', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    
    const result = await pool.query(
      `SELECT 
         ROW_NUMBER() OVER (ORDER BY current_streak DESC, last_solve_date DESC) as rank,
         user_id,
         username,
         name,
         profile_avatar,
         avatar_animal_id,
         current_streak as score,
         streak_frozen,
         streak_recovery_solves,
         streak_recovery_deadline
       FROM users
       WHERE is_active = TRUE AND deleted_at IS NULL
       ORDER BY current_streak DESC
       LIMIT $1`,
      [limit]
    );
    
    res.json({
      success: true,
      data: result.rows,
    });
  } catch (error) {
    console.error('Error getting streak leaderboard:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ===== ERROR HANDLER =====
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
  });
});

// ===== START SERVER =====
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Backend API server running on http://localhost:${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
  console.log(`🔐 Authentication endpoints ready`);
  console.log(`💾 Database integration active`);
});

server.on('error', (error) => {
  if (error.code === 'EADDRINUSE') {
    console.error(`❌ Port ${PORT} is already in use`);
  } else {
    console.error('❌ Server error:', error);
  }
  process.exit(1);
});
