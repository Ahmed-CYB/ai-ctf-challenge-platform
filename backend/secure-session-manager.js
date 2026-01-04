/**
 * Secure Session Manager
 * Implements OWASP session management best practices
 * - Cryptographically secure session ID generation
 * - Session fixation prevention (regeneration after login)
 * - Session timeout and inactivity tracking
 * - Secure cookie attributes (Secure, HttpOnly, SameSite)
 * - Session hijacking prevention
 */

const crypto = require('crypto');

class SecureSessionManager {
  constructor(pool) {
    this.pool = pool;
    this.SESSION_TIMEOUT = 60 * 60 * 1000; // 60 minutes
    this.INACTIVITY_TIMEOUT = 30 * 60 * 1000; // 30 minutes
    this.SESSION_ID_LENGTH = 32; // 256 bits
  }

  /**
   * Generate cryptographically secure session ID
   * Uses crypto.randomBytes for CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)
   */
  generateSecureSessionId() {
    return crypto.randomBytes(this.SESSION_ID_LENGTH).toString('base64url');
  }

  /**
   * Create new session with secure ID
   */
  async createSession(userId = null, ipAddress = null, userAgent = null) {
    const sessionId = this.generateSecureSessionId();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + this.SESSION_TIMEOUT);

    try {
      await this.pool.query(
        `INSERT INTO sessions (session_id, user_id, created_at, last_activity, expires_at, ip_address, user_agent)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [sessionId, userId, now, now, expiresAt, ipAddress, userAgent]
      );

      return {
        sessionId,
        expiresAt,
        maxAge: this.SESSION_TIMEOUT
      };
    } catch (error) {
      console.error('Error creating session:', error);
      throw new Error('Failed to create session');
    }
  }

  /**
   * Regenerate session ID (prevent session fixation)
   * Called after login or privilege escalation
   */
  async regenerateSessionId(oldSessionId, userId = null) {
    const newSessionId = this.generateSecureSessionId();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + this.SESSION_TIMEOUT);

    try {
      // Get old session data
      const result = await this.pool.query(
        'SELECT user_id, ip_address, user_agent FROM sessions WHERE session_id = $1',
        [oldSessionId]
      );

      if (result.rows.length === 0) {
        throw new Error('Session not found');
      }

      const oldSession = result.rows[0];

      // Delete old session
      await this.pool.query('DELETE FROM sessions WHERE session_id = $1', [oldSessionId]);

      // Create new session with new ID
      await this.pool.query(
        `INSERT INTO sessions (session_id, user_id, created_at, last_activity, expires_at, ip_address, user_agent)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          newSessionId,
          userId || oldSession.user_id,
          now,
          now,
          expiresAt,
          oldSession.ip_address,
          oldSession.user_agent
        ]
      );

      console.log(`✅ Session regenerated: ${oldSessionId.substring(0, 8)}... → ${newSessionId.substring(0, 8)}...`);

      return {
        sessionId: newSessionId,
        expiresAt,
        maxAge: this.SESSION_TIMEOUT
      };
    } catch (error) {
      console.error('Error regenerating session:', error);
      throw new Error('Failed to regenerate session');
    }
  }

  /**
   * Validate session and check expiration/timeout
   */
  async validateSession(sessionId, ipAddress = null) {
    try {
      const result = await this.pool.query(
        'SELECT session_id, user_id, created_at, last_activity, expires_at, ip_address FROM sessions WHERE session_id = $1',
        [sessionId]
      );

      if (result.rows.length === 0) {
        return { valid: false, reason: 'Session not found' };
      }

      const session = result.rows[0];
      const now = new Date();

      // Check absolute timeout
      if (new Date(session.expires_at) < now) {
        await this.destroySession(sessionId);
        return { valid: false, reason: 'Session expired' };
      }

      // Check inactivity timeout
      const lastActivity = new Date(session.last_activity);
      const inactiveDuration = now - lastActivity;
      
      if (inactiveDuration > this.INACTIVITY_TIMEOUT) {
        await this.destroySession(sessionId);
        return { valid: false, reason: 'Session timeout due to inactivity' };
      }

      // Optional: Check IP address consistency (prevent session hijacking)
      if (ipAddress && session.ip_address && session.ip_address !== ipAddress) {
        console.warn(`⚠️ Session IP mismatch: ${session.ip_address} → ${ipAddress}`);
        // Uncomment to enforce strict IP checking:
        // await this.destroySession(sessionId);
        // return { valid: false, reason: 'IP address mismatch' };
      }

      // Update last activity
      await this.updateActivity(sessionId);

      return {
        valid: true,
        session: {
          sessionId: session.session_id,
          userId: session.user_id,
          createdAt: session.created_at,
          lastActivity: session.last_activity
        }
      };
    } catch (error) {
      console.error('Error validating session:', error);
      return { valid: false, reason: 'Validation error' };
    }
  }

  /**
   * Update last activity timestamp
   */
  async updateActivity(sessionId) {
    try {
      await this.pool.query(
        'UPDATE sessions SET last_activity = $1 WHERE session_id = $2',
        [new Date(), sessionId]
      );
    } catch (error) {
      console.error('Error updating activity:', error);
    }
  }

  /**
   * Destroy session (logout)
   */
  async destroySession(sessionId) {
    try {
      await this.pool.query('DELETE FROM sessions WHERE session_id = $1', [sessionId]);
      console.log(`🗑️ Session destroyed: ${sessionId.substring(0, 8)}...`);
    } catch (error) {
      console.error('Error destroying session:', error);
      throw new Error('Failed to destroy session');
    }
  }

  /**
   * Cleanup expired sessions (run periodically)
   */
  async cleanupExpiredSessions() {
    try {
      const now = new Date();
      const inactivityCutoff = new Date(now.getTime() - this.INACTIVITY_TIMEOUT);

      const result = await this.pool.query(
        `DELETE FROM sessions 
         WHERE expires_at < $1 
         OR last_activity < $2
         RETURNING session_id`,
        [now, inactivityCutoff]
      );

      if (result.rows.length > 0) {
        console.log(`🧹 Cleaned up ${result.rows.length} expired sessions`);
      }

      return result.rows.length;
    } catch (error) {
      console.error('Error cleaning up sessions:', error);
      return 0;
    }
  }

  /**
   * Get all active sessions for a user
   */
  async getUserSessions(userId) {
    try {
      const result = await this.pool.query(
        `SELECT session_id, created_at, last_activity, ip_address, user_agent 
         FROM sessions 
         WHERE user_id = $1 
         AND expires_at > NOW()
         ORDER BY last_activity DESC`,
        [userId]
      );

      return result.rows;
    } catch (error) {
      console.error('Error getting user sessions:', error);
      return [];
    }
  }

  /**
   * Destroy all sessions for a user (e.g., on password change)
   */
  async destroyAllUserSessions(userId, exceptSessionId = null) {
    try {
      let query = 'DELETE FROM sessions WHERE user_id = $1';
      const params = [userId];

      if (exceptSessionId) {
        query += ' AND session_id != $2';
        params.push(exceptSessionId);
      }

      const result = await this.pool.query(query + ' RETURNING session_id', params);
      
      console.log(`🗑️ Destroyed ${result.rows.length} sessions for user ${userId}`);
      return result.rows.length;
    } catch (error) {
      console.error('Error destroying user sessions:', error);
      throw new Error('Failed to destroy user sessions');
    }
  }

  /**
   * Get secure cookie options
   */
  getSecureCookieOptions(maxAge = this.SESSION_TIMEOUT) {
    return {
      httpOnly: true,       // Prevent XSS access to cookies
      secure: process.env.NODE_ENV === 'production', // HTTPS only in production
      sameSite: 'strict',   // CSRF protection
      maxAge: maxAge,       // Cookie expiration
      path: '/'            // Cookie available for entire site
    };
  }

  /**
   * Set session cookie with secure attributes
   */
  setSessionCookie(res, sessionId, maxAge = this.SESSION_TIMEOUT) {
    res.cookie('sessionId', sessionId, this.getSecureCookieOptions(maxAge));
  }

  /**
   * Clear session cookie
   */
  clearSessionCookie(res) {
    res.clearCookie('sessionId', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/'
    });
  }
}

module.exports = SecureSessionManager;
