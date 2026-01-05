import pg from 'pg';
import dotenv from 'dotenv';
import { Logger } from './core/logger.js';

dotenv.config();

const logger = new Logger();

const { Pool } = pg;

class DatabaseManager {
  constructor() {
    // Use environment variables if set, otherwise use defaults
    // Inside Docker: DB_HOST should be set to 'postgres-new' and DB_PORT to 5432
    // Outside Docker: defaults to 'ctf-postgres-new' and port 5433
    this.pool = new Pool({
      host: process.env.DB_HOST || 'ctf-postgres-new',
      port: process.env.DB_PORT ? parseInt(process.env.DB_PORT) : 5433,
      database: process.env.DB_NAME || 'ctf_platform',
      user: process.env.DB_USER || 'ctf_user',
      password: process.env.DB_PASSWORD || 'ctf_password_123',
    });
    
    // Log connection info for debugging (without password)
    logger.info('DatabaseManager', 'Database connection configured', {
      host: this.pool.options.host,
      port: this.pool.options.port,
      database: this.pool.options.database
    });
    
    // ✅ FIX: Register graceful shutdown handlers for connection pool cleanup
    this._registerShutdownHandlers();
  }

  /**
   * ✅ FIX: Register graceful shutdown handlers to close database connections
   * Prevents connection leaks on application shutdown
   */
  _registerShutdownHandlers() {
    const gracefulShutdown = async (signal) => {
      logger.info('DatabaseManager', `Received ${signal}, closing database connections`);
      try {
        await this.pool.end();
        logger.success('DatabaseManager', 'Database connections closed gracefully');
        process.exit(0);
      } catch (error) {
        logger.error('DatabaseManager', 'Error closing database connections', error.stack);
        process.exit(1);
      }
    };

    // Register handlers for common termination signals
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    
    // Handle uncaught exceptions
    process.on('uncaughtException', async (error) => {
      logger.error('DatabaseManager', 'Uncaught exception', error.stack);
      try {
        await this.pool.end();
      } catch (poolError) {
        logger.error('DatabaseManager', 'Error closing pool during exception', poolError.stack);
      }
      process.exit(1);
    });

    // Handle unhandled promise rejections
    process.on('unhandledRejection', async (reason, promise) => {
      logger.error('DatabaseManager', 'Unhandled rejection', null, { promise, reason });
      // Don't exit immediately, but log the error
    });
  }

  /**
   * Get conversation history for a session
   * @param {string} sessionId - The session ID
   * @param {number} limit - Maximum number of messages to retrieve (default: 20)
   * @returns {Promise<Array>} Array of messages
   */
  async getConversationHistory(sessionId, limit = 20) {
    try {
      const query = `
        SELECT role, message_text, timestamp, metadata
        FROM chat_messages
        WHERE session_id = $1
        ORDER BY timestamp ASC
        LIMIT $2
      `;
      
      const result = await this.pool.query(query, [sessionId, limit]);
      return result.rows.map(row => ({
        role: row.role,
        content: row.message_text,
        timestamp: row.timestamp,
        metadata: row.metadata
      }));
    } catch (error) {
      console.error('Error fetching conversation history:', error);
      return [];
    }
  }

  /**
   * Save a message to the database
   * @param {string} sessionId - The session ID
   * @param {string} role - 'user' or 'assistant'
   * @param {string} messageText - The message content
   * @param {object} metadata - Optional metadata
   * @returns {Promise<object>} Saved message
   */
  async saveMessage(sessionId, role, messageText, metadata = null) {
    try {
      const query = `
        INSERT INTO chat_messages (session_id, role, message_text, metadata)
        VALUES ($1, $2, $3, $4)
        RETURNING message_id, timestamp
      `;
      
      const result = await this.pool.query(query, [
        sessionId,
        role,
        messageText,
        metadata ? JSON.stringify(metadata) : null
      ]);
      
      return result.rows[0];
    } catch (error) {
      logger.error('DatabaseManager', 'Error saving message', error.stack);
      throw error;
    }
  }

  /**
   * Clear old conversation history (optional cleanup function)
   * @param {number} daysOld - Remove messages older than this many days
   */
  async clearOldMessages(daysOld = 30) {
    try {
      const query = `
        DELETE FROM chat_messages
        WHERE timestamp < NOW() - INTERVAL '${daysOld} days'
      `;
      
      const result = await this.pool.query(query);
      logger.info('DatabaseManager', `Cleared ${result.rowCount} old messages`);
      return result.rowCount;
    } catch (error) {
      logger.error('DatabaseManager', 'Error clearing old messages', error.stack);
      throw error;
    }
  }

  /**
   * ✅ IMPROVEMENT: Validate session exists and is not expired
   * @param {string} sessionId - The session ID to validate
   * @returns {Promise<object|null>} Session data if valid, null if expired/invalid
   */
  async validateSession(sessionId) {
    try {
      const query = `
        SELECT session_id, expires_at, last_activity, user_id
        FROM sessions
        WHERE session_id = $1
      `;
      
      const result = await this.pool.query(query, [sessionId]);
      
      if (result.rows.length === 0) {
        return null; // Session doesn't exist
      }
      
      const session = result.rows[0];
      const now = new Date();
      const expiresAt = new Date(session.expires_at);
      
      if (expiresAt < now) {
        return null; // Session expired
      }
      
      return session;
    } catch (error) {
      console.error('Error validating session:', error);
      return null;
    }
  }

  /**
   * ✅ IMPROVEMENT: Extend session expiration (sliding window)
   * @param {string} sessionId - The session ID
   * @param {number} hours - Hours to extend (default: 24)
   * @returns {Promise<boolean>} Success status
   */
  async extendSessionExpiration(sessionId, hours = 24) {
    try {
      const newExpiresAt = new Date();
      newExpiresAt.setHours(newExpiresAt.getHours() + hours);
      
      const query = `
        UPDATE sessions
        SET expires_at = $1, last_activity = NOW()
        WHERE session_id = $2
        RETURNING session_id
      `;
      
      const result = await this.pool.query(query, [newExpiresAt, sessionId]);
      return result.rows.length > 0;
    } catch (error) {
      logger.error('DatabaseManager', 'Error extending session expiration', error.stack);
      return false;
    }
  }

  /**
   * ✅ IMPROVEMENT: Get session data
   * @param {string} sessionId - The session ID
   * @returns {Promise<object|null>} Session data or null
   */
  async getSession(sessionId) {
    try {
      const query = `
        SELECT session_id, user_id, created_at, last_activity, expires_at, ip_address, user_agent
        FROM sessions
        WHERE session_id = $1
      `;
      
      const result = await this.pool.query(query, [sessionId]);
      return result.rows.length > 0 ? result.rows[0] : null;
    } catch (error) {
      logger.error('DatabaseManager', 'Error getting session', error.stack);
      return null;
    }
  }

  /**
   * ✅ IMPROVEMENT: Track session activity
   * @param {string} sessionId - The session ID
   * @param {string} activityType - Type of activity ('message', 'deployment', 'connection', 'validation')
   * @param {object} activityData - Activity-specific data
   * @returns {Promise<boolean>} Success status
   */
  async trackSessionActivity(sessionId, activityType, activityData = {}) {
    try {
      const query = `
        INSERT INTO session_activity (session_id, activity_type, activity_data)
        VALUES ($1, $2, $3)
      `;
      
      await this.pool.query(query, [
        sessionId,
        activityType,
        JSON.stringify(activityData)
      ]);
      return true;
    } catch (error) {
      logger.error('DatabaseManager', 'Error tracking session activity', error.stack);
      // Don't throw - activity tracking is non-critical
      return false;
    }
  }

  /**
   * ✅ IMPROVEMENT: Get session activity history
   * @param {string} sessionId - The session ID
   * @param {number} limit - Maximum number of activities to retrieve
   * @returns {Promise<Array>} Array of activities
   */
  async getSessionActivity(sessionId, limit = 50) {
    try {
      const query = `
        SELECT activity_type, activity_data, timestamp
        FROM session_activity
        WHERE session_id = $1
        ORDER BY timestamp DESC
        LIMIT $2
      `;
      
      const result = await this.pool.query(query, [sessionId, limit]);
      return result.rows.map(row => ({
        type: row.activity_type,
        data: row.activity_data,
        timestamp: row.timestamp
      }));
    } catch (error) {
      logger.error('DatabaseManager', 'Error getting session activity', error.stack);
      return [];
    }
  }

  /**
   * Store pending deployment (waiting for confirmation)
   */
  async storePendingDeployment(sessionId, challengeName, existingChallengeName) {
    try {
      // Create table if it doesn't exist (for backward compatibility)
      await this.pool.query(`
        CREATE TABLE IF NOT EXISTS pending_deployments (
          session_id VARCHAR(255) PRIMARY KEY,
          challenge_name VARCHAR(255) NOT NULL,
          existing_challenge_name VARCHAR(255),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);
      
      const query = `
        INSERT INTO pending_deployments (session_id, challenge_name, existing_challenge_name, created_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (session_id) DO UPDATE 
        SET challenge_name = $2, existing_challenge_name = $3, created_at = NOW()
      `;
      await this.pool.query(query, [sessionId, challengeName, existingChallengeName]);
      logger.info('DatabaseManager', 'Stored pending deployment', { sessionId, challengeName, existingChallengeName });
      return true;
    } catch (error) {
      logger.error('DatabaseManager', 'Error storing pending deployment', error.stack);
      return false;
    }
  }

  /**
   * Get pending deployment for session
   */
  async getPendingDeployment(sessionId) {
    try {
      // Check if table exists first
      const tableCheck = await this.pool.query(`
        SELECT EXISTS (
          SELECT FROM information_schema.tables 
          WHERE table_name = 'pending_deployments'
        )
      `);
      
      if (!tableCheck.rows[0]?.exists) {
        return null; // Table doesn't exist yet
      }
      
      const query = `
        SELECT challenge_name, existing_challenge_name, created_at
        FROM pending_deployments
        WHERE session_id = $1
      `;
      const result = await this.pool.query(query, [sessionId]);
      if (result.rows.length > 0) {
        return result.rows[0];
      }
      return null;
    } catch (error) {
      // If table doesn't exist, return null (graceful fallback)
      if (error.message.includes('does not exist') || error.message.includes('relation')) {
        return null;
      }
      logger.error('DatabaseManager', 'Error getting pending deployment', error.stack);
      return null;
    }
  }

  /**
   * Clear pending deployment
   */
  async clearPendingDeployment(sessionId) {
    try {
      // Check if table exists first
      const tableCheck = await this.pool.query(`
        SELECT EXISTS (
          SELECT FROM information_schema.tables 
          WHERE table_name = 'pending_deployments'
        )
      `);
      
      if (!tableCheck.rows[0]?.exists) {
        return true; // Table doesn't exist, nothing to clear
      }
      
      const query = `DELETE FROM pending_deployments WHERE session_id = $1`;
      await this.pool.query(query, [sessionId]);
      logger.info('DatabaseManager', 'Cleared pending deployment', { sessionId });
      return true;
    } catch (error) {
      // If table doesn't exist, return true (graceful fallback)
      if (error.message.includes('does not exist') || error.message.includes('relation')) {
        return true;
      }
      logger.error('DatabaseManager', 'Error clearing pending deployment', error.stack);
      return false;
    }
  }

  /**
   * Close database connection
   */
  async close() {
    await this.pool.end();
  }
}

export const dbManager = new DatabaseManager();

/**
 * Direct query function for convenience
 * @param {string} sql - SQL query string
 * @param {Array} params - Query parameters
 * @returns {Promise<object>} Query result
 */
export async function query(sql, params = []) {
  return await dbManager.pool.query(sql, params);
}
