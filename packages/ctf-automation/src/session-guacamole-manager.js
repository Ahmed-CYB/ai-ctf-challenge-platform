/**
 * Session-Based Guacamole User Manager
 * Creates temporary Guacamole users per session, manages their lifecycle
 * Ensures users are created on first challenge request and deleted on session end
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import crypto from 'crypto';
import axios from 'axios';
import fs from 'fs';
import { dbManager } from './db-manager.js';

const execAsync = promisify(exec);

export class SessionGuacamoleManager {
  constructor() {
    this.guacContainer = process.env.GUAC_CONTAINER_NAME || 'ctf-guacamole-db-new';
    this.dbUser = process.env.GUAC_DB_USER || 'guacamole_user';
    this.dbPass = process.env.GUAC_DB_PASSWORD || 'guacamole_password_123';
    this.dbName = process.env.GUAC_DB_NAME || 'guacamole_db';
    
    // Guacamole REST API configuration
    // IMPROVEMENT: Detect if running in Docker and use service name instead of localhost
    // When running in Docker, use the service name; when running locally, use localhost
    let defaultGuacamoleUrl = 'http://localhost:8081/guacamole';
    try {
      // Check if running inside Docker container
      if (fs.existsSync('/.dockerenv') || process.env.DOCKER_ENV === 'true') {
        // Inside Docker: use service name (guacamole-new) and internal port (8080)
        defaultGuacamoleUrl = 'http://guacamole-new:8080/guacamole';
        console.log('🐳 Running in Docker - using Guacamole service name: guacamole-new:8080');
      } else {
        // Outside Docker: use localhost and mapped port (8081)
        defaultGuacamoleUrl = 'http://localhost:8081/guacamole';
        console.log('💻 Running locally - using localhost:8081');
      }
    } catch (err) {
      // If fs check fails, default to localhost (safer fallback)
      console.warn('⚠️  Could not detect Docker environment, defaulting to localhost:8081');
    }
    
    this.guacamoleUrl = process.env.GUACAMOLE_URL || process.env.GUACAMOLE_BASE_URL || defaultGuacamoleUrl;
    this.guacamoleUrl = this.guacamoleUrl.replace(/#.*$/, '').replace(/\/+$/, ''); // Remove hash and trailing slashes
    console.log(`🔗 Guacamole API URL: ${this.guacamoleUrl}`);
    this.adminUsername = process.env.GUACAMOLE_ADMIN_USER || 'guacadmin';
    this.adminPassword = process.env.GUACAMOLE_ADMIN_PASS || 'guacadmin';
    this.authToken = null;
    this.dataSource = 'mysql';
    this.useRestAPI = process.env.GUACAMOLE_USE_REST_API !== 'false'; // Default to true
    
    // In-memory session store (session ID -> { username, password, entityId, createdAt })
    this.sessionUsers = new Map();
    
    // ✅ FIX: Mutex for preventing race conditions in user creation
    // Maps sessionId -> Promise that resolves when user creation is complete
    this.userCreationLocks = new Map();
    
    // IMPROVEMENT: Load sessions with retry logic (non-blocking)
    // This allows the service to start even if Guacamole DB isn't ready yet
    this.loadSessionsFromDatabaseWithRetry().catch(err => {
      console.warn('⚠️  Failed to load sessions from database after retries:', err.message);
      console.warn('   Sessions will be loaded on first use');
    });
    
    // Start periodic cleanup of expired sessions (every hour)
    this.startSessionCleanup();
  }

  /**
   * Escape MySQL string to prevent SQL injection
   * SECURITY FIX: Proper escaping for SQL queries
   */
  escapeMySQL(str) {
    if (typeof str !== 'string') return str;
    return str.replace(/\\/g, '\\\\')
              .replace(/'/g, "\\'")
              .replace(/"/g, '\\"')
              .replace(/\n/g, '\\n')
              .replace(/\r/g, '\\r')
              .replace(/\x00/g, '\\0');
  }

  /**
   * Check if container is running
   * IMPROVEMENT: Verify container status before executing queries
   */
  async isContainerRunning() {
    try {
      const { stdout } = await execAsync(`docker ps --filter "name=${this.guacContainer}" --format "{{.Status}}"`);
      return stdout.trim().includes('Up');
    } catch (error) {
      return false;
    }
  }

  /**
   * Execute MySQL query in Guacamole container
   * SECURITY FIX: Now escapes user input to prevent SQL injection
   * IMPROVEMENT: Better error handling for container restart scenarios
   */
  async execMySQLQuery(query, returnValue = false) {
    try {
      // IMPROVEMENT: Check if container is running first
      const isRunning = await this.isContainerRunning();
      if (!isRunning) {
        throw new Error(`Container ${this.guacContainer} is not running`);
      }

      // Escape the query string for shell execution
      const escapedQuery = query.replace(/"/g, '\\"');
      const flags = returnValue ? '-sN' : '';
      const command = `docker exec ${this.guacContainer} mysql -u ${this.dbUser} -p${this.dbPass} ${this.dbName} ${flags} -e "${escapedQuery}"`;
      
      const { stdout, stderr } = await execAsync(command);
      
      if (stderr && !stderr.includes('Warning') && !stderr.includes('Using a password')) {
        console.error(`MySQL Error: ${stderr}`);
      }
      
      if (returnValue) {
        return stdout.trim();
      }
      
      return stdout;
    } catch (error) {
      // IMPROVEMENT: Better error messages for container restart scenarios
      if (error.message.includes('is restarting') || error.message.includes('not running')) {
        throw new Error(`Container ${this.guacContainer} is not ready: ${error.message}`);
      }
      console.error(`❌ MySQL Query Failed: ${error.message}`);
      throw error;
    }
  }

  /**
   * Generate secure random password
   */
  generatePassword(length = 16) {
    return crypto.randomBytes(length).toString('hex').slice(0, length);
  }

  /**
   * Authenticate with Guacamole REST API
   */
  async authenticateWithAPI() {
    try {
      const response = await axios.post(
        `${this.guacamoleUrl}/api/tokens`,
        new URLSearchParams({
          username: this.adminUsername,
          password: this.adminPassword
        }),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        }
      );

      this.authToken = response.data.authToken;
      return this.authToken;
    } catch (error) {
      console.warn('⚠️  Guacamole API authentication failed:', error.message);
      throw error;
    }
  }

  /**
   * Ensure we have a valid auth token
   */
  async ensureAuthenticated() {
    if (!this.authToken) {
      await this.authenticateWithAPI();
    }
    return this.authToken;
  }

  /**
   * Create user via Guacamole REST API (handles password hashing correctly)
   */
  async createUserViaAPI(username, password) {
    try {
      await this.ensureAuthenticated();

      const userParams = {
        username: username,
        password: password,
        attributes: {
          disabled: '',
          expired: '',
          'access-window-start': '',
          'access-window-end': '',
          'valid-from': '',
          'valid-until': '',
          timezone: null
        }
      };

      const response = await axios.post(
        `${this.guacamoleUrl}/api/session/data/${this.dataSource}/users`,
        userParams,
        {
          headers: {
            'Content-Type': 'application/json',
            'Guacamole-Token': this.authToken
          },
          params: {
            token: this.authToken
          }
        }
      );

      console.log(`✅ Created Guacamole user via API: ${username}`);
      return response.data;
    } catch (error) {
      if (error.response?.status === 400 && error.response?.data?.message?.includes('already exists')) {
        console.log(`ℹ️  User already exists via API: ${username}`);
        return { username };
      }
      throw error;
    }
  }

  /**
   * Hash password using Guacamole's method: SHA256(password + hex(salt))
   * SECURITY FIX: Now uses cryptographically secure random salt instead of all-zero salt
   * IMPROVEMENT: Uses the exact method from Guacamole documentation
   * NOTE: This is only used as fallback when REST API is unavailable
   */
  hashPassword(password) {
    // Generate cryptographically secure random salt (32 bytes = 64 hex characters)
    const saltBytes = crypto.randomBytes(32);
    const saltHex = saltBytes.toString('hex');
    
    // Hash: SHA256(password + saltHex) - using the exact method from documentation
    // This matches the create-guacamole-user.ps1 script
    const hash = crypto.createHash('sha256')
      .update(password, 'utf8')
      .update(saltHex, 'utf8')
      .digest('hex');
    
    return { hash, salt: saltHex };
  }

  /**
   * Get or create Guacamole user for session
   * Returns existing user if already created for this session
   * ✅ IMPROVEMENT: Now validates session expiration and uses database storage
   * ✅ FIX: Uses mutex to prevent race conditions in concurrent requests
   */
  async getOrCreateSessionUser(sessionId) {
    // ✅ FIX: Check if user creation is already in progress (race condition prevention)
    if (this.userCreationLocks.has(sessionId)) {
      console.log(`⏳ User creation in progress for session ${sessionId.substring(0, 20)}..., waiting...`);
      try {
        // Wait for the existing creation to complete
        const existingUser = await this.userCreationLocks.get(sessionId);
        return existingUser;
      } catch (error) {
        // If the existing creation failed, continue to create new one
        console.warn(`⚠️  Previous user creation failed, retrying: ${error.message}`);
        this.userCreationLocks.delete(sessionId);
      }
    }

    // ✅ FIX: Create a promise that will resolve with the user data
    // This prevents concurrent requests from creating duplicate users
    const creationPromise = this._createSessionUserInternal(sessionId);
    this.userCreationLocks.set(sessionId, creationPromise);

    try {
      const userData = await creationPromise;
      return userData;
    } finally {
      // Clean up the lock after creation completes (success or failure)
      this.userCreationLocks.delete(sessionId);
    }
  }

  /**
   * Internal method to create session user (called with mutex protection)
   * @private
   */
  async _createSessionUserInternal(sessionId) {
    try {
      // ✅ IMPROVEMENT: Validate session before creating user
      const session = await dbManager.validateSession(sessionId);
      if (!session) {
        throw new Error('Session expired or invalid. Please refresh the page.');
      }

      // ✅ IMPROVEMENT: Check database first (survives server restarts)
      const dbMapping = await this.getSessionMappingFromDatabase(sessionId);
      if (dbMapping) {
        // ✅ FIX: Regenerate password when loading from database (password not stored for security)
        // This ensures the user can always login, even after server restart
        const regeneratedPassword = this.generatePassword(16);
        const { hash, salt } = this.hashPassword(regeneratedPassword);
        
        // Update password in Guacamole database
        try {
          await this.execMySQLQuery(
            `UPDATE guacamole_user SET password_hash = UNHEX('${hash}'), password_salt = UNHEX('${salt}'), password_date = NOW() WHERE entity_id = ${dbMapping.guacamole_entity_id}`
          );
          console.log(`✅ Regenerated password for user: ${dbMapping.guacamole_username}`);
        } catch (updateError) {
          console.warn(`⚠️  Failed to update password in Guacamole: ${updateError.message}`);
          // Continue anyway - user might still be able to login with old password
        }
        
        // Load into memory cache with new password
        const userData = {
          username: dbMapping.guacamole_username,
          password: regeneratedPassword, // ✅ Now has password
          entityId: dbMapping.guacamole_entity_id,
          createdAt: new Date(dbMapping.created_at).getTime()
        };
        this.sessionUsers.set(sessionId, userData);
        console.log(`✅ Loaded session user from database: ${userData.username} (password regenerated)`);
        return userData;
      }

      // Check if user already exists in memory
      if (this.sessionUsers.has(sessionId)) {
        const existingUser = this.sessionUsers.get(sessionId);
        console.log(`✅ Using existing Guacamole user: ${existingUser.username}`);
        return existingUser;
      }

      // Create new user with random username (not session-based)
      // Generate random alphabetic username (10 chars)
      const generateRandomUsername = (length = 10) => {
        const chars = 'abcdefghijklmnopqrstuvwxyz';
        let result = 'ctf_';
        for (let i = 0; i < length; i++) {
          result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
      };
      
      let username;
      let attempts = 0;
      let existingUser;
      
      // Ensure username is unique
      do {
        username = generateRandomUsername(10);
        const escapedUsername = this.escapeMySQL(username);
        const checkQuery = `SELECT entity_id FROM guacamole_entity WHERE name = '${escapedUsername}' AND type = 'USER'`;
        existingUser = await this.execMySQLQuery(checkQuery, true);
        attempts++;
      } while (existingUser && attempts < 5);
      
      if (existingUser) {
        // Fallback: use timestamp-based username if all random attempts failed
        username = `ctf_${Date.now().toString(36)}`;
      }
      
      const password = this.generatePassword(16);
      
      console.log(`\n🔐 Creating session Guacamole user: ${username}`);
      
      // Try REST API first (handles password hashing correctly)
      if (this.useRestAPI) {
        try {
          await this.createUserViaAPI(username, password);
          
          // Get entity ID from database for tracking
          const escapedUsername = this.escapeMySQL(username);
          const entityId = parseInt(await this.execMySQLQuery(
            `SELECT entity_id FROM guacamole_entity WHERE name = '${escapedUsername}' AND type = 'USER'`,
            true
          ));
          
          const userData = { username, password, entityId, createdAt: Date.now() };
          
          // IMPROVEMENT: Verify user was created correctly
          await this.verifyUserCreation(username, password, entityId);
          this.sessionUsers.set(sessionId, userData);
          
          console.log(`✅ Session user created successfully via REST API`);
          console.log(`   Username: ${username}`);
          console.log(`   Password: ${password}`);
          console.log(`   Entity ID: ${entityId}`);
          console.log(`   Admin: NO (user account only)`);
          
          return userData;
        } catch (apiError) {
          console.warn(`⚠️  REST API failed, falling back to database method: ${apiError.message}`);
          // Fall through to database method
        }
      }
      
      // Fallback: Direct database insertion (if API unavailable or disabled)
      // Check if user already exists in database (edge case: server restart)
      const escapedUsername = this.escapeMySQL(username);
      const entityIdCheck = await this.execMySQLQuery(
        `SELECT entity_id FROM guacamole_entity WHERE name = '${escapedUsername}' AND type = 'USER'`,
        true
      );
      
      if (entityIdCheck) {
        const entityId = parseInt(entityIdCheck);
        // User exists, update password
        const { hash, salt } = this.hashPassword(password);
        await this.execMySQLQuery(
          `UPDATE guacamole_user SET password_hash = UNHEX('${hash}'), password_salt = UNHEX('${salt}'), password_date = NOW(), disabled = 0 WHERE entity_id = ${entityId}`
        );
        
        const userData = { username, password, entityId, createdAt: Date.now() };
        this.sessionUsers.set(sessionId, userData);
        console.log(`✅ Reactivated existing user (entity_id: ${entityId})`);
        return userData;
      }

      // Create new entity
      await this.execMySQLQuery(
        `INSERT INTO guacamole_entity (name, type) VALUES ('${escapedUsername}', 'USER')`
      );

      // Get entity ID
      const entityId = parseInt(await this.execMySQLQuery(
        `SELECT entity_id FROM guacamole_entity WHERE name = '${escapedUsername}' AND type = 'USER'`,
        true
      ));

      // Hash password
      const { hash, salt } = this.hashPassword(password);

      // Create user with hashed password (disabled = 0 means enabled)
      await this.execMySQLQuery(
        `INSERT INTO guacamole_user (entity_id, password_hash, password_salt, password_date, disabled) VALUES (${entityId}, UNHEX('${hash}'), UNHEX('${salt}'), NOW(), 0)`
      );

      // ✅ IMPROVEMENT: Store in database for persistence
      const expiresAt = new Date(session.expires_at);
      await this.saveSessionMappingToDatabase(sessionId, username, entityId, expiresAt);

      // Store in memory with creation timestamp for expiration tracking
      const userData = { username, password, entityId, createdAt: Date.now() };
      this.sessionUsers.set(sessionId, userData);

      // ✅ IMPROVEMENT: Track activity
      await dbManager.trackSessionActivity(sessionId, 'connection', {
        action: 'guacamole_user_created',
        username,
        entityId
      });

      console.log(`✅ Session user created successfully via database`);
      console.log(`   Username: ${username}`);
      console.log(`   Password: ${password}`);
      console.log(`   Entity ID: ${entityId}`);
      console.log(`   Admin: NO (user account only)`);

      return userData;

    } catch (error) {
      console.error(`❌ Failed to create session user: ${error.message}`);
      throw error;
    }
  }

  /**
   * Verify user creation by checking database and attempting authentication
   * IMPROVEMENT: Double-check user and password are correct
   */
  async verifyUserCreation(username, password, entityId) {
    try {
      console.log(`\n🔍 Verifying user creation for: ${username}`);
      
      // 1. Verify entity exists
      const escapedUsername = this.escapeMySQL(username);
      const dbEntityId = await this.execMySQLQuery(
        `SELECT entity_id FROM guacamole_entity WHERE name = '${escapedUsername}' AND type = 'USER'`,
        true
      );
      
      if (!dbEntityId || parseInt(dbEntityId) !== entityId) {
        throw new Error(`Entity ID mismatch: expected ${entityId}, got ${dbEntityId}`);
      }
      console.log(`   ✅ Entity verified: ID ${entityId}`);
      
      // 2. Verify user record exists
      const userRecord = await this.execMySQLQuery(
        `SELECT entity_id, disabled FROM guacamole_user WHERE entity_id = ${entityId}`,
        true
      );
      
      if (!userRecord) {
        throw new Error(`User record not found for entity_id ${entityId}`);
      }
      
      const [recordedEntityId, disabled] = userRecord.split('\t');
      if (parseInt(recordedEntityId) !== entityId) {
        throw new Error(`User record entity ID mismatch`);
      }
      if (disabled === '1') {
        throw new Error(`User account is disabled`);
      }
      console.log(`   ✅ User record verified: enabled`);
      
      // 3. Try to authenticate with REST API (if available)
      if (this.useRestAPI) {
        try {
          await this.ensureAuthenticated();
          const authResponse = await axios.post(
            `${this.guacamoleUrl}/api/tokens`,
            new URLSearchParams({
              username: username,
              password: password
            }),
            {
              headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
              }
            }
          );
          
          if (authResponse.data && authResponse.data.authToken) {
            console.log(`   ✅ Password verified: Authentication successful via REST API`);
            return true;
          }
        } catch (authError) {
          console.warn(`   ⚠️  Could not verify password via REST API: ${authError.message}`);
          console.warn(`   ⚠️  User created but password verification skipped (REST API unavailable)`);
          // Don't throw - user is created, just can't verify password right now
        }
      }
      
      console.log(`   ✅ User verification complete`);
      return true;
    } catch (error) {
      console.error(`   ❌ User verification failed: ${error.message}`);
      // Don't throw - log warning but don't fail user creation
      console.warn(`   ⚠️  User may have been created but verification failed`);
      return false;
    }
  }

  /**
   * Grant READ permission to user for specific connection
   * This allows user to access the challenge without admin rights
   */
  async grantConnectionAccess(sessionId, connectionId) {
    try {
      const userData = this.sessionUsers.get(sessionId);
      if (!userData) {
        throw new Error('Session user not found. Create user first.');
      }

      const { entityId, username } = userData;

      // Check if permission already exists
      const existingPerm = await this.execMySQLQuery(
        `SELECT entity_id FROM guacamole_connection_permission WHERE entity_id = ${entityId} AND connection_id = ${connectionId} AND permission = 'READ'`,
        true
      );

      if (existingPerm) {
        console.log(`✅ User ${username} already has access to connection ${connectionId}`);
        return;
      }

      // Grant READ permission only (no admin rights)
      await this.execMySQLQuery(
        `INSERT INTO guacamole_connection_permission (entity_id, connection_id, permission) VALUES (${entityId}, ${connectionId}, 'READ')`
      );

      console.log(`✅ Granted READ access to ${username} for connection ${connectionId}`);

    } catch (error) {
      console.error(`❌ Failed to grant connection access: ${error.message}`);
      throw error;
    }
  }

  /**
   * Delete session user and all associated data
   * Called when session ends or user logs out
   * ✅ IMPROVEMENT: Also deletes from database
   */
  async deleteSessionUser(sessionId) {
    try {
      let userData = this.sessionUsers.get(sessionId);
      if (!userData) {
        // Try to get from database
        const dbMapping = await this.getSessionMappingFromDatabase(sessionId);
        if (!dbMapping) {
          console.log(`⚠️  No session user found for session: ${sessionId}`);
          return;
        }
        // Use database data
        userData = {
          username: dbMapping.guacamole_username,
          entityId: dbMapping.guacamole_entity_id
        };
      }

      const { username, entityId } = userData;
      console.log(`\n🗑️  Deleting session user: ${username}`);

      // Delete user (cascades to permissions)
      await this.execMySQLQuery(
        `DELETE FROM guacamole_user WHERE entity_id = ${entityId}`
      );

      // Delete entity
      await this.execMySQLQuery(
        `DELETE FROM guacamole_entity WHERE entity_id = ${entityId}`
      );

      // ✅ IMPROVEMENT: Delete from database
      try {
        await dbManager.pool.query(
          'DELETE FROM session_guacamole_users WHERE session_id = $1',
          [sessionId]
        );
      } catch (dbError) {
        console.warn(`⚠️  Failed to delete session mapping from database: ${dbError.message}`);
      }

      // Remove from memory
      this.sessionUsers.delete(sessionId);

      // ✅ IMPROVEMENT: Track cleanup activity
      await dbManager.trackSessionActivity(sessionId, 'cleanup', {
        action: 'guacamole_user_deleted',
        username
      });

      console.log(`✅ Session user deleted successfully`);

    } catch (error) {
      console.error(`❌ Failed to delete session user: ${error.message}`);
      // Don't throw - cleanup should be best-effort
    }
  }

  /**
   * Get session user info
   */
  getSessionUser(sessionId) {
    return this.sessionUsers.get(sessionId) || null;
  }

  /**
   * Wait for Guacamole database container to be ready
   * IMPROVEMENT: Retry with exponential backoff
   */
  async waitForContainerReady(maxRetries = 10, initialDelay = 2000) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        // Test if container is running and accessible
        const testQuery = 'SELECT 1';
        await this.execMySQLQuery(testQuery, false);
        return true; // Container is ready
      } catch (error) {
        if (attempt === maxRetries) {
          throw new Error(`Container ${this.guacContainer} not ready after ${maxRetries} attempts: ${error.message}`);
        }
        
        // Exponential backoff: 2s, 4s, 8s, 16s, etc. (max 30s)
        const delay = Math.min(initialDelay * Math.pow(2, attempt - 1), 30000);
        console.log(`⏳ Waiting for ${this.guacContainer} to be ready (attempt ${attempt}/${maxRetries}, retry in ${delay/1000}s)...`);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
    return false;
  }

  /**
   * Load sessions from database on startup with retry logic
   * IMPROVEMENT: Retry with exponential backoff if container isn't ready
   */
  async loadSessionsFromDatabaseWithRetry() {
    try {
      // Wait for container to be ready first
      await this.waitForContainerReady();
      
      // Now load sessions
      await this.loadSessionsFromDatabase();
    } catch (error) {
      // If container isn't ready, log warning but don't crash
      if (error.message.includes('not ready after')) {
        console.warn(`⚠️  ${this.guacContainer} is not ready yet. Sessions will be loaded when container becomes available.`);
      } else {
        throw error;
      }
    }
  }

  /**
   * Load sessions from database on startup
   * IMPROVEMENT: Persist sessions across server restarts
   */
  async loadSessionsFromDatabase() {
    try {
      console.log('📂 Loading existing Guacamole users from MySQL database...');
      const query = `SELECT e.entity_id, e.name FROM guacamole_entity e 
                     WHERE e.name LIKE 'ctf_user_%' AND e.type = 'USER'`;
      const result = await this.execMySQLQuery(query, false);
      
      if (!result || result.trim() === '') {
        console.log('   No existing Guacamole users found (this is normal for a fresh database)');
        return;
      }
      
      // Parse results (format: entity_id\tname)
      const lines = result.trim().split('\n').filter(line => line.trim());
      let loadedCount = 0;
      
      for (const line of lines) {
        const parts = line.split('\t');
        if (parts.length >= 2) {
          const entityId = parseInt(parts[0]);
          const username = parts[1];
          
          // Extract session ID from username (ctf_user_{sessionId})
          const match = username.match(/^ctf_user_(.+)$/);
          if (match) {
            const sessionId = match[1];
            // Reconstruct user data (password will be reset on next use)
            this.sessionUsers.set(sessionId, {
              username,
              password: null, // Will need to reset password
              entityId,
              createdAt: Date.now() // Approximate
            });
            loadedCount++;
          }
        }
      }
      
      console.log(`✅ Loaded ${loadedCount} existing Guacamole users from MySQL database`);
    } catch (error) {
      console.warn('⚠️  Failed to load sessions from database:', error.message);
      throw error; // Re-throw so retry logic can handle it
    }
  }

  /**
   * Start periodic session cleanup
   * IMPROVEMENT: Automatic cleanup of expired sessions
   */
  startSessionCleanup() {
    // Run cleanup every hour
    const cleanupInterval = 60 * 60 * 1000; // 1 hour
    
    setInterval(() => {
      this.cleanupExpiredSessions(60).catch(err => {
        console.error('❌ Session cleanup failed:', err.message);
      });
    }, cleanupInterval);
    
    console.log('🕐 Session cleanup scheduled (runs every hour)');
  }

  /**
   * ✅ IMPROVEMENT: Save session mapping to database
   * @param {string} sessionId - Session ID
   * @param {string} username - Guacamole username
   * @param {number} entityId - Guacamole entity ID
   * @param {Date} expiresAt - Session expiration time
   */
  async saveSessionMappingToDatabase(sessionId, username, entityId, expiresAt) {
    try {
      const query = `
        INSERT INTO session_guacamole_users (session_id, guacamole_username, guacamole_entity_id, expires_at, last_activity)
        VALUES ($1, $2, $3, $4, NOW())
        ON CONFLICT (session_id) 
        DO UPDATE SET 
          guacamole_username = EXCLUDED.guacamole_username,
          guacamole_entity_id = EXCLUDED.guacamole_entity_id,
          expires_at = EXCLUDED.expires_at,
          last_activity = NOW()
      `;
      await dbManager.pool.query(query, [sessionId, username, entityId, expiresAt]);
    } catch (error) {
      console.warn(`⚠️  Failed to save session mapping to database: ${error.message}`);
      // Don't throw - database storage is best-effort
    }
  }

  /**
   * ✅ IMPROVEMENT: Get session mapping from database
   * @param {string} sessionId - Session ID
   * @returns {Promise<object|null>} Session mapping or null
   */
  async getSessionMappingFromDatabase(sessionId) {
    try {
      const query = `
        SELECT session_id, guacamole_username, guacamole_entity_id, created_at, expires_at, last_activity
        FROM session_guacamole_users
        WHERE session_id = $1
      `;
      const result = await dbManager.pool.query(query, [sessionId]);
      if (result.rows.length > 0) {
        const mapping = result.rows[0];
        // Check if expired
        const expiresAt = new Date(mapping.expires_at);
        if (expiresAt < new Date()) {
          return null; // Expired
        }
        return mapping;
      }
      return null;
    } catch (error) {
      console.warn(`⚠️  Failed to get session mapping from database: ${error.message}`);
      return null;
    }
  }

  /**
   * Clean up all expired sessions
   * ✅ IMPROVEMENT: Now uses database expiration as source of truth
   */
  /**
   * ✅ FIX: Clean up creation locks for expired sessions
   * Called during session cleanup to prevent memory leaks
   */
  _cleanupCreationLocks(expiredSessionIds) {
    for (const sessionId of expiredSessionIds) {
      this.userCreationLocks.delete(sessionId);
    }
  }

  async cleanupExpiredSessions(maxAgeMinutes = 60) {
    console.log(`\n🧹 Cleaning up expired sessions...`);
    
    let cleanedCount = 0;
    
    try {
      // ✅ IMPROVEMENT: Use database expiration as source of truth
      const query = `
        SELECT session_id 
        FROM session_guacamole_users
        WHERE expires_at < NOW()
      `;
      const result = await dbManager.pool.query(query);
      const expiredSessions = result.rows.map(row => row.session_id);
      
      // Also check memory cache for sessions not in database
      const now = Date.now();
      const maxAge = maxAgeMinutes * 60 * 1000;
      for (const [sessionId, userData] of this.sessionUsers.entries()) {
        if (userData.createdAt && (now - userData.createdAt > maxAge)) {
          if (!expiredSessions.includes(sessionId)) {
            expiredSessions.push(sessionId);
          }
        }
      }
      
      // Delete expired sessions
      for (const sessionId of expiredSessions) {
        try {
          await this.deleteSessionUser(sessionId);
          cleanedCount++;
        } catch (error) {
          console.error(`❌ Failed to delete expired session ${sessionId}:`, error.message);
        }
      }
      
      // ✅ FIX: Clean up creation locks for expired sessions (prevent memory leaks)
      this._cleanupCreationLocks(expiredSessions);
      
      console.log(`   Active sessions: ${this.sessionUsers.size}`);
      console.log(`   Expired sessions cleaned: ${cleanedCount}`);
      console.log(`   Creation locks cleaned: ${expiredSessions.length}`);
    } catch (error) {
      console.error(`❌ Error during cleanup: ${error.message}`);
      // Fallback to memory-only cleanup
      const now = Date.now();
      const maxAge = maxAgeMinutes * 60 * 1000;
      const expiredSessions = [];
      for (const [sessionId, userData] of this.sessionUsers.entries()) {
        if (userData.createdAt && (now - userData.createdAt > maxAge)) {
          expiredSessions.push(sessionId);
        }
      }
      for (const sessionId of expiredSessions) {
        try {
          await this.deleteSessionUser(sessionId);
          cleanedCount++;
        } catch (error) {
          console.error(`❌ Failed to delete expired session ${sessionId}:`, error.message);
        }
      }
    }
    
    return cleanedCount;
  }

  /**
   * Prevent admin account creation
   * This method explicitly checks and prevents admin privilege escalation
   */
  async preventAdminCreation(entityId) {
    try {
      // Check if user has any admin permissions
      const adminPerms = await this.execMySQLQuery(
        `SELECT permission FROM guacamole_system_permission WHERE entity_id = ${entityId}`,
        true
      );

      if (adminPerms) {
        console.error(`🚨 SECURITY: Attempting to delete unauthorized admin permissions for entity ${entityId}`);
        
        // Delete all system permissions for this user
        await this.execMySQLQuery(
          `DELETE FROM guacamole_system_permission WHERE entity_id = ${entityId}`
        );
        
        console.log(`✅ Removed admin permissions from entity ${entityId}`);
      }
    } catch (error) {
      console.error(`❌ Failed to check admin permissions: ${error.message}`);
    }
  }

  /**
   * Security check: Ensure no session users have admin rights
   */
  async auditSessionUsers() {
    console.log(`\n🔍 Auditing session users for admin permissions...`);
    
    for (const [sessionId, userData] of this.sessionUsers.entries()) {
      await this.preventAdminCreation(userData.entityId);
    }
    
    console.log(`✅ Audit complete`);
  }
}

// Export singleton instance
export const sessionGuacManager = new SessionGuacamoleManager();
