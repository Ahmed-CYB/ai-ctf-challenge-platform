/**
 * Guacamole PostgreSQL Manager
 * Manages Guacamole users, connections, and permissions via Docker exec
 * Integrates with HackyTalk database for SSO
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import pg from 'pg';
import crypto from 'crypto';
import dotenv from 'dotenv';
import Anthropic from '@anthropic-ai/sdk';

dotenv.config();

const execAsync = promisify(exec);
const { Pool } = pg;

// Initialize Claude for SQL validation
const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY
});

class GuacamolePostgreSQLManager {
  constructor() {
    // Guacamole MySQL connection via Docker exec (bypasses Windows networking issues)
    this.guacContainer = process.env.GUAC_CONTAINER_NAME || 'ctf-guacamole-db-new';
    this.guacDbUser = process.env.GUAC_DB_USER || 'guacamole_user';
    this.guacDbPass = process.env.GUAC_DB_PASSWORD || 'guacamole_password_123';
    this.guacDbName = process.env.GUAC_DB_NAME || 'guacamole_db';

    // HackyTalk database pool
    this.hackyTalkPool = new Pool({
      host: process.env.DB_HOST || '127.0.0.1',
      port: process.env.DB_PORT || 5432,
      database: process.env.DB_NAME || 'hackytalk_db',
      user: process.env.DB_USER || 'postgres',
      password: process.env.DB_PASSWORD || 'hackytalk',
      connectionTimeoutMillis: 10000
    });
    
    console.log('✅ Guacamole PostgreSQL Manager initialized (using Docker exec)');
  }

  /**
   * Validate SQL query with Claude before execution
   * @param {string} sql - SQL query to validate
   * @returns {object} { valid: boolean, correctedSql: string, issues: string }
   */
  async validateSQLWithClaude(sql) {
    try {
      const message = await anthropic.messages.create({
        model: process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-20250514',
        max_tokens: 1024,
        messages: [{
          role: 'user',
          content: `You are a MySQL syntax validator. Analyze this SQL query for a MySQL 8.0 database and respond ONLY with a JSON object (no markdown, no explanation):

SQL Query:
${sql}

Context:
- This will be executed via: docker exec ctf-guacamole-db-new mysql -u guacamole_user -pguacamole_pass guacamole_db -e "QUERY" -sN
- The query is wrapped in double quotes in the shell command
- Single quotes inside the query work fine
- Table: guacamole_entity (columns: entity_id, name, type)
- Table: guacamole_user (columns: user_id, entity_id, password_salt, password_hash, password_date, email_address, full_name)
- Table: guacamole_connection (columns: connection_id, connection_name, protocol, parent_id, max_connections)
- Table: guacamole_connection_parameter (columns: connection_id, parameter_name, parameter_value)
- Table: guacamole_connection_permission (columns: entity_id, connection_id, permission)

Respond with JSON only:
{
  "valid": true/false,
  "correctedSql": "the corrected SQL if needed, or original if valid",
  "issues": "explanation of any syntax errors, or empty string if valid"
}`
        }]
      });

      const response = message.content[0].text.trim();
      const jsonMatch = response.match(/\{[\s\S]*\}/);
      
      if (jsonMatch) {
        const result = JSON.parse(jsonMatch[0]);
        if (!result.valid) {
          console.log(`🤖 Claude found SQL issue: ${result.issues}`);
          console.log(`📝 Suggested fix: ${result.correctedSql}`);
        }
        return result;
      }
      
      // Fallback if Claude doesn't return JSON
      return { valid: true, correctedSql: sql, issues: '' };
    } catch (error) {
      console.error('⚠️  Claude validation failed:', error.message);
      // Don't block execution if Claude fails
      return { valid: true, correctedSql: sql, issues: '' };
    }
  }

  /**
   * Execute MySQL query via Docker exec (bypasses Windows networking)
   * @param {string} sql - SQL query to execute
   * @returns {string} Query result as JSON string
   */
  async execMySQLQuery(sql) {
    // Validate SQL with Claude first
    const validation = await this.validateSQLWithClaude(sql);
    
    if (!validation.valid && validation.correctedSql !== sql) {
      console.log(`✨ Using Claude's corrected SQL`);
      sql = validation.correctedSql;
    }
    
    // Normalize SQL: remove extra whitespace and newlines for shell execution
    sql = sql.replace(/\s+/g, ' ').trim();
    
    // Escape only double quotes for the shell, single quotes work fine inside double quotes
    const escapedSql = sql.replace(/"/g, '\\"');
    const command = `docker exec ${this.guacContainer} mysql -u ${this.guacDbUser} -p${this.guacDbPass} ${this.guacDbName} -e "${escapedSql}" -sN`;
    
    try {
      const { stdout, stderr } = await execAsync(command);
      if (stderr && !stderr.includes('Using a password on the command line')) {
        console.error('⚠️  MySQL stderr:', stderr);
      }
      return stdout.trim();
    } catch (error) {
      console.error('❌ MySQL exec failed:', error.message);
      throw error;
    }
  }

  /**
   * Execute MySQL query and get JSON result
   * @param {string} sql - SQL query
   * @returns {Array} Array of row objects
   */
  async queryMySQL(sql) {
    const command = `docker exec ${this.guacContainer} mysql -u ${this.guacDbUser} -p${this.guacDbPass} ${this.guacDbName} --batch --skip-column-names -e "${sql.replace(/"/g, '\\"')}"`;
    
    try {
      const { stdout } = await execAsync(command);
      const lines = stdout.trim().split('\n').filter(line => line);
      
      if (lines.length === 0) return [];
      
      // Parse tab-separated values into objects
      return lines.map(line => {
        const values = line.split('\t');
        return values;
      });
    } catch (error) {
      console.error('❌ MySQL query failed:', error.message);
      throw error;
    }
  }

  async testConnection() {
    try {
      console.log('🔍 Testing MySQL connection via Docker exec...');
      const result = await this.execMySQLQuery('SELECT 1');
      console.log('✅ MySQL connection test successful:', result);
    } catch (error) {
      console.error('❌ MySQL connection test failed:', error.message);
      console.error(`   Make sure container '${this.guacContainer}' is running`);
    }
  }

  /**
   * Retry a database operation with exponential backoff
   */
  async retryOperation(operation, maxRetries = 3, baseDelay = 1000) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await operation();
      } catch (error) {
        console.error(`   ❌ Attempt ${attempt} failed:`, error.code, error.message);
        if (attempt === maxRetries) {
          throw error;
        }
        
        const delay = baseDelay * Math.pow(2, attempt - 1);
        console.log(`   ⏳ Retry ${attempt}/${maxRetries} after ${delay}ms...`);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }

  /**
   * Hash password with SHA-256 and salt (Guacamole format)
   * Guacamole uses: SHA256(password + hex(salt))
   */
  hashPassword(password, salt) {
    const saltHex = salt.toString('hex');
    const hash = crypto.createHash('sha256');
    hash.update(password + saltHex);
    return hash.digest();
  }

  /**
   * Generate random salt (32 bytes)
   */
  generateSalt() {
    return crypto.randomBytes(32);
  }

  /**
   * Generate random alphabetic username
   */
  generateAlphabeticUsername(length = 10) {
    const letters = 'abcdefghijklmnopqrstuvwxyz';
    let username = 'ctf';
    for (let i = 0; i < length; i++) {
      username += letters.charAt(Math.floor(Math.random() * letters.length));
    }
    return username;
  }

  /**
   * Create a Guacamole user with connection access
   * @param {string} sessionId - HackyTalk session ID
   * @param {string} challengeName - Challenge name
   * @param {string} attackerIP - IP of Kali attacker container
   * @returns {object} User and connection info
   */
  async createUserWithConnection(sessionId, challengeName, attackerIP) {
    console.log(`\n🔐 Creating Guacamole connection for ${challengeName} at ${attackerIP}`);
    console.log(`   Using Docker exec to ${this.guacContainer}`);
    
    return await this.retryOperation(async () => {
      try {
        // Get user info from HackyTalk database
        const { rows: userResult } = await this.hackyTalkPool.query(
          `SELECT u.user_id, u.username, u.email 
           FROM users u
           JOIN sessions s ON u.user_id = s.user_id
           WHERE s.session_id = $1 AND s.is_active = true`,
          [sessionId]
        );

        let user_id, username, email;
        
        if (userResult.length === 0) {
          // FALLBACK: Create unique user per challenge (not guacadmin)
          console.warn(`⚠️  No active session found, creating unique challenge user`);
          user_id = `user-${challengeName}-${Date.now()}`;
          username = challengeName.substring(0, 20).replace(/[^a-z0-9]/g, '-');
          email = `${username}@ctf.local`;
        } else {
          ({ user_id, username, email } = userResult[0]);
        }

        // Generate alphabetic username (e.g., "ctfabcdefghij")
        const guacUsername = this.generateAlphabeticUsername(10);

        // Generate password based on user_id + sessionId (for SSO)
        const password = crypto.createHash('sha256')
          .update(`${user_id}${sessionId}${challengeName}`)
          .digest('hex');

        // Generate salt and hash password
        const salt = this.generateSalt();
        const passwordHash = this.hashPassword(password, salt);
        const saltHex = salt.toString('hex');
        const passwordHashHex = passwordHash.toString('hex');

        // 1. Check if entity exists
        const entityCheckSql = `SELECT entity_id FROM guacamole_entity WHERE name = '${guacUsername}' AND type = 'USER'`;
        const entityRows = await this.queryMySQL(entityCheckSql);

        let entityId;
        
        if (entityRows.length > 0) {
          entityId = entityRows[0][0];
          console.log(`📝 Entity already exists: ${guacUsername} (ID: ${entityId})`);
        } else {
          // 2. Create entity
          const createEntitySql = `INSERT INTO guacamole_entity (name, type) VALUES ('${guacUsername}', 'USER')`;
          await this.execMySQLQuery(createEntitySql);
          
          // Get the inserted entity_id
          const getEntityIdSql = `SELECT entity_id FROM guacamole_entity WHERE name = '${guacUsername}' AND type = 'USER'`;
          const newEntityRows = await this.queryMySQL(getEntityIdSql);
          entityId = newEntityRows[0][0];
          console.log(`✅ Created entity: ${guacUsername} (ID: ${entityId})`);
        }

        // 3. Create or update user
        const userCheckSql = `SELECT user_id FROM guacamole_user WHERE entity_id = ${entityId}`;
        const userRows = await this.queryMySQL(userCheckSql);

        let userId;

        if (userRows.length > 0) {
          userId = userRows[0][0];
          // Update password (using hex strings for binary data)
          const updateUserSql = `UPDATE guacamole_user SET password_salt = UNHEX('${saltHex}'), password_hash = UNHEX('${passwordHashHex}'), password_date = CURRENT_TIMESTAMP, email_address = '${email}' WHERE user_id = ${userId}`;
          await this.execMySQLQuery(updateUserSql);
          console.log(`📝 Updated user: ${guacUsername} (ID: ${userId})`);
        } else {
          const createUserSql = `INSERT INTO guacamole_user (entity_id, password_salt, password_hash, password_date, email_address, full_name) VALUES (${entityId}, UNHEX('${saltHex}'), UNHEX('${passwordHashHex}'), CURRENT_TIMESTAMP, '${email}', '${username}')`;
          await this.execMySQLQuery(createUserSql);
          
          // Get the inserted user_id
          const getUserIdSql = `SELECT user_id FROM guacamole_user WHERE entity_id = ${entityId}`;
          const newUserRows = await this.queryMySQL(getUserIdSql);
          userId = newUserRows[0][0];
          console.log(`✅ Created user: ${guacUsername} (ID: ${userId})`);
        }

        // 4. Create SSH connection
        const connectionName = `${guacUsername}-ssh`;
        const createConnectionSql = `INSERT INTO guacamole_connection (connection_name, protocol, max_connections) VALUES ('${connectionName}', 'ssh', 5)`;
        await this.execMySQLQuery(createConnectionSql);
        
        // Get connection_id
        const getConnectionIdSql = `SELECT connection_id FROM guacamole_connection ORDER BY connection_id DESC LIMIT 1`;
        const connectionRows = await this.queryMySQL(getConnectionIdSql);
        const connectionId = connectionRows[0][0];
        console.log(`✅ Created connection: ${connectionName} (ID: ${connectionId})`);

        // 5. Add SSH connection parameters (AI can modify these)
        const parameters = [
          ['hostname', attackerIP],
          ['port', '22'],
          ['username', 'root'],
          ['password', 'kali'],
          ['enable-sftp', 'true'],
          ['sftp-root-directory', '/root']
        ];

        const paramValues = parameters.map(([name, value]) => 
          `(${connectionId}, '${name}', '${value}')`
        ).join(', ');
        
        const createParamsSql = `INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value) VALUES ${paramValues}`;
        await this.execMySQLQuery(createParamsSql);
        console.log(`✅ Added ${parameters.length} connection parameters`);

        // 6. Grant READ permission to user
        const grantUserPermSql = `INSERT INTO guacamole_connection_permission (entity_id, connection_id, permission) VALUES (${entityId}, ${connectionId}, 'READ')`;
        await this.execMySQLQuery(grantUserPermSql);

        // 7. ALWAYS grant permission to guacadmin (entity_id=1)
        if (entityId !== 1) {
          const grantAdminPermSql = `INSERT INTO guacamole_connection_permission (entity_id, connection_id, permission) VALUES (1, ${connectionId}, 'READ')`;
          await this.execMySQLQuery(grantAdminPermSql);
          console.log(`   ✅ Also granted access to guacadmin`);
        }

        console.log(`✅ Guacamole setup complete for ${guacUsername}`);
        console.log(`   Connection ID: ${connectionId}`);
        console.log(`   Target: ${attackerIP}:22 (SSH)`);
        console.log(`   Login: root / kali`);

        return {
          guacUsername,
          password, // Return for SSO token generation
          userId,
          entityId,
          connectionId,
          connectionName,
          attackerIP,
          sessionId
        };

      } catch (error) {
        console.error('❌ Failed to create Guacamole user:', error);
        throw error;
      }
    }); // End retryOperation
  }

  /**
   * Generate pre-authenticated URL for direct access
   * @param {string} sessionId - HackyTalk session ID
   * @param {number} connectionId - Guacamole connection ID
   * @returns {string} Pre-authenticated URL
   */
  async generateDirectAccessURL(sessionId, connectionId) {
    try {
      // Verify session in HackyTalk database
      const userResult = await this.hackyTalkPool.query(
        `SELECT u.user_id, u.username 
         FROM users u
         JOIN sessions s ON u.user_id = s.user_id
         WHERE s.session_id = $1 AND s.is_active = true`,
        [sessionId]
      );

      // Fallback to latest created connection if no active session found
      let username, userId;
      if (userResult.rows.length === 0) {
        console.log('⚠️  No active session for URL generation');
        // Get the connection username from the connection_id
        try {
          const connResult = await this.execMySQLQuery(
            `SELECT c.connection_name FROM guacamole_connection c WHERE c.connection_id = ${connectionId}`
          );
          if (connResult && connResult.length > 0 && connResult[0] && connResult[0].connection_name) {
            username = connResult[0].connection_name.replace(/-ssh$/, '');
            userId = `user-${connectionId}`;
          } else {
            username = 'guacadmin';
            userId = 'guacadmin-user';
          }
        } catch (err) {
          console.warn('⚠️  Could not query connection name:', err.message);
          username = 'guacadmin';
          userId = 'guacadmin-user';
        }
      } else {
        username = userResult.rows[0].username;
        userId = userResult.rows[0].user_id;
      }

      // Generate Guacamole access URL
      // For now, return direct URL - user needs to login with guacadmin
      // In production, implement token-based authentication
      const baseUrl = process.env.GUACAMOLE_URL || 'http://localhost:8080/guacamole';
      
      console.log(`📋 Access Instructions:`);
      console.log(`   1. Navigate to: ${baseUrl}`);
      console.log(`   2. Login with username: ${username}`);
      console.log(`   3. Password: (generated based on challenge)`);
      console.log(`   4. Connection will be available automatically`);
      console.log(`   💡 Or use guacadmin/guacadmin to see all connections`);
      
      return {
        url: baseUrl,
        username: 'guacadmin',
        password: 'guacadmin',
        connectionId: connectionId,
        instructions: 'Login to Guacamole with guacadmin/guacadmin and select your connection from the dashboard'
      };

    } catch (error) {
      console.error('❌ Failed to generate access URL:', error);
      throw error;
    }
  }

  /**
   * Verify auth token for SSO
   * @param {string} token - Auth token
   * @param {number} connectionId - Connection ID
   * @returns {object} User info if valid
   */
  async verifyAuthToken(token, connectionId) {
    try {
      const [result] = await this.hackyTalkPool.query(
        `SELECT t.session_id, u.user_id, u.username, u.email
         FROM guacamole_auth_tokens t
         JOIN sessions s ON t.session_id = s.session_id
         JOIN users u ON s.user_id = u.user_id
         WHERE t.token = ? AND t.connection_id = ?
         AND t.created_at > NOW() - INTERVAL 24 HOUR
         AND s.is_active = true`,
        [token, connectionId]
      );

      if (result.length === 0) {
        return null;
      }

      return result[0];
    } catch (error) {
      console.error('❌ Token verification failed:', error);
      return null;
    }
  }

  /**
   * Remove user and connection when challenge is deleted
   * @param {string} challengeName - Challenge name
   * @param {string} sessionId - Session ID
   */
  async removeUserAndConnection(challengeName, sessionId) {
    const connection = await this.guacPool.getConnection();
    
    try {
      const [userResult] = await this.hackyTalkPool.query(
        `SELECT u.username 
         FROM users u
         JOIN sessions s ON u.user_id = s.user_id
         WHERE s.session_id = ?`,
        [sessionId]
      );

      if (userResult.length === 0) {
        console.log('⚠️  User not found in HackyTalk database');
        return;
      }

      const guacUsername = `${userResult[0].username}-${challengeName}`;

      await connection.query('START TRANSACTION');

      // Delete will cascade to user, permissions, and connections
      const [result] = await connection.query(
        'DELETE FROM guacamole_entity WHERE name = ? AND type = ?',
        [guacUsername, 'USER']
      );

      await connection.commit();

      if (result.affectedRows > 0) {
        console.log(`✅ Removed Guacamole user and connections: ${guacUsername}`);
      } else {
        console.log(`⚠️  User not found in Guacamole: ${guacUsername}`);
      }

    } catch (error) {
      await connection.rollback();
      console.error('❌ Failed to remove user:', error);
      throw error;
    } finally {
      connection.release();
    }
  }

  /**
   * Clean up expired tokens (run periodically)
   */
  async cleanupExpiredTokens() {
    try {
      const result = await this.hackyTalkPool.query(
        `DELETE FROM guacamole_auth_tokens 
         WHERE created_at < NOW() - INTERVAL '24 hours'`
      );
      
      if (result.rowCount > 0) {
        console.log(`🧹 Cleaned up ${result.rowCount} expired tokens`);
      }
    } catch (error) {
      console.error('❌ Token cleanup failed:', error);
    }
  }

  /**
   * Close database connections
   */
  async close() {
    await this.guacPool.end();
    await this.hackyTalkPool.end();
  }
}

export default GuacamolePostgreSQLManager;
