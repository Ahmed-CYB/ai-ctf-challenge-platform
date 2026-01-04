/**
 * Guacamole Connection Agent
 * Specialized agent for managing Guacamole SSH connections and SQL operations
 * Handles connection creation, updates, and validation for CTF challenges
 */

import Anthropic from '@anthropic-ai/sdk';
import { exec } from 'child_process';
import { promisify } from 'util';
import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

const execAsync = promisify(exec);

// Initialize Claude
const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY
});

const SYSTEM_PROMPT = `You are a Guacamole Connection Specialist Agent. Your expertise:

**PRIMARY RESPONSIBILITIES:**
1. Create session-based Guacamole user accounts with random credentials
2. Create SSH connections in Guacamole database (MySQL)
3. Manage connection parameters (hostname, port, username, password)
4. Update existing connections when IP addresses change
5. Grant READ permissions to session users for their challenges
6. Validate SQL queries before execution

**GUACAMOLE DATABASE SCHEMA (MySQL 8.0):**

Tables:
- guacamole_entity (entity_id, name, type)
- guacamole_user (user_id, entity_id, password_salt, password_hash, password_date, email_address, full_name)
- guacamole_connection (connection_id, connection_name, protocol, parent_id, max_connections, max_connections_per_user)
- guacamole_connection_parameter (connection_id, parameter_name, parameter_value)
- guacamole_connection_permission (entity_id, connection_id, permission)

**CONNECTION PARAMETERS FOR SSH:**
Required parameters:
- hostname: IP address of attacker container
- port: 22 (SSH default)
- username: kali (default Kali user)
- password: kali (default Kali password)

Optional but recommended:
- enable-sftp: true (enable file transfer)
- sftp-root-directory: / (SFTP root)

**SQL EXECUTION CONTEXT:**
- Executed via: docker exec ctf-guacamole-db-new mysql -u guacamole_user -pguacamole_password_123 guacamole_db -e "QUERY" -sN
- Query wrapped in double quotes in shell
- Use single quotes inside SQL queries
- Use -sN flags for raw output (no table borders)

**USER ACCOUNT MANAGEMENT:**
- Each session gets unique Guacamole account: ctf_user_{sessionId}
- Random password generated per user (16 chars, alphanumeric)
- Users get READ permission only to their assigned challenges
- Password hashing: SHA-256 with salt (Guacamole standard)
- Entity created first, then user linked to entity

**CRITICAL RULES:**
1. ALWAYS validate SQL before execution
2. Use parameterized queries when possible
3. Check if connection exists before creating
4. Update hostname when container IP changes
5. Grant READ permission to session users automatically
6. Use ctf-instances-network IP (172.22.x.x), NOT challenge network IP
7. Connection names format: {challengeName}-ssh
8. User names format: ctf_user_{sessionId}
9. Handle duplicate entry errors gracefully

**OUTPUT FORMAT:**
Return JSON with:
{
  "action": "create|update|validate|error",
  "sql": "the SQL query to execute",
  "explanation": "what this query does",
  "connectionInfo": {
    "connectionId": number,
    "connectionName": "string",
    "hostname": "string",
    "port": number,
    "protocol": "ssh"
  },
  "validation": {
    "valid": boolean,
    "issues": "any problems found"
  }
}`;

/**
 * GuacamoleAgent - Handles all Guacamole connection operations
 */
export class GuacamoleAgent {
  constructor() {
    this.guacContainer = process.env.GUAC_CONTAINER_NAME || 'ctf-guacamole-db-new';
    this.guacDbUser = process.env.GUAC_DB_USER || 'guacamole_user';
    this.guacDbPass = process.env.GUAC_DB_PASSWORD || 'guacamole_password_123';
    this.guacDbName = process.env.GUAC_DB_NAME || 'guacamole_db';
    
    console.log('🤖 Guacamole Agent initialized');
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
   * Execute MySQL query via Docker exec
   */
  async execMySQLQuery(query, silent = false) {
    const escapedQuery = query.replace(/"/g, '\\"');
    const command = `docker exec ${this.guacContainer} mysql -u ${this.guacDbUser} -p${this.guacDbPass} ${this.guacDbName} -e "${escapedQuery}" -sN`;
    
    if (!silent) {
      console.log(`📊 Executing SQL: ${query.substring(0, 100)}...`);
    }
    
    const { stdout, stderr } = await execAsync(command);
    
    if (stderr && !stderr.includes('Using a password')) {
      throw new Error(`MySQL Error: ${stderr}`);
    }
    
    return stdout.trim();
  }

  /**
   * Execute multiple MySQL queries in a transaction
   * IMPROVEMENT: Wraps multiple operations in BEGIN/COMMIT for atomicity
   * @param {Array<string>} queries - Array of SQL queries to execute
   * @returns {Promise<{success: boolean, results: Array}>}
   */
  async execMySQLTransaction(queries) {
    if (!queries || queries.length === 0) {
      throw new Error('No queries provided for transaction');
    }

    // Escape all queries
    const escapedQueries = queries.map(q => q.replace(/"/g, '\\"'));
    
    // Combine queries with BEGIN/COMMIT
    const transactionSQL = `BEGIN; ${escapedQueries.join('; ')}; COMMIT;`;
    
    const command = `docker exec ${this.guacContainer} mysql -u ${this.guacDbUser} -p${this.guacDbPass} ${this.guacDbName} -e "${transactionSQL}" -sN`;
    
    try {
      console.log(`📊 Executing transaction with ${queries.length} queries...`);
      const { stdout, stderr } = await execAsync(command);
      
      if (stderr && !stderr.includes('Using a password') && !stderr.includes('Warning')) {
        // If error, try to rollback
        try {
          await this.execMySQLQuery('ROLLBACK', true);
        } catch (rollbackError) {
          console.warn('⚠️  Rollback failed:', rollbackError.message);
        }
        throw new Error(`MySQL Transaction Error: ${stderr}`);
      }
      
      return { success: true, results: stdout.trim() };
    } catch (error) {
      // Attempt rollback on error
      try {
        await this.execMySQLQuery('ROLLBACK', true);
      } catch (rollbackError) {
        console.warn('⚠️  Rollback failed:', rollbackError.message);
      }
      throw error;
    }
  }

  /**
   * Ask Claude to generate/validate SQL for connection management
   * IMPROVEMENT: Added retry logic with exponential backoff for rate limit errors
   */
  async consultClaude(task, context, maxRetries = 3) {
    let lastError;
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const message = await anthropic.messages.create({
          model: process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-20250514',
          max_tokens: 2000,
          temperature: 0,
          system: SYSTEM_PROMPT,
          messages: [{
            role: 'user',
            content: `Task: ${task}

Context:
${JSON.stringify(context, null, 2)}

Generate the appropriate SQL query and return JSON response.`
          }]
        });

        const response = message.content[0].text.trim();
        const jsonMatch = response.match(/\{[\s\S]*\}/);
        
        if (jsonMatch) {
          return JSON.parse(jsonMatch[0]);
        }
        
        throw new Error('Claude did not return valid JSON');
      } catch (error) {
        lastError = error;
        
        // Check if it's a rate limit error (429)
        const isRateLimit = error.status === 429 || 
                           error.message?.includes('rate_limit') || 
                           error.message?.includes('rate limit') ||
                           (error.error && error.error.type === 'rate_limit_error');
        
        if (isRateLimit && attempt < maxRetries) {
          // Exponential backoff: wait 2^attempt seconds (2s, 4s, 8s)
          const waitTime = Math.pow(2, attempt) * 1000;
          console.warn(`⚠️  Rate limit hit (attempt ${attempt}/${maxRetries}). Waiting ${waitTime/1000}s before retry...`);
          await new Promise(resolve => setTimeout(resolve, waitTime));
          continue;
        }
        
        // If not a rate limit error or we've exhausted retries, throw
        console.error(`❌ Claude consultation failed (attempt ${attempt}/${maxRetries}):`, error.message);
        if (attempt === maxRetries) {
          throw error;
        }
      }
    }
    
    throw lastError;
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
   * Create Guacamole user account for session
   * Each user gets unique credentials tied to their session ID
   */
  async createUser({ sessionId }) {
    console.log(`\n👤 Creating Guacamole user for session: ${sessionId}`);

    try {
      // Generate unique alphabetic username
      let guacUsername;
      let attempts = 0;
      let existingEntityId;
      
      do {
        guacUsername = this.generateAlphabeticUsername(10);
        // SECURITY FIX: Escape username to prevent SQL injection
        const escapedUsername = this.escapeMySQL(guacUsername);
        const checkUserQuery = `SELECT entity_id FROM guacamole_entity WHERE name = '${escapedUsername}' AND type = 'USER'`;
        existingEntityId = await this.execMySQLQuery(checkUserQuery, true);
        attempts++;
      } while (existingEntityId && attempts < 5);
      
      if (existingEntityId) {
        console.log(`✅ User already exists: ${guacUsername}`);
        
        // Get existing password from database (we'll return a new one)
        const existingPassword = crypto.randomBytes(8).toString('hex');
        
        return {
          username: guacUsername,
          password: existingPassword,
          entityId: parseInt(existingEntityId),
          isNew: false
        };
      }

      // Generate random password (16 chars: alphanumeric)
      const randomPassword = crypto.randomBytes(8).toString('hex');
      
      // Generate salt and hash (Guacamole uses hex-encoded SHA-256)
      // FIX: Use saltHex (string) not salt (binary) for hashing
      const salt = crypto.randomBytes(32);
      const saltHex = salt.toString('hex');
      const hash = crypto.createHash('sha256')
        .update(randomPassword, 'utf8')
        .update(saltHex, 'utf8')  // FIX: Use saltHex (hex string), not salt (binary)
        .digest('hex');

      // Step 1: Create entity
      // IMPROVEMENT: Use direct SQL instead of Claude for simple INSERT to reduce API calls
      const escapedUsername = this.escapeMySQL(guacUsername);
      const createEntityQuery = `INSERT INTO guacamole_entity (name, type) VALUES ('${escapedUsername}', 'USER')`;
      console.log(`📝 Creating user entity: ${guacUsername}`);
      await this.execMySQLQuery(createEntityQuery);

      // Step 2: Get entity ID
      // SECURITY FIX: Escape username (reuse escapedUsername from above)
      const getEntityQuery = `SELECT entity_id FROM guacamole_entity WHERE name = '${escapedUsername}' AND type = 'USER'`;
      const entityId = await this.execMySQLQuery(getEntityQuery, true);

      // Step 3: Create user with hashed password using UNHEX()
      // FIX: Ensure disabled = 0 (enabled) for login to work
      const createUserQuery = `INSERT INTO guacamole_user (entity_id, password_hash, password_salt, password_date, disabled) VALUES (${entityId}, UNHEX('${hash}'), UNHEX('${saltHex}'), NOW(), 0)`;
      await this.execMySQLQuery(createUserQuery, true);

      console.log(`✅ User created: ${guacUsername}`);
      console.log(`   Password: ${randomPassword}`);
      console.log(`   Entity ID: ${entityId}`);

      return {
        username: guacUsername,
        password: randomPassword,
        entityId: parseInt(entityId),
        isNew: true
      };

    } catch (error) {
      console.error(`❌ Failed to create user: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get user entity ID by username
   * SECURITY FIX: Escapes username to prevent SQL injection
   */
  async getUserByUsername(guacUsername) {
    // SECURITY FIX: Escape username
    const escapedUsername = this.escapeMySQL(guacUsername);
    const query = `SELECT entity_id FROM guacamole_entity WHERE name = '${escapedUsername}' AND type = 'USER'`;
    
    try {
      const entityId = await this.execMySQLQuery(query, true);
      return entityId ? parseInt(entityId) : null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Create Guacamole SSH connection for challenge
   * IMPROVEMENT: Connection names now include session ID for uniqueness
   * Automatically grants access to session user
   */
  async createConnection({ challengeName, attackerIP, username = 'kali', password = 'kali', guacUsername = null, sessionId = null }) {
    console.log(`\n🔗 Creating Guacamole connection for ${challengeName}`);
    console.log(`   Target: ${username}@${attackerIP}:22`);

    try {
      // IMPROVEMENT: Validate all connection parameters before creating
      this.validateConnectionParameters({
        hostname: attackerIP,
        port: 22,
        username,
        password
      });

      // IMPROVEMENT: Make connection name unique by including session ID
      const connectionNameSuffix = sessionId ? `-${sessionId.substring(0, 8)}` : '';
      const connectionName = `${challengeName}${connectionNameSuffix}-ssh`;
      
      // Step 1: Check if connection already exists
      const escapedConnectionName = this.escapeMySQL(connectionName);
      const checkQuery = `SELECT connection_id FROM guacamole_connection WHERE connection_name = '${escapedConnectionName}'`;
      const existingConn = await this.execMySQLQuery(checkQuery, true);
      
      if (existingConn) {
        console.log(`⚠️  Connection already exists, updating instead...`);
        return await this.updateConnection({
          connectionName,
          hostname: attackerIP,
          port: 22,
          username,
          password
        });
      }

      // Step 2-5: Create connection and parameters in a transaction
      // IMPROVEMENT: Use transaction for atomicity
      const escapedConnectionName2 = this.escapeMySQL(connectionName);
      const escapedHostname = this.escapeMySQL(attackerIP);
      const escapedUsername = this.escapeMySQL(username);
      const escapedPassword = this.escapeMySQL(password);

      const transactionQueries = [
        // Create connection
        `INSERT INTO guacamole_connection (connection_name, protocol, max_connections) VALUES ('${escapedConnectionName2}', 'ssh', 5)`,
        // Get connection ID (will be executed separately after transaction)
      ];

      // Execute transaction to create connection
      await this.execMySQLTransaction([transactionQueries[0]]);

      // Get connection ID
      const getConnectionIdQuery = `SELECT connection_id FROM guacamole_connection WHERE connection_name = '${escapedConnectionName2}'`;
      const connectionId = await this.execMySQLQuery(getConnectionIdQuery, true);

      // Add connection parameters in a transaction
      // IMPROVEMENT: Ensure all SSH parameters are set correctly
      const paramQueries = [
        `DELETE FROM guacamole_connection_parameter WHERE connection_id = ${connectionId}`,
        `INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value) VALUES (${connectionId}, 'hostname', '${escapedHostname}')`,
        `INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value) VALUES (${connectionId}, 'port', '22')`,
        `INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value) VALUES (${connectionId}, 'username', '${escapedUsername}')`,
        `INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value) VALUES (${connectionId}, 'password', '${escapedPassword}')`,
        `INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value) VALUES (${connectionId}, 'enable-sftp', 'true')`,
        `INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value) VALUES (${connectionId}, 'sftp-root-directory', '/')`,
        // IMPROVEMENT: Explicitly set protocol-related parameters to ensure SSH is used
        `INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value) VALUES (${connectionId}, 'server-alive-interval', '60')`,
        `INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value) VALUES (${connectionId}, 'server-alive-count-max', '3')`
      ];

      await this.execMySQLTransaction(paramQueries);

      // IMPROVEMENT: Verify connection was created correctly with SSH protocol
      const verifyQuery = `SELECT protocol FROM guacamole_connection WHERE connection_id = ${connectionId}`;
      const protocol = await this.execMySQLQuery(verifyQuery, true);
      if (protocol !== 'ssh') {
        console.error(`❌ Protocol mismatch: expected 'ssh', got '${protocol}'. Fixing...`);
        const fixProtocolQuery = `UPDATE guacamole_connection SET protocol = 'ssh' WHERE connection_id = ${connectionId}`;
        await this.execMySQLQuery(fixProtocolQuery);
        console.log(`✅ Protocol fixed to 'ssh'`);
      }

      // IMPROVEMENT: Verify all parameters were set correctly
      const paramCheckQuery = `SELECT parameter_name, parameter_value FROM guacamole_connection_parameter WHERE connection_id = ${connectionId} ORDER BY parameter_name`;
      const params = await this.execMySQLQuery(paramCheckQuery);
      console.log(`📋 Connection parameters verified:`);
      const paramLines = params.split('\n').filter(line => line.trim());
      const paramMap = {};
      paramLines.forEach(line => {
        const [name, value] = line.split('\t');
        if (name && value) {
          paramMap[name] = value;
          console.log(`   ${name}: ${value}`);
        }
      });

      // Verify required parameters exist
      const requiredParams = ['hostname', 'port', 'username', 'password'];
      const missingParams = requiredParams.filter(p => !paramMap[p]);
      if (missingParams.length > 0) {
        throw new Error(`Missing required connection parameters: ${missingParams.join(', ')}`);
      }

      console.log(`✅ Connection created: ${connectionName} (ID: ${connectionId})`);
      console.log(`   Protocol: SSH (verified)`);
      console.log(`   Target: ${username}@${attackerIP}:22`);
      
      // IMPROVEMENT: Test SSH connectivity (non-blocking)
      this.testSSHConnection(attackerIP, username, password).catch(err => {
        console.warn(`   ⚠️  SSH connectivity test: ${err.message}`);
        console.warn(`   Connection will be available once SSH service is ready.`);
      });
      
      // IMPROVEMENT: Double-check protocol one more time before returning
      const finalProtocolCheck = await this.execMySQLQuery(verifyQuery, true);
      if (finalProtocolCheck !== 'ssh') {
        console.error(`❌ CRITICAL: Protocol still incorrect after fix: ${finalProtocolCheck}`);
        throw new Error(`Failed to set connection protocol to SSH. Current: ${finalProtocolCheck}`);
      }

      // Step 6: Grant access to session user (if guacUsername provided)
      if (guacUsername) {
        try {
          const entityId = await this.getUserByUsername(guacUsername);
          if (entityId) {
            await this.grantConnectionAccess({
              username: guacUsername,
              connectionName,
              permission: 'READ'
            });
            console.log(`   🔐 Access granted to ${guacUsername}`);
          }
        } catch (error) {
          console.warn(`⚠️  Could not grant access to user: ${error.message}`);
        }
      }

      return {
        connectionId: parseInt(connectionId),
        connectionName,
        hostname: attackerIP,
        port: 22,
        protocol: 'ssh',
        username,
        success: true
      };

    } catch (error) {
      console.error(`❌ Failed to create connection: ${error.message}`);
      throw error;
    }
  }

  /**
   * Update existing connection parameters
   * IMPROVEMENT: Update all parameters, not just hostname
   */
  async updateConnection({ connectionName, hostname, port, username, password }) {
    console.log(`\n🔄 Updating connection: ${connectionName}`);

    try {
      // IMPROVEMENT: Validate all parameters if provided
      if (hostname) {
        this.validateConnectionParameters({
          hostname,
          port: port || 22,
          username: username || 'kali',
          password: password || 'kali'
        });
      }

      // Get connection ID
      const escapedConnectionName = this.escapeMySQL(connectionName);
      const getConnectionIdQuery = `SELECT connection_id FROM guacamole_connection WHERE connection_name = '${escapedConnectionName}'`;
      const connectionId = await this.execMySQLQuery(getConnectionIdQuery, true);

      if (!connectionId) {
        throw new Error(`Connection not found: ${connectionName}`);
      }

      // Update parameters
      const updates = [];
      
      if (hostname) {
        const escapedHostname = this.escapeMySQL(hostname);
        const updateHostnameQuery = `UPDATE guacamole_connection_parameter SET parameter_value = '${escapedHostname}' WHERE connection_id = ${connectionId} AND parameter_name = 'hostname'`;
        await this.execMySQLQuery(updateHostnameQuery);
        updates.push(`hostname: ${hostname}`);
      }

      if (port) {
        const updatePortQuery = `UPDATE guacamole_connection_parameter SET parameter_value = '${port}' WHERE connection_id = ${connectionId} AND parameter_name = 'port'`;
        await this.execMySQLQuery(updatePortQuery);
        updates.push(`port: ${port}`);
      }

      if (username) {
        const escapedUsername = this.escapeMySQL(username);
        const updateUsernameQuery = `UPDATE guacamole_connection_parameter SET parameter_value = '${escapedUsername}' WHERE connection_id = ${connectionId} AND parameter_name = 'username'`;
        await this.execMySQLQuery(updateUsernameQuery);
        updates.push(`username: ${username}`);
      }

      if (password) {
        const escapedPassword = this.escapeMySQL(password);
        const updatePasswordQuery = `UPDATE guacamole_connection_parameter SET parameter_value = '${escapedPassword}' WHERE connection_id = ${connectionId} AND parameter_name = 'password'`;
        await this.execMySQLQuery(updatePasswordQuery);
        updates.push(`password: ***`);
      }

      console.log(`✅ Connection updated: ${connectionName}`);
      console.log(`   Updated: ${updates.join(', ')}`);

      return {
        connectionId: parseInt(connectionId),
        connectionName,
        hostname: hostname || 'unchanged',
        port: port || 'unchanged',
        username: username || 'unchanged',
        success: true
      };

    } catch (error) {
      console.error(`❌ Failed to update connection: ${error.message}`);
      throw error;
    }
  }

  /**
   * Grant connection access to user
   */
  async grantConnectionAccess({ username, connectionName, permission = 'READ' }) {
    console.log(`\n🔐 Granting ${permission} access to ${username}`);

    try {
      // Get entity ID for user
      const entityResult = await this.consultClaude('Get user entity ID', {
        username
      });
      
      const entityId = await this.execMySQLQuery(entityResult.sql, true);

      if (!entityId) {
        throw new Error(`User not found: ${username}`);
      }

      // Get connection ID
      const connResult = await this.consultClaude('Get connection ID', {
        connectionName
      });
      
      const connectionId = await this.execMySQLQuery(connResult.sql, true);

      if (!connectionId) {
        throw new Error(`Connection not found: ${connectionName}`);
      }

      // Grant permission
      const grantResult = await this.consultClaude('Grant connection permission', {
        entityId,
        connectionId,
        permission
      });

      console.log(`📝 ${grantResult.explanation}`);
      await this.execMySQLQuery(grantResult.sql);

      console.log(`✅ Access granted: ${username} → ${connectionName}`);

      return {
        username,
        connectionName,
        permission,
        success: true
      };

    } catch (error) {
      // Ignore duplicate entry errors
      if (error.message.includes('Duplicate entry')) {
        console.log(`   ℹ️  Permission already exists`);
        return { success: true, alreadyExists: true };
      }
      
      console.error(`❌ Failed to grant access: ${error.message}`);
      throw error;
    }
  }

  /**
   * Test connection to Guacamole database
   */
  async testConnection() {
    try {
      console.log('🔍 Testing Guacamole database connection...');
      const result = await this.execMySQLQuery('SELECT 1', true);
      console.log('✅ Guacamole database connection successful');
      return true;
    } catch (error) {
      console.error('❌ Guacamole database connection failed:', error.message);
      console.error(`   Make sure container '${this.guacContainer}' is running`);
      return false;
    }
  }

  /**
   * List all connections for debugging
   */
  async listConnections() {
    try {
      const sql = `SELECT c.connection_id, c.connection_name, c.protocol, 
                   GROUP_CONCAT(CONCAT(p.parameter_name, '=', p.parameter_value) SEPARATOR ', ') as parameters
                   FROM guacamole_connection c
                   LEFT JOIN guacamole_connection_parameter p ON c.connection_id = p.connection_id
                   GROUP BY c.connection_id
                   ORDER BY c.connection_id DESC
                   LIMIT 10`;
      
      const result = await this.execMySQLQuery(sql);
      console.log('\n📋 Recent connections:');
      console.log(result || '  (none)');
      
      return result;
    } catch (error) {
      console.error('❌ Failed to list connections:', error.message);
      throw error;
    }
  }

  /**
   * Delete connection by name
   * IMPROVEMENT: Direct SQL instead of Claude for better performance
   */
  async deleteConnection(connectionName) {
    console.log(`\n🗑️  Deleting connection: ${connectionName}`);

    try {
      // Get connection ID
      const escapedConnectionName = this.escapeMySQL(connectionName);
      const getConnectionIdQuery = `SELECT connection_id FROM guacamole_connection WHERE connection_name = '${escapedConnectionName}'`;
      const connectionId = await this.execMySQLQuery(getConnectionIdQuery, true);

      if (!connectionId) {
        console.log(`⚠️  Connection not found: ${connectionName}`);
        return { connectionName, success: false, notFound: true };
      }

      // Delete connection permissions (cascades)
      const deletePermsQuery = `DELETE FROM guacamole_connection_permission WHERE connection_id = ${connectionId}`;
      await this.execMySQLQuery(deletePermsQuery, true);

      // Delete connection parameters
      const deleteParamsQuery = `DELETE FROM guacamole_connection_parameter WHERE connection_id = ${connectionId}`;
      await this.execMySQLQuery(deleteParamsQuery, true);

      // Delete connection
      const deleteConnQuery = `DELETE FROM guacamole_connection WHERE connection_id = ${connectionId}`;
      await this.execMySQLQuery(deleteConnQuery, true);

      console.log(`✅ Connection deleted: ${connectionName}`);

      return { connectionName, success: true };

    } catch (error) {
      console.error(`❌ Failed to delete connection: ${error.message}`);
      throw error;
    }
  }

  /**
   * Clean up old connections for a challenge and session
   * IMPROVEMENT: Prevents orphaned connections on redeploy
   */
  async cleanupOldConnections(challengeName, sessionId) {
    try {
      console.log(`🧹 Cleaning up old connections for ${challengeName} (session: ${sessionId?.substring(0, 8) || 'N/A'})...`);

      // Find all connections matching this challenge (with or without session suffix)
      const escapedChallengeName = this.escapeMySQL(challengeName);
      const findConnectionsQuery = `SELECT connection_id, connection_name FROM guacamole_connection WHERE connection_name LIKE '${escapedChallengeName}%-ssh'`;
      const connectionsResult = await this.execMySQLQuery(findConnectionsQuery, false);

      if (!connectionsResult || connectionsResult.trim() === '') {
        console.log(`   No old connections found`);
        return { cleaned: 0 };
      }

      // Parse connection IDs and names
      const lines = connectionsResult.trim().split('\n').filter(line => line.trim());
      let cleanedCount = 0;

      for (const line of lines) {
        const parts = line.split('\t');
        if (parts.length >= 2) {
          const connectionId = parts[0];
          const connectionName = parts[1];

          // Delete this connection
          try {
            await this.deleteConnection(connectionName);
            cleanedCount++;
          } catch (error) {
            console.warn(`⚠️  Failed to delete connection ${connectionName}: ${error.message}`);
          }
        }
      }

      console.log(`✅ Cleaned up ${cleanedCount} old connection(s)`);
      return { cleaned: cleanedCount };

    } catch (error) {
      console.warn(`⚠️  Failed to cleanup old connections: ${error.message}`);
      // Don't throw - cleanup is best-effort
      return { cleaned: 0, error: error.message };
    }
  }

  /**
   * Validate connection parameters before creation
   * IMPROVEMENT: Prevents invalid connections
   */
  validateConnectionParameters({ hostname, port, username, password }) {
    const errors = [];

    // Validate IP address
    if (!hostname || !hostname.match(/^\d+\.\d+\.\d+\.\d+$/)) {
      errors.push(`Invalid IP address: ${hostname}`);
    } else {
      // Validate IP range (private IPs for CTF)
      const parts = hostname.split('.').map(Number);
      if (parts[0] !== 172 || parts[1] < 20 || parts[1] > 30) {
        errors.push(`IP address ${hostname} is not in allowed range (172.20-30.x.x)`);
      }
    }

    // Validate port
    if (port && (isNaN(port) || port < 1 || port > 65535)) {
      errors.push(`Invalid port: ${port}`);
    }

    // Validate username
    if (!username || username.trim().length === 0) {
      errors.push('Username is required');
    }

    // Validate password (optional but warn if missing)
    if (!password) {
      console.warn('⚠️  No password provided for connection');
    }

    if (errors.length > 0) {
      throw new Error(`Connection validation failed: ${errors.join(', ')}`);
    }

    return true;
  }

  /**
   * Test SSH connectivity to verify connection works
   * IMPROVEMENT: Non-blocking test to verify SSH is accessible
   */
  async testSSHConnection(hostname, username, password) {
    try {
      // Simple port check using timeout
      const { exec } = await import('child_process');
      const { promisify } = await import('util');
      const execAsync = promisify(exec);
      
      // Test if port 22 is open (non-blocking, timeout after 3 seconds)
      const testCommand = `timeout 3 bash -c "echo > /dev/tcp/${hostname}/22" 2>&1 || echo 'port_closed'`;
      
      try {
        const { stdout } = await execAsync(testCommand);
        if (!stdout.includes('port_closed') && !stdout.includes('timeout')) {
          console.log(`   ✅ SSH port 22 is accessible on ${hostname}`);
          return true;
        }
      } catch (err) {
        // Port might not be ready yet, this is OK
        console.log(`   ⚠️  SSH port test inconclusive (container may still be starting)`);
        return false;
      }
      
      return false;
    } catch (error) {
      // Don't throw - this is just a connectivity check
      console.log(`   ⚠️  SSH connectivity test skipped: ${error.message}`);
      return false;
    }
  }

  /**
   * Clean up orphaned connections (connections for non-existent challenges)
   * IMPROVEMENT: Periodic cleanup to prevent database bloat
   * @param {Array<string>} validChallengeNames - List of valid challenge names
   * @returns {Promise<{cleaned: number, orphaned: Array}>}
   */
  async cleanupOrphanedConnections(validChallengeNames = []) {
    try {
      console.log(`🧹 Cleaning up orphaned Guacamole connections...`);

      // Get all connections
      const allConnectionsQuery = `SELECT connection_id, connection_name FROM guacamole_connection WHERE connection_name LIKE '%-ssh'`;
      const connectionsResult = await this.execMySQLQuery(allConnectionsQuery, false);

      if (!connectionsResult || connectionsResult.trim() === '') {
        console.log(`   No connections found`);
        return { cleaned: 0, orphaned: [] };
      }

      const lines = connectionsResult.trim().split('\n').filter(line => line.trim());
      const orphaned = [];
      let cleanedCount = 0;

      for (const line of lines) {
        const parts = line.split('\t');
        if (parts.length >= 2) {
          const connectionName = parts[1];
          
          // Extract challenge name from connection name (format: challengeName-sessionId-ssh)
          const match = connectionName.match(/^(.+?)(?:-\w{8})?-ssh$/);
          if (match) {
            const challengeName = match[1];
            
            // Check if challenge is valid
            if (validChallengeNames.length > 0 && !validChallengeNames.includes(challengeName)) {
              orphaned.push(connectionName);
              try {
                await this.deleteConnection(connectionName);
                cleanedCount++;
              } catch (error) {
                console.warn(`⚠️  Failed to delete orphaned connection ${connectionName}: ${error.message}`);
              }
            }
          }
        }
      }

      console.log(`✅ Cleaned up ${cleanedCount} orphaned connection(s)`);
      return { cleaned: cleanedCount, orphaned };

    } catch (error) {
      console.warn(`⚠️  Failed to cleanup orphaned connections: ${error.message}`);
      return { cleaned: 0, orphaned: [], error: error.message };
    }
  }
}

// Export singleton instance
export const guacamoleAgent = new GuacamoleAgent();

// Export for direct usage
export default GuacamoleAgent;
