/**
 * NEW CTF Automation Service - Main Entry Point
 * 
 * This is the new, rebuilt version of the CTF automation service.
 * It uses the new orchestrator-based architecture for perfect challenge creation and deployment.
 */

import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import crypto from 'crypto';
import { orchestrator } from './core/orchestrator.js';
import { dbManager } from './db-manager.js';
import { Logger } from './core/logger.js';
import { guacamoleAgent } from './agents/guacamole-agent.js';
import { sessionGuacManager } from './session-guacamole-manager.js';
import { initializeToolLearning, getCacheStats } from './tool-learning-service.js';
import { checkpointManager } from './checkpoint-manager.js';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load .env from packages/ctf-automation/.env (relative to packages/ctf-automation/src)
dotenv.config({ 
  path: path.resolve(__dirname, '../.env') 
});

const app = express();
const PORT = process.env.CTF_API_PORT || process.env.PORT || 4003;
const logger = new Logger();

app.use(cors());
app.use(express.json());

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', message: 'CTF Automation Service (NEW) is running' });
});

// Cache statistics endpoint
app.get('/api/cache/stats', (req, res) => {
  try {
    const stats = getCacheStats();
    res.json({ success: true, stats });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Tool test statistics endpoints
app.get('/api/tools/:toolName/stats', async (req, res) => {
  try {
    const { toolName } = req.params;
    const { getToolTestStats } = await import('./tool-learning-service.js');
    const stats = await getToolTestStats(toolName);
    res.json({ success: true, stats });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/tools/stats/overall', async (req, res) => {
  try {
    const { getOverallTestStats } = await import('./tool-learning-service.js');
    const stats = await getOverallTestStats();
    res.json({ success: true, stats });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/tools/stats/problematic', async (req, res) => {
  try {
    const { getProblematicTools } = await import('./tool-learning-service.js');
    const minTests = parseInt(req.query.minTests) || 3;
    const maxSuccessRate = parseInt(req.query.maxSuccessRate) || 50;
    const tools = await getProblematicTools(minTests, maxSuccessRate);
    res.json({ success: true, tools });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Main chat endpoint
app.post('/api/chat', async (req, res) => {
  try {
    const { message, sessionId } = req.body;

    // Validate input
    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }

    if (!sessionId) {
      return res.status(400).json({ 
        error: 'Session ID is required',
        sessionRequired: true
      });
    }

    logger.info('API', `Received request: ${message.substring(0, 50)}...`);

    // Validate session
    const sessionData = await dbManager.validateSession(sessionId);
    if (!sessionData) {
      return res.status(401).json({ 
        error: 'Session expired or invalid',
        sessionExpired: true
      });
    }

    // Extend session expiration
    try {
      await dbManager.extendSessionExpiration(sessionId);
    } catch (error) {
      logger.warn('API', `Failed to extend session: ${error.message}`);
    }

    // Track activity
    try {
      await dbManager.trackSessionActivity(sessionId, 'message', {
        action: 'chat_message',
        messageLength: message.length
      });
    } catch (trackError) {
      // Silent fail - activity tracking is non-critical
    }

    // Get conversation history
    const conversationHistory = await dbManager.getConversationHistory(sessionId);

    // Save user message
    await dbManager.saveMessage(sessionId, 'user', message);

    // Process request through orchestrator
    const result = await orchestrator.processRequest({
      message,
      sessionId,
      conversationHistory
    });

    // Save assistant response with metadata
    const responseText = result.answer || result.message || JSON.stringify(result);
    const messageMetadata = {
      category: result.category || 'unknown',
      success: result.success !== false
    };
    
    // Include deployment info if available
    if (result.deployment) {
      messageMetadata.deployment = {
        challengeName: result.challengeName || result.challenge?.name,
        attackerIP: result.deployment.attackerIP,
        victimIP: result.deployment.victimIP,
        attackerContainerName: result.deployment.attackerContainerName || result.deployment.attackerContainer,
        victimContainerName: result.deployment.victimContainerName || result.deployment.victimContainer,
        subnet: result.deployment.subnet,
        services: result.deployment.services
      };
    }
    
    await dbManager.saveMessage(sessionId, 'assistant', responseText, messageMetadata);

    // Return result
    res.json(result);

  } catch (error) {
    logger.error('API', 'Request processing failed', error.stack);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: 'An error occurred while processing your request'
    });
  }
});

// ===== GUACAMOLE USER MANAGEMENT ENDPOINTS =====

app.post('/api/guacamole/create-user', async (req, res) => {
  try {
    const { username, password, email, fullName } = req.body;

    if (!username || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Username and password are required' 
      });
    }

    // Use GuacamolePostgreSQLManager for creating users
    const { GuacamolePostgreSQLManager } = await import('./guacamole-postgresql-manager.js');
    const guacManager = new GuacamolePostgreSQLManager();

    // Generate random alphabetic username
    const letters = 'abcdefghijklmnopqrstuvwxyz';
    let guacUsername = 'ctf';
    for (let i = 0; i < 10; i++) {
      guacUsername += letters.charAt(Math.floor(Math.random() * letters.length));
    }

    // Hash password using Guacamole's format
    const salt = crypto.randomBytes(32);
    const saltHex = salt.toString('hex');
    const hash = crypto.createHash('sha256')
      .update(password)
      .update(saltHex)
      .digest('hex');

    // Create entity
    const createEntitySql = `INSERT INTO guacamole_entity (name, type) VALUES ('${guacUsername}', 'USER')`;
    await guacManager.execMySQLQuery(createEntitySql);

    // Get entity ID
    const getEntityIdSql = `SELECT entity_id FROM guacamole_entity WHERE name = '${guacUsername}' AND type = 'USER'`;
    const entityRows = await guacManager.queryMySQL(getEntityIdSql);
    const entityId = entityRows[0][0];

    // Create user with hashed password
    const createUserSql = `INSERT INTO guacamole_user (entity_id, password_hash, password_salt, password_date, email_address, full_name) 
      VALUES (${entityId}, UNHEX('${hash}'), UNHEX('${saltHex}'), NOW(), '${email || guacUsername + '@ctf.local'}', '${fullName || guacUsername}')`;
    await guacManager.execMySQLQuery(createUserSql);

    // Get user ID
    const getUserIdSql = `SELECT user_id FROM guacamole_user WHERE entity_id = ${entityId}`;
    const userRows = await guacManager.queryMySQL(getUserIdSql);
    const userId = userRows[0][0];

    await guacManager.close();

    logger.info('Guacamole', `Created user: ${guacUsername} (entity_id: ${entityId}, user_id: ${userId})`);

    res.json({
      success: true,
      message: 'User created successfully',
      user: {
        username: guacUsername,
        userId: parseInt(userId),
        entityId: parseInt(entityId)
      },
      loginInfo: {
        url: 'http://localhost:8080/guacamole',
        username: guacUsername,
        password: password
      }
    });

  } catch (error) {
    logger.error('Guacamole', 'Error creating user', error.stack);
    res.status(500).json({
      success: false,
      error: error.message || 'Failed to create user'
    });
  }
});

app.post('/api/guacamole/add-connection', async (req, res) => {
  try {
    const { 
      username, 
      connectionName, 
      protocol, 
      hostname, 
      port, 
      connectionUsername, 
      connectionPassword,
      parameters 
    } = req.body;

    if (!username || !connectionName || !protocol || !hostname) {
      return res.status(400).json({ 
        success: false, 
        error: 'Username, connectionName, protocol, and hostname are required' 
      });
    }

    const { GuacamolePostgreSQLManager } = await import('./guacamole-postgresql-manager.js');
    const guacManager = new GuacamolePostgreSQLManager();

    // Get entity ID for username
    const getEntitySql = `SELECT entity_id FROM guacamole_entity WHERE name = '${username}' AND type = 'USER'`;
    const entityRows = await guacManager.queryMySQL(getEntitySql);
    
    if (entityRows.length === 0) {
      await guacManager.close();
      return res.status(404).json({
        success: false,
        error: `User '${username}' not found`
      });
    }

    const entityId = entityRows[0][0];

    // Create connection
    const createConnSql = `INSERT INTO guacamole_connection (connection_name, protocol, max_connections) 
      VALUES ('${connectionName}', '${protocol}', 5)`;
    await guacManager.execMySQLQuery(createConnSql);

    // Get connection ID
    const getConnIdSql = `SELECT connection_id FROM guacamole_connection ORDER BY connection_id DESC LIMIT 1`;
    const connRows = await guacManager.queryMySQL(getConnIdSql);
    const connectionId = connRows[0][0];

    // Add connection parameters
    const params = [
      ['hostname', hostname],
      ['port', port || (protocol === 'ssh' ? '22' : '3389')],
      ['username', connectionUsername || 'root'],
      ['password', connectionPassword || 'kali']
    ];

    // Add additional parameters if provided
    if (parameters) {
      for (const [key, value] of Object.entries(parameters)) {
        params.push([key, value]);
      }
    }

    const paramValues = params.map(([name, value]) => 
      `(${connectionId}, '${name}', '${value}')`
    ).join(', ');

    const createParamsSql = `INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value) VALUES ${paramValues}`;
    await guacManager.execMySQLQuery(createParamsSql);

    // Grant READ permission to user
    const grantUserPermSql = `INSERT INTO guacamole_connection_permission (entity_id, connection_id, permission) 
      VALUES (${entityId}, ${connectionId}, 'READ')`;
    await guacManager.execMySQLQuery(grantUserPermSql);

    // Also grant to guacadmin for admin access
    const grantAdminPermSql = `INSERT INTO guacamole_connection_permission (entity_id, connection_id, permission) 
      VALUES (1, ${connectionId}, 'READ')`;
    await guacManager.execMySQLQuery(grantAdminPermSql);

    await guacManager.close();

    logger.info('Guacamole', `Created connection: ${connectionName} (ID: ${connectionId}) for user ${username}`);

    res.json({
      success: true,
      message: 'Connection created successfully',
      connection: {
        connectionId: parseInt(connectionId),
        connectionName,
        protocol,
        hostname,
        port: port || (protocol === 'ssh' ? '22' : '3389')
      },
      access: {
        url: 'http://localhost:8080/guacamole',
        username,
        note: 'Login and select the connection from the dashboard'
      }
    });

  } catch (error) {
    logger.error('Guacamole', 'Error adding connection', error.stack);
    res.status(500).json({
      success: false,
      error: error.message || 'Failed to add connection'
    });
  }
});

// ===== SESSION MANAGEMENT API =====

// Delete session and cleanup Guacamole user
app.delete('/api/sessions/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    
    logger.info('Session', `Cleaning up session: ${sessionId}`);
    
    // Delete Guacamole user for this session
    await sessionGuacManager.deleteSessionUser(sessionId);
    
    res.json({
      success: true,
      message: 'Session cleaned up successfully',
      sessionId
    });
  } catch (error) {
    logger.error('Session', 'Error cleaning up session', error.stack);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Delete challenge Guacamole connection
app.delete('/api/challenges/:challengeName/guacamole', async (req, res) => {
  try {
    const { challengeName } = req.params;
    const { sessionId } = req.body;
    
    if (!sessionId) {
      return res.status(400).json({
        success: false,
        error: 'Session ID is required in request body'
      });
    }
    
    logger.info('Guacamole', `Cleaning up connection for challenge: ${challengeName}`);
    
    // Get connection name (with session ID suffix)
    const sessionPrefix = sessionId.substring(0, 8);
    const connectionName = `${challengeName}-${sessionPrefix}-ssh`;
    
    // Delete connection
    await guacamoleAgent.deleteConnection(connectionName);
    
    res.json({
      success: true,
      message: 'Connection deleted successfully',
      challengeName,
      connectionName
    });
  } catch (error) {
    logger.error('Guacamole', 'Error deleting connection', error.stack);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Get session user info
app.get('/api/sessions/:sessionId/guacamole', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const userInfo = sessionGuacManager.getSessionUser(sessionId);
    
    if (!userInfo) {
      return res.status(404).json({
        success: false,
        error: 'No Guacamole user for this session'
      });
    }
    
    res.json({
      success: true,
      user: {
        username: userInfo.username,
        entityId: userInfo.entityId,
        hasAccount: true
      }
    });
  } catch (error) {
    logger.error('Session', 'Error getting session user', error.stack);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Security audit endpoint
app.post('/api/guacamole/audit', async (req, res) => {
  try {
    await sessionGuacManager.auditSessionUsers();
    
    res.json({
      success: true,
      message: 'Security audit completed'
    });
  } catch (error) {
    logger.error('Guacamole', 'Error during audit', error.stack);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ===== PERIODIC CLEANUP =====

// Periodic cleanup of orphaned Guacamole connections
const CLEANUP_INTERVAL = 6 * 60 * 60 * 1000; // 6 hours

async function periodicGuacamoleCleanup() {
  try {
    logger.info('Cleanup', 'Starting periodic Guacamole cleanup...');
    
    // Get list of valid challenges from GitHub
    const { gitManager } = await import('./git-manager.js');
    const challenges = await gitManager.listChallenges();
    
    // Clean up orphaned connections
    const result = await guacamoleAgent.cleanupOrphanedConnections(challenges);
    
    logger.success('Cleanup', `Periodic cleanup complete: ${result.cleaned} orphaned connection(s) removed`);
  } catch (error) {
    logger.error('Cleanup', `Periodic cleanup failed: ${error.message}`);
  }
}

// Start periodic cleanup
setInterval(periodicGuacamoleCleanup, CLEANUP_INTERVAL);
logger.info('Server', 'Periodic Guacamole cleanup scheduled (runs every 6 hours)');

// Run initial cleanup after 1 minute (to allow service to start)
setTimeout(periodicGuacamoleCleanup, 60000);

// ===== GLOBAL ERROR HANDLERS =====

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Process', 'Unhandled Rejection', { reason, promise });
});

process.on('uncaughtException', (error) => {
  logger.error('Process', 'Uncaught Exception', error.stack);
  process.exit(1);
});

// ===== SERVER STARTUP =====

const server = app.listen(PORT, '0.0.0.0', async () => {
  logger.info('Server', `CTF Automation Service (NEW) started successfully`);
  logger.info('Server', `Server running on port ${PORT}`);
  logger.info('Server', `API endpoint: http://localhost:${PORT}/api/chat`);
  logger.info('Server', `Health check: http://localhost:${PORT}/health`);
  logger.info('Server', `Cache stats: http://localhost:${PORT}/api/cache/stats`);
  
  // Cleanup old checkpoints on startup
  checkpointManager.cleanupOld(7).catch(err => {
    logger.warn('Checkpoint', `Failed to cleanup old checkpoints: ${err.message}`);
  });
  
  // Initialize tool learning system
  try {
    await initializeToolLearning();
  } catch (error) {
    logger.warn('ToolLearning', `Initialization failed: ${error.message}`);
    logger.warn('ToolLearning', 'Will use fallback mode without cached base image');
  }
});

server.on('error', (error) => {
  logger.error('Server', `Server error: ${error.message}`);
  if (error.code === 'EADDRINUSE') {
    logger.error('Server', `Port ${PORT} is already in use. Please kill the process or use a different port.`);
  }
  process.exit(1);
});

