/**
 * Guacamole Service - Manages Guacamole connections
 * 
 * Responsibilities:
 * - Create Guacamole users
 * - Create connections
 * - Grant access
 * - Generate access URLs
 */

import { sessionGuacManager } from '../session-guacamole-manager.js';
import { guacamoleAgent } from '../agents/guacamole-agent.js';
import { Logger } from '../core/logger.js';

export class GuacamoleService {
  constructor() {
    this.logger = new Logger();
  }

  /**
   * Setup Guacamole connection for a challenge
   */
  async setupConnection(challengeName, attackerContainer, sessionId) {
    try {
      this.logger.info('GuacamoleService', 'Setting up Guacamole connection', { 
        challengeName, 
        attackerIP: attackerContainer?.ip 
      });

      if (!attackerContainer || !attackerContainer.ip) {
        return {
          success: false,
          error: 'Attacker container IP not available'
        };
      }

      // Step 1: Get or create session user
      const userAccount = await sessionGuacManager.getOrCreateSessionUser(sessionId);

      // Step 2: Create connection
      const connectionResult = await guacamoleAgent.createConnection({
        challengeName,
        attackerIP: attackerContainer.ip,
        username: 'kali',
        password: 'kali',
        guacUsername: null,
        sessionId
      });

      // Step 3: Grant access
      await sessionGuacManager.grantConnectionAccess(sessionId, connectionResult.connectionId);

      // Step 4: Generate access URL
      const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:4000';
      const guacamoleUrl = process.env.GUACAMOLE_URL || 'http://localhost:8081';
      const url = `${guacamoleUrl}/guacamole/#/client/${connectionResult.connectionId}?username=${userAccount.username}`;

      // Get user data (contains password)
      const userData = await sessionGuacManager.getOrCreateSessionUser(sessionId);

      this.logger.success('GuacamoleService', 'Guacamole connection setup complete');

      return {
        success: true,
        url,
        username: userAccount.username,
        password: userData.password,
        connectionId: connectionResult.connectionId
      };

    } catch (error) {
      this.logger.error('GuacamoleService', 'Setup failed', error.stack);
      return {
        success: false,
        error: error.message,
        details: error.stack
      };
    }
  }
}

export const guacamoleService = new GuacamoleService();

