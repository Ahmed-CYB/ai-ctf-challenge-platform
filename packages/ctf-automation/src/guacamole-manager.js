import axios from 'axios';
import crypto from 'crypto';

/**
 * Guacamole Connection Manager
 * Automatically creates and manages Guacamole connections for user CTF instances
 */
class GuacamoleManager {
  constructor() {
    this.guacamoleUrl = process.env.GUACAMOLE_URL || 'http://guacamole:8080/guacamole';
    this.adminUsername = process.env.GUACAMOLE_ADMIN_USER || 'guacadmin';
    this.adminPassword = process.env.GUACAMOLE_ADMIN_PASS || 'guacadmin';
    
    this.authToken = null;
    this.dataSource = 'mysql';
    this.connections = new Map(); // instanceId -> connectionId
  }

  /**
   * Authenticate with Guacamole API
   */
  async authenticate() {
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
      console.log('✅ Authenticated with Guacamole');
      return this.authToken;

    } catch (error) {
      console.error('❌ Guacamole authentication failed:', error.message);
      throw error;
    }
  }

  /**
   * Ensure we have a valid auth token
   */
  async ensureAuthenticated() {
    if (!this.authToken) {
      await this.authenticate();
    }
    return this.authToken;
  }

  /**
   * Create a Guacamole connection for a CTF instance
   */
  async createConnection(instanceId, userId, challengeName, kaliIP, vncPassword = 'password') {
    try {
      await this.ensureAuthenticated();

      const connectionName = `${userId}-${challengeName}`;
      const connectionParams = {
        parentIdentifier: 'ROOT',
        name: connectionName,
        protocol: 'vnc',
        parameters: {
          hostname: kaliIP,
          port: '5901',
          password: vncPassword,
          'enable-sftp': 'true',
          'sftp-port': '22',
          'sftp-username': 'kali',
          'sftp-password': 'kali',
          'color-depth': '24',
          'swap-red-blue': 'false',
          'cursor': 'remote',
          'read-only': 'false',
          'enable-audio': 'false',
          'enable-clipboard': 'true',
          'clipboard-encoding': 'UTF-8'
        },
        attributes: {
          'max-connections': '1',
          'max-connections-per-user': '1',
          'guacd-hostname': 'guacd',
          'guacd-port': '4822',
          'failover-only': 'false'
        }
      };

      const response = await axios.post(
        `${this.guacamoleUrl}/api/session/data/${this.dataSource}/connections`,
        connectionParams,
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

      const connectionId = response.data.identifier;
      this.connections.set(instanceId, connectionId);

      console.log(`✅ Created Guacamole connection: ${connectionName} (ID: ${connectionId})`);
      console.log(`   Kali IP: ${kaliIP}:5901`);

      // Generate direct access URL with embedded token (bypasses login page)
      const directAccessUrl = `http://localhost/guacamole/#/client/${connectionId}?token=${this.authToken}`;

      return {
        connectionId,
        connectionName,
        guacamoleUrl: `${this.guacamoleUrl}/#/client/${connectionId}`,
        directUrl: directAccessUrl, // Use this to bypass login - shows Kali directly
        requiresLogin: false // Frontend can check this flag
      };

    } catch (error) {
      console.error('❌ Failed to create Guacamole connection:', error.response?.data || error.message);
      
      // Try to re-authenticate and retry once
      if (error.response?.status === 401 || error.response?.status === 403) {
        console.log('🔄 Re-authenticating and retrying...');
        this.authToken = null;
        await this.authenticate();
        return await this.createConnection(instanceId, userId, challengeName, kaliIP, vncPassword);
      }
      
      throw error;
    }
  }

  /**
   * Delete a Guacamole connection
   */
  async deleteConnection(instanceId) {
    try {
      const connectionId = this.connections.get(instanceId);
      if (!connectionId) {
        console.log(`⚠️  No Guacamole connection found for instance: ${instanceId}`);
        return;
      }

      await this.ensureAuthenticated();

      await axios.delete(
        `${this.guacamoleUrl}/api/session/data/${this.dataSource}/connections/${connectionId}`,
        {
          headers: {
            'Guacamole-Token': this.authToken
          },
          params: {
            token: this.authToken
          }
        }
      );

      this.connections.delete(instanceId);
      console.log(`✅ Deleted Guacamole connection: ${connectionId}`);

    } catch (error) {
      console.error('❌ Failed to delete Guacamole connection:', error.response?.data || error.message);
    }
  }

  /**
   * Get connection details
   */
  async getConnection(connectionId) {
    try {
      await this.ensureAuthenticated();

      const response = await axios.get(
        `${this.guacamoleUrl}/api/session/data/${this.dataSource}/connections/${connectionId}`,
        {
          headers: {
            'Guacamole-Token': this.authToken
          },
          params: {
            token: this.authToken
          }
        }
      );

      return response.data;

    } catch (error) {
      console.error('❌ Failed to get Guacamole connection:', error.message);
      return null;
    }
  }

  /**
   * List all connections
   */
  async listConnections() {
    try {
      await this.ensureAuthenticated();

      const response = await axios.get(
        `${this.guacamoleUrl}/api/session/data/${this.dataSource}/connections`,
        {
          headers: {
            'Guacamole-Token': this.authToken
          },
          params: {
            token: this.authToken
          }
        }
      );

      return Object.values(response.data);

    } catch (error) {
      console.error('❌ Failed to list Guacamole connections:', error.message);
      return [];
    }
  }

  /**
   * Create a user in Guacamole
   */
  async createUser(username, password) {
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

      console.log(`✅ Created Guacamole user: ${username}`);
      return response.data;

    } catch (error) {
      if (error.response?.status === 400 && error.response?.data?.message?.includes('already exists')) {
        console.log(`ℹ️  User already exists: ${username}`);
        return { username };
      }
      console.error('❌ Failed to create Guacamole user:', error.response?.data || error.message);
      throw error;
    }
  }

  /**
   * Grant user permission to a connection
   */
  async grantUserAccess(username, connectionId) {
    try {
      await this.ensureAuthenticated();

      const permissions = [{
        op: 'add',
        path: `/connectionPermissions/${connectionId}`,
        value: 'READ'
      }];

      await axios.patch(
        `${this.guacamoleUrl}/api/session/data/${this.dataSource}/users/${username}/permissions`,
        permissions,
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

      console.log(`✅ Granted ${username} access to connection ${connectionId}`);

    } catch (error) {
      console.error('❌ Failed to grant user access:', error.response?.data || error.message);
    }
  }

  /**
   * Get active sessions
   */
  async getActiveSessions() {
    try {
      await this.ensureAuthenticated();

      const response = await axios.get(
        `${this.guacamoleUrl}/api/session/data/${this.dataSource}/activeConnections`,
        {
          headers: {
            'Guacamole-Token': this.authToken
          },
          params: {
            token: this.authToken
          }
        }
      );

      return Object.values(response.data);

    } catch (error) {
      console.error('❌ Failed to get active sessions:', error.message);
      return [];
    }
  }

  /**
   * Get connection ID for instance
   */
  getConnectionId(instanceId) {
    return this.connections.get(instanceId);
  }

  /**
   * Health check
   */
  async healthCheck() {
    try {
      const response = await axios.get(`${this.guacamoleUrl}/`, {
        timeout: 5000
      });
      return response.status === 200;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get statistics
   */
  getStats() {
    return {
      totalConnections: this.connections.size,
      guacamoleUrl: this.guacamoleUrl,
      authenticated: !!this.authToken
    };
  }
}

// Export singleton
export default new GuacamoleManager();
