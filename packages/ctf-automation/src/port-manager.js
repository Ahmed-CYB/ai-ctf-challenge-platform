import { execSync } from 'child_process';
import net from 'net';

/**
 * Port Manager - Check and allocate available ports
 */

export class PortManager {
  constructor() {
    this.allocatedPorts = new Set();
  }

  /**
   * Check if a port is in use on the host
   * @param {number} port - Port number to check
   * @returns {Promise<boolean>} - True if port is in use
   */
  async isPortInUse(port) {
    return new Promise((resolve) => {
      const server = net.createServer();
      
      server.once('error', (err) => {
        if (err.code === 'EADDRINUSE') {
          resolve(true);
        } else {
          resolve(false);
        }
      });
      
      server.once('listening', () => {
        server.close();
        resolve(false);
      });
      
      server.listen(port, '0.0.0.0');
    });
  }

  /**
   * Get list of ports currently used by Docker containers
   * @returns {Set<number>} - Set of port numbers in use
   */
  getDockerPorts() {
    try {
      const output = execSync('docker ps --format "{{.Ports}}"', { encoding: 'utf8' });
      const ports = new Set();
      
      const lines = output.trim().split('\n').filter(l => l);
      for (const line of lines) {
        // Parse formats like: "0.0.0.0:8080->80/tcp"
        const matches = line.matchAll(/0\.0\.0\.0:(\d+)->/g);
        for (const match of matches) {
          ports.add(parseInt(match[1]));
        }
      }
      
      return ports;
    } catch (error) {
      console.warn('Could not get Docker ports:', error.message);
      return new Set();
    }
  }

  /**
   * Find an available port in a range
   * @param {number} startPort - Starting port number
   * @param {number} endPort - Ending port number
   * @param {number} maxAttempts - Maximum attempts
   * @returns {Promise<number|null>} - Available port or null
   */
  async findAvailablePort(startPort = 8080, endPort = 65535, maxAttempts = 100) {
    const dockerPorts = this.getDockerPorts();
    
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      // Generate random port in range
      const port = Math.floor(Math.random() * (endPort - startPort + 1)) + startPort;
      
      // Skip if already allocated in this session
      if (this.allocatedPorts.has(port)) {
        continue;
      }
      
      // Skip if used by Docker
      if (dockerPorts.has(port)) {
        continue;
      }
      
      // Check if port is actually available
      const inUse = await this.isPortInUse(port);
      if (!inUse) {
        this.allocatedPorts.add(port);
        console.log(`✅ Allocated available port: ${port}`);
        return port;
      }
    }
    
    console.error(`❌ Could not find available port after ${maxAttempts} attempts`);
    return null;
  }

  /**
   * Check if specific port is available, or find alternative
   * @param {number} preferredPort - Preferred port number
   * @param {number} startPort - Fallback start port
   * @param {number} endPort - Fallback end port
   * @returns {Promise<number>} - Available port
   */
  async allocatePort(preferredPort, startPort = 8080, endPort = 65535) {
    // Check if preferred port is available
    const inUse = await this.isPortInUse(preferredPort);
    
    if (!inUse) {
      this.allocatedPorts.add(preferredPort);
      console.log(`✅ Using preferred port: ${preferredPort}`);
      return preferredPort;
    }
    
    console.log(`⚠️ Preferred port ${preferredPort} is in use, finding alternative...`);
    const alternativePort = await this.findAvailablePort(startPort, endPort);
    
    if (!alternativePort) {
      throw new Error(`Cannot allocate port: ${preferredPort} in use and no alternatives found`);
    }
    
    return alternativePort;
  }

  /**
   * Release a port allocation
   * @param {number} port - Port to release
   */
  releasePort(port) {
    this.allocatedPorts.delete(port);
    console.log(`Released port: ${port}`);
  }

  /**
   * Get all allocated ports
   * @returns {Array<number>}
   */
  getAllocatedPorts() {
    return Array.from(this.allocatedPorts);
  }
}

// Singleton instance
export const portManager = new PortManager();
