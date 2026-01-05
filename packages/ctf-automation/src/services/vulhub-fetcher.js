/**
 * Vulhub Fetcher Service
 * Fetches and caches Vulhub configurations from GitHub
 * 
 * Vulhub: https://github.com/vulhub/vulhub
 * Provides 200+ pre-built vulnerable Docker environments
 */

import fs from 'fs/promises';
import path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';
import { Logger } from '../core/logger.js';

const execAsync = promisify(exec);

export class VulhubFetcher {
  constructor() {
    this.logger = new Logger();
    this.vulhubRepoUrl = 'https://github.com/vulhub/vulhub.git';
    this.cacheDir = path.join(process.cwd(), '.vulhub-cache');
    this.repoDir = path.join(this.cacheDir, 'vulhub');
  }

  /**
   * Initialize cache directory
   */
  async initializeCache() {
    try {
      await fs.mkdir(this.cacheDir, { recursive: true });
      this.logger.info('VulhubFetcher', 'Cache directory initialized', { path: this.cacheDir });
    } catch (error) {
      this.logger.error('VulhubFetcher', 'Failed to initialize cache', error.stack);
      throw error;
    }
  }

  /**
   * Clone or update Vulhub repository
   */
  async ensureRepository() {
    try {
      const repoExists = await fs.access(this.repoDir).then(() => true).catch(() => false);

      if (repoExists) {
        this.logger.info('VulhubFetcher', 'Repository exists, updating...');
        // Update existing repository
        await execAsync(`cd "${this.repoDir}" && git pull`, { timeout: 60000 });
        this.logger.success('VulhubFetcher', 'Repository updated');
      } else {
        this.logger.info('VulhubFetcher', 'Cloning Vulhub repository (this may take a few minutes)...');
        // Clone repository
        await execAsync(`git clone --depth 1 "${this.vulhubRepoUrl}" "${this.repoDir}"`, { timeout: 300000 });
        this.logger.success('VulhubFetcher', 'Repository cloned');
      }
    } catch (error) {
      this.logger.error('VulhubFetcher', 'Failed to clone/update repository', error.stack);
      throw new Error(`Failed to fetch Vulhub repository: ${error.message}`);
    }
  }

  /**
   * Get service type variations for searching Vulhub
   * Maps common service names to their Vulhub directory name variations
   */
  getServiceTypeVariations(serviceType) {
    const serviceLower = serviceType.toLowerCase();
    
    // Service type to Vulhub directory name mappings
    const serviceMappings = {
      'ftp': ['ftp', 'vsftpd', 'proftpd', 'pure-ftpd', 'filezilla'],
      'samba': ['samba', 'smb', 'cifs'],
      'smb': ['samba', 'smb', 'cifs'],
      'ssh': ['ssh', 'openssh', 'dropbear'],
      'http': ['http', 'apache', 'httpd', 'apache2'],
      'web': ['http', 'apache', 'httpd', 'apache2', 'nginx', 'web'],
      'apache': ['apache', 'httpd', 'apache2', 'http'],
      'nginx': ['nginx', 'http'],
      'php': ['php', 'apache', 'nginx'],
      'mysql': ['mysql', 'mariadb', 'database'],
      'postgres': ['postgres', 'postgresql', 'database'],
      'postgresql': ['postgres', 'postgresql', 'database'],
      'database': ['mysql', 'mariadb', 'postgres', 'postgresql', 'database'],
      'dns': ['dns', 'bind', 'bind9'],
      'ldap': ['ldap', 'openldap'],
      'redis': ['redis'],
      'mongodb': ['mongodb', 'mongo'],
      'elasticsearch': ['elasticsearch', 'elastic'],
      'tomcat': ['tomcat', 'apache'],
      'jboss': ['jboss', 'wildfly'],
      'weblogic': ['weblogic', 'oracle'],
      'struts': ['struts', 'struts2'],
      'spring': ['spring', 'springboot']
    };
    
    // Return mapped variations or default to service name
    return serviceMappings[serviceLower] || [serviceLower];
  }

  /**
   * Find Vulhub examples matching a service type
   * @param {string} serviceType - Service type (ftp, samba, apache, nginx, etc.)
   * @returns {Array} List of matching Vulhub examples
   */
  async findExamples(serviceType) {
    try {
      await this.initializeCache();
      await this.ensureRepository();

      const examples = [];
      const serviceLower = serviceType.toLowerCase();
      
      // Get all variations to search for
      const searchTerms = this.getServiceTypeVariations(serviceType);

      // Search for matching directories
      const rootDir = this.repoDir;
      const entries = await fs.readdir(rootDir, { withFileTypes: true });

      for (const entry of entries) {
        if (!entry.isDirectory() || entry.name.startsWith('.')) {
          continue;
        }

        const dirName = entry.name.toLowerCase();
        
        // Check if directory name matches any of the service type variations
        const matches = searchTerms.some(term => dirName.includes(term));
        
        // Special handling for smb/samba
        if (!matches && (serviceLower === 'smb' || serviceLower === 'samba')) {
          if (dirName.includes('samba') || dirName.includes('smb') || dirName.includes('cifs')) {
            const examplePath = path.join(rootDir, entry.name);
            const example = await this.parseExample(examplePath, entry.name);
            if (example) {
              examples.push(example);
            }
            continue;
          }
        }
        
        if (matches) {
          const examplePath = path.join(rootDir, entry.name);
          const example = await this.parseExample(examplePath, entry.name);
          if (example) {
            examples.push(example);
          }
        }
      }

      this.logger.info('VulhubFetcher', `Found ${examples.length} examples for ${serviceType}`, { 
        searchTerms,
        examplesFound: examples.map(e => e.name)
      });
      return examples;

    } catch (error) {
      this.logger.error('VulhubFetcher', 'Failed to find examples', error.stack);
      return [];
    }
  }

  /**
   * Parse a Vulhub example directory
   * @param {string} examplePath - Path to example directory
   * @param {string} exampleName - Name of the example
   * @returns {Object|null} Parsed example data
   */
  async parseExample(examplePath, exampleName) {
    try {
      const example = {
        name: exampleName,
        path: examplePath,
        dockerfile: null,
        dockerCompose: null,
        configFiles: [],
        readme: null
      };

      // Read directory contents
      const entries = await fs.readdir(examplePath, { withFileTypes: true });

      for (const entry of entries) {
        const entryPath = path.join(examplePath, entry.name);
        const entryName = entry.name.toLowerCase();

        if (entry.isFile()) {
          // Check for Dockerfile
          if (entryName === 'dockerfile') {
            example.dockerfile = await fs.readFile(entryPath, 'utf-8');
          }
          // Check for docker-compose.yml
          else if (entryName.includes('docker-compose') || entryName.includes('compose')) {
            example.dockerCompose = await fs.readFile(entryPath, 'utf-8');
          }
          // Check for README
          else if (entryName.includes('readme')) {
            example.readme = await fs.readFile(entryPath, 'utf-8');
          }
          // Check for config files
          else if (entryName.endsWith('.conf') || 
                   entryName.endsWith('.config') ||
                   entryName.endsWith('.ini') ||
                   entryName.endsWith('.yml') ||
                   entryName.endsWith('.yaml')) {
            const content = await fs.readFile(entryPath, 'utf-8');
            example.configFiles.push({
              name: entry.name,
              path: entryPath,
              content
            });
          }
        } else if (entry.isDirectory()) {
          // Recursively check subdirectories for Dockerfiles and configs
          const subEntries = await fs.readdir(entryPath, { withFileTypes: true });
          for (const subEntry of subEntries) {
            const subPath = path.join(entryPath, subEntry.name);
            const subName = subEntry.name.toLowerCase();

            if (subEntry.isFile()) {
              if (subName === 'dockerfile') {
                example.dockerfile = await fs.readFile(subPath, 'utf-8');
              } else if (subName.includes('docker-compose') || subName.includes('compose')) {
                example.dockerCompose = await fs.readFile(subPath, 'utf-8');
              } else if (subName.endsWith('.conf') || 
                         subName.endsWith('.config') ||
                         subName.endsWith('.ini')) {
                const content = await fs.readFile(subPath, 'utf-8');
                example.configFiles.push({
                  name: subEntry.name,
                  path: subPath,
                  relativePath: path.relative(examplePath, subPath),
                  content
                });
              }
            }
          }
        }
      }

      // Only return if we found at least a Dockerfile or docker-compose
      if (example.dockerfile || example.dockerCompose) {
        return example;
      }

      return null;

    } catch (error) {
      this.logger.warn('VulhubFetcher', `Failed to parse example ${exampleName}`, error.message);
      return null;
    }
  }

  /**
   * Get the best matching Vulhub example for a service
   * @param {string} serviceType - Service type
   * @param {string} vulnerability - Optional vulnerability name (e.g., "CVE-2017-0144")
   * @returns {Object|null} Best matching example
   */
  async getBestExample(serviceType, vulnerability = null) {
    try {
      const examples = await this.findExamples(serviceType);

      if (examples.length === 0) {
        return null;
      }

      // If vulnerability specified, try to find exact match
      if (vulnerability) {
        const vulnLower = vulnerability.toLowerCase();
        const exactMatch = examples.find(ex => 
          ex.name.toLowerCase().includes(vulnLower) ||
          (ex.readme && ex.readme.toLowerCase().includes(vulnLower))
        );
        if (exactMatch) {
          return exactMatch;
        }
      }

      // Return the first example (can be enhanced with scoring)
      return examples[0];

    } catch (error) {
      this.logger.error('VulhubFetcher', 'Failed to get best example', error.stack);
      return null;
    }
  }

  /**
   * Get cached example (if available) without fetching
   */
  async getCachedExample(serviceType) {
    try {
      const examples = await this.findExamples(serviceType);
      return examples.length > 0 ? examples[0] : null;
    } catch (error) {
      return null;
    }
  }
}

export const vulhubFetcher = new VulhubFetcher();

