/**
 * Multi-Repository CTF Configuration Fetcher
 * 
 * Searches multiple trusted GitHub repositories for CTF/Docker configurations
 * 
 * Trusted Repositories:
 * - Vulhub: https://github.com/vulhub/vulhub (200+ vulnerable Docker environments)
 * - DVWA: https://github.com/digininja/DVWA (Damn Vulnerable Web Application)
 * - CTF-Archives: https://github.com/CTF-Archives/ctf-docker-template (CTF Docker templates)
 * - CTFd-Docker-Challenges: https://github.com/offsecginger/CTFd-Docker-Challenges
 * - HackTheBox: https://github.com/HackTheBox (various challenge repositories)
 */

import fs from 'fs/promises';
import path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';
import { Logger } from '../core/logger.js';

const execAsync = promisify(exec);

/**
 * Trusted CTF/Docker configuration repositories
 */
const TRUSTED_REPOSITORIES = [
  {
    name: 'vulhub',
    url: 'https://github.com/vulhub/vulhub.git',
    description: '200+ pre-built vulnerable Docker environments',
    searchPaths: ['*'], // Search all directories
    priority: 1 // Highest priority
  },
  {
    name: 'dvwa',
    url: 'https://github.com/digininja/DVWA.git',
    description: 'Damn Vulnerable Web Application',
    searchPaths: ['*'],
    priority: 2
  },
  {
    name: 'ctf-archives',
    url: 'https://github.com/CTF-Archives/ctf-docker-template.git',
    description: 'CTF Docker deployment templates',
    searchPaths: ['*'],
    priority: 3
  },
  {
    name: 'ctfd-docker-challenges',
    url: 'https://github.com/offsecginger/CTFd-Docker-Challenges.git',
    description: 'CTFd Docker challenge examples',
    searchPaths: ['*'],
    priority: 4
  }
];

export class MultiRepoCTFFetcher {
  constructor() {
    this.logger = new Logger();
    this.cacheDir = path.join(process.cwd(), '.ctf-config-cache');
    this.repositories = new Map();
    
    // Initialize repository paths
    for (const repo of TRUSTED_REPOSITORIES) {
      this.repositories.set(repo.name, {
        ...repo,
        repoDir: path.join(this.cacheDir, repo.name)
      });
    }
  }

  /**
   * Initialize cache directory
   */
  async initializeCache() {
    try {
      await fs.mkdir(this.cacheDir, { recursive: true });
      this.logger.info('MultiRepoCTFFetcher', 'Cache directory initialized', { path: this.cacheDir });
    } catch (error) {
      this.logger.error('MultiRepoCTFFetcher', 'Failed to initialize cache', error.stack);
      throw error;
    }
  }

  /**
   * Ensure a specific repository is cloned/updated
   */
  async ensureRepository(repoName, forceUpdate = false) {
    const repo = this.repositories.get(repoName);
    if (!repo) {
      throw new Error(`Unknown repository: ${repoName}`);
    }

    try {
      const repoExists = await fs.access(repo.repoDir).then(() => true).catch(() => false);

      if (repoExists) {
        // Check if we need to update (only if cache is older than 24 hours)
        if (!forceUpdate) {
          try {
            const gitDir = path.join(repo.repoDir, '.git');
            const gitDirStats = await fs.stat(gitDir);
            const lastUpdateTime = gitDirStats.mtime.getTime();
            const now = Date.now();
            const hoursSinceUpdate = (now - lastUpdateTime) / (1000 * 60 * 60);
            
            // Only update if cache is older than 24 hours
            if (hoursSinceUpdate < 24) {
              this.logger.debug('MultiRepoCTFFetcher', `Repository ${repoName} cache is recent, skipping update`, { 
                hoursSinceUpdate: hoursSinceUpdate.toFixed(1) 
              });
              return; // Skip update
            }
          } catch (statError) {
            // If we can't check stats, proceed with update
            this.logger.debug('MultiRepoCTFFetcher', `Could not check cache age for ${repoName}, proceeding with update`);
          }
        }
        
        this.logger.info('MultiRepoCTFFetcher', `Updating repository: ${repoName}...`);
        await execAsync(`cd "${repo.repoDir}" && git pull`, { timeout: 60000 });
        this.logger.success('MultiRepoCTFFetcher', `Repository ${repoName} updated`);
      } else {
        this.logger.info('MultiRepoCTFFetcher', `Cloning repository: ${repoName} (this may take a few minutes)...`);
        await execAsync(`git clone --depth 1 "${repo.url}" "${repo.repoDir}"`, { timeout: 300000 });
        this.logger.success('MultiRepoCTFFetcher', `Repository ${repoName} cloned`);
      }
    } catch (error) {
      this.logger.warn('MultiRepoCTFFetcher', `Failed to clone/update repository ${repoName}`, error.message);
      // Don't throw - continue with other repositories
    }
  }

  /**
   * Ensure all repositories are available (clone/update in parallel)
   */
  async ensureAllRepositories(forceUpdate = false) {
    await this.initializeCache();
    
    // Clone/update all repositories in parallel
    const promises = Array.from(this.repositories.keys()).map(repoName => 
      this.ensureRepository(repoName, forceUpdate).catch(err => {
        this.logger.warn('MultiRepoCTFFetcher', `Failed to ensure repository ${repoName}`, err.message);
        return null; // Continue with other repos
      })
    );
    
    await Promise.all(promises);
    this.logger.info('MultiRepoCTFFetcher', 'All repositories ensured', { 
      count: this.repositories.size 
    });
  }

  /**
   * Get service type variations for searching
   */
  getServiceTypeVariations(serviceType) {
    const serviceLower = serviceType.toLowerCase();
    
    // Service type to directory name mappings
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
    
    return serviceMappings[serviceLower] || [serviceLower];
  }

  /**
   * Search a single repository for examples
   */
  async searchRepository(repoName, serviceType) {
    const repo = this.repositories.get(repoName);
    if (!repo) {
      return [];
    }

    try {
      // Check if repository exists
      await fs.access(repo.repoDir);
    } catch {
      this.logger.debug('MultiRepoCTFFetcher', `Repository ${repoName} not available, skipping`);
      return [];
    }

    const examples = [];
    const searchTerms = this.getServiceTypeVariations(serviceType);

    try {
      // Search repository directory
      const entries = await fs.readdir(repo.repoDir, { withFileTypes: true });

      for (const entry of entries) {
        if (!entry.isDirectory() || entry.name.startsWith('.')) {
          continue;
        }

        const dirName = entry.name.toLowerCase();
        const matches = searchTerms.some(term => dirName.includes(term));

        if (matches) {
          const examplePath = path.join(repo.repoDir, entry.name);
          const example = await this.parseExample(examplePath, entry.name, repoName);
          if (example) {
            examples.push(example);
          }
        }
      }
    } catch (error) {
      this.logger.warn('MultiRepoCTFFetcher', `Error searching repository ${repoName}`, error.message);
    }

    return examples;
  }

  /**
   * Find examples across all trusted repositories
   * @param {string} serviceType - Service type (ftp, samba, apache, etc.)
   * @returns {Array} List of matching examples from all repositories
   */
  async findExamples(serviceType) {
    try {
      // Ensure all repositories are available
      await this.ensureAllRepositories();

      const allExamples = [];
      const searchTerms = this.getServiceTypeVariations(serviceType);

      // Search all repositories in parallel
      const searchPromises = Array.from(this.repositories.keys()).map(repoName =>
        this.searchRepository(repoName, serviceType)
      );

      const results = await Promise.all(searchPromises);

      // Combine results from all repositories
      for (const examples of results) {
        allExamples.push(...examples);
      }

      // Sort by repository priority (lower number = higher priority)
      allExamples.sort((a, b) => {
        const repoA = this.repositories.get(a.sourceRepo);
        const repoB = this.repositories.get(b.sourceRepo);
        const priorityA = repoA?.priority || 999;
        const priorityB = repoB?.priority || 999;
        return priorityA - priorityB;
      });

      this.logger.info('MultiRepoCTFFetcher', `Found ${allExamples.length} examples for ${serviceType}`, { 
        searchTerms,
        examplesFound: allExamples.map(e => `${e.name} (${e.sourceRepo})`),
        repositories: Array.from(this.repositories.keys())
      });

      return allExamples;

    } catch (error) {
      this.logger.error('MultiRepoCTFFetcher', 'Failed to find examples', error.stack);
      return [];
    }
  }

  /**
   * Parse a CTF example directory
   */
  async parseExample(examplePath, exampleName, sourceRepo) {
    try {
      const example = {
        name: exampleName,
        path: examplePath,
        sourceRepo: sourceRepo,
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
          // Recursively check subdirectories
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
      this.logger.warn('MultiRepoCTFFetcher', `Failed to parse example ${exampleName} from ${sourceRepo}`, error.message);
      return null;
    }
  }

  /**
   * Get the best matching example from all repositories
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

      // Return the first example (highest priority repository)
      return examples[0];

    } catch (error) {
      this.logger.error('MultiRepoCTFFetcher', 'Failed to get best example', error.stack);
      return null;
    }
  }
}

export const multiRepoCTFFetcher = new MultiRepoCTFFetcher();

