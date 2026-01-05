/**
 * Structure Builder - Builds challenge directory structure
 * 
 * Responsibilities:
 * - Create directory structure
 * - Allocate IPs and subnets
 * - Generate unique challenge names
 * - Save to repository
 */

import path from 'path';
import fs from 'fs/promises';
import { fileURLToPath } from 'url';
import { subnetAllocator } from '../subnet-allocator.js';
import { gitManager } from '../git-manager.js';
import { Logger } from '../core/logger.js';
import { linuxOnlyValidator } from '../core/linux-only-validator.js';

// Get project root directory (3 levels up from this file: src/challenge/ -> src/ -> packages/ctf-automation/ -> packages/ -> project root)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '../../..');
const DEFAULT_CLONE_PATH = path.join(projectRoot, 'challenges-repo');

const CLONE_PATH = process.env.CLONE_PATH || DEFAULT_CLONE_PATH;

export class StructureBuilder {
  constructor() {
    this.logger = new Logger();
  }

  /**
   * Build challenge structure from design
   */
  async build(design) {
    try {
      this.logger.info('StructureBuilder', 'Building challenge structure', { name: design.name });

      // Step 1: Generate unique challenge name
      const uniqueName = await gitManager.generateUniqueChallengeName(design.name);
      this.logger.info('StructureBuilder', 'Generated unique name', { uniqueName });

      // 🔥 NEW: Preserve Vulhub template if available
      const vulhubTemplate = design.vulhubTemplate || null;
      if (vulhubTemplate) {
        this.logger.info('StructureBuilder', 'Vulhub template preserved', {
          name: vulhubTemplate.originalVulhub?.name
        });
      }

      // Step 2: Count victim machines for IP allocation
      const victimCount = design.machines?.filter(m => m.role === 'victim').length || 0;
      this.logger.info('StructureBuilder', 'Counted victim machines', { victimCount });

      // Step 3: Allocate subnet and IPs (with correct victim count)
      const subnet = await subnetAllocator.allocateSubnet(uniqueName, 'default', {
        victimCount: victimCount,
        randomizeIPs: true
      });
      this.logger.info('StructureBuilder', 'Allocated subnet', { subnet: subnet.subnet, victimCount });

      // Step 4: Collect attacker tools based on challenge category
      const categories = this.extractCategories(design.type);
      const requiredTools = design.requirements?.tools || [];
      const attackerTools = await this.collectAttackerTools(categories, requiredTools);
      
      this.logger.info('StructureBuilder', 'Collected attacker tools', { 
        category: categories[0] || 'misc',
        toolCount: attackerTools.length 
      });

      // Step 5: Build structure data
      const machines = this.buildMachines(design.machines, subnet.ips, attackerTools);
      
      // 🔒 CRITICAL: Validate all machines are Linux-based
      const linuxValidation = linuxOnlyValidator.validateDesignMachines(machines);
      if (!linuxValidation.valid) {
        this.logger.error('StructureBuilder', 'Windows OS detected in structure', linuxValidation.errors);
        throw new Error(
          `Challenge structure contains Windows machines. Only Linux-based challenges are supported. ` +
          `Errors: ${linuxValidation.errors.join('; ')}`
        );
      }

      if (linuxValidation.warnings.length > 0) {
        this.logger.warn('StructureBuilder', 'Linux validation warnings', linuxValidation.warnings);
      }

      const structure = {
        name: uniqueName,
        type: design.type,
        categories: categories, // Add categories for dockerfile generator
        difficulty: design.difficulty,
        description: design.description,
        scenario: design.scenario,
        subnet: subnet.subnet,
        ips: subnet.ips,
        machines: machines,
        attackerTools: attackerTools, // Add tools for dockerfile generator
        requirements: design.requirements,
        hints: design.hints,
        vulhubTemplate: vulhubTemplate // 🔥 NEW: Preserve Vulhub template for dockerfile generator
      };

      // Step 6: Create directory structure
      await this.createDirectories(uniqueName, structure.machines);

      this.logger.success('StructureBuilder', 'Structure built successfully', { name: uniqueName });

      return {
        success: true,
        data: structure
      };

    } catch (error) {
      this.logger.error('StructureBuilder', 'Structure building failed', error.stack);
      return {
        success: false,
        error: error.message,
        details: error.stack
      };
    }
  }

  /**
   * Build machines structure with IPs
   * CRITICAL: Always ensures attacker machine is included
   */
  buildMachines(machines, ips, attackerTools = []) {
    const builtMachines = [];
    let victimIndex = 0;
    let hasAttacker = false;

    // First, process all machines from design
    for (const machine of machines) {
      const builtMachine = {
        name: machine.name,
        role: machine.role,
        os: machine.os,
        services: machine.services || [],
        vulnerabilities: machine.vulnerabilities || [],
        flagLocation: machine.flagLocation,
        flagFormat: machine.flagFormat,
        ip: null
      };

      // Track if attacker exists
      if (machine.role === 'attacker') {
        hasAttacker = true;
        builtMachine.ip = ips.attacker; // Always .3
      } else if (machine.role === 'victim') {
        // Use victim IPs from allocation
        const victimIPs = ips.victims || [];
        if (victimIndex < victimIPs.length) {
          builtMachine.ip = victimIPs[victimIndex];
          victimIndex++;
        } else {
          throw new Error(`Not enough victim IPs allocated. Need ${victimIndex + 1}, got ${victimIPs.length}`);
        }
      }

      builtMachines.push(builtMachine);
    }

    // ✅ CRITICAL FIX: Always add attacker machine if not present
    if (!hasAttacker) {
      this.logger.warn('StructureBuilder', 'Attacker machine missing from design, adding automatically', {
        toolCount: attackerTools.length
      });
      builtMachines.push({
        name: 'attacker',
        role: 'attacker',
        os: 'kalilinux/kali-rolling:latest',
        services: [],
        vulnerabilities: [],
        flagLocation: null,
        flagFormat: null,
        ip: ips.attacker // Always .3
      });
    }

    return builtMachines;
  }

  /**
   * Extract categories from challenge type
   */
  extractCategories(type) {
    // Map design type to categories
    const typeToCategory = {
      'network': ['network'],
      'crypto': ['crypto'],
      'web': ['web'],
      'misc': ['misc']
    };
    
    return typeToCategory[type] || [type] || ['misc'];
  }

  /**
   * Collect attacker tools based on categories and required tools
   */
  async collectAttackerTools(categories, additionalTools = []) {
    try {
      const { getToolsByCategory } = await import('../package-mapping-db-manager.js');
      
      const tools = new Set(additionalTools);
      for (const category of categories) {
        const categoryTools = await getToolsByCategory(category);
        if (categoryTools && Array.isArray(categoryTools)) {
          categoryTools.forEach(tool => tools.add(tool));
        }
      }

      const toolArray = Array.from(tools);
      this.logger.debug('StructureBuilder', 'Collected tools', { 
        categories, 
        toolCount: toolArray.length 
      });
      
      return toolArray;
    } catch (error) {
      this.logger.warn('StructureBuilder', 'Failed to collect tools, using fallback', {
        error: error.message
      });
      // Fallback to basic tools
      return ['nmap', 'netcat-traditional', 'curl', 'wget', 'tcpdump'];
    }
  }

  /**
   * Create directory structure
   */
  async createDirectories(challengeName, machines) {
    const challengePath = path.join(CLONE_PATH, 'challenges', challengeName);

    // Create main challenge directory
    await fs.mkdir(challengePath, { recursive: true });

    // Create machine directories
    for (const machine of machines) {
      const machinePath = path.join(challengePath, machine.name);
      await fs.mkdir(machinePath, { recursive: true });
    }

    this.logger.debug('StructureBuilder', 'Directories created', { challengePath });
  }

  /**
   * Save challenge to repository
   */
  async save(structure, dockerfiles = [], compose = null) {
    try {
      this.logger.info('StructureBuilder', 'Saving challenge to repository', { name: structure.name });

      // Ensure repository is up to date
      await gitManager.ensureRepository();

      // Create README.md content
      const readmeContent = this.generateREADMEContent(structure);
      
      // Add README.md using gitManager (tracks for commit)
      const readmePath = `challenges/${structure.name}/README.md`;
      await gitManager.addFile(readmePath, readmeContent);
      this.logger.debug('StructureBuilder', 'Added README.md to git tracking');

      // Save docker-compose.yml using gitManager
      if (compose && compose.content) {
        const composePath = `challenges/${structure.name}/docker-compose.yml`;
        await gitManager.addFile(composePath, compose.content);
        this.logger.debug('StructureBuilder', 'Added docker-compose.yml to git tracking');
      }

      // Save Dockerfiles for each machine using gitManager
      for (const dockerfile of dockerfiles) {
        if (dockerfile.dockerfile && dockerfile.machineName) {
          const dockerfilePath = `challenges/${structure.name}/${dockerfile.machineName}/Dockerfile`;
          await gitManager.addFile(dockerfilePath, dockerfile.dockerfile);
          this.logger.debug('StructureBuilder', `Added Dockerfile for ${dockerfile.machineName} to git tracking`);
        }
      }

      // Commit and push to GitHub (REQUIRED)
      this.logger.info('StructureBuilder', 'Committing and pushing to GitHub', { name: structure.name });
      const commitResult = await gitManager.commitAndPush(`Challenge created: ${structure.name}`, 'Challenge created via automation');
      
      if (commitResult.committed && commitResult.pushed) {
        this.logger.success('StructureBuilder', '✅ Challenge saved and pushed to GitHub', { 
          name: structure.name,
          commitSha: commitResult.commitSha,
          branch: commitResult.branch,
          githubUrl: `https://github.com/${process.env.GITHUB_OWNER || 'Ahmed-CYB'}/${process.env.GITHUB_REPO || 'mcp-test'}/tree/${commitResult.branch}/challenges/${structure.name}`
        });
        this.logger.success('StructureBuilder', `Challenge "${structure.name}" pushed to GitHub`, { 
          commitSha: commitResult.commitSha.substring(0, 7) 
        });
      } else if (commitResult.committed) {
        this.logger.error('StructureBuilder', '❌ Challenge committed but NOT pushed to GitHub', { 
          name: structure.name,
          message: commitResult.message
        });
        throw new Error(`Failed to push challenge to GitHub: ${commitResult.message}`);
      } else {
        this.logger.error('StructureBuilder', '❌ Challenge files saved but NOT committed', { 
          name: structure.name,
          message: commitResult.message
        });
        throw new Error(`Failed to commit challenge: ${commitResult.message}`);
      }

      return {
        success: true,
        challengeName: structure.name,
        committed: commitResult.committed || false,
        pushed: commitResult.pushed || false,
        commitSha: commitResult.commitSha || null
      };

    } catch (error) {
      this.logger.error('StructureBuilder', 'Save failed', error.stack);
      return {
        success: false,
        error: error.message,
        details: error.stack
      };
    }
  }

  /**
   * Generate README.md content for challenge
   */
  generateREADMEContent(structure) {
    return `# ${structure.name}

## Description
${structure.description}

## Scenario
${structure.scenario}

## Difficulty
${structure.difficulty}

## Machines
${structure.machines.map(m => `- **${m.name}** (${m.role}): ${m.ip} - ${m.services.join(', ')}`).join('\n')}

## Hints
${structure.hints.map((hint, i) => `${i + 1}. ${hint}`).join('\n')}

## Flag Format
${structure.machines.find(m => m.flagFormat)?.flagFormat || 'CTF{...}'}
`;
  }
}


