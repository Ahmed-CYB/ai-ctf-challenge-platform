/**
 * Checkpoint Manager
 * IMPROVEMENT: Saves intermediate results during challenge creation for error recovery
 */

import fs from 'fs/promises';
import path from 'path';

export class CheckpointManager {
  constructor() {
    this.checkpointDir = path.join(process.cwd(), '.checkpoints');
  }

  /**
   * Ensure checkpoint directory exists
   */
  async ensureCheckpointDir() {
    try {
      await fs.mkdir(this.checkpointDir, { recursive: true });
    } catch (error) {
      console.warn('⚠️  Failed to create checkpoint directory:', error.message);
    }
  }

  /**
   * Save checkpoint for a challenge creation phase
   * @param {string} challengeName - Challenge name
   * @param {string} phase - Phase name (e.g., 'scenario-analysis', 'content-generation')
   * @param {object} data - Data to save
   */
  async saveCheckpoint(challengeName, phase, data) {
    try {
      await this.ensureCheckpointDir();
      const checkpointPath = path.join(this.checkpointDir, `${challengeName}-${phase}.json`);
      await fs.writeFile(checkpointPath, JSON.stringify(data, null, 2));
      console.log(`💾 Checkpoint saved: ${phase} for ${challengeName}`);
    } catch (error) {
      console.warn(`⚠️  Failed to save checkpoint ${phase}:`, error.message);
    }
  }

  /**
   * Load checkpoint for a challenge creation phase
   * @param {string} challengeName - Challenge name
   * @param {string} phase - Phase name
   * @returns {object|null} Checkpoint data or null if not found
   */
  async loadCheckpoint(challengeName, phase) {
    try {
      const checkpointPath = path.join(this.checkpointDir, `${challengeName}-${phase}.json`);
      const data = await fs.readFile(checkpointPath, 'utf8');
      console.log(`📂 Checkpoint loaded: ${phase} for ${challengeName}`);
      return JSON.parse(data);
    } catch (error) {
      return null;
    }
  }

  /**
   * Check if checkpoint exists
   * @param {string} challengeName - Challenge name
   * @param {string} phase - Phase name
   * @returns {boolean} True if checkpoint exists
   */
  async hasCheckpoint(challengeName, phase) {
    try {
      const checkpointPath = path.join(this.checkpointDir, `${challengeName}-${phase}.json`);
      await fs.access(checkpointPath);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get all checkpoints for a challenge
   * @param {string} challengeName - Challenge name
   * @returns {Array} List of checkpoint phases
   */
  async listCheckpoints(challengeName) {
    try {
      await this.ensureCheckpointDir();
      const files = await fs.readdir(this.checkpointDir);
      const prefix = `${challengeName}-`;
      return files
        .filter(file => file.startsWith(prefix) && file.endsWith('.json'))
        .map(file => file.replace(prefix, '').replace('.json', ''));
    } catch {
      return [];
    }
  }

  /**
   * Cleanup checkpoints for a challenge
   * @param {string} challengeName - Challenge name
   */
  async cleanup(challengeName) {
    try {
      const checkpoints = await this.listCheckpoints(challengeName);
      for (const phase of checkpoints) {
        const checkpointPath = path.join(this.checkpointDir, `${challengeName}-${phase}.json`);
        await fs.unlink(checkpointPath);
      }
      console.log(`🗑️  Cleaned up ${checkpoints.length} checkpoints for ${challengeName}`);
    } catch (error) {
      console.warn(`⚠️  Failed to cleanup checkpoints:`, error.message);
    }
  }

  /**
   * Cleanup old checkpoints (older than specified days)
   * @param {number} maxAgeDays - Maximum age in days (default: 7)
   */
  async cleanupOld(maxAgeDays = 7) {
    try {
      await this.ensureCheckpointDir();
      const files = await fs.readdir(this.checkpointDir);
      const maxAge = maxAgeDays * 24 * 60 * 60 * 1000;
      let cleaned = 0;

      for (const file of files) {
        if (!file.endsWith('.json')) continue;
        
        const filePath = path.join(this.checkpointDir, file);
        const stats = await fs.stat(filePath);
        const age = Date.now() - stats.mtimeMs;
        
        if (age > maxAge) {
          await fs.unlink(filePath);
          cleaned++;
        }
      }

      if (cleaned > 0) {
        console.log(`🧹 Cleaned up ${cleaned} old checkpoints (older than ${maxAgeDays} days)`);
      }
    } catch (error) {
      console.warn('⚠️  Failed to cleanup old checkpoints:', error.message);
    }
  }
}

// Export singleton instance
export const checkpointManager = new CheckpointManager();

