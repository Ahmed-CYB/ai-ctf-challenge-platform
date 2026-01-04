/**
 * Content Cache
 * IMPROVEMENT: Caches successful content patterns for reuse
 */

import crypto from 'crypto';
import { query } from './db-manager.js';
import { isContentTooSimilar } from './content-variation-manager.js';

/**
 * Generate hash for scenario to find similar content
 * IMPROVEMENT: Include more context for better uniqueness
 */
function hashScenario(scenario, category) {
  // Include more context to ensure uniqueness
  const key = `${category}:${scenario.title}:${scenario.difficulty || 'medium'}:${scenario.description?.substring(0, 50) || ''}:${Date.now() % 10000}`;
  return crypto.createHash('sha256').update(key).digest('hex').substring(0, 16);
}

/**
 * Get cached content for similar scenario
 * @param {string} category - Content category
 * @param {object} scenario - Scenario object
 * @returns {object|null} Cached content or null
 */
export async function getCachedContent(category, scenario) {
  try {
    const scenarioHash = hashScenario(scenario, category);
    
    const result = await query(`
      SELECT content_data, quality_score, usage_count, last_used
      FROM content_cache
      WHERE category = $1 
        AND scenario_hash = $2
        AND quality_score >= 0.7
      ORDER BY quality_score DESC, usage_count DESC
      LIMIT 1
    `, [category, scenarioHash]);

    if (result.rows.length > 0) {
      const cached = result.rows[0];
      const cachedContent = JSON.parse(cached.content_data);
      
      // IMPROVEMENT: Skip cache if content was used recently (force uniqueness)
      // If used more than 2 times in last hour, skip cache to ensure variation
      const hoursSinceLastUse = (Date.now() - new Date(cached.last_used).getTime()) / (1000 * 60 * 60);
      
      if (cached.usage_count >= 2 && hoursSinceLastUse < 1) {
        console.log(`⚠️  Skipping cache: Content used ${cached.usage_count} times recently (forcing uniqueness)`);
        return null; // Force new generation for uniqueness
      }
      
      // IMPROVEMENT: Check similarity and skip if too similar
      try {
        const { isContentTooSimilar } = await import('./content-variation-manager.js');
        // Note: We'd need to compare with recent content, but for now we'll use usage count
        if (cached.usage_count >= 5) {
          console.log(`⚠️  Skipping cache: Content used ${cached.usage_count} times (forcing variation)`);
          return null; // Force variation after 5 uses
        }
      } catch (e) {
        // Variation manager not available, continue
      }
      
      // Update usage stats
      await query(`
        UPDATE content_cache
        SET usage_count = usage_count + 1,
            last_used = NOW()
        WHERE category = $1 AND scenario_hash = $2
      `, [category, scenarioHash]);

      console.log(`💨 Content cache HIT: ${category} (quality: ${cached.quality_score}, uses: ${cached.usage_count + 1})`);
      
      return cachedContent;
    }

    console.log(`❌ Content cache MISS: ${category}`);
    return null;
  } catch (error) {
    console.warn('⚠️  Content cache lookup failed:', error.message);
    return null;
  }
}

/**
 * Save content to cache
 * @param {string} category - Content category
 * @param {object} scenario - Scenario object
 * @param {object} content - Content to cache
 * @param {number} qualityScore - Quality score (0-1)
 */
export async function saveToCache(category, scenario, content, qualityScore) {
  try {
    // Only cache high-quality content
    if (qualityScore < 0.7) {
      console.log(`⚠️  Content quality too low (${qualityScore}) to cache`);
      return;
    }

    const scenarioHash = hashScenario(scenario, category);
    
    // Check if already exists
    const existing = await query(`
      SELECT id FROM content_cache
      WHERE category = $1 AND scenario_hash = $2
    `, [category, scenarioHash]);

    if (existing.rows.length > 0) {
      // Update existing
      await query(`
        UPDATE content_cache
        SET content_data = $3,
            quality_score = $4,
            updated_at = NOW()
        WHERE category = $1 AND scenario_hash = $2
      `, [category, scenarioHash, JSON.stringify(content), qualityScore]);
      console.log(`✅ Updated content cache: ${category}`);
    } else {
      // Insert new
      await query(`
        INSERT INTO content_cache 
        (category, scenario_hash, content_data, quality_score, usage_count, created_at, last_used)
        VALUES ($1, $2, $3, $4, 0, NOW(), NOW())
      `, [category, scenarioHash, JSON.stringify(content), qualityScore]);
      console.log(`✅ Cached content: ${category} (quality: ${qualityScore})`);
    }
  } catch (error) {
    console.warn('⚠️  Failed to cache content:', error.message);
  }
}

/**
 * Initialize content cache table
 */
export async function initializeContentCache() {
  try {
    await query(`
      CREATE TABLE IF NOT EXISTS content_cache (
        id SERIAL PRIMARY KEY,
        category VARCHAR(50) NOT NULL,
        scenario_hash VARCHAR(32) NOT NULL,
        content_data TEXT NOT NULL,
        quality_score DECIMAL(3,2) NOT NULL,
        usage_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        last_used TIMESTAMP DEFAULT NOW(),
        UNIQUE(category, scenario_hash)
      )
    `);
    console.log('✅ Content cache table initialized');
  } catch (error) {
    console.warn('⚠️  Failed to initialize content cache table:', error.message);
  }
}

/**
 * Cleanup old cache entries (older than 30 days, low quality, unused)
 */
export async function cleanupContentCache() {
  try {
    const result = await query(`
      DELETE FROM content_cache
      WHERE (
        (last_used < NOW() - INTERVAL '30 days' AND usage_count < 5)
        OR quality_score < 0.6
      )
      RETURNING id
    `);
    
    if (result.rows.length > 0) {
      console.log(`🧹 Cleaned up ${result.rows.length} old cache entries`);
    }
  } catch (error) {
    console.warn('⚠️  Failed to cleanup content cache:', error.message);
  }
}

