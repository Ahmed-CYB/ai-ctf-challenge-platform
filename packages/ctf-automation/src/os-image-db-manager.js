/**
 * OS Image Database Manager
 * Manages validated OS images in PostgreSQL database
 * BEST PRACTICE: Persistent storage avoids re-validation on every request
 */

import { dbManager } from './db-manager.js';

// Add query method to dbManager if it doesn't exist
if (!dbManager.query) {
  dbManager.query = async function(sql, params = []) {
    return await this.pool.query(sql, params);
  };
}
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

/**
 * Get all validated OS images from database
 * BEST PRACTICE: Cache results, only query database when needed
 */
let cachedValidatedImages = null;
let cacheTimestamp = null;
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes cache

export async function getValidatedOSImagesFromDB() {
  const now = Date.now();
  
  // Return cached results if still valid
  if (cachedValidatedImages && cacheTimestamp && (now - cacheTimestamp) < CACHE_TTL) {
    return cachedValidatedImages;
  }
  
  try {
    const query = `
      SELECT 
        image_name,
        package_manager,
        description,
        os_type,
        os_family,
        image_size_mb,
        os_info,
        usage_count,
        success_rate
      FROM validated_os_images
      WHERE is_valid = true 
        AND is_pullable = true 
        AND is_runnable = true
        AND (os_family = 'linux' OR os_family IS NULL OR os_family NOT IN ('windows', 'Windows'))
        AND image_name NOT LIKE 'mcr.microsoft.com/%'
        AND image_name NOT LIKE '%windows%'
        AND image_name NOT LIKE '%Windows%'
      ORDER BY usage_count DESC, image_name ASC
    `;
    
    const result = await dbManager.query(query);
    
    const validatedImages = result.rows.map(row => ({
      image: row.image_name,
      manager: row.package_manager,
      description: row.description || row.image_name,
      osType: row.os_type,
      osFamily: row.os_family,
      size: row.image_size_mb ? `${row.image_size_mb} MB` : null,
      osInfo: row.os_info,
      usageCount: row.usage_count || 0,
      successRate: row.success_rate || 100.0
    }));
    
    // Update cache
    cachedValidatedImages = validatedImages;
    cacheTimestamp = now;
    
    console.log(`✅ Loaded ${validatedImages.length} validated OS images from database`);
    return validatedImages;
    
  } catch (error) {
    console.error('❌ Error loading validated OS images from database:', error.message);
    // Fallback to default images
    return getDefaultValidatedImages();
  }
}

/**
 * Check if an OS image is validated in database
 */
export async function isValidOSImageInDB(imageName) {
  try {
    const query = `
      SELECT image_name 
      FROM validated_os_images 
      WHERE image_name = $1 
        AND is_valid = true 
        AND is_pullable = true 
        AND is_runnable = true
    `;
    
    const result = await dbManager.query(query, [imageName]);
    return result.rows.length > 0;
    
  } catch (error) {
    console.error(`❌ Error checking image validation: ${error.message}`);
    return false;
  }
}

/**
 * Get OS image info from database
 */
export async function getOSImageInfoFromDB(imageName) {
  try {
    const query = `
      SELECT 
        image_name,
        package_manager,
        description,
        os_type,
        os_family,
        image_size_mb,
        os_info
      FROM validated_os_images
      WHERE image_name = $1
    `;
    
    const result = await dbManager.query(query, [imageName]);
    
    if (result.rows.length > 0) {
      const row = result.rows[0];
      return {
        image: row.image_name,
        manager: row.package_manager,
        description: row.description || row.image_name,
        osType: row.os_type,
        osFamily: row.os_family,
        size: row.image_size_mb ? `${row.image_size_mb} MB` : null,
        osInfo: row.os_info
      };
    }
    
    return null;
    
  } catch (error) {
    console.error(`❌ Error getting OS image info: ${error.message}`);
    return null;
  }
}

/**
 * Validate a new OS image and save to database
 * CRITICAL: Only Linux images are supported - Windows is NOT supported
 * BEST PRACTICE: Only validate when image is not in database
 */
export async function validateAndSaveOSImage(imageName, options = {}) {
  // CRITICAL: Reject Windows images immediately
  const imageLower = imageName.toLowerCase();
  if (imageLower.includes('windows') || imageName.includes('mcr.microsoft.com')) {
    throw new Error(`Windows image rejected: ${imageName}. Only Linux images are supported.`);
  }
  
  const {
    description = null,
    packageManager = null,
    osType = 'linux',
    osFamily = null
  } = options;
  
  // Check if already validated
  const existing = await getOSImageInfoFromDB(imageName);
  if (existing) {
    console.log(`✅ Image ${imageName} already validated in database`);
    return existing;
  }
  
  console.log(`🔍 Validating new OS image: ${imageName}`);
  
  try {
    // Test if image can be pulled
    console.log(`📥 Testing if ${imageName} can be pulled...`);
    await execAsync(`docker pull ${imageName}`, { timeout: 300000 });
    console.log(`✅ Successfully pulled ${imageName}`);
    
    // Test if image can run
    const testContainerName = `test-${imageName.replace(/[^a-z0-9]/g, '-')}-${Date.now()}`;
    try {
      await execAsync(`docker run --rm --name ${testContainerName} ${imageName} echo "test"`, { timeout: 60000 });
      console.log(`✅ Image ${imageName} can run`);
    } catch (runError) {
      console.warn(`⚠️  Image ${imageName} may not run with default command: ${runError.message}`);
    } finally {
      // Cleanup
      await execAsync(`docker rm -f ${testContainerName}`).catch(() => {});
    }
    
    // Get image size
    let imageSize = null;
    try {
      const { stdout } = await execAsync(`docker image inspect ${imageName} --format "{{.Size}}"`);
      const sizeBytes = parseInt(stdout.trim());
      imageSize = (sizeBytes / 1024 / 1024).toFixed(2);
    } catch (e) {
      console.warn(`⚠️  Could not get image size: ${e.message}`);
    }
    
    // Detect package manager if not provided
    let detectedManager = packageManager || detectPackageManager(imageName);
    
    // Detect OS family if not provided
    let detectedFamily = osFamily || detectOSFamily(imageName);
    
    // Save to database
    const insertQuery = `
      INSERT INTO validated_os_images (
        image_name,
        package_manager,
        description,
        os_type,
        os_family,
        image_size_mb,
        is_valid,
        is_pullable,
        is_runnable,
        ports_configurable,
        services_configurable,
        validated_by,
        validation_method
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      ON CONFLICT (image_name) 
      DO UPDATE SET
        package_manager = EXCLUDED.package_manager,
        description = COALESCE(EXCLUDED.description, validated_os_images.description),
        os_type = EXCLUDED.os_type,
        os_family = COALESCE(EXCLUDED.os_family, validated_os_images.os_family),
        image_size_mb = COALESCE(EXCLUDED.image_size_mb, validated_os_images.image_size_mb),
        is_valid = EXCLUDED.is_valid,
        is_pullable = EXCLUDED.is_pullable,
        is_runnable = EXCLUDED.is_runnable,
        ports_configurable = EXCLUDED.ports_configurable,
        services_configurable = EXCLUDED.services_configurable,
        updated_at = NOW()
      RETURNING *
    `;
    
    const result = await dbManager.query(insertQuery, [
      imageName,
      detectedManager,
      description || imageName,
      osType,
      detectedFamily,
      imageSize ? parseFloat(imageSize) : null,
      true,  // is_valid
      true,  // is_pullable
      true,  // is_runnable
      true,  // ports_configurable (assumed, can be tested separately)
      true,  // services_configurable (assumed, can be tested separately)
      'system',
      'automated'
    ]);
    
    // Clear cache to force reload
    cachedValidatedImages = null;
    cacheTimestamp = null;
    
    console.log(`✅ Saved validated OS image ${imageName} to database`);
    
    return {
      image: result.rows[0].image_name,
      manager: result.rows[0].package_manager,
      description: result.rows[0].description,
      osType: result.rows[0].os_type,
      osFamily: result.rows[0].os_family
    };
    
  } catch (error) {
    console.error(`❌ Failed to validate image ${imageName}: ${error.message}`);
    
    // Save as invalid to avoid retrying immediately
    try {
      await dbManager.query(`
        INSERT INTO validated_os_images (
          image_name, package_manager, description, os_type, 
          is_valid, is_pullable, is_runnable, validated_by, validation_method
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (image_name) DO UPDATE SET
          is_valid = EXCLUDED.is_valid,
          is_pullable = EXCLUDED.is_pullable,
          is_runnable = EXCLUDED.is_runnable,
          updated_at = NOW()
      `, [
        imageName,
        detectPackageManager(imageName),
        description || imageName,
        osType,
        false,  // is_valid
        false,  // is_pullable
        false,  // is_runnable
        'system',
        'automated'
      ]);
    } catch (saveError) {
      console.error(`❌ Failed to save invalid image to database: ${saveError.message}`);
    }
    
    throw error;
  }
}

/**
 * Record OS image usage (for analytics)
 */
export async function recordOSImageUsage(imageName, challengeName = null, machineName = null, usageType = 'victim', success = true, errorMessage = null) {
  try {
    await dbManager.query(`
      INSERT INTO os_image_usage_history (
        image_name, challenge_name, machine_name, usage_type, success, error_message
      ) VALUES ($1, $2, $3, $4, $5, $6)
    `, [imageName, challengeName, machineName, usageType, success, errorMessage]);
    
    // Update success rate for the image
    if (imageName) {
      await dbManager.query(`
        UPDATE validated_os_images
        SET success_rate = (
          SELECT 
            CASE 
              WHEN COUNT(*) = 0 THEN 100.0
              ELSE (COUNT(*) FILTER (WHERE success = true)::DECIMAL / COUNT(*)::DECIMAL * 100)
            END
          FROM os_image_usage_history
          WHERE image_name = validated_os_images.image_name
        )
        WHERE image_name = $1
      `, [imageName]);
    }
    
  } catch (error) {
    console.warn(`⚠️  Failed to record OS image usage: ${error.message}`);
    // Don't throw - usage tracking is non-critical
  }
}

/**
 * Add image to validation queue (for async validation)
 */
export async function queueImageValidation(imageName, requestedBy = 'system', priority = 0) {
  try {
    await dbManager.query(`
      INSERT INTO os_image_validation_queue (image_name, requested_by, priority, status)
      VALUES ($1, $2, $3, 'pending')
      ON CONFLICT (image_name) DO UPDATE SET
        priority = GREATEST(os_image_validation_queue.priority, EXCLUDED.priority),
        status = CASE 
          WHEN os_image_validation_queue.status = 'failed' THEN 'pending'
          ELSE os_image_validation_queue.status
        END,
        updated_at = NOW()
    `, [imageName, requestedBy, priority]);
    
    console.log(`📋 Queued ${imageName} for validation`);
    
  } catch (error) {
    console.error(`❌ Failed to queue image validation: ${error.message}`);
  }
}

/**
 * Detect package manager from image name
 * CRITICAL: Only supports Linux images - Windows is NOT supported
 */
function detectPackageManager(imageName) {
  const image = imageName.toLowerCase();
  
  // Reject Windows images
  if (image.includes('windows') || image.includes('mcr.microsoft.com')) {
    throw new Error(`Windows images are not supported. Only Linux images are allowed. Received: ${imageName}`);
  }
  
  if (image.includes('alpine')) return 'apk';
  // Rocky Linux, Fedora, and RHEL use dnf
  if (image.includes('rocky') || image.includes('fedora') || image.includes('rhel')) return 'dnf';
  if (image.includes('arch')) return 'pacman';
  return 'apt-get'; // Default for Ubuntu, Debian
}

/**
 * Detect OS family from image name
 * CRITICAL: Only supports Linux images - Windows is NOT supported
 */
function detectOSFamily(imageName) {
  const image = imageName.toLowerCase();
  
  // Reject Windows images
  if (image.includes('windows') || image.includes('mcr.microsoft.com')) {
    return null; // Windows is not supported
  }
  
  if (image.includes('ubuntu') || image.includes('debian')) return 'debian';
  if (image.includes('rocky') || image.includes('fedora') || image.includes('rhel')) return 'rhel';
  if (image.includes('alpine')) return 'alpine';
  if (image.includes('arch')) return 'arch';
  return 'linux'; // Default to Linux for unknown Linux distributions
}

/**
 * Default validated images (fallback if database unavailable)
 */
function getDefaultValidatedImages() {
  return [
    { image: 'ubuntu:22.04', manager: 'apt-get', description: 'Ubuntu 22.04 LTS' },
    { image: 'ubuntu:20.04', manager: 'apt-get', description: 'Ubuntu 20.04 LTS' },
    { image: 'alpine:latest', manager: 'apk', description: 'Alpine Linux - Minimal' },
    { image: 'rockylinux:9', manager: 'dnf', description: 'Rocky Linux 9 - Enterprise' },
    { image: 'debian:bookworm', manager: 'apt-get', description: 'Debian Bookworm' },
    { image: 'debian:bullseye', manager: 'apt-get', description: 'Debian Bullseye' },
    { image: 'fedora:latest', manager: 'dnf', description: 'Fedora - Cutting-edge' },
    { image: 'archlinux:latest', manager: 'pacman', description: 'Arch Linux - Rolling' }
  ];
}

/**
 * Clear cache (useful after database updates)
 */
export function clearOSImageCache() {
  cachedValidatedImages = null;
  cacheTimestamp = null;
}

