/**
 * Save Validated OS Images to Database
 * Saves the test results from test-and-save-os-images.mjs to the database
 * Run this from inside the Docker container or with proper DB connection
 */

// Validated images from test results
const validatedImages = [
  { image: 'ubuntu:22.04', description: 'Ubuntu 22.04 LTS - Popular Debian-based Linux', packageManager: 'apt-get', osFamily: 'debian', size: 28.18 },
  { image: 'ubuntu:20.04', description: 'Ubuntu 20.04 LTS - Stable Debian-based Linux', packageManager: 'apt-get', osFamily: 'debian', size: 26.24 },
  { image: 'debian:bullseye', description: 'Debian Bullseye - Stable Linux distribution', packageManager: 'apt-get', osFamily: 'debian', size: 51.27 },
  { name: 'debian:bookworm', description: 'Debian Bookworm - Latest stable Debian', packageManager: 'apt-get', osFamily: 'debian', size: 46.24 },
  { image: 'alpine:latest', description: 'Alpine Linux - Minimal lightweight Linux', packageManager: 'apk', osFamily: 'alpine', size: 3.69 },
  { image: 'rockylinux:9', description: 'Rocky Linux 9 - RHEL-compatible Linux', packageManager: 'dnf', osFamily: 'rhel', size: 61.34 },
  { image: 'fedora:latest', description: 'Fedora - Cutting-edge Linux distribution', packageManager: 'dnf', osFamily: 'rhel', size: 64.23 },
  { image: 'centos:7', description: 'CentOS 7 - Enterprise Linux (legacy)', packageManager: 'yum', osFamily: 'rhel', size: 72.58 },
  { image: 'archlinux:latest', description: 'Arch Linux - Rolling release Linux', packageManager: 'pacman', osFamily: 'arch', size: 166.61 },
];

// SQL to insert/update validated images
const insertSQL = `
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
`;

console.log('💾 Saving validated OS images to database...\n');

// This script should be run inside the Docker container where DB connection works
// Or update DB_HOST in .env to use localhost:5433 from host

