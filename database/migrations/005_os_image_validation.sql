-- OS Image Validation System
-- Stores validated Docker OS images that can be used for CTF challenges
-- Only validates new images when requested, avoids re-validation

-- Validated OS images catalog
CREATE TABLE IF NOT EXISTS validated_os_images (
    id SERIAL PRIMARY KEY,
    image_name VARCHAR(255) UNIQUE NOT NULL,  -- e.g., 'ubuntu:22.04'
    package_manager VARCHAR(50) NOT NULL,     -- 'apt-get', 'apk', 'dnf', 'yum', 'pacman'
    description TEXT,
    os_type VARCHAR(100),                     -- 'linux', 'windows', 'bsd'
    os_family VARCHAR(100),                  -- 'debian', 'rhel', 'alpine', etc.
    
    -- Validation status
    is_valid BOOLEAN DEFAULT TRUE,
    is_pullable BOOLEAN DEFAULT TRUE,
    is_runnable BOOLEAN DEFAULT TRUE,
    ports_configurable BOOLEAN DEFAULT TRUE,
    services_configurable BOOLEAN DEFAULT TRUE,
    
    -- Image metadata
    image_size_mb DECIMAL(10, 2),
    os_info TEXT,
    
    -- Usage statistics
    usage_count INTEGER DEFAULT 0,
    last_used_at TIMESTAMP,
    success_rate DECIMAL(5, 2) DEFAULT 100.0,  -- Percentage of successful uses
    
    -- Validation metadata
    validated_at TIMESTAMP DEFAULT NOW(),
    validated_by VARCHAR(50) DEFAULT 'system',  -- 'system', 'manual', 'test-script'
    validation_method VARCHAR(50) DEFAULT 'automated',  -- 'automated', 'manual', 'test-script'
    validation_notes TEXT,
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    CONSTRAINT validated_os_images_image_name_key UNIQUE (image_name)
);

-- Image validation requests queue (for new images not yet validated)
CREATE TABLE IF NOT EXISTS os_image_validation_queue (
    id SERIAL PRIMARY KEY,
    image_name VARCHAR(255) NOT NULL,
    requested_by VARCHAR(100),  -- 'user', 'system', 'challenge-creation'
    priority INTEGER DEFAULT 0,
    status VARCHAR(50) DEFAULT 'pending',  -- 'pending', 'validating', 'validated', 'failed'
    error_message TEXT,
    attempts INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    CONSTRAINT os_image_validation_queue_image_name_key UNIQUE (image_name)
);

-- Image usage history (track which challenges use which images)
CREATE TABLE IF NOT EXISTS os_image_usage_history (
    id SERIAL PRIMARY KEY,
    image_id INTEGER REFERENCES validated_os_images(id) ON DELETE SET NULL,
    image_name VARCHAR(255) NOT NULL,
    challenge_name VARCHAR(255),
    machine_name VARCHAR(255),
    usage_type VARCHAR(50),  -- 'victim', 'attacker', 'database', 'service'
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    used_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_validated_os_images_package_manager ON validated_os_images(package_manager);
CREATE INDEX IF NOT EXISTS idx_validated_os_images_is_valid ON validated_os_images(is_valid);
CREATE INDEX IF NOT EXISTS idx_validated_os_images_os_family ON validated_os_images(os_family);
CREATE INDEX IF NOT EXISTS idx_validated_os_images_usage_count ON validated_os_images(usage_count DESC);
CREATE INDEX IF NOT EXISTS idx_validation_queue_status ON os_image_validation_queue(status);
CREATE INDEX IF NOT EXISTS idx_validation_queue_priority ON os_image_validation_queue(priority DESC);
CREATE INDEX IF NOT EXISTS idx_usage_history_image_id ON os_image_usage_history(image_id);
CREATE INDEX IF NOT EXISTS idx_usage_history_used_at ON os_image_usage_history(used_at DESC);

-- Function to update last_used_at and usage_count
CREATE OR REPLACE FUNCTION update_os_image_usage()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE validated_os_images
    SET usage_count = usage_count + 1,
        last_used_at = NOW(),
        updated_at = NOW()
    WHERE image_name = NEW.image_name;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Drop trigger if exists before creating (to handle re-runs)
DROP TRIGGER IF EXISTS trigger_update_os_image_usage ON os_image_usage_history;
CREATE TRIGGER trigger_update_os_image_usage
AFTER INSERT ON os_image_usage_history
FOR EACH ROW
EXECUTE FUNCTION update_os_image_usage();

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_os_image_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Drop trigger if exists before creating (to handle re-runs)
DROP TRIGGER IF EXISTS trigger_update_os_image_updated_at ON validated_os_images;
CREATE TRIGGER trigger_update_os_image_updated_at
BEFORE UPDATE ON validated_os_images
FOR EACH ROW
EXECUTE FUNCTION update_os_image_updated_at();

-- Seed initial validated images (from test results)
INSERT INTO validated_os_images (image_name, package_manager, description, os_type, os_family, is_valid, is_pullable, is_runnable, ports_configurable, services_configurable) VALUES
('ubuntu:22.04', 'apt-get', 'Ubuntu 22.04 LTS - Popular Debian-based Linux', 'linux', 'debian', true, true, true, true, true),
('ubuntu:20.04', 'apt-get', 'Ubuntu 20.04 LTS - Stable Debian-based Linux', 'linux', 'debian', true, true, true, true, true),
('alpine:latest', 'apk', 'Alpine Linux - Minimal lightweight Linux', 'linux', 'alpine', true, true, true, true, true),
('rockylinux:9', 'dnf', 'Rocky Linux 9 - RHEL-compatible Linux', 'linux', 'rhel', true, true, true, true, true),
('debian:bookworm', 'apt-get', 'Debian Bookworm - Latest stable Debian', 'linux', 'debian', true, true, true, true, true),
('debian:bullseye', 'apt-get', 'Debian Bullseye - Previous stable Debian', 'linux', 'debian', true, true, true, true, true),
('centos:7', 'yum', 'CentOS 7 - Enterprise Linux (legacy)', 'linux', 'rhel', true, true, true, true, true),
('fedora:latest', 'dnf', 'Fedora - Cutting-edge Linux distribution', 'linux', 'rhel', true, true, true, true, true),
('archlinux:latest', 'pacman', 'Arch Linux - Rolling release Linux', 'linux', 'arch', true, true, true, true, true)
ON CONFLICT (image_name) DO NOTHING;

COMMENT ON TABLE validated_os_images IS 'Catalog of validated Docker OS images that can be used for CTF challenges';
COMMENT ON TABLE os_image_validation_queue IS 'Queue of new OS images waiting to be validated';
COMMENT ON TABLE os_image_usage_history IS 'History of OS image usage in challenges for analytics';

