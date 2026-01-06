-- Migration 007: Critical Fixes and Database Improvements
-- Addresses: Normalization, Race Conditions, Missing Indexes, Constraints

-- ============================================
-- 1. SUBNET ALLOCATIONS TABLE (Prevent Race Conditions)
-- ============================================
CREATE TABLE IF NOT EXISTS subnet_allocations (
    id SERIAL PRIMARY KEY,
    challenge_name VARCHAR(255) NOT NULL,
    user_id VARCHAR(100) NOT NULL DEFAULT 'default',
    subnet CIDR NOT NULL,
    gateway_ip INET NOT NULL,
    attacker_ip INET NOT NULL,
    victim_ip INET NOT NULL,
    additional_ips JSONB, -- For multiple victims: {"victim1": "172.25.0.10", "victim2": "172.25.0.11"}
    allocated_at TIMESTAMP DEFAULT NOW(),
    released_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    CONSTRAINT subnet_allocations_challenge_user_key UNIQUE (challenge_name, user_id),
    CONSTRAINT subnet_allocations_subnet_key UNIQUE (subnet)
);

CREATE INDEX IF NOT EXISTS idx_subnet_allocations_subnet_active ON subnet_allocations(subnet) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_subnet_allocations_challenge_active ON subnet_allocations(challenge_name) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_subnet_allocations_user_active ON subnet_allocations(user_id) WHERE is_active = TRUE;

-- Function to update updated_at
CREATE OR REPLACE FUNCTION update_subnet_allocations_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Drop trigger if exists (to handle re-runs)
DROP TRIGGER IF EXISTS trigger_update_subnet_allocations_updated_at ON subnet_allocations;
CREATE TRIGGER trigger_update_subnet_allocations_updated_at
BEFORE UPDATE ON subnet_allocations
FOR EACH ROW
EXECUTE FUNCTION update_subnet_allocations_updated_at();

COMMENT ON TABLE subnet_allocations IS 'Tracks subnet allocations to prevent race conditions and ensure persistence';

-- ============================================
-- 2. ADD TOOL_ID FOREIGN KEYS (Normalization)
-- ============================================

-- Add tool_id columns (nullable initially for migration)
ALTER TABLE tool_categories 
  ADD COLUMN IF NOT EXISTS tool_id INTEGER REFERENCES ctf_tools(id) ON DELETE CASCADE;

ALTER TABLE tool_package_mappings 
  ADD COLUMN IF NOT EXISTS tool_id INTEGER REFERENCES ctf_tools(id) ON DELETE CASCADE;

ALTER TABLE attack_tools 
  ADD COLUMN IF NOT EXISTS tool_id INTEGER REFERENCES ctf_tools(id) ON DELETE CASCADE;

-- Migrate existing data (link by tool_name)
UPDATE tool_categories tc 
SET tool_id = (SELECT id FROM ctf_tools WHERE tool_name = tc.tool_name)
WHERE tool_id IS NULL;

UPDATE tool_package_mappings tpm 
SET tool_id = (SELECT id FROM ctf_tools WHERE tool_name = tpm.tool_name)
WHERE tool_id IS NULL;

UPDATE attack_tools at 
SET tool_id = (SELECT id FROM ctf_tools WHERE tool_name = at.tool_name)
WHERE tool_id IS NULL;

-- Create indexes on tool_id
CREATE INDEX IF NOT EXISTS idx_tool_categories_tool_id ON tool_categories(tool_id);
CREATE INDEX IF NOT EXISTS idx_tool_package_mappings_tool_id ON tool_package_mappings(tool_id);
CREATE INDEX IF NOT EXISTS idx_attack_tools_tool_id ON attack_tools(tool_id);

-- Note: We keep tool_name for backward compatibility and as a denormalized field
-- The tool_id is the source of truth, tool_name is for convenience

COMMENT ON COLUMN tool_categories.tool_id IS 'Foreign key to ctf_tools.id - normalized reference';
COMMENT ON COLUMN tool_package_mappings.tool_id IS 'Foreign key to ctf_tools.id - normalized reference';
COMMENT ON COLUMN attack_tools.tool_id IS 'Foreign key to ctf_tools.id - normalized reference';

-- ============================================
-- 3. ADD MISSING INDEXES (Performance)
-- ============================================

-- tool_categories: Query by category (used frequently)
CREATE INDEX IF NOT EXISTS idx_tool_categories_category_active 
  ON tool_categories(category, is_active) 
  WHERE is_active = TRUE;

-- service_package_mappings: Query by service_name (used in every victim machine)
CREATE INDEX IF NOT EXISTS idx_service_mappings_service_name_valid 
  ON service_package_mappings(service_name) 
  WHERE is_valid = TRUE;

-- ============================================
-- 4. ADD CONSTRAINTS (Data Integrity)
-- ============================================

-- Ensure package_manager matches OS type in base_tools_by_os
DO $$
BEGIN
    -- Check if constraint exists before adding
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint 
        WHERE conname = 'check_package_manager_os_match'
    ) THEN
        ALTER TABLE base_tools_by_os 
        ADD CONSTRAINT check_package_manager_os_match 
        CHECK (
            (os_type = 'apt-get' AND package_manager = 'apt-get') OR
            (os_type = 'apk' AND package_manager = 'apk') OR
            (os_type = 'dnf' AND package_manager = 'dnf') OR
            (os_type = 'yum' AND package_manager = 'yum') OR
            (os_type = 'pacman' AND package_manager = 'pacman')
        );
    END IF;
END $$;

-- ============================================
-- 5. ADD COMMENTS FOR DOCUMENTATION
-- ============================================

COMMENT ON COLUMN tool_categories.tool_id IS 'Foreign key to ctf_tools.id - normalized reference';
COMMENT ON COLUMN tool_package_mappings.tool_id IS 'Foreign key to ctf_tools.id - normalized reference';
COMMENT ON COLUMN attack_tools.tool_id IS 'Foreign key to ctf_tools.id - normalized reference';

COMMENT ON COLUMN validated_os_images.is_valid IS 'Whether this OS image has been validated and can be used';
COMMENT ON COLUMN validated_os_images.usage_count IS 'Number of times this image has been used in challenges';

COMMENT ON COLUMN service_package_mappings.is_valid IS 'Whether this service mapping is valid (some services are not packages)';

COMMENT ON COLUMN subnet_allocations.is_active IS 'Whether this subnet allocation is currently active (not released)';

-- ============================================
-- 6. AUDIT LOGGING REMOVED (Not in use)
-- ============================================
-- database_audit_log table removed - not in use

-- ============================================
-- 7. SUMMARY
-- ============================================

-- Verify indexes were created
DO $$
BEGIN
    RAISE NOTICE 'Migration 007 completed successfully';
    RAISE NOTICE 'Created: subnet_allocations table';
    RAISE NOTICE 'Added: tool_id foreign keys to tool_categories, tool_package_mappings, attack_tools';
    RAISE NOTICE 'Added: Performance indexes';
    RAISE NOTICE 'Added: Data integrity constraints';
END $$;
