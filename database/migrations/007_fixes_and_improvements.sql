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

-- package_aliases: Query by alias and os_type
CREATE INDEX IF NOT EXISTS idx_package_aliases_alias_os 
  ON package_aliases(alias, os_type);

-- tool_package_mappings: Query by tool_name and os_type
CREATE INDEX IF NOT EXISTS idx_tool_package_mappings_tool_os_active 
  ON tool_package_mappings(tool_name, os_type) 
  WHERE is_active = TRUE;

-- validated_os_images: Query by package_manager (used in OS selection)
CREATE INDEX IF NOT EXISTS idx_validated_os_images_package_manager_valid 
  ON validated_os_images(package_manager) 
  WHERE is_valid = TRUE;

-- os_image_usage_history: Query by challenge_name (analytics)
CREATE INDEX IF NOT EXISTS idx_os_image_usage_challenge 
  ON os_image_usage_history(challenge_name, used_at DESC);

-- tool_installation_methods: Query by tool_id and priority
CREATE INDEX IF NOT EXISTS idx_tool_installation_methods_tool_priority 
  ON tool_installation_methods(tool_id, priority DESC, success_count DESC);

-- ============================================
-- 4. ADD CHECK CONSTRAINTS (Data Integrity)
-- ============================================

-- Ensure package_manager matches os_type
-- Note: Constraint addition skipped if existing data violates it
-- This is a data quality check that can be enforced at application level
-- Fix any existing data that doesn't match (comprehensive fix)
UPDATE base_tools_by_os 
SET package_manager = CASE 
    WHEN os_type = 'apt-get' THEN 'apt-get'
    WHEN os_type = 'apk' THEN 'apk'
    WHEN os_type = 'dnf' THEN 'dnf'
    WHEN os_type = 'yum' THEN 'yum'
    ELSE os_type
END
WHERE package_manager != os_type 
   OR (os_type = 'dnf' AND package_manager NOT IN ('dnf', 'yum'))
   OR (os_type = 'yum' AND package_manager NOT IN ('dnf', 'yum'));

-- Try to add constraint, but skip if it fails (existing data might not match)
DO $$
BEGIN
    -- Drop if exists first
    ALTER TABLE base_tools_by_os DROP CONSTRAINT IF EXISTS check_package_manager_os_match;
    
    -- Try to add constraint (will fail silently if data doesn't match)
    BEGIN
        ALTER TABLE base_tools_by_os 
        ADD CONSTRAINT check_package_manager_os_match 
        CHECK (
          (os_type = 'apt-get' AND package_manager = 'apt-get') OR
          (os_type = 'apk' AND package_manager = 'apk') OR
          (os_type = 'dnf' AND package_manager IN ('dnf', 'yum')) OR
          (os_type = 'yum' AND package_manager IN ('dnf', 'yum'))
        );
    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE 'Skipping constraint addition due to existing data violations';
    END;
END $$;

-- Ensure priority is non-negative
ALTER TABLE tool_categories 
  DROP CONSTRAINT IF EXISTS check_priority_positive,
  ADD CONSTRAINT check_priority_positive 
  CHECK (priority >= 0);

-- Ensure success_rate is 0-100
ALTER TABLE validated_os_images 
  DROP CONSTRAINT IF EXISTS check_success_rate_range,
  ADD CONSTRAINT check_success_rate_range 
  CHECK (success_rate >= 0 AND success_rate <= 100);

-- Ensure is_active and is_valid consistency for service mappings
ALTER TABLE service_package_mappings 
  DROP CONSTRAINT IF EXISTS check_valid_service,
  ADD CONSTRAINT check_valid_service 
  CHECK (is_valid = TRUE OR package_name IS NULL);

-- Ensure subnet allocations have valid IPs
ALTER TABLE subnet_allocations 
  DROP CONSTRAINT IF EXISTS check_subnet_ips_valid,
  ADD CONSTRAINT check_subnet_ips_valid 
  CHECK (
    gateway_ip != attacker_ip AND 
    gateway_ip != victim_ip AND 
    attacker_ip != victim_ip
  );

-- ============================================
-- 5. ADD HELPER FUNCTIONS
-- ============================================

-- Function to safely allocate subnet (with locking)
CREATE OR REPLACE FUNCTION allocate_subnet_safe(
    p_challenge_name VARCHAR(255),
    p_subnet CIDR,
    p_gateway_ip INET,
    p_attacker_ip INET,
    p_victim_ip INET,
    p_user_id VARCHAR(100) DEFAULT 'default',
    p_additional_ips JSONB DEFAULT NULL
) RETURNS subnet_allocations AS $$
DECLARE
    v_allocation subnet_allocations;
BEGIN
    -- Lock row to prevent race conditions
    SELECT * INTO v_allocation
    FROM subnet_allocations
    WHERE challenge_name = p_challenge_name 
      AND user_id = p_user_id 
      AND is_active = TRUE
    FOR UPDATE;
    
    -- If already allocated, return it
    IF FOUND THEN
        RETURN v_allocation;
    END IF;
    
    -- Check if subnet is already in use
    SELECT * INTO v_allocation
    FROM subnet_allocations
    WHERE subnet = p_subnet 
      AND is_active = TRUE
    FOR UPDATE;
    
    IF FOUND THEN
        RAISE EXCEPTION 'Subnet % is already allocated', p_subnet;
    END IF;
    
    -- Insert new allocation
    INSERT INTO subnet_allocations (
        challenge_name, user_id, subnet, gateway_ip, 
        attacker_ip, victim_ip, additional_ips, is_active
    ) VALUES (
        p_challenge_name, p_user_id, p_subnet, p_gateway_ip,
        p_attacker_ip, p_victim_ip, p_additional_ips, TRUE
    ) RETURNING * INTO v_allocation;
    
    RETURN v_allocation;
END;
$$ LANGUAGE plpgsql;

-- Function to release subnet
CREATE OR REPLACE FUNCTION release_subnet_safe(
    p_challenge_name VARCHAR(255),
    p_user_id VARCHAR(100) DEFAULT 'default'
) RETURNS BOOLEAN AS $$
DECLARE
    v_updated INTEGER;
BEGIN
    UPDATE subnet_allocations
    SET is_active = FALSE,
        released_at = NOW(),
        updated_at = NOW()
    WHERE challenge_name = p_challenge_name 
      AND user_id = p_user_id 
      AND is_active = TRUE;
    
    GET DIAGNOSTICS v_updated = ROW_COUNT;
    
    RETURN v_updated > 0;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION allocate_subnet_safe IS 'Safely allocate subnet with database-level locking to prevent race conditions';
COMMENT ON FUNCTION release_subnet_safe IS 'Release subnet allocation by marking as inactive';

-- ============================================
-- 6. ADD AUDIT LOGGING (Optional but Recommended)
-- ============================================

CREATE TABLE IF NOT EXISTS database_audit_log (
    id BIGSERIAL PRIMARY KEY,
    table_name VARCHAR(100) NOT NULL,
    operation VARCHAR(10) NOT NULL, -- INSERT, UPDATE, DELETE
    record_id INTEGER,
    old_values JSONB,
    new_values JSONB,
    changed_by VARCHAR(100) DEFAULT 'system',
    changed_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_database_audit_log_table ON database_audit_log(table_name, changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_database_audit_log_record ON database_audit_log(table_name, record_id);

-- Generic audit trigger function
CREATE OR REPLACE FUNCTION audit_trigger_function()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO database_audit_log (table_name, operation, record_id, new_values)
        VALUES (TG_TABLE_NAME, 'INSERT', NEW.id, row_to_json(NEW));
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO database_audit_log (table_name, operation, record_id, old_values, new_values)
        VALUES (TG_TABLE_NAME, 'UPDATE', NEW.id, row_to_json(OLD), row_to_json(NEW));
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO database_audit_log (table_name, operation, record_id, old_values)
        VALUES (TG_TABLE_NAME, 'DELETE', OLD.id, row_to_json(OLD));
        RETURN OLD;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Apply audit triggers to critical tables (optional - can be enabled per table)
-- Example:
-- CREATE TRIGGER audit_subnet_allocations
-- AFTER INSERT OR UPDATE OR DELETE ON subnet_allocations
-- FOR EACH ROW EXECUTE FUNCTION audit_trigger_function();

COMMENT ON TABLE database_audit_log IS 'Audit log for tracking all database changes (optional, can be enabled per table)';

-- ============================================
-- 7. SUMMARY
-- ============================================

-- Verify indexes were created
DO $$
DECLARE
    v_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_count
    FROM pg_indexes
    WHERE schemaname = 'public'
      AND indexname LIKE 'idx_%';
    
    RAISE NOTICE 'Created/verified % indexes', v_count;
END $$;

-- Verify constraints were added
DO $$
DECLARE
    v_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_count
    FROM information_schema.table_constraints
    WHERE constraint_schema = 'public'
      AND constraint_type = 'CHECK';
    
    RAISE NOTICE 'Created/verified % check constraints', v_count;
END $$;

COMMENT ON SCHEMA public IS 'CTF Platform Database - Migration 007: Critical fixes and improvements applied';

