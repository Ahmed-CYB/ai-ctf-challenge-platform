-- Migration: Add missing columns to sessions table
-- Date: 2025-12-30
-- Description: Add expires_at, ip_address, and user_agent columns for secure session management

-- Add expires_at column (nullable first)
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'sessions' AND column_name = 'expires_at') THEN
        ALTER TABLE sessions ADD COLUMN expires_at TIMESTAMP;
    END IF;
END $$;

-- Add ip_address column
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'sessions' AND column_name = 'ip_address') THEN
        ALTER TABLE sessions ADD COLUMN ip_address VARCHAR(45);
    END IF;
END $$;

-- Add user_agent column
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'sessions' AND column_name = 'user_agent') THEN
        ALTER TABLE sessions ADD COLUMN user_agent TEXT;
    END IF;
END $$;

-- Update existing sessions to have expires_at (set to 1 hour from last_activity)
UPDATE sessions 
SET expires_at = last_activity + INTERVAL '1 hour'
WHERE expires_at IS NULL;

-- Make expires_at NOT NULL for new sessions (after setting defaults)
ALTER TABLE sessions 
ALTER COLUMN expires_at SET NOT NULL;

-- Add index for expired session cleanup
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

