-- Update sessions table for secure session management
-- Run this migration to add required fields

-- Add new columns to sessions table
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ip_address VARCHAR(45);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS user_agent TEXT;

-- Update existing sessions with default expiration (1 hour from now)
UPDATE sessions 
SET expires_at = NOW() + INTERVAL '1 hour' 
WHERE expires_at IS NULL;

-- Create index for faster session cleanup
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_last_activity ON sessions(last_activity);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);

-- Add comment to table
COMMENT ON TABLE sessions IS 'Secure session management with OWASP best practices';
COMMENT ON COLUMN sessions.session_id IS 'Cryptographically secure random session ID (256 bits)';
COMMENT ON COLUMN sessions.expires_at IS 'Absolute session expiration (60 minutes from creation)';
COMMENT ON COLUMN sessions.last_activity IS 'Last activity timestamp for inactivity timeout (30 minutes)';
COMMENT ON COLUMN sessions.ip_address IS 'IP address for session hijacking detection';
COMMENT ON COLUMN sessions.user_agent IS 'User agent for session validation';

