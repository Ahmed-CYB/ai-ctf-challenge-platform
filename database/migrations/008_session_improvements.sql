-- Session Management Improvements
-- Phase 1 & 2: Database-backed session storage and activity tracking
-- Created: 2026-01-02

-- ============================================
-- 1. Session Guacamole Users Table
-- Stores session -> Guacamole user mappings in database
-- ============================================
CREATE TABLE IF NOT EXISTS session_guacamole_users (
  session_id VARCHAR(255) PRIMARY KEY,
  guacamole_username VARCHAR(255) NOT NULL,
  guacamole_entity_id INT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  expires_at TIMESTAMP NOT NULL,
  last_activity TIMESTAMP DEFAULT NOW(),
  FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_session_guacamole_expires ON session_guacamole_users(expires_at);
CREATE INDEX IF NOT EXISTS idx_session_guacamole_username ON session_guacamole_users(guacamole_username);

-- ============================================
-- 2. Session Activity Tracking Table
-- Tracks detailed activity per session for analytics and debugging
-- ============================================
CREATE TABLE IF NOT EXISTS session_activity (
  id SERIAL PRIMARY KEY,
  session_id VARCHAR(255) NOT NULL,
  activity_type VARCHAR(50) NOT NULL, -- 'message', 'deployment', 'connection', 'validation'
  activity_data JSONB,
  timestamp TIMESTAMP DEFAULT NOW(),
  FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_session_activity_session ON session_activity(session_id);
CREATE INDEX IF NOT EXISTS idx_session_activity_type ON session_activity(activity_type);
CREATE INDEX IF NOT EXISTS idx_session_activity_timestamp ON session_activity(timestamp);

-- ============================================
-- 3. Add index to sessions table for faster expiration queries
-- ============================================
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_last_activity ON sessions(last_activity);

-- ============================================
-- 4. Comments
-- ============================================
COMMENT ON TABLE session_guacamole_users IS 'Maps CTF platform sessions to Guacamole user accounts for persistence across server restarts';
COMMENT ON TABLE session_activity IS 'Tracks detailed activity per session for analytics, debugging, and audit purposes';
COMMENT ON COLUMN session_activity.activity_type IS 'Type of activity: message, deployment, connection, validation, cleanup';
COMMENT ON COLUMN session_activity.activity_data IS 'JSON object containing activity-specific data (e.g., challenge name, IP addresses, error messages)';

