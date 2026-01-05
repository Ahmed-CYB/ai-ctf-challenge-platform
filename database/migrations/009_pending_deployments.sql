-- Migration 009: Add pending_deployments table for deployment confirmation flow
-- Created: 2025-01-XX
-- Purpose: Store pending deployment requests waiting for user confirmation

CREATE TABLE IF NOT EXISTS pending_deployments (
    session_id VARCHAR(255) PRIMARY KEY,
    challenge_name VARCHAR(255) NOT NULL,
    existing_challenge_name VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_pending_deployment_session FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_pending_deployments_session ON pending_deployments(session_id);
CREATE INDEX IF NOT EXISTS idx_pending_deployments_challenge ON pending_deployments(challenge_name);

-- Add comment
COMMENT ON TABLE pending_deployments IS 'Stores pending deployment requests waiting for user confirmation when another challenge is already running';

