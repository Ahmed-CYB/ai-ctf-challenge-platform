-- ============================================
-- AI CTF Challenge Platform - Database Schema
-- ============================================
-- Created: December 14, 2025
-- Database: PostgreSQL
-- ============================================

-- Drop existing tables (if recreating)
DROP TABLE IF EXISTS user_activity_log CASCADE;
DROP TABLE IF EXISTS challenge_submissions CASCADE;
DROP TABLE IF EXISTS chat_messages CASCADE;
DROP TABLE IF EXISTS challenges CASCADE;
DROP TABLE IF EXISTS sessions CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- ============================================
-- USERS TABLE
-- ============================================
CREATE TABLE users (
  -- Primary Key
  user_id SERIAL PRIMARY KEY,
  
  -- Authentication (Required)
  username VARCHAR(50) UNIQUE NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  
  -- Profile Information
  name VARCHAR(100),
  bio TEXT,
  profile_avatar VARCHAR(500),
  
  -- Role & Permissions
  role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('user', 'admin', 'moderator')),
  is_verified BOOLEAN DEFAULT FALSE,
  is_active BOOLEAN DEFAULT TRUE,
  
  -- Leaderboard Stats (NO POINTS!)
  challenges_solved INTEGER DEFAULT 0,
  challenges_created INTEGER DEFAULT 0,
  solve_rank INTEGER,
  
  -- Social/Contact
  github_username VARCHAR(100),
  twitter_handle VARCHAR(100),
  website_url VARCHAR(500),
  
  -- Security & Privacy
  two_factor_enabled BOOLEAN DEFAULT FALSE,
  two_factor_secret VARCHAR(255),
  last_login TIMESTAMP,
  failed_login_attempts INTEGER DEFAULT 0,
  account_locked_until TIMESTAMP,
  
  -- Privacy Settings
  profile_visibility VARCHAR(20) DEFAULT 'public' CHECK (profile_visibility IN ('public', 'private', 'friends')),
  show_email BOOLEAN DEFAULT FALSE,
  
  -- Preferences
  theme VARCHAR(20) DEFAULT 'dark',
  notifications_enabled BOOLEAN DEFAULT TRUE,
  email_notifications BOOLEAN DEFAULT TRUE,
  
  -- Metadata
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_active TIMESTAMP,
  deleted_at TIMESTAMP,
  
  -- Animal Avatar
  avatar_animal_id VARCHAR(50),
  
  CONSTRAINT users_username_key UNIQUE (username),
  CONSTRAINT users_email_key UNIQUE (email)
);

-- Indexes for Users
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_challenges_solved ON users(challenges_solved DESC);
CREATE INDEX idx_users_created_at ON users(created_at);

-- ============================================
-- SESSIONS TABLE
-- ============================================
CREATE TABLE sessions (
  session_id VARCHAR(255) PRIMARY KEY,
  user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL,
  ip_address VARCHAR(45),
  user_agent TEXT,
  is_active BOOLEAN DEFAULT TRUE
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_created_at ON sessions(created_at);

-- ============================================
-- CHALLENGES TABLE
-- ============================================
CREATE TABLE challenges (
  challenge_id SERIAL PRIMARY KEY,
  challenge_name VARCHAR(255) NOT NULL,
  slug VARCHAR(255) UNIQUE NOT NULL,
  user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
  
  -- Challenge Details
  category VARCHAR(50) NOT NULL,
  difficulty VARCHAR(20),
  description TEXT,
  hints TEXT[],
  flag VARCHAR(255) NOT NULL,
  
  -- Deployment Info
  github_link VARCHAR(500),
  docker_image VARCHAR(255),
  dockerfile_path VARCHAR(500),
  build_command TEXT,
  deploy_command TEXT,
  run_command TEXT,
  container_name VARCHAR(255),
  target_url VARCHAR(500),
  expected_ports INTEGER[],
  deployment_notes TEXT,
  
  -- Status
  is_active BOOLEAN DEFAULT TRUE,
  is_deployed BOOLEAN DEFAULT FALSE,
  
  -- Metadata
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  
  CONSTRAINT challenges_slug_key UNIQUE (slug)
);

CREATE INDEX idx_challenges_user_id ON challenges(user_id);
CREATE INDEX idx_challenges_category ON challenges(category);
CREATE INDEX idx_challenges_difficulty ON challenges(difficulty);
CREATE INDEX idx_challenges_slug ON challenges(slug);
CREATE INDEX idx_challenges_is_active ON challenges(is_active);
CREATE INDEX idx_challenges_created_at ON challenges(created_at DESC);

-- ============================================
-- CHAT MESSAGES TABLE
-- ============================================
CREATE TABLE chat_messages (
  message_id SERIAL PRIMARY KEY,
  session_id VARCHAR(255) NOT NULL,
  user_id INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
  role VARCHAR(20) NOT NULL CHECK (role IN ('user', 'assistant')),
  message_text TEXT NOT NULL,
  challenge_id INTEGER REFERENCES challenges(challenge_id) ON DELETE SET NULL,
  metadata JSON,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_chat_messages_session_id ON chat_messages(session_id);
CREATE INDEX idx_chat_messages_user_id ON chat_messages(user_id);
CREATE INDEX idx_chat_messages_timestamp ON chat_messages(timestamp DESC);
CREATE INDEX idx_chat_messages_challenge_id ON chat_messages(challenge_id);

-- ============================================
-- CHALLENGE SUBMISSIONS TABLE
-- ============================================
CREATE TABLE challenge_submissions (
  submission_id SERIAL PRIMARY KEY,
  challenge_id INTEGER REFERENCES challenges(challenge_id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
  submitted_flag VARCHAR(255),
  is_correct BOOLEAN,
  solve_date DATE,
  submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(challenge_id, user_id)
);

CREATE INDEX idx_submissions_challenge_id ON challenge_submissions(challenge_id);
CREATE INDEX idx_submissions_user_id ON challenge_submissions(user_id);
CREATE INDEX idx_submissions_user_date ON challenge_submissions(user_id, solve_date DESC);
CREATE INDEX idx_submissions_correct ON challenge_submissions(is_correct);

-- ============================================
-- USER ACTIVITY LOG TABLE
-- ============================================
CREATE TABLE user_activity_log (
  log_id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
  activity_type VARCHAR(50) NOT NULL,
  ip_address VARCHAR(45),
  user_agent TEXT,
  metadata JSON,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_activity_log_user_id ON user_activity_log(user_id);
CREATE INDEX idx_activity_log_activity_type ON user_activity_log(activity_type);
CREATE INDEX idx_activity_log_created_at ON user_activity_log(created_at DESC);

-- ============================================
-- FUNCTIONS & TRIGGERS
-- ============================================

-- Function: Update updated_at timestamp automatically
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers for updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_challenges_updated_at BEFORE UPDATE ON challenges
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================
-- SAMPLE DATA (Optional - Remove if not needed)
-- ============================================

-- Insert admin user (password: 'admin123' - CHANGE THIS!)
-- Note: Use bcrypt to hash passwords in production
INSERT INTO users (username, email, password_hash, name, role, is_verified)
VALUES 
  ('admin', 'admin@ctfplatform.com', '$2b$10$rBV2MhMkYq0f7E0N2CqKZuGXFpEy7BZKgPnGvOZ9xH9kSq5P0qYne', 'Admin User', 'admin', TRUE);

-- ============================================
-- USEFUL QUERIES
-- ============================================

-- Leaderboard: Most Challenges Solved
-- SELECT 
--   ROW_NUMBER() OVER (ORDER BY challenges_solved DESC, created_at ASC) as rank,
--   username, name, profile_avatar, avatar_animal_id, challenges_solved
-- FROM users
-- WHERE is_active = TRUE AND deleted_at IS NULL
-- ORDER BY challenges_solved DESC LIMIT 100;

-- Get user's chat history
-- SELECT message_text, role, timestamp
-- FROM chat_messages
-- WHERE session_id = 'your-session-id'
-- ORDER BY timestamp ASC;

-- Get user's solve history
-- SELECT c.challenge_name, cs.solve_date, cs.submitted_at
-- FROM challenge_submissions cs
-- JOIN challenges c ON cs.challenge_id = c.challenge_id
-- WHERE cs.user_id = 1 AND cs.is_correct = TRUE
-- ORDER BY cs.solve_date DESC;

-- ============================================
-- END OF SCHEMA
-- ============================================
