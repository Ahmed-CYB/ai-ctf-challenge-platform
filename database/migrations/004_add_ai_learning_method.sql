-- Add AI learning method tracking
-- Migration: 004_add_ai_learning_method.sql

-- Add learning_method column to track how the tool was learned
ALTER TABLE tool_learning_queue 
ADD COLUMN IF NOT EXISTS learning_method VARCHAR(50) DEFAULT 'unknown';

-- Update existing records
UPDATE tool_learning_queue 
SET learning_method = 'legacy' 
WHERE learning_method = 'unknown' AND status = 'learned';

-- Add comment
COMMENT ON COLUMN tool_learning_queue.learning_method IS 'Method used to learn installation: ai, readme, web, pattern, manual';

-- Create index for querying by learning method
CREATE INDEX IF NOT EXISTS idx_learning_queue_method ON tool_learning_queue(learning_method);

-- Add statistics view for learning methods
CREATE OR REPLACE VIEW tool_learning_stats AS
SELECT 
    learning_method,
    status,
    COUNT(*) as tool_count,
    AVG(attempts) as avg_attempts,
    MAX(updated_at) as last_learned
FROM tool_learning_queue
GROUP BY learning_method, status
ORDER BY tool_count DESC;
