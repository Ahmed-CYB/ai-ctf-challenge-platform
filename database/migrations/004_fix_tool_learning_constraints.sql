-- Fix tool_learning_queue to add UNIQUE constraint on tool_name
-- This fixes: "there is no unique or exclusion constraint matching the ON CONFLICT specification"

-- Check if constraint exists before adding (PostgreSQL doesn't support IF NOT EXISTS for constraints)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint 
        WHERE conname = 'tool_learning_queue_tool_name_unique'
    ) THEN
        ALTER TABLE tool_learning_queue 
        ADD CONSTRAINT tool_learning_queue_tool_name_unique UNIQUE (tool_name);
    END IF;
END $$;

-- Add index for performance
CREATE INDEX IF NOT EXISTS idx_tool_learning_queue_tool_name ON tool_learning_queue(tool_name);

