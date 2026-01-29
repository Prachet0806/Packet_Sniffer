-- Database Migration: Add DHCP Column
-- Description: Adds DHCP protocol tracking column to protocol_stats table

-- Check if column exists before adding
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_name = 'protocol_stats' 
        AND column_name = 'dhcp'
    ) THEN
        -- Add DHCP column
        ALTER TABLE protocol_stats 
        ADD COLUMN dhcp BIGINT NOT NULL DEFAULT 0;
        
        RAISE NOTICE 'DHCP column added successfully';
    ELSE
        RAISE NOTICE 'DHCP column already exists, skipping';
    END IF;
END $$;

-- Verify the change
SELECT column_name, data_type, is_nullable, column_default
FROM information_schema.columns
WHERE table_name = 'protocol_stats'
ORDER BY ordinal_position;
