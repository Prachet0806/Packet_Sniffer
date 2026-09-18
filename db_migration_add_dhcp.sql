-- Database Migration: bring protocol_stats up to the current schema
-- Description: adds any missing per-protocol packet/byte columns, including
-- DHCP. Fresh installs don't need this (the app's db_ensure_schema creates
-- the full table); run it once against databases created by older versions.

DO $$
DECLARE
    col TEXT;
    cols TEXT[] := ARRAY[
        'total_packets', 'total_bytes',
        'ethernet', 'ethernet_bytes',
        'ipv4', 'ipv4_bytes',
        'ipv6', 'ipv6_bytes',
        'tcp', 'tcp_bytes',
        'udp', 'udp_bytes',
        'icmp', 'icmp_bytes',
        'arp', 'arp_bytes',
        'dns', 'dns_bytes',
        'http', 'http_bytes',
        'https', 'https_bytes',
        'dhcp', 'dhcp_bytes'
    ];
BEGIN
    FOREACH col IN ARRAY cols LOOP
        IF NOT EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_name = 'protocol_stats'
            AND column_name = col
        ) THEN
            EXECUTE format('ALTER TABLE protocol_stats ADD COLUMN %I BIGINT NOT NULL DEFAULT 0', col);
            RAISE NOTICE 'Column % added successfully', col;
        ELSE
            RAISE NOTICE 'Column % already exists, skipping', col;
        END IF;
    END LOOP;
END $$;

-- Verify the change
SELECT column_name, data_type, is_nullable, column_default
FROM information_schema.columns
WHERE table_name = 'protocol_stats'
ORDER BY ordinal_position;
