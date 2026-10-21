BEGIN;
CREATE TABLE IF NOT EXISTS sniffer_schema(version INTEGER PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
-- Preserve all historical protocol_stats tables: their aggregate semantics cannot be repaired.
CREATE TABLE IF NOT EXISTS protocol_stats_v2 (
    event_id TEXT PRIMARY KEY,
    sensor_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    interval_start TIMESTAMPTZ NOT NULL,
    interval_end TIMESTAMPTZ NOT NULL,
    duration_seconds DOUBLE PRECISION NOT NULL CHECK (duration_seconds > 0),
    semantics_version INTEGER NOT NULL DEFAULT 2,
    total_packets BIGINT NOT NULL DEFAULT 0,
    total_bytes BIGINT NOT NULL DEFAULT 0,
    wire_bytes BIGINT NOT NULL DEFAULT 0,
    analyzed BIGINT NOT NULL DEFAULT 0,
    queue_drops BIGINT NOT NULL DEFAULT 0,
    allocation_drops BIGINT NOT NULL DEFAULT 0,
    recording_errors BIGINT NOT NULL DEFAULT 0,
    malformed BIGINT NOT NULL DEFAULT 0,
    truncated BIGINT NOT NULL DEFAULT 0,
    unsupported BIGINT NOT NULL DEFAULT 0,
    incomplete BIGINT NOT NULL DEFAULT 0,
    alert_drops BIGINT NOT NULL DEFAULT 0,
    state_evictions BIGINT NOT NULL DEFAULT 0,
    ethernet BIGINT NOT NULL DEFAULT 0,
    ethernet_bytes BIGINT NOT NULL DEFAULT 0,
    ipv4 BIGINT NOT NULL DEFAULT 0,
    ipv4_bytes BIGINT NOT NULL DEFAULT 0,
    ipv6 BIGINT NOT NULL DEFAULT 0,
    ipv6_bytes BIGINT NOT NULL DEFAULT 0,
    tcp BIGINT NOT NULL DEFAULT 0,
    tcp_bytes BIGINT NOT NULL DEFAULT 0,
    udp BIGINT NOT NULL DEFAULT 0,
    udp_bytes BIGINT NOT NULL DEFAULT 0,
    icmp BIGINT NOT NULL DEFAULT 0,
    icmp_bytes BIGINT NOT NULL DEFAULT 0,
    arp BIGINT NOT NULL DEFAULT 0,
    arp_bytes BIGINT NOT NULL DEFAULT 0,
    dns BIGINT NOT NULL DEFAULT 0,
    dns_bytes BIGINT NOT NULL DEFAULT 0,
    http BIGINT NOT NULL DEFAULT 0,
    http_bytes BIGINT NOT NULL DEFAULT 0,
    https BIGINT NOT NULL DEFAULT 0,
    https_bytes BIGINT NOT NULL DEFAULT 0,
    dhcp BIGINT NOT NULL DEFAULT 0,
    dhcp_bytes BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS stats_v2_sensor_time ON protocol_stats_v2(sensor_id, interval_start);
CREATE TABLE IF NOT EXISTS alerts_v2 (
    event_id TEXT PRIMARY KEY, sensor_id TEXT NOT NULL, session_id TEXT NOT NULL,
    time TIMESTAMPTZ NOT NULL, type TEXT NOT NULL, src TEXT NOT NULL, dst TEXT NOT NULL, detail TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'warning', confidence TEXT NOT NULL DEFAULT 'heuristic'
);
CREATE INDEX IF NOT EXISTS alerts_v2_sensor_time ON alerts_v2(sensor_id, time);
INSERT INTO sniffer_schema(version) VALUES (2) ON CONFLICT DO NOTHING;
COMMIT;
