# AWS RDS Quick Reference

Quick commands and configurations for AWS RDS PostgreSQL setup.

## Environment Variable Setup

### Windows PowerShell
```powershell
$env:AWS_RDS_CONNINFO="host=YOUR-ENDPOINT.REGION.rds.amazonaws.com port=5432 dbname=snifferdb user=sniffer_admin password=YOUR-PASSWORD sslmode=require"
```

### Linux/macOS
```bash
export AWS_RDS_CONNINFO="host=YOUR-ENDPOINT.REGION.rds.amazonaws.com port=5432 dbname=snifferdb user=sniffer_admin password=YOUR-PASSWORD sslmode=require"
```

### .env File
```bash
AWS_RDS_CONNINFO=host=YOUR-ENDPOINT.REGION.rds.amazonaws.com port=5432 dbname=snifferdb user=sniffer_admin password=YOUR-PASSWORD sslmode=require
```

## Common AWS CLI Commands

### List RDS Instances
```bash
aws rds describe-db-instances --query "DBInstances[*].[DBInstanceIdentifier,Endpoint.Address,DBInstanceStatus]" --output table
```

### Get RDS Endpoint
```bash
aws rds describe-db-instances --db-instance-identifier packet-sniffer-db --query "DBInstances[0].Endpoint.Address" --output text
```

### Modify Security Group
```bash
# Get security group ID
aws rds describe-db-instances --db-instance-identifier packet-sniffer-db --query "DBInstances[0].VpcSecurityGroups[0].VpcSecurityGroupId" --output text

# Add your IP to security group
aws ec2 authorize-security-group-ingress \
  --group-id YOUR-SG-ID \
  --protocol tcp \
  --port 5432 \
  --cidr YOUR-IP/32
```

### Stop RDS Instance (Save Costs)
```bash
aws rds stop-db-instance --db-instance-identifier packet-sniffer-db
```

### Start RDS Instance
```bash
aws rds start-db-instance --db-instance-identifier packet-sniffer-db
```

### Create Snapshot
```bash
aws rds create-db-snapshot \
  --db-instance-identifier packet-sniffer-db \
  --db-snapshot-identifier packet-sniffer-snapshot-$(date +%Y%m%d)
```

## PostgreSQL Commands

### Connect to Database
```bash
psql "$AWS_RDS_CONNINFO"
```

### Quick Connection Test
```bash
psql "$AWS_RDS_CONNINFO" -c "SELECT version();"
```

### Create Schema
```sql
CREATE TABLE IF NOT EXISTS protocol_stats (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_packets BIGINT NOT NULL DEFAULT 0,
    ethernet BIGINT NOT NULL DEFAULT 0,
    ipv4 BIGINT NOT NULL DEFAULT 0,
    ipv6 BIGINT NOT NULL DEFAULT 0,
    tcp BIGINT NOT NULL DEFAULT 0,
    udp BIGINT NOT NULL DEFAULT 0,
    icmp BIGINT NOT NULL DEFAULT 0,
    arp BIGINT NOT NULL DEFAULT 0,
    dns BIGINT NOT NULL DEFAULT 0,
    http BIGINT NOT NULL DEFAULT 0,
    https BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_protocol_stats_timestamp 
    ON protocol_stats(timestamp);
```

### Useful Queries

```sql
-- Check recent stats
SELECT * FROM protocol_stats ORDER BY timestamp DESC LIMIT 10;

-- Count total rows
SELECT COUNT(*) FROM protocol_stats;

-- Get stats for last hour
SELECT * FROM protocol_stats 
WHERE timestamp > NOW() - INTERVAL '1 hour'
ORDER BY timestamp DESC;

-- Aggregate stats by hour
SELECT 
    DATE_TRUNC('hour', timestamp) AS hour,
    SUM(total_packets) AS packets,
    SUM(tcp) AS tcp,
    SUM(udp) AS udp
FROM protocol_stats
WHERE timestamp > NOW() - INTERVAL '24 hours'
GROUP BY hour
ORDER BY hour DESC;

-- Delete old data (keep last 30 days)
DELETE FROM protocol_stats 
WHERE timestamp < NOW() - INTERVAL '30 days';

-- Table size
SELECT pg_size_pretty(pg_total_relation_size('protocol_stats'));
```

## Monitoring

### Check Connection Count
```sql
SELECT count(*) FROM pg_stat_activity;
```

### View Active Connections
```sql
SELECT 
    datname,
    usename,
    application_name,
    client_addr,
    state
FROM pg_stat_activity
WHERE datname = 'snifferdb';
```

### Check Last Write
```sql
SELECT MAX(timestamp) as last_write FROM protocol_stats;
```

## Troubleshooting

### Test Network Connectivity
```bash
# Test if port is open
nc -zv YOUR-ENDPOINT.REGION.rds.amazonaws.com 5432

# Or using telnet
telnet YOUR-ENDPOINT.REGION.rds.amazonaws.com 5432
```

### Download SSL Certificate
```bash
mkdir -p certs
curl -o certs/rds-ca-bundle.pem https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem
```

### Check Application Logs
Look for these messages:
```
[+] Using Postgres conninfo from AWS_RDS_CONNINFO     # Good
[+] Postgres connection established                    # Good
[!] Postgres connection failed                         # Problem
[!] Postgres insert failed: ...                        # Problem
```

### Common Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| "Connection refused" | Security group blocks access | Add your IP to security group |
| "Authentication failed" | Wrong credentials | Verify username/password |
| "SSL required" | Missing sslmode | Add `sslmode=require` |
| "Database does not exist" | Database not created | Create database first |
| "Timeout" | Network/VPC issue | Check VPC, subnets, routing |

## AWS Console URLs

### RDS Dashboard
```
https://console.aws.amazon.com/rds/home?region=us-east-1#databases:
```

### Security Groups
```
https://console.aws.amazon.com/ec2/v2/home?region=us-east-1#SecurityGroups:
```

### CloudWatch Metrics
```
https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:
```

## Cost Management

### View Current Costs
```bash
# Get RDS costs for current month
aws ce get-cost-and-usage \
  --time-period Start=2026-01-01,End=2026-01-31 \
  --granularity MONTHLY \
  --metrics UnblendedCost \
  --filter file://filter.json

# filter.json content:
# {
#   "Dimensions": {
#     "Key": "SERVICE",
#     "Values": ["Amazon Relational Database Service"]
#   }
# }
```

### Set Up Billing Alarm
```bash
aws cloudwatch put-metric-alarm \
  --alarm-name rds-monthly-cost \
  --alarm-description "Alert if RDS cost exceeds threshold" \
  --metric-name EstimatedCharges \
  --namespace AWS/Billing \
  --statistic Maximum \
  --period 86400 \
  --evaluation-periods 1 \
  --threshold 50.0 \
  --comparison-operator GreaterThanThreshold
```

## Backup and Restore

### Manual Backup (Using pg_dump)
```bash
# Backup
pg_dump "$AWS_RDS_CONNINFO" > backup_$(date +%Y%m%d_%H%M%S).sql

# Restore
psql "$AWS_RDS_CONNINFO" < backup_20260129_120000.sql
```

### List Automated Backups
```bash
aws rds describe-db-snapshots \
  --db-instance-identifier packet-sniffer-db \
  --snapshot-type automated
```

### Restore from Snapshot
```bash
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier packet-sniffer-db-restored \
  --db-snapshot-identifier YOUR-SNAPSHOT-ID
```

## Performance Tuning

### Key PostgreSQL Parameters
```sql
-- View current settings
SHOW all;

-- Important settings for this workload
SHOW max_connections;           -- Should be >= 10
SHOW shared_buffers;            -- 25% of RAM is typical
SHOW effective_cache_size;      -- 50-75% of RAM
SHOW work_mem;                  -- For query operations
SHOW maintenance_work_mem;      -- For maintenance operations
```

### RDS Parameter Groups
```bash
# List parameter groups
aws rds describe-db-parameter-groups

# View parameters
aws rds describe-db-parameters \
  --db-parameter-group-name default.postgres15
```

## Useful Aliases

Add to your shell profile (~/.bashrc or ~/.zshrc):

```bash
# AWS RDS aliases
alias rds-connect='psql "$AWS_RDS_CONNINFO"'
alias rds-status='psql "$AWS_RDS_CONNINFO" -c "SELECT version();"'
alias rds-stats='psql "$AWS_RDS_CONNINFO" -c "SELECT * FROM protocol_stats ORDER BY timestamp DESC LIMIT 10;"'
alias rds-count='psql "$AWS_RDS_CONNINFO" -c "SELECT COUNT(*) FROM protocol_stats;"'
alias rds-backup='pg_dump "$AWS_RDS_CONNINFO" > backup_$(date +%Y%m%d_%H%M%S).sql'
```

Windows PowerShell (add to $PROFILE):
```powershell
function rds-connect { psql $env:AWS_RDS_CONNINFO }
function rds-status { psql $env:AWS_RDS_CONNINFO -c "SELECT version();" }
function rds-stats { psql $env:AWS_RDS_CONNINFO -c "SELECT * FROM protocol_stats ORDER BY timestamp DESC LIMIT 10;" }
```

## Security Checklist

- [ ] Security group restricted to specific IPs
- [ ] SSL/TLS enabled (sslmode=require)
- [ ] Strong password (12+ characters)
- [ ] Encryption at rest enabled
- [ ] Automated backups enabled
- [ ] CloudWatch alarms configured
- [ ] Credentials in environment variables (not hardcoded)
- [ ] Regular password rotation scheduled
- [ ] VPC properly configured
- [ ] Monitoring and alerting active

## Further Reading

- [AWS RDS Best Practices](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_BestPractices.html)
- [PostgreSQL Performance Tuning](https://wiki.postgresql.org/wiki/Performance_Optimization)
- [AWS RDS Pricing Calculator](https://calculator.aws/)
- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)
