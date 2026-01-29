# AWS RDS PostgreSQL Quick Start Guide

## Prerequisites
- AWS account with RDS access
- AWS RDS PostgreSQL instance created
- Security group configured to allow your IP
- SSL certificate downloaded (optional but recommended)

## Step 1: Create RDS PostgreSQL Instance

1. Go to AWS Console → RDS → Databases
2. Click **Create database**
3. Choose **PostgreSQL** as engine type
4. Select **Free tier** (for testing) or appropriate instance class
5. Configure:
   - **DB instance identifier**: `packet-sniffer-db`
   - **Master username**: `sniffer_admin`
   - **Master password**: (choose a strong password)
   - **DB name**: `snifferdb`
6. Under **Connectivity**:
   - **Public access**: Yes (if connecting from outside AWS)
   - **VPC security group**: Create new or use existing
7. Click **Create database**

## Step 2: Configure Security Group

1. Go to EC2 → Security Groups
2. Find the security group attached to your RDS instance
3. Add inbound rule:
   - **Type**: PostgreSQL
   - **Port**: 5432
   - **Source**: Your IP address (or 0.0.0.0/0 for testing only)

## Step 3: Get Your Connection String

Once the RDS instance is available:

1. Go to RDS → Databases → Your Instance
2. Copy the **Endpoint** (e.g., `packet-sniffer-db.abc123.us-east-1.rds.amazonaws.com`)
3. Note the **Port** (default: 5432)

Your connection string format:
```
host=YOUR-ENDPOINT.REGION.rds.amazonaws.com
port=5432
dbname=snifferdb
user=sniffer_admin
password=YOUR-PASSWORD
sslmode=require
```

## Step 4: Set Environment Variable

### Windows (PowerShell)
```powershell
$env:AWS_RDS_CONNINFO="host=YOUR-ENDPOINT.REGION.rds.amazonaws.com port=5432 dbname=snifferdb user=sniffer_admin password=YOUR-PASSWORD sslmode=require"
```

### Windows (Command Prompt)
```cmd
set AWS_RDS_CONNINFO=host=YOUR-ENDPOINT.REGION.rds.amazonaws.com port=5432 dbname=snifferdb user=sniffer_admin password=YOUR-PASSWORD sslmode=require
```

### Windows (Permanent - System Properties)
1. Right-click "This PC" → Properties
2. Advanced system settings → Environment Variables
3. Add new User/System variable:
   - Name: `AWS_RDS_CONNINFO`
   - Value: Your connection string

### Linux/macOS
```bash
export AWS_RDS_CONNINFO="host=YOUR-ENDPOINT.REGION.rds.amazonaws.com port=5432 dbname=snifferdb user=sniffer_admin password=YOUR-PASSWORD sslmode=require"
```

Add to `~/.bashrc` or `~/.zshrc` for persistence.

## Step 5: Test Connection

Use `psql` to test:
```bash
psql "host=YOUR-ENDPOINT.REGION.rds.amazonaws.com port=5432 dbname=snifferdb user=sniffer_admin password=YOUR-PASSWORD sslmode=require"
```

Or use AWS RDS certificate for enhanced security:
```bash
# Download the RDS CA certificate
curl -o rds-ca-bundle.pem https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem

# Test with certificate validation
psql "host=YOUR-ENDPOINT.REGION.rds.amazonaws.com port=5432 dbname=snifferdb user=sniffer_admin password=YOUR-PASSWORD sslmode=verify-full sslrootcert=./rds-ca-bundle.pem"
```

## Step 6: Create Database Schema

Connect to your AWS RDS PostgreSQL and run:
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
    https BIGINT NOT NULL DEFAULT 0,
    dhcp BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_protocol_stats_timestamp 
    ON protocol_stats(timestamp);
```

## Step 7: Run Application

The application will automatically use the `AWS_RDS_CONNINFO` environment variable if set.

If not using environment variables, create a `.env` file:
```
AWS_RDS_CONNINFO=host=YOUR-ENDPOINT.REGION.rds.amazonaws.com port=5432 dbname=snifferdb user=sniffer_admin password=YOUR-PASSWORD sslmode=require
```

## Troubleshooting

### Connection Refused
- Check security group inbound rules
- Verify your IP is whitelisted
- Check RDS instance status is "Available"
- Verify the endpoint and port are correct

### SSL Error
- Ensure `sslmode=require` is in connection string
- Download RDS CA certificate bundle for `sslmode=verify-full`
- Check that your libpq supports SSL

### Authentication Failed
- Verify username and password
- Check username format (should be just the username, no additional suffixes)
- Ensure user has proper permissions
- Try resetting the master password in RDS console

### Timeout Errors
- Check network connectivity
- Verify security group rules
- Check if RDS instance is in the correct VPC
- Consider increasing `connect_timeout` parameter

### DNS Resolution Issues
- Verify the RDS endpoint URL is correct
- Check your DNS settings
- Try using the endpoint IP directly (not recommended for production)

## Cost Optimization

1. **Free Tier**: Use db.t3.micro or db.t4g.micro for 750 hours/month free
2. **Stop When Not Using**: Stop RDS instance when not needed (up to 7 days)
3. **Right-size**: Start small, scale up only when needed
4. **Storage**: Start with minimum required (20 GB)
5. **Multi-AZ**: Disable for development/testing

## Security Best Practices

1. **Never commit credentials** to version control
2. **Use environment variables** for sensitive data
3. **Enable SSL** (always use `sslmode=require` or higher)
4. **Use strong passwords** (12+ characters with mixed characters)
5. **Limit security group rules** to necessary IPs only
6. **Use IAM authentication** for production (advanced)
7. **Enable encryption at rest** in RDS settings
8. **Enable automated backups** (enabled by default)
9. **Monitor with CloudWatch** for unusual activity
10. **Rotate passwords** regularly

## AWS-Specific Features

### Enhanced Monitoring
Enable in RDS console for detailed OS metrics (CPU, memory, I/O)

### Performance Insights
Free tier available - shows database performance metrics and query analysis

### Automated Backups
- Retention period: 1-35 days
- Backup window: Specify or let AWS choose
- Point-in-time recovery available

### Read Replicas
Create read replicas for scaling read operations (not needed for this project initially)

### Multi-AZ Deployment
For high availability in production (creates synchronous standby replica)

## Next Steps

- Configure CloudWatch alarms for monitoring
- Set up automated backups retention policy
- Review and optimize RDS parameter groups
- Consider using AWS Secrets Manager for credentials
- Set up VPC peering if connecting from EC2 instances

## Additional Resources

- [AWS RDS PostgreSQL Documentation](https://docs.aws.amazon.com/rds/postgresql/)
- [RDS Best Practices](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_BestPractices.html)
- [PostgreSQL on RDS Performance Tuning](https://aws.amazon.com/blogs/database/category/database/amazon-rds/amazon-rds-for-postgresql/)
