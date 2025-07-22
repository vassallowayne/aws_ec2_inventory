# aws_ec2_inventory
Lists all AWS ec2 instances in all AWS profiles



## AWS EC2 Instances Inventory

This script automates the discovery and reporting of ec2 instances across multiple AWS accounts by leveraging locally configured AWS CLI profiles.

### What It Does

- Connects to AWS accounts using profiles defined in `~/.aws/credentials` and `~/.aws/config`.
- For each profile, it retrieves:
  - The AWS account ID
  - The list of all ec2 instances
- Outputs the results into a CSV file, including:
  - AWS account name (profile)
  - AWS account ID
  - EC2 instance name

### Requirements

- Python 3.x
- boto3 and botocore (`pip install boto3`)
- AWS CLI profiles properly configured under your user account
- 'credentials' file updated with creds for AWS profiles required

### Usage

Scan specific profiles:
```bash
python aws_ec2_inventory.py --profiles default,prod,dev
