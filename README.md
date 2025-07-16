# AWS-PyScripts

**AWS-PyScripts** is a collection of Python scripts designed to help security engineers and cloud practitioners **analyze and audit the security posture** of AWS infrastructure.

These scripts use the [boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) AWS SDK and CLI to check for common misconfigurations, insecure resources, and best practice violations — all from the command line.

---

## Features

- **S3 Bucket Security Scanner**
  - Detects public access via ACLs and bucket policies
  - Verifies encryption settings
- **IAM Security Analyzer**
  - Flags users without MFA
  - Detects overly permissive inline policies
  - Identifies stale access keys and inactive users
- **CloudFront Inspector** *(coming soon)*
  - Checks for secure protocol enforcement
  - Reviews caching and origin configurations
- **Basic External S3 Scanner**
  - Tests public access externally (no AWS credentials required)

---

## Requirements

- Python 3.7+
- `boto3` (`pip install boto3`)
- AWS CLI (for configuring credentials)

```bash
pip install -r requirements.txt
aws configure
