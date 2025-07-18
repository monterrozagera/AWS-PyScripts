# Requirements:
#     boto3 installed (pip install boto3)
#     AWS credentials configured (aws configure)# Requirements:
#     boto3 installed (pip install boto3)
#     AWS credentials configured (aws configure)
import boto3
import json
from botocore.exceptions import ClientError

def analyze_iam():
    print("\nIAM Policy Audit")
    iam = boto3.client('iam')
    try:
        users = iam.list_users()['Users']
        for user in users:
            name = user['UserName']
            keys = iam.list_access_keys(UserName=name)['AccessKeyMetadata']
            for key in keys:
                if key['Status'] == 'Active':
                    print(f"  Active access key found for user: {name} (KeyID: {key['AccessKeyId']})")
    except ClientError as e:
        print(f"Error fetching IAM info: {e}")

def check_s3_buckets():
    print("\nPublic S3 Buckets")
    s3 = boto3.client('s3')
    try:
        buckets = s3.list_buckets()['Buckets']
        for bucket in buckets: 
            name = bucket['Name']
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl['Grants']:
                    grantee = grant['Grantee']
                    if grantee.get('URI', '').endswith('AllUsers'):
                        print(f"  Public bucket found: {name}")
            except ClientError:
                print(f"  Skipped: {name} (access denied)")
    except ClientError as e:
        print(f"Error listing buckets: {e}")

def check_security_groups():
    print("\nSecurity Groups with Wide Access")
    ec2 = boto3.client('ec2')
    try:
        groups = ec2.describe_security_groups()['SecurityGroups']
        for sg in groups:
            for perm in sg.get('IpPermissions', []):
                for ip_range in perm.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        print(f"  Security Group {sg['GroupId']} allows open access on port(s): {perm.get('FromPort')}")
    except ClientError as e:
        print(f"Error describing security groups: {e}")

def check_cloudtrail():
    print("\nCloudTrail Configuration")
    ct = boto3.client('cloudtrail')
    try:
        trails = ct.describe_trails()['trailList']
        if not trails:
            print("  No trails found!")
        for trail in trails:
            status = ct.get_trail_status(Name=trail['TrailARN'])
            logging = status.get('IsLogging')
            print(f"  Trail: {trail['Name']} - Logging: {'Enabled' if logging else 'Disabled'}")
    except ClientError as e:
        print(f"Error fetching CloudTrail info: {e}")

def main():
    print("=== AWS Advanced Security Analyzer ===")
    analyze_iam()
    check_s3_buckets()
    check_security_groups()
    check_cloudtrail()
    print("\nAudit complete.")

if __name__ == "__main__":
    main()
