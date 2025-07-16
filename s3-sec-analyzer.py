# To check for potential security risks in your AWS S3 buckets, such as:
#     Public access
#     Bucket policy issues
#     ACL settings
#     Encryption status

# Requirements:
#     AWS credentials configured (~/.aws/credentials or environment variables)
#     boto3 installed (pip install boto3)

import boto3
import json
from botocore.exceptions import ClientError

def check_bucket_public_access(s3_client, bucket_name):
    try:
        public_access = s3_client.get_bucket_policy_status(Bucket=bucket_name)
        return public_access['PolicyStatus']['IsPublic']
    except ClientError as e:
        return False  # no policy, assume not public

def check_bucket_acl(s3_client, bucket_name):
    try:
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        for grant in acl['Grants']:
            grantee = grant.get('Grantee', {})
            if grantee.get('URI') == "http://acs.amazonaws.com/groups/global/AllUsers":
                return True
        return False
    except ClientError:
        return False

def check_bucket_encryption(s3_client, bucket_name):
    try:
        s3_client.get_bucket_encryption(Bucket=bucket_name)
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            return False
        return False

def check_bucket_policy(s3_client, bucket_name):
    try:
        policy = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy_dict = json.loads(policy['Policy'])
        statements = policy_dict.get("Statement", [])
        for statement in statements:
            effect = statement.get("Effect")
            principal = statement.get("Principal")
            condition = statement.get("Condition", {})
            if effect == "Allow" and (principal == "*" or principal == {"AWS": "*"}) and not condition:
                return True
        return False
    except ClientError as e:
        return False

def main():
    s3 = boto3.client('s3')
    buckets = s3.list_buckets().get('Buckets', [])

    print(f"{'Bucket Name':<30} {'Public?':<8} {'ACL Public?':<11} {'Policy Public?':<15} {'Encrypted?'}")
    print("-" * 75)

    for bucket in buckets:
        name = bucket['Name']
        is_public = check_bucket_public_access(s3, name)
        acl_public = check_bucket_acl(s3, name)
        policy_public = check_bucket_policy(s3, name)
        encrypted = check_bucket_encryption(s3, name)

        print(f"{name:<30} {str(is_public):<8} {str(acl_public):<11} {str(policy_public):<15} {str(encrypted)}")

if __name__ == "__main__":
    main()
