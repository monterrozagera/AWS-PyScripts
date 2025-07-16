# To check for potential security risks in your AWS IAM users, such as:
#     Users without MFA
#     Users with inline or overly permissive policies (e.g., "Action": "*" or "Resource": "*").
#     Unused IAM users (no recent login)
#     Users with access keys older than 90 days
#     Policies that allow administrative access

# Requirements:
#     boto3 installed (pip install boto3)
#     AWS credentials configured (aws configure)

import boto3
from datetime import datetime, timezone

iam = boto3.client('iam')

def list_users():
    return iam.list_users()['Users']

def check_mfa(user):
    mfa_devices = iam.list_mfa_devices(UserName=user)['MFADevices']
    return len(mfa_devices) > 0

def check_last_login(user):
    login = user.get('PasswordLastUsed')
    if login:
        return (datetime.now(timezone.utc) - login).days
    return None

def list_access_keys(user):
    return iam.list_access_keys(UserName=user)['AccessKeyMetadata']

def is_key_old(key, days=90):
    age = (datetime.now(timezone.utc) - key['CreateDate']).days
    return age > days

def is_policy_admin(policy_document):
    for stmt in policy_document.get('Statement', []):
        if stmt['Effect'] == 'Allow':
            if stmt.get('Action') == "*" or stmt.get('Action') == ["*"]:
                return True
            if stmt.get('Resource') == "*" or stmt.get('Resource') == ["*"]:
                return True
    return False

def check_inline_policies(user):
    inline_policies = iam.list_user_policies(UserName=user)['PolicyNames']
    for policy_name in inline_policies:
        policy_doc = iam.get_user_policy(UserName=user, PolicyName=policy_name)['PolicyDocument']
        if is_policy_admin(policy_doc):
            return True
    return False

def analyze_users():
    print(f"{'User':<20} {'MFA?':<6} {'LastLogin(Days)':<15} {'OldKey?':<8} {'InlineAdmin?':<13}")
    print("-" * 70)

    users = list_users()
    for user in users:
        username = user['UserName']
        mfa_enabled = check_mfa(username)
        last_login_days = check_last_login(user)
        old_key = any(is_key_old(key) for key in list_access_keys(username))
        inline_admin = check_inline_policies(username)

        print(f"{username:<20} {str(mfa_enabled):<6} {str(last_login_days):<15} {str(old_key):<8} {str(inline_admin):<13}")

if __name__ == "__main__":
    analyze_users()
