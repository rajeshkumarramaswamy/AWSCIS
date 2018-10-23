from __future__ import print_function
import json
import csv
import time
import sys
import re
import tempfile
import getopt
import os
from datetime import datetime
import boto3

# Global constants

# Control 1.1 - Days allowed since use of root account.
CONTROL_1_1_DAYS = 0

def find_in_string(pattern, target):
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    for n in pattern:
        if not re.search(n, target):
            result = False
            break
    return result

def control_1_1_root_user(credreport):
    """Summary

    Args:
        credreport (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.1"
    description = "Avoid the use of the root account"
    scored = True
    if "Fail" in credreport:  # Report failure in control
        failReason = "No Credential report available"
        result = False

    # Check if root is used in the last 24h
    now = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(time.time()))
    frm = "%Y-%m-%dT%H:%M:%S+00:00"
    try:
        pwdDelta = (datetime.strptime(now, frm) -
                    datetime.strptime(credreport[0]['password_last_used'], frm))
        if (pwdDelta.days == CONTROL_1_1_DAYS) & (pwdDelta.seconds > 0):  # Used within last 24h
            failReason = "Used within 24h"
            result = False
    except:
        if credreport[0]['password_last_used'] == "N/A" or "no_information":
            pass
        else:
            failReason = "Something went wrong"

    try:
        key1Delta = (datetime.strptime(
            now, frm) - datetime.strptime(credreport[0]['access_key_1_last_used_date'], frm))
        if (key1Delta.days == CONTROL_1_1_DAYS) & (key1Delta.seconds > 0):  # Used within last 24h
            failReason = "Used within 24h"
            result = False
    except:
        if credreport[0]['access_key_1_last_used_date'] == "N/A" or "no_information":
            pass
        else:
            failReason = "Something went wrong"
    try:
        key2Delta = datetime.strptime(
            now, frm) - datetime.strptime(credreport[0]['access_key_2_last_used_date'], frm)
        if (key2Delta.days == CONTROL_1_1_DAYS) & (key2Delta.seconds > 0):  # Used within last 24h
            failReason = "Used within 24h"
            result = False
    except:
        if credreport[0]['access_key_2_last_used_date'] == "N/A" or "no_information":
            pass
        else:
            failReason = "Something went wrong"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


def control_1_2_mfa_on_password_enabled_iam(credreport):
    """Summary

    Args:
        credreport (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.2"
    description = "Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password"
    scored = True
    for i in range(len(credreport)):
        # Verify if the user have a password configured
        if credreport[i]['password_enabled'] == "true":
            # Verify if password users have MFA assigned
            if credreport[i]['mfa_active'] == "false":
                result = False
                failReason = "No MFA on users with password. "
                offenders.append(str(credreport[i]['arn']))
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


def control_1_3_unused_credentials(credreport):
    """Summary

    Args:
        credreport (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.3"
    description = "Ensure credentials unused for 90 days or greater are disabled"
    scored = True
    # Get current time
    now = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(time.time()))
    frm = "%Y-%m-%dT%H:%M:%S+00:00"

    # Look for unused credentails
    for i in range(len(credreport)):
        if credreport[i]['password_enabled'] == "true":
            try:
                delta = datetime.strptime(
                    now, frm) - datetime.strptime(credreport[i]['password_last_used'], frm)
                # Verify password have been used in the last 90 days
                if delta.days > 90:
                    result = False
                    failReason = "Credentials unused > 90 days detected. "
                    offenders.append(str(credreport[i]['arn']) + ":password")
            except:
                pass  # Never used
        if credreport[i]['access_key_1_active'] == "true":
            try:
                delta = datetime.strptime(
                    now, frm) - datetime.strptime(credreport[i]['access_key_1_last_used_date'], frm)
                # Verify password have been used in the last 90 days
                if delta.days > 90:
                    result = False
                    failReason = "Credentials unused > 90 days detected. "
                    offenders.append(str(credreport[i]['arn']) + ":key1")
            except:
                pass
        if credreport[i]['access_key_2_active'] == "true":
            try:
                delta = datetime.strptime(
                    now, frm) - datetime.strptime(credreport[i]['access_key_2_last_used_date'], frm)
                # Verify password have been used in the last 90 days
                if delta.days > 90:
                    result = False
                    failReason = "Credentials unused > 90 days detected. "
                    offenders.append(str(credreport[i]['arn']) + ":key2")
            except:
                # Never used
                pass
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.5 Ensure IAM password policy requires at least one uppercase letter (Scored)
def control_1_5_password_policy_uppercase(passwordpolicy):
    """Summary

    Args:
        passwordpolicy (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.5"
    description = "Ensure IAM password policy requires at least one uppercase letter"
    scored = True
    if passwordpolicy is False:
        result = False
        failReason = "Account does not have a IAM password policy."
    else:
        if passwordpolicy['RequireUppercaseCharacters'] is False:
            result = False
            failReason = "Password policy does not require at least one uppercase letter"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}

# 1.4 Ensure access keys are rotated every 90 days or less (Scored)


def control_1_4_rotated_keys(credreport):
    """Summary

    Args:
        credreport (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.4"
    description = "Ensure access keys are rotated every 90 days or less"
    scored = True
    # Get current time
    now = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(time.time()))
    frm = "%Y-%m-%dT%H:%M:%S+00:00"

    # Look for unused credentails
    for i in range(len(credreport)):
        if credreport[i]['access_key_1_active'] == "true":
            try:
                delta = datetime.strptime(
                    now, frm) - datetime.strptime(credreport[i]['access_key_1_last_rotated'], frm)
                # Verify keys have rotated in the last 90 days
                if delta.days > 90:
                    result = False
                    failReason = "Key rotation >90 days or not used since rotation"
                    offenders.append(
                        str(credreport[i]['arn']) + ":unrotated key1")
            except:
                pass
            try:
                last_used_datetime = datetime.strptime(
                    credreport[i]['access_key_1_last_used_date'], frm)
                last_rotated_datetime = datetime.strptime(
                    credreport[i]['access_key_1_last_rotated'], frm)
                # Verify keys have been used since rotation.
                if last_used_datetime < last_rotated_datetime:
                    result = False
                    failReason = "Key rotation >90 days or not used since rotation"
                    offenders.append(
                        str(credreport[i]['arn']) + ":unused key1")
            except:
                pass
        if credreport[i]['access_key_2_active'] == "true":
            try:
                delta = datetime.strptime(
                    now, frm) - datetime.strptime(credreport[i]['access_key_2_last_rotated'], frm)
                # Verify keys have rotated in the last 90 days
                if delta.days > 90:
                    result = False
                    failReason = "Key rotation >90 days or not used since rotation"
                    offenders.append(
                        str(credreport[i]['arn']) + ":unrotated key2")
            except:
                pass
            try:
                last_used_datetime = datetime.strptime(
                    credreport[i]['access_key_2_last_used_date'], frm)
                last_rotated_datetime = datetime.strptime(
                    credreport[i]['access_key_2_last_rotated'], frm)
                # Verify keys have been used since rotation.
                if last_used_datetime < last_rotated_datetime:
                    result = False
                    failReason = "Key rotation >90 days or not used since rotation"
                    offenders.append(
                        str(credreport[i]['arn']) + ":unused key2")
            except:
                pass
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}

# 1.6 Ensure IAM password policy requires at least one lowercase letter (Scored)


def control_1_6_password_policy_lowercase(passwordpolicy):
    """Summary

    Args:
        passwordpolicy (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.6"
    description = "Ensure IAM password policy requires at least one lowercase letter"
    scored = True
    if passwordpolicy is False:
        result = False
        failReason = "Account does not have a IAM password policy."
    else:
        if passwordpolicy['RequireLowercaseCharacters'] is False:
            result = False
            failReason = "Password policy does not require at least one uppercase letter"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


def control_1_7_password_policy_symbol(passwordpolicy):
    """Summary

    Args:
        passwordpolicy (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.7"
    description = "Ensure IAM password policy requires at least one symbol"
    scored = True
    if passwordpolicy is False:
        result = False
        failReason = "Account does not have a IAM password policy."
    else:
        if passwordpolicy['RequireSymbols'] is False:
            result = False
            failReason = "Password policy does not require at least one symbol"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.8 Ensure IAM password policy requires at least one number (Scored)
def control_1_8_password_policy_number(passwordpolicy):
    """Summary

    Args:
        passwordpolicy (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.8"
    description = "Ensure IAM password policy requires at least one number"
    scored = True
    if passwordpolicy is False:
        result = False
        failReason = "Account does not have a IAM password policy."
    else:
        if passwordpolicy['RequireNumbers'] is False:
            result = False
            failReason = "Password policy does not require at least one number"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.9 Ensure IAM password policy requires minimum length of 14 or greater (Scored)
def control_1_9_password_policy_length(passwordpolicy):
    """Summary

    Args:
        passwordpolicy (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.9"
    description = "Ensure IAM password policy requires minimum length of 14 or greater"
    scored = True
    if passwordpolicy is False:
        result = False
        failReason = "Account does not have a IAM password policy."
    else:
        if passwordpolicy['MinimumPasswordLength'] < 14:
            result = False
            failReason = "Password policy does not require at least 14 characters"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.10 Ensure IAM password policy prevents password reuse (Scored)
def control_1_10_password_policy_reuse(passwordpolicy):
    """Summary

    Args:
        passwordpolicy (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.10"
    description = "Ensure IAM password policy prevents password reuse"
    scored = True
    if passwordpolicy is False:
        result = False
        failReason = "Account does not have a IAM password policy."
    else:
        try:
            if passwordpolicy['PasswordReusePrevention'] == 24:
                pass
            else:
                result = False
                failReason = "Password policy does not prevent reusing last 24 passwords"
        except:
            result = False
            failReason = "Password policy does not prevent reusing last 24 passwords"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.11 Ensure IAM password policy expires passwords within 90 days or less (Scored)
def control_1_11_password_policy_expire(passwordpolicy):
    """Summary

    Args:
        passwordpolicy (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.11"
    description = "Ensure IAM password policy expires passwords within 90 days or less"
    scored = True
    if passwordpolicy is False:
        result = False
        failReason = "Account does not have a IAM password policy."
    else:
        if passwordpolicy['ExpirePasswords'] is True:
            if 0 < passwordpolicy['MaxPasswordAge'] > 90:
                result = False
                failReason = "Password policy does not expire passwords after 90 days or less"
        else:
            result = False
            failReason = "Password policy does not expire passwords after 90 days or less"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.12 Ensure no root account access key exists (Scored)
def control_1_12_root_key_exists(credreport):
    """Summary

    Args:
        credreport (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.12"
    description = "Ensure no root account access key exists"
    scored = True
    if (credreport[0]['access_key_1_active'] == "true") or (credreport[0]['access_key_2_active'] == "true"):
        result = False
        failReason = "Root have active access keys"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.21 Ensure IAM instance roles are used for AWS resource access from instances (Scored)
def control_1_21_ensure_iam_instance_roles_used(ec2_client):
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.21"
    description = "Ensure IAM instance roles are used for AWS resource access from instances, application code is not audited"
    scored = True
    failReason = "Instance not assigned IAM role for EC2"
    response = ec2_client.describe_instances()
    offenders = []
    for n, _ in enumerate(response['Reservations']):
        try:
            if response['Reservations'][n]['Instances'][0]['IamInstanceProfile']:
                pass
        except:
            result = False
            offenders.append(
                str(response['Reservations'][n]['Instances'][0]['InstanceId']))
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}

# 1.22 Ensure a support role has been created to manage incidents with AWS Support (Scored)


def control_1_22_ensure_incident_management_roles(iam_client):
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.22"
    description = "Ensure a support role has been created to manage incidents with AWS Support"
    scored = True
    offenders = []
    try:
        response = iam_client.list_entities_for_policy(
            PolicyArn='arn:aws:iam::aws:policy/AWSSupportAccess'
        )
        if (len(response['PolicyGroups']) + len(response['PolicyUsers']) + len(response['PolicyRoles'])) == 0:
            result = False
            failReason = "No user, group or role assigned AWSSupportAccess"
    except:
        result = False
        failReason = "AWSSupportAccess policy not created"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}

# 1.23 Do not setup access keys during initial user setup for all IAM users that have a console password (Not Scored)


def control_1_23_no_active_initial_access_keys_with_iam_user(credreport, iam_client):
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.23"
    description = "Do not setup access keys during initial user setup for all IAM users that have a console password"
    scored = False
    offenders = []
    for n, _ in enumerate(credreport):
        if (credreport[n]['access_key_1_active'] or credreport[n]['access_key_2_active'] == 'true') and n > 0:
            response = iam_client.list_access_keys(
                UserName=str(credreport[n]['user'])
            )
            for m in response['AccessKeyMetadata']:
                if re.sub(r"\s", "T", str(m['CreateDate'])) == credreport[n]['user_creation_time']:
                    result = False
                    failReason = "Users with keys created at user creation time found"
                    offenders.append(
                        str(credreport[n]['arn']) + ":" + str(m['AccessKeyId']))
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.24  Ensure IAM policies that allow full "*:*" administrative privileges are not created (Scored)
def control_1_24_no_overly_permissive_policies(iam_client):
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.24"
    description = "Ensure IAM policies that allow full administrative privileges are not created"
    scored = True
    offenders = []
    paginator = iam_client.get_paginator('list_policies')
    response_iterator = paginator.paginate(
        Scope='Local',
        OnlyAttached=False,
    )
    pagedResult = []
    for page in response_iterator:
        for n in page['Policies']:
            pagedResult.append(n)
    for m in pagedResult:
        policy = iam_client.get_policy_version(
            PolicyArn=m['Arn'],
            VersionId=m['DefaultVersionId']
        )

        statements = []
        # a policy may contain a single statement, a single statement in an array, or multiple statements in an array
        if isinstance(policy['PolicyVersion']['Document']['Statement'], list):
            for statement in policy['PolicyVersion']['Document']['Statement']:
                statements.append(statement)
        else:
            statements.append(policy['PolicyVersion']['Document']['Statement'])

        for n in statements:
            # a policy statement has to contain either an Action or a NotAction
            if 'Action' in n.keys() and n['Effect'] == 'Allow':
                if ("'*'" in str(n['Action']) or str(n['Action']) == "*") and ("'*'" in str(n['Resource']) or str(n['Resource']) == "*"):
                    result = False
                    failReason = "Found full administrative policy"
                    offenders.append(str(m['Arn']))
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}

# --- 2 Logging ---

# 2.1 Ensure CloudTrail is enabled in all regions (Scored)


def control_2_1_ensure_cloud_trail_all_regions(cloudtrails, ak, sk):
    """Summary

    Args:
        cloudtrails (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = False
    failReason = ""
    offenders = []
    control = "2.1"
    description = "Ensure CloudTrail is enabled in all regions"
    scored = True
    print('cloudtrails 1', cloudtrails)
    for m, n in cloudtrails.items():
        for o in n:
            if o['IsMultiRegionTrail']:
                client = boto3.client('cloudtrail',
                    aws_access_key_id=ak, 
                    aws_secret_access_key=sk,
                    region_name=m)
                response = client.get_trail_status(
                    Name=o['TrailARN']
                )
                if response['IsLogging'] is True:
                    result = True
                    break
    if result is False:
        failReason = "No enabled multi region trails found"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}

# 2.2 Ensure CloudTrail log file validation is enabled (Scored)


def control_2_2_ensure_cloudtrail_validation(cloudtrails):
    """Summary

    Args:
        cloudtrails (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "2.2"
    description = "Ensure CloudTrail log file validation is enabled"
    scored = True
    for m, n in cloudtrails.iteritems():
        for o in n:
            if o['LogFileValidationEnabled'] is False:
                result = False
                failReason = "CloudTrails without log file validation discovered"
                offenders.append(str(o['TrailARN']))
    offenders = set(offenders)
    offenders = list(offenders)
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}

# 2.3 Ensure the S3 bucket CloudTrail logs to is not publicly accessible (Scored)


def control_2_3_ensure_cloudtrail_bucket_not_public(cloudtrails, S3_CLIENT):
    """Summary

    Args:
        cloudtrails (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "2.3"
    description = "Ensure the S3 bucket CloudTrail logs to is not publicly accessible"
    scored = True
    for m, n in cloudtrails.iteritems():
        for o in n:
            #  We only want to check cases where there is a bucket
            if "S3BucketName" in str(o):
                try:
                    response = S3_CLIENT.get_bucket_acl(
                        Bucket=o['S3BucketName'])
                    for p in response['Grants']:
                        # print("Grantee is " + str(p['Grantee']))
                        if re.search(r'(global/AllUsers|global/AuthenticatedUsers)', str(p['Grantee'])):
                            result = False
                            offenders.append(
                                str(o['TrailARN']) + ":PublicBucket")
                            if "Publically" not in failReason:
                                failReason = failReason + "Publically accessible CloudTrail bucket discovered."
                except Exception as e:
                    result = False
                    if "AccessDenied" in str(e):
                        offenders.append(str(o['TrailARN']) + ":AccessDenied")
                        if "Missing" not in failReason:
                            failReason = "Missing permissions to verify bucket ACL. " + failReason
                    elif "NoSuchBucket" in str(e):
                        offenders.append(str(o['TrailARN']) + ":NoBucket")
                        if "Trailbucket" not in failReason:
                            failReason = "Trailbucket doesn't exist. " + failReason
                    else:
                        offenders.append(str(o['TrailARN']) + ":CannotVerify")
                        if "Cannot" not in failReason:
                            failReason = "Cannot verify bucket ACL. " + failReason
            else:
                result = False
                offenders.append(str(o['TrailARN']) + "NoS3Logging")
                failReason = "Cloudtrail not configured to log to S3. " + failReason
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 2.4 Ensure CloudTrail trails are integrated with CloudWatch Logs (Scored)
def control_2_4_ensure_cloudtrail_cloudwatch_logs_integration(cloudtrails):
    """Summary

    Args:
        cloudtrails (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "2.4"
    description = "Ensure CloudTrail trails are integrated with CloudWatch Logs"
    scored = True
    for m, n in cloudtrails.iteritems():
        for o in n:
            try:
                if "arn:aws:logs" in o['CloudWatchLogsLogGroupArn']:
                    pass
                else:
                    result = False
                    failReason = "CloudTrails without CloudWatch Logs discovered"
                    offenders.append(str(o['TrailARN']))
            except:
                result = False
                failReason = "CloudTrails without CloudWatch Logs discovered"
                offenders.append(str(o['TrailARN']))
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 2.5 Ensure AWS Config is enabled in all regions (Scored)
def control_2_5_ensure_config_all_regions(regions, ak, sk):
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "2.5"
    description = "Ensure AWS Config is enabled in all regions"
    scored = True
    globalConfigCapture = False  # Only one region needs to capture global events
    for n in regions:
        configClient = boto3.client('config',
                    aws_access_key_id=ak, 
                    aws_secret_access_key=sk,
                    region_name=n)
        response = configClient.describe_configuration_recorder_status()
        # Get recording status
        try:
            if not response['ConfigurationRecordersStatus'][0]['recording'] is True:
                result = False
                failReason = "Config not enabled in all regions, not capturing all/global events or delivery channel errors"
                offenders.append(str(n) + ":NotRecording")
        except:
            result = False
            failReason = "Config not enabled in all regions, not capturing all/global events or delivery channel errors"
            offenders.append(str(n) + ":NotRecording")

        # Verify that each region is capturing all events
        response = configClient.describe_configuration_recorders()
        try:
            if not response['ConfigurationRecorders'][0]['recordingGroup']['allSupported'] is True:
                result = False
                failReason = "Config not enabled in all regions, not capturing all/global events or delivery channel errors"
                offenders.append(str(n) + ":NotAllEvents")
        except:
            pass  # This indicates that Config is disabled in the region and will be captured above.

        # Check if region is capturing global events. Fail is verified later since only one region needs to capture them.
        try:
            if response['ConfigurationRecorders'][0]['recordingGroup']['includeGlobalResourceTypes'] is True:
                globalConfigCapture = True
        except:
            pass

        # Verify the delivery channels
        response = configClient.describe_delivery_channel_status()
        try:
            if response['DeliveryChannelsStatus'][0]['configHistoryDeliveryInfo']['lastStatus'] != "SUCCESS":
                result = False
                failReason = "Config not enabled in all regions, not capturing all/global events or delivery channel errors"
                offenders.append(str(n) + ":S3orSNSDelivery")
        except:
            pass  # Will be captured by earlier rule
        try:
            if response['DeliveryChannelsStatus'][0]['configStreamDeliveryInfo']['lastStatus'] != "SUCCESS":
                result = False
                failReason = "Config not enabled in all regions, not capturing all/global events or delivery channel errors"
                offenders.append(str(n) + ":SNSDelivery")
        except:
            pass  # Will be captured by earlier rule

    # Verify that global events is captured by any region
    if globalConfigCapture is False:
        result = False
        failReason = "Config not enabled in all regions, not capturing all/global events or delivery channel errors"
        offenders.append("Global:NotRecording")
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 2.6 Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket (Scored)
def control_2_6_ensure_cloudtrail_bucket_logging(cloudtrails, s3_client):
    """Summary

    Args:
        cloudtrails (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "2.6"
    description = "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket"
    scored = True
    for m, n in cloudtrails.items():
        for o in n:
            # it is possible to have a cloudtrail configured with a nonexistant bucket
            try:
                response = s3_client.get_bucket_logging(Bucket=o['S3BucketName'])
            except:
                result = False
                failReason = "Cloudtrail not configured to log to S3. "
                offenders.append(str(o['TrailARN']))
            try:
                if response['LoggingEnabled']:
                    pass
            except:
                result = False
                failReason = failReason + "CloudTrail S3 bucket without logging discovered"
                offenders.append("Trail:" + str(o['TrailARN']) + " - S3Bucket:" + str(o['S3BucketName']))
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 2.7 Ensure CloudTrail logs are encrypted at rest using KMS CMKs (Scored)
def control_2_7_ensure_cloudtrail_encryption_kms(cloudtrails):
    """Summary

    Args:
        cloudtrails (TYPE): Description

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "2.7"
    description = "Ensure CloudTrail logs are encrypted at rest using KMS CMKs"
    scored = True
    for m, n in cloudtrails.iteritems():
        for o in n:
            try:
                if o['KmsKeyId']:
                    pass
            except:
                result = False
                failReason = "CloudTrail not using KMS CMK for encryption discovered"
                offenders.append("Trail:" + str(o['TrailARN']))
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 2.8 Ensure rotation for customer created CMKs is enabled (Scored)
def control_2_8_ensure_kms_cmk_rotation(regions, ak , sk):
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "2.8"
    description = "Ensure rotation for customer created CMKs is enabled"
    scored = True
    for n in regions:
        kms_client = boto3.client('kms',
            aws_access_key_id=ak, 
            aws_secret_access_key=sk,
            region_name=n)
        paginator = kms_client.get_paginator('list_keys')
        response_iterator = paginator.paginate()
        for page in response_iterator:
            for n in page['Keys']:
                try:
                    rotationStatus = kms_client.get_key_rotation_status(KeyId=n['KeyId'])
                    if rotationStatus['KeyRotationEnabled'] is False:
                        keyDescription = kms_client.describe_key(KeyId=n['KeyId'])
                        if "Default master key that protects my" not in str(keyDescription['KeyMetadata']['Description']):  # Ignore service keys
                            result = False
                            failReason = "KMS CMK rotation not enabled"
                            offenders.append("Key:" + str(keyDescription['KeyMetadata']['Arn']))
                except:
                    pass  # Ignore keys without permission, for example ACM key
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# --- Monitoring ---

# 3.1 Ensure a log metric filter and alarm exist for unauthorized API calls (Scored)
def control_3_1_ensure_log_metric_filter_unauthorized_api_calls(cloudtrails, ak , sk):
    """Summary

    Returns:
        TYPE: Description
    """
    result = False
    failReason = ""
    offenders = []
    control = "3.1"
    description = "Ensure log metric filter unauthorized api calls"
    scored = True
    failReason = "Incorrect log metric alerts for unauthorized_api_calls"
    for m, n in cloudtrails.iteritems():
        for o in n:
            try:
                if o['CloudWatchLogsLogGroupArn']:
                    group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                    client = boto3.client('logs', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                    filters = client.describe_metric_filters(
                        logGroupName=group
                    )
                    for p in filters['metricFilters']:
                        patterns = ["\$\.errorCode\s*=\s*\"?\*UnauthorizedOperation(\"|\)|\s)", "\$\.errorCode\s*=\s*\"?AccessDenied\*(\"|\)|\s)"]
                        if find_in_string(patterns, str(p['filterPattern'])):
                            cwclient = boto3.client('cloudwatch', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                            response = cwclient.describe_alarms_for_metric(
                                MetricName=p['metricTransformations'][0]['metricName'],
                                Namespace=p['metricTransformations'][0]['metricNamespace']
                            )
                            snsClient = boto3.client('sns', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                            subscribers = snsClient.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                #  Pagination not used since only 1 subscriber required
                            )
                            if not len(subscribers['Subscriptions']) == 0:
                                result = True
            except:
                pass
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}

# 3.2 Ensure a log metric filter and alarm exist for Management Console sign-in without MFA (Scored)
def control_3_2_ensure_log_metric_filter_console_signin_no_mfa(cloudtrails, ak , sk):
    """Summary

    Returns:
        TYPE: Description
    """
    result = False
    failReason = ""
    offenders = []
    control = "3.2"
    description = "Ensure a log metric filter and alarm exist for Management Console sign-in without MFA"
    scored = True
    failReason = "Incorrect log metric alerts for management console signin without MFA"
    for m, n in cloudtrails.iteritems():
        for o in n:
            try:
                if o['CloudWatchLogsLogGroupArn']:
                    group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                    client = boto3.client('logs', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                    filters = client.describe_metric_filters(
                        logGroupName=group
                    )
                    for p in filters['metricFilters']:
                        patterns = ["\$\.eventName\s*=\s*\"?ConsoleLogin(\"|\)|\s)", "\$\.additionalEventData\.MFAUsed\s*\!=\s*\"?Yes"]
                        if find_in_string(patterns, str(p['filterPattern'])):
                            cwclient = boto3.client('cloudwatch', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                            response = cwclient.describe_alarms_for_metric(
                                MetricName=p['metricTransformations'][0]['metricName'],
                                Namespace=p['metricTransformations'][0]['metricNamespace']
                            )
                            snsClient = boto3.client('sns', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                            subscribers = snsClient.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                #  Pagination not used since only 1 subscriber required
                            )
                            if not len(subscribers['Subscriptions']) == 0:
                                result = True
            except:
                pass
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}

# 3.3 Ensure a log metric filter and alarm exist for usage of "root" account (Scored)
def control_3_3_ensure_log_metric_filter_root_usage(cloudtrails, ak , sk):
    """Summary

    Returns:
        TYPE: Description
    """
    result = False
    failReason = ""
    offenders = []
    control = "3.3"
    description = "Ensure a log metric filter and alarm exist for root usage"
    scored = True
    failReason = "Incorrect log metric alerts for root usage"
    for m, n in cloudtrails.iteritems():
        for o in n:
            try:
                if o['CloudWatchLogsLogGroupArn']:
                    group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                    client = boto3.client('logs', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                    filters = client.describe_metric_filters(
                        logGroupName=group
                    )
                    for p in filters['metricFilters']:
                        patterns = ["\$\.userIdentity\.type\s*=\s*\"?Root", "\$\.userIdentity\.invokedBy\s*NOT\s*EXISTS", "\$\.eventType\s*\!=\s*\"?AwsServiceEvent(\"|\)|\s)"]
                        if find_in_string(patterns, str(p['filterPattern'])):
                            cwclient = boto3.client('cloudwatch', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                            response = cwclient.describe_alarms_for_metric(
                                MetricName=p['metricTransformations'][0]['metricName'],
                                Namespace=p['metricTransformations'][0]['metricNamespace']
                            )
                            snsClient = boto3.client('sns', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                            subscribers = snsClient.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                #  Pagination not used since only 1 subscriber required
                            )
                            if not len(subscribers['Subscriptions']) == 0:
                                result = True
            except:
                pass
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}

# 3.4 Ensure a log metric filter and alarm exist for IAM policy changes  (Scored)
def control_3_4_ensure_log_metric_iam_policy_change(cloudtrails, ak , sk):
    """Summary

    Returns:
        TYPE: Description
    """
    result = False
    failReason = ""
    offenders = []
    control = "3.4"
    description = "Ensure a log metric filter and alarm exist for IAM changes"
    scored = True
    failReason = "Incorrect log metric alerts for IAM policy changes"
    for m, n in cloudtrails.iteritems():
        for o in n:
            try:
                if o['CloudWatchLogsLogGroupArn']:
                    group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                    client = boto3.client('logs', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                    filters = client.describe_metric_filters(
                        logGroupName=group
                    )
                    for p in filters['metricFilters']:
                        patterns = ["\$\.eventName\s*=\s*\"?DeleteGroupPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteRolePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteUserPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutGroupPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutRolePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutUserPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreatePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeletePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreatePolicyVersion(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeletePolicyVersion(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AttachRolePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachRolePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AttachUserPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachUserPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AttachGroupPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachGroupPolicy(\"|\)|\s)"]
                        if find_in_string(patterns, str(p['filterPattern'])):
                            cwclient = boto3.client('cloudwatch', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                            response = cwclient.describe_alarms_for_metric(
                                MetricName=p['metricTransformations'][0]['metricName'],
                                Namespace=p['metricTransformations'][0]['metricNamespace']
                            )
                            snsClient = boto3.client('sns', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                            subscribers = snsClient.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                #  Pagination not used since only 1 subscriber required
                            )
                            if not len(subscribers['Subscriptions']) == 0:
                                result = True
            except:
                pass
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 3.5 Ensure a log metric filter and alarm exist for CloudTrail configuration changes (Scored)
def control_3_5_ensure_log_metric_cloudtrail_configuration_changes(cloudtrails, ak , sk):
    """Summary

    Returns:
        TYPE: Description
    """
    result = False
    failReason = ""
    offenders = []
    control = "3.5"
    description = "Ensure a log metric filter and alarm exist for CloudTrail configuration changes"
    scored = True
    failReason = "Incorrect log metric alerts for CloudTrail configuration changes"
    for m, n in cloudtrails.iteritems():
        for o in n:
            try:
                if o['CloudWatchLogsLogGroupArn']:
                    group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                    client = boto3.client('logs', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                    filters = client.describe_metric_filters(
                        logGroupName=group
                    )
                    for p in filters['metricFilters']:
                        patterns = ["\$\.eventName\s*=\s*\"?CreateTrail(\"|\)|\s)", "\$\.eventName\s*=\s*\"?UpdateTrail(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteTrail(\"|\)|\s)", "\$\.eventName\s*=\s*\"?StartLogging(\"|\)|\s)", "\$\.eventName\s*=\s*\"?StopLogging(\"|\)|\s)"]
                        if find_in_string(patterns, str(p['filterPattern'])):
                            cwclient = boto3.client('cloudwatch', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                            response = cwclient.describe_alarms_for_metric(
                                MetricName=p['metricTransformations'][0]['metricName'],
                                Namespace=p['metricTransformations'][0]['metricNamespace']
                            )
                            snsClient = boto3.client('sns', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                            subscribers = snsClient.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                #  Pagination not used since only 1 subscriber required
                            )
                            if not len(subscribers['Subscriptions']) == 0:
                                result = True
            except:
                pass
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 3.6 Ensure a log metric filter and alarm exist for AWS Management Console authentication failures (Scored)
def control_3_6_ensure_log_metric_console_auth_failures(cloudtrails, ak , sk):
    """Summary

    Returns:
        TYPE: Description
    """
    result = False
    failReason = ""
    offenders = []
    control = "3.6"
    description = "Ensure a log metric filter and alarm exist for console auth failures"
    scored = True
    failReason = "Ensure a log metric filter and alarm exist for console auth failures"
    for m, n in cloudtrails.iteritems():
        for o in n:
            try:
                if o['CloudWatchLogsLogGroupArn']:
                    group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                    client = boto3.client('logs', aws_access_key_id=ak, aws_secret_access_key=sk,  region_name=m)
                    filters = client.describe_metric_filters(
                        logGroupName=group
                    )
                    for p in filters['metricFilters']:
                        patterns = ["\$\.eventName\s*=\s*\"?ConsoleLogin(\"|\)|\s)", "\$\.errorMessage\s*=\s*\"?Failed authentication(\"|\)|\s)"]
                        if find_in_string(patterns, str(p['filterPattern'])):
                            cwclient = boto3.client('cloudwatch', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                            response = cwclient.describe_alarms_for_metric(
                                MetricName=p['metricTransformations'][0]['metricName'],
                                Namespace=p['metricTransformations'][0]['metricNamespace']
                            )
                            snsClient = boto3.client('sns', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                            subscribers = snsClient.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                #  Pagination not used since only 1 subscriber required
                            )
                            if not len(subscribers['Subscriptions']) == 0:
                                result = True
            except:
                pass
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 3.7 Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs (Scored)
def control_3_7_ensure_log_metric_disabling_scheduled_delete_of_kms_cmk(cloudtrails, ak , sk):
    """Summary

    Returns:
        TYPE: Description
    """
    result = False
    failReason = ""
    offenders = []
    control = "3.7"
    description = "Ensure a log metric filter and alarm exist for disabling or scheduling deletion of KMS CMK"
    scored = True
    failReason = "Ensure a log metric filter and alarm exist for disabling or scheduling deletion of KMS CMK"
    for m, n in cloudtrails.iteritems():
        for o in n:
            try:
                if o['CloudWatchLogsLogGroupArn']:
                    group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                    client = boto3.client('logs', aws_access_key_id=ak, aws_secret_access_key=sk,  region_name=m)
                    filters = client.describe_metric_filters(
                        logGroupName=group
                    )
                    for p in filters['metricFilters']:
                        patterns = ["\$\.eventSource\s*=\s*\"?kms\.amazonaws\.com(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DisableKey(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ScheduleKeyDeletion(\"|\)|\s)"]
                        if find_in_string(patterns, str(p['filterPattern'])):
                            cwclient = boto3.client('cloudwatch', aws_access_key_id=ak, aws_secret_access_key=sk,  region_name=m)
                            response = cwclient.describe_alarms_for_metric(
                                MetricName=p['metricTransformations'][0]['metricName'],
                                Namespace=p['metricTransformations'][0]['metricNamespace']
                            )
                            snsClient = boto3.client('sns', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                            subscribers = snsClient.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                #  Pagination not used since only 1 subscriber required
                            )
                            if not len(subscribers['Subscriptions']) == 0:
                                result = True
            except:
                pass
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}

# 3.8 Ensure a log metric filter and alarm exist for S3 bucket policy changes (Scored)
def control_3_8_ensure_log_metric_s3_bucket_policy_changes(cloudtrails, ak , sk):
    """Summary

    Returns:
        TYPE: Description
    """
    result = False
    failReason = ""
    offenders = []
    control = "3.8"
    description = "Ensure a log metric filter and alarm exist for S3 bucket policy changes"
    scored = True
    failReason = "Ensure a log metric filter and alarm exist for S3 bucket policy changes"
    for m, n in cloudtrails.iteritems():
        for o in n:
            try:
                if o['CloudWatchLogsLogGroupArn']:
                    group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                    client = boto3.client('logs', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                    filters = client.describe_metric_filters(
                        logGroupName=group
                    )
                    for p in filters['metricFilters']:
                        patterns = ["\$\.eventSource\s*=\s*\"?s3\.amazonaws\.com(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutBucketAcl(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutBucketPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutBucketCors(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutBucketLifecycle(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutBucketReplication(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteBucketPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteBucketCors(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteBucketLifecycle(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteBucketReplication(\"|\)|\s)"]
                        if find_in_string(patterns, str(p['filterPattern'])):
                            cwclient = boto3.client('cloudwatch', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                            response = cwclient.describe_alarms_for_metric(
                                MetricName=p['metricTransformations'][0]['metricName'],
                                Namespace=p['metricTransformations'][0]['metricNamespace']
                            )
                            snsClient = boto3.client('sns', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                            subscribers = snsClient.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                #  Pagination not used since only 1 subscriber required
                            )
                            if not len(subscribers['Subscriptions']) == 0:
                                result = True
            except:
                pass
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 3.9 Ensure a log metric filter and alarm exist for AWS Config configuration changes (Scored)
def control_3_9_ensure_log_metric_config_configuration_changes(cloudtrails, ak , sk):
    """Summary

    Returns:
        TYPE: Description
    """
    result = False
    failReason = ""
    offenders = []
    control = "3.9"
    description = "Ensure a log metric filter and alarm exist for for AWS Config configuration changes"
    scored = True
    failReason = "Ensure a log metric filter and alarm exist for for AWS Config configuration changes"
    for m, n in cloudtrails.iteritems():
        for o in n:
            try:
                if o['CloudWatchLogsLogGroupArn']:
                    group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                    client = boto3.client('logs', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                    filters = client.describe_metric_filters(
                        logGroupName=group
                    )
                    for p in filters['metricFilters']:
                        patterns = ["\$\.eventSource\s*=\s*\"?config\.amazonaws\.com(\"|\)|\s)", "\$\.eventName\s*=\s*\"?StopConfigurationRecorder(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteDeliveryChannel(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutDeliveryChannel(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutConfigurationRecorder(\"|\)|\s)"]
                        if find_in_string(patterns, str(p['filterPattern'])):
                            cwclient = boto3.client('cloudwatch', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                            response = cwclient.describe_alarms_for_metric(
                                MetricName=p['metricTransformations'][0]['metricName'],
                                Namespace=p['metricTransformations'][0]['metricNamespace']
                            )
                            snsClient = boto3.client('sns', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                            subscribers = snsClient.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                #  Pagination not used since only 1 subscriber required
                            )
                            if not len(subscribers['Subscriptions']) == 0:
                                result = True
            except:
                pass
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}

# 3.10 Ensure a log metric filter and alarm exist for security group changes (Scored)
def control_3_10_ensure_log_metric_security_group_changes(cloudtrails, ak , sk):
    """Summary

    Returns:
        TYPE: Description
    """
    result = False
    failReason = ""
    offenders = []
    control = "3.10"
    description = "Ensure a log metric filter and alarm exist for security group changes"
    scored = True
    failReason = "Ensure a log metric filter and alarm exist for security group changes"
    for m, n in cloudtrails.iteritems():
        for o in n:
            try:
                if o['CloudWatchLogsLogGroupArn']:
                    group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                    client = boto3.client('logs', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                    filters = client.describe_metric_filters(
                        logGroupName=group
                    )
                    for p in filters['metricFilters']:
                        patterns = ["\$\.eventName\s*=\s*\"?AuthorizeSecurityGroupIngress(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AuthorizeSecurityGroupEgress(\"|\)|\s)", "\$\.eventName\s*=\s*\"?RevokeSecurityGroupIngress(\"|\)|\s)", "\$\.eventName\s*=\s*\"?RevokeSecurityGroupEgress(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateSecurityGroup(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteSecurityGroup(\"|\)|\s)"]
                        if find_in_string(patterns, str(p['filterPattern'])):
                            cwclient = boto3.client('cloudwatch', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                            response = cwclient.describe_alarms_for_metric(
                                MetricName=p['metricTransformations'][0]['metricName'],
                                Namespace=p['metricTransformations'][0]['metricNamespace']
                            )
                            snsClient = boto3.client('sns', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                            subscribers = snsClient.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                #  Pagination not used since only 1 subscriber required
                            )
                            if not len(subscribers['Subscriptions']) == 0:
                                result = True
            except:
                pass
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 3.11 Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL) (Scored)
def control_3_11_ensure_log_metric_nacl(cloudtrails, ak , sk):
    """Summary

    Returns:
        TYPE: Description
    """
    result = False
    failReason = ""
    offenders = []
    control = "3.11"
    description = "Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)"
    scored = True
    failReason = "Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)"
    for m, n in cloudtrails.iteritems():
        for o in n:
            try:
                if o['CloudWatchLogsLogGroupArn']:
                    group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                    client = boto3.client('logs', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                    filters = client.describe_metric_filters(
                        logGroupName=group
                    )
                    for p in filters['metricFilters']:
                        patterns = ["\$\.eventName\s*=\s*\"?CreateNetworkAcl(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateNetworkAclEntry(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteNetworkAcl(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteNetworkAclEntry(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ReplaceNetworkAclEntry(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ReplaceNetworkAclAssociation(\"|\)|\s)"]
                        if find_in_string(patterns, str(p['filterPattern'])):
                            cwclient = boto3.client('cloudwatch', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                            response = cwclient.describe_alarms_for_metric(
                                MetricName=p['metricTransformations'][0]['metricName'],
                                Namespace=p['metricTransformations'][0]['metricNamespace']
                            )
                            snsClient = boto3.client('sns', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                            subscribers = snsClient.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                #  Pagination not used since only 1 subscriber required
                            )
                            if not len(subscribers['Subscriptions']) == 0:
                                result = True
            except:
                pass
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}

# 3.12 Ensure a log metric filter and alarm exist for changes to network gateways (Scored)
def control_3_12_ensure_log_metric_changes_to_network_gateways(cloudtrails, ak , sk):
    """Summary

    Returns:
        TYPE: Description
    """
    result = False
    failReason = ""
    offenders = []
    control = "3.12"
    description = "Ensure a log metric filter and alarm exist for changes to network gateways"
    scored = True
    failReason = "Ensure a log metric filter and alarm exist for changes to network gateways"
    for m, n in cloudtrails.iteritems():
        for o in n:
            try:
                if o['CloudWatchLogsLogGroupArn']:
                    group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                    client = boto3.client('logs', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                    filters = client.describe_metric_filters(
                        logGroupName=group
                    )
                    for p in filters['metricFilters']:
                        patterns = ["\$\.eventName\s*=\s*\"?CreateCustomerGateway(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteCustomerGateway(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AttachInternetGateway(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateInternetGateway(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteInternetGateway(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachInternetGateway(\"|\)|\s)"]
                        if find_in_string(patterns, str(p['filterPattern'])):
                            cwclient = boto3.client('cloudwatch', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                            response = cwclient.describe_alarms_for_metric(
                                MetricName=p['metricTransformations'][0]['metricName'],
                                Namespace=p['metricTransformations'][0]['metricNamespace']
                            )
                            snsClient = boto3.client('sns', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                            subscribers = snsClient.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                #  Pagination not used since only 1 subscriber required
                            )
                            if not len(subscribers['Subscriptions']) == 0:
                                result = True
            except:
                pass
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 3.13 Ensure a log metric filter and alarm exist for route table changes (Scored)
def control_3_13_ensure_log_metric_changes_to_route_tables(cloudtrails, ak , sk):
    """Summary

    Returns:
        TYPE: Description
    """
    result = False
    failReason = ""
    offenders = []
    control = "3.13"
    description = "Ensure a log metric filter and alarm exist for route table changes"
    scored = True
    failReason = "Ensure a log metric filter and alarm exist for route table changes"
    for m, n in cloudtrails.iteritems():
        for o in n:
            try:
                if o['CloudWatchLogsLogGroupArn']:
                    group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                    client = boto3.client('logs', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                    filters = client.describe_metric_filters(
                        logGroupName=group
                    )
                    for p in filters['metricFilters']:
                        patterns = ["\$\.eventName\s*=\s*\"?CreateRoute(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateRouteTable(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ReplaceRoute(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ReplaceRouteTableAssociation(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteRouteTable(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteRoute(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DisassociateRouteTable(\"|\)|\s)"]
                        if find_in_string(patterns, str(p['filterPattern'])):
                            cwclient = boto3.client('cloudwatch', aws_access_key_id=ak, aws_secret_access_key=sk,region_name=m)
                            response = cwclient.describe_alarms_for_metric(
                                MetricName=p['metricTransformations'][0]['metricName'],
                                Namespace=p['metricTransformations'][0]['metricNamespace']
                            )
                            snsClient = boto3.client('sns', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                            subscribers = snsClient.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                #  Pagination not used since only 1 subscriber required
                            )
                            if not len(subscribers['Subscriptions']) == 0:
                                result = True
            except:
                pass
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 3.14 Ensure a log metric filter and alarm exist for VPC changes (Scored)
def control_3_14_ensure_log_metric_changes_to_vpc(cloudtrails, ak , sk):
    """Summary

    Returns:
        TYPE: Description
    """
    result = False
    failReason = ""
    offenders = []
    control = "3.14"
    description = "Ensure a log metric filter and alarm exist for VPC changes"
    scored = True
    failReason = "Ensure a log metric filter and alarm exist for VPC changes"
    for m, n in cloudtrails.iteritems():
        for o in n:
            try:
                if o['CloudWatchLogsLogGroupArn']:
                    group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                    client = boto3.client('logs', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                    filters = client.describe_metric_filters(
                        logGroupName=group
                    )
                    for p in filters['metricFilters']:
                        patterns = ["\$\.eventName\s*=\s*\"?CreateVpc(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteVpc(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ModifyVpcAttribute(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AcceptVpcPeeringConnection(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateVpcPeeringConnection(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteVpcPeeringConnection(\"|\)|\s)", "\$\.eventName\s*=\s*\"?RejectVpcPeeringConnection(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AttachClassicLinkVpc(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachClassicLinkVpc(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DisableVpcClassicLink(\"|\)|\s)", "\$\.eventName\s*=\s*\"?EnableVpcClassicLink(\"|\)|\s)"]
                        if find_in_string(patterns, str(p['filterPattern'])):
                            cwclient = boto3.client('cloudwatch', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                            response = cwclient.describe_alarms_for_metric(
                                MetricName=p['metricTransformations'][0]['metricName'],
                                Namespace=p['metricTransformations'][0]['metricNamespace']
                            )
                            snsClient = boto3.client('sns',aws_access_key_id=ak, aws_secret_access_key=sk, region_name=m)
                            subscribers = snsClient.list_subscriptions_by_topic(
                                TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                #  Pagination not used since only 1 subscriber required
                            )
                            if not len(subscribers['Subscriptions']) == 0:
                                result = True
            except:
                pass
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 3.15 Ensure appropriate subscribers to each SNS topic (Not Scored)
def control_3_15_verify_sns_subscribers():
    """Summary

    Returns:
        TYPE: Description
    """
    result = "Manual"
    failReason = ""
    offenders = []
    control = "3.15"
    description = "Ensure appropriate subscribers to each SNS topic, please verify manually"
    scored = False
    failReason = "Control not implemented using API, please verify manually"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# --- Networking ---

# 4.1 Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 (Scored)
def control_4_1_ensure_ssh_not_open_to_world(regions, ak , sk):
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "4.1"
    description = "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22"
    scored = True
    for n in regions:
        client = boto3.client('ec2', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=n)
        response = client.describe_security_groups()
        for m in response['SecurityGroups']:
            if "0.0.0.0/0" in str(m['IpPermissions']):
                for o in m['IpPermissions']:
                    try:
                        if int(o['FromPort']) <= 22 <= int(o['ToPort']) and '0.0.0.0/0' in str(o['IpRanges']):
                            result = False
                            failReason = "Found Security Group with port 22 open to the world (0.0.0.0/0)"
                            offenders.append(str(m['GroupId']))
                    except:
                        if str(o['IpProtocol']) == "-1" and '0.0.0.0/0' in str(o['IpRanges']):
                            result = False
                            failReason = "Found Security Group with port 22 open to the world (0.0.0.0/0)"
                            offenders.append(str(n) + " : " + str(m['GroupId']))
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 4.2 Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 (Scored)
def control_4_2_ensure_rdp_not_open_to_world(regions, ak , sk):
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "4.2"
    description = "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389"
    scored = True
    for n in regions:
        client = boto3.client('ec2', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=n)
        response = client.describe_security_groups()
        for m in response['SecurityGroups']:
            if "0.0.0.0/0" in str(m['IpPermissions']):
                for o in m['IpPermissions']:
                    try:
                        if int(o['FromPort']) <= 3389 <= int(o['ToPort']) and '0.0.0.0/0' in str(o['IpRanges']):
                            result = False
                            failReason = "Found Security Group with port 3389 open to the world (0.0.0.0/0)"
                            offenders.append(str(m['GroupId']))
                    except:
                        if str(o['IpProtocol']) == "-1" and '0.0.0.0/0' in str(o['IpRanges']):
                            result = False
                            failReason = "Found Security Group with port 3389 open to the world (0.0.0.0/0)"
                            offenders.append(str(n) + " : " + str(m['GroupId']))
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 4.3 Ensure VPC flow logging is enabled in all VPCs (Scored)
def control_4_3_ensure_flow_logs_enabled_on_all_vpc(regions, ak , sk):
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "4.3"
    description = "Ensure VPC flow logging is enabled in all VPCs"
    scored = True
    for n in regions:
        client = boto3.client('ec2', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=n)
        flowlogs = client.describe_flow_logs(
            #  No paginator support in boto atm.
        )
        activeLogs = []
        for m in flowlogs['FlowLogs']:
            if "vpc-" in str(m['ResourceId']):
                activeLogs.append(m['ResourceId'])
        vpcs = client.describe_vpcs(
            Filters=[
                {
                    'Name': 'state',
                    'Values': [
                        'available',
                    ]
                },
            ]
        )
        for m in vpcs['Vpcs']:
            if not str(m['VpcId']) in str(activeLogs):
                result = False
                failReason = "VPC without active VPC Flow Logs found"
                offenders.append(str(n) + " : " + str(m['VpcId']))
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 4.4 Ensure the default security group of every VPC restricts all traffic (Scored)
def control_4_4_ensure_default_security_groups_restricts_traffic(regions, ak , sk):
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "4.4"
    description = "Ensure the default security group of every VPC restricts all traffic"
    scored = True
    for n in regions:
        client = boto3.client('ec2', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=n)
        response = client.describe_security_groups(
            Filters=[
                {
                    'Name': 'group-name',
                    'Values': [
                        'default',
                    ]
                },
            ]
        )
        for m in response['SecurityGroups']:
            if not (len(m['IpPermissions']) + len(m['IpPermissionsEgress'])) == 0:
                result = False
                failReason = "Default security groups with ingress or egress rules discovered"
                offenders.append(str(n) + " : " + str(m['GroupId']))
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 4.5 Ensure routing tables for VPC peering are "least access" (Not Scored)
def control_4_5_ensure_route_tables_are_least_access(regions, ak , sk):
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "4.5"
    description = "Ensure routing tables for VPC peering are least access"
    scored = False
    for n in regions:
        client = boto3.client('ec2', aws_access_key_id=ak, aws_secret_access_key=sk, region_name=n)
        response = client.describe_route_tables()
        for m in response['RouteTables']:
            for o in m['Routes']:
                try:
                    if o['VpcPeeringConnectionId']:
                        if int(str(o['DestinationCidrBlock']).split("/", 1)[1]) < 24:
                            result = False
                            failReason = "Large CIDR block routed to peer discovered, please investigate"
                            offenders.append(str(n) + " : " + str(m['RouteTableId']))
                except:
                    pass
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}
