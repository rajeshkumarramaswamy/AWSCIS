from django.shortcuts import render, HttpResponse
import boto3
import time, json
from . import checks
import csv
from django.http import JsonResponse
sel_service = {'1': 'iam', '2': 'ec2', '3':'s3'}
# Create your views here.
ACCESS_KEY = ''
SUCCESS_KEY = ''


def index(request):
    return render(request, 'index.html')

def enterDetails(request):
    sk = request.POST.get('sk')
    ak = request.POST.get('ak')
    ACCESS_KEY = ak
    SUCCESS_KEY = sk
    iam_client = boto3.client('iam', aws_access_key_id=ak, aws_secret_access_key=sk)
    ec2_client = boto3.client('ec2', aws_access_key_id=ak, aws_secret_access_key=sk,region_name='us-east-1')
    cloud_client = boto3.client('cloudtrail', aws_access_key_id=ak, aws_secret_access_key=sk,region_name='us-east-1')
    s3_client = boto3.client('s3', aws_access_key_id=ak, aws_secret_access_key=sk,region_name='us-east-1')
    final_result = []
    region_list = get_regions(ec2_client)
    cred_report = get_cred_report(iam_client)
    cloud_trails = get_cloudtrails(region_list, ak, sk)
    password_policy = get_account_password_policy(iam_client)
    try:
        final_result.append(checks.control_1_1_root_user(cred_report))
        final_result.append(checks.control_1_2_mfa_on_password_enabled_iam(cred_report))
        final_result.append(checks.control_1_3_unused_credentials(cred_report))
        final_result.append(checks.control_1_4_rotated_keys(cred_report))
        final_result.append(checks.control_1_5_password_policy_uppercase(password_policy))
        final_result.append(checks.control_1_6_password_policy_lowercase(password_policy))
        final_result.append(checks.control_1_7_password_policy_symbol(password_policy))
        final_result.append(checks.control_1_8_password_policy_number(password_policy))
        final_result.append(checks.control_1_10_password_policy_reuse(password_policy))
        final_result.append(checks.control_1_11_password_policy_expire(password_policy))
        final_result.append(control_1_13_root_mfa_enabled(iam_client))
        final_result.append(control_1_16_no_policies_on_iam_users(iam_client))
        final_result.append(checks.control_1_21_ensure_iam_instance_roles_used(ec2_client))
        final_result.append(checks.control_1_22_ensure_incident_management_roles(iam_client))
        final_result.append(checks.control_1_23_no_active_initial_access_keys_with_iam_user(cred_report, iam_client))
        final_result.append(checks.control_1_24_no_overly_permissive_policies(iam_client))
        # CloudTrail
        final_result.append(checks.control_2_1_ensure_cloud_trail_all_regions(cloud_trails, ak , sk))
        final_result.append(checks.control_2_2_ensure_cloudtrail_validation(cloud_trails))
        final_result.append(checks.control_2_3_ensure_cloudtrail_bucket_not_public(cloud_trails, s3_client))
        final_result.append(checks.control_2_4_ensure_cloudtrail_cloudwatch_logs_integration(cloud_trails))
        final_result.append(checks.control_2_5_ensure_config_all_regions(region_list, ak , sk))
        final_result.append(checks.control_2_6_ensure_cloudtrail_bucket_logging(cloud_trails, s3_client))
        final_result.append(checks.control_2_7_ensure_cloudtrail_encryption_kms(cloud_trails))
        final_result.append(checks.control_2_8_ensure_kms_cmk_rotation(region_list, ak, sk))
        final_result.append(checks.control_3_1_ensure_log_metric_filter_unauthorized_api_calls(cloud_trails, ak , sk))
        final_result.append(checks.control_3_2_ensure_log_metric_filter_console_signin_no_mfa(cloud_trails, ak , sk))
        final_result.append(checks.control_3_3_ensure_log_metric_filter_root_usage(cloud_trails, ak, sk))
        final_result.append(checks.control_3_4_ensure_log_metric_iam_policy_change(cloud_trails, ak , sk))
        final_result.append(checks.control_3_5_ensure_log_metric_cloudtrail_configuration_changes(cloud_trails, ak , sk))
        final_result.append(checks.control_3_6_ensure_log_metric_console_auth_failures(cloud_trails, ak , sk))
        final_result.append(checks.control_3_7_ensure_log_metric_disabling_scheduled_delete_of_kms_cmk(cloud_trails, ak , sk))
        final_result.append(checks.control_3_8_ensure_log_metric_s3_bucket_policy_changes(cloud_trails, ak , sk))
        final_result.append(checks.control_3_9_ensure_log_metric_config_configuration_changes(cloud_trails, ak, sk))
        final_result.append(checks.control_3_10_ensure_log_metric_security_group_changes(cloud_trails, ak , sk))
        final_result.append(checks.control_3_11_ensure_log_metric_nacl(cloud_trails, ak , sk))
        final_result.append(checks.control_3_12_ensure_log_metric_changes_to_network_gateways(cloud_trails, ak, sk))
        final_result.append(checks.control_3_13_ensure_log_metric_changes_to_route_tables(cloud_trails, ak , sk))
        final_result.append(checks.control_3_14_ensure_log_metric_changes_to_vpc(cloud_trails, ak , sk))
        #final_result.append(checks.control_3_15_verify_sns_subscribers()) #Need to check
        #Networking
        final_result.append(checks.control_4_1_ensure_ssh_not_open_to_world(region_list, ak , sk))
        final_result.append(checks.control_4_2_ensure_rdp_not_open_to_world(region_list, ak , sk))
        final_result.append(checks.control_4_3_ensure_flow_logs_enabled_on_all_vpc(region_list, ak , sk))
        final_result.append(checks.control_4_4_ensure_default_security_groups_restricts_traffic(region_list, ak , sk))
        final_result.append(checks.control_4_5_ensure_route_tables_are_least_access(region_list, ak, sk))
        rsul = json.dumps({'data':final_result})
    except Exception as e:
        rsul = e
    
    return HttpResponse(rsul) 

def get_regions(ec2_client):
    """Summary

    Returns:
        TYPE: Description
    """
    region_response = ec2_client.describe_regions()
    regions = [region['RegionName'] for region in region_response['Regions']]
    return regions

def get_cloudtrails(regions, ak , sk):
    """Summary

    Returns:
        TYPE: Description
    """
    trails = dict()
    for n in regions:
        client = boto3.client('cloudtrail',
                aws_access_key_id=ak, 
                aws_secret_access_key=sk,
                region_name=n
            )
        response = client.describe_trails()
        temp = []
        for m in response['trailList']:
            if m['IsMultiRegionTrail'] is True:
                if m['HomeRegion'] == n:
                    temp.append(m)
            else:
                temp.append(m)
        if len(temp) > 0:
            trails[n] = temp
    return trails
    
def get_cred_report(report):
    """Summary

    Returns:
        TYPE: Description
    """
    x = 0
    status = ""
    cred = report.generate_credential_report()['State']
    while cred != "COMPLETE":
        time.sleep(2)
        x += 1
        # If no credentail report is delivered within this time fail the check.
        if x > 10:
            status = "Fail: rootUse - no CredentialReport available."
            break
    if "Fail" in status:
        return status
    response = report.get_credential_report()
    report = []
    reader = csv.DictReader(response['Content'].splitlines(), delimiter=',')
    for row in reader:
        report.append(row)

    # Verify if root key's never been used, if so add N/A
    try:
        if report[0]['access_key_1_last_used_date']:
            pass
    except:
        report[0]['access_key_1_last_used_date'] = "N/A"
    try:
        if report[0]['access_key_2_last_used_date']:
            pass
    except:
        report[0]['access_key_2_last_used_date'] = "N/A"
    return report


def get_account_password_policy(iam_client):
    """Check if a IAM password policy exists, if not return false

    Returns:
        Account IAM password policy or False
    """
    try:
        response = iam_client.get_account_password_policy()
        return response['PasswordPolicy']
    except Exception as e:
        if "cannot be found" in str(e):
            return False


# 1.13 Ensure MFA is enabled for the "root" account (Scored)
def control_1_13_root_mfa_enabled(iam_client):
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.13"
    description = "Ensure MFA is enabled for the root account"
    scored = True
    response = iam_client.get_account_summary()
    if response['SummaryMap']['AccountMFAEnabled'] != 1:
        result = False
        failReason = "Root account not using MFA"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.15 Ensure security questions are registered in the AWS account (Not Scored/Manual)
def control_1_15_security_questions_registered():
    """Summary

    Returns:
        TYPE: Description
    """
    result = "Manual"
    failReason = ""
    offenders = []
    control = "1.15"
    description = "Ensure security questions are registered in the AWS account, please verify manually"
    scored = False
    failReason = "Control not implemented using API, please verify manually"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.16 Ensure IAM policies are attached only to groups or roles (Scored)
def control_1_16_no_policies_on_iam_users(iam_client):
    """Summary

    Returns:
        TYPE: Description
    """
    result = True
    failReason = ""
    offenders = []
    control = "1.16"
    description = "Ensure IAM policies are attached only to groups or roles"
    scored = True
    paginator = iam_client.get_paginator('list_users')
    response_iterator = paginator.paginate()
    pagedResult = []
    for page in response_iterator:
        for n in page['Users']:
            pagedResult.append(n)
    offenders = []
    for n in pagedResult:
        policies = iam_client.list_user_policies(
            UserName=n['UserName'],
            MaxItems=1
        )
        if policies['PolicyNames'] != []:
            result = False
            failReason = "IAM user have inline policy attached"
            offenders.append(str(n['Arn']))
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}


# 1.17 Enable detailed billing (Scored)
def control_1_17_detailed_billing_enabled():
    """Summary

    Returns:
        TYPE: Description
    """
    result = "Manual"
    failReason = ""
    offenders = []
    control = "1.17"
    description = "Enable detailed billing, please verify manually"
    scored = True
    failReason = "Control not implemented using API, please verify manually"
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored, 'Description': description, 'ControlId': control}
