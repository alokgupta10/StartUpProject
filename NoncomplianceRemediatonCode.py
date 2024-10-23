import boto3
import logging
import json

# Initialize AWS service clients
ec2_client = boto3.client('ec2')
iam_client = boto3.client('iam')
s3_client = boto3.client('s3')
lambda_client = boto3.client('lambda')
ssm_client = boto3.client('ssm')
kms_client = boto3.client('kms')
secrets_manager_client = boto3.client('secretsmanager')
sns_client = boto3.client('sns')
config_client = boto3.client('config')
macie_client = boto3.client('macie2')
guardduty_client = boto3.client('guardduty')
eks_client = boto3.client('eks')
elb_client = boto3.client('elbv2')
athena_client = boto3.client('athena')
cloudtrail_client = boto3.client('cloudtrail')

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Set the desired retention period (in days)
RETENTION_PERIOD_DAYS = 1095  # Adjust this value as needed

def lambda_handler(event, context):
    logger.info("Event received: %s", event)

    try:
        # Handle CloudWatch Events for remediation
        rule = event.get('detail', {}).get('rule', {}).get('id')

        if rule:
            if rule == 'cmk-backing-key-rotation-enabled-conformance-pack-aaplmz7xo':
                enable_key_rotation(kms_client)
            elif rule == 'ec2-volume-inuse-check-conformance-pack-aaplmz7xo':
                check_ec2_volume_inuse(ec2_client)
            elif rule == 'iam-no-inline-policy-check-conformance-pack-aaplmz7xo':
                remove_inline_policies(iam_client)
            elif rule == 'lambda-inside-vpc-conformance-pack-aaplmz7xo':
                move_lambda_to_vpc(lambda_client)
            elif rule == 'iam-user-no-policies-check-conformance-pack-aaplmz7xo':
                remove_user_policies(iam_client)
            elif rule == 's3-bucket-default-lock-enabled-conformance-pack-aaplmz7xo':
                enable_s3_default_lock(s3_client)
            elif rule == 's3-bucket-logging-enabled-conformance-pack-aaplmz7xo':
                enable_s3_logging(s3_client)
            elif rule == 's3-bucket-policy-grantee-check-conformance-pack-aaplmz7xo':
                check_s3_bucket_policy(s3_client)
            elif rule == 's3-bucket-ssl-requests-only-conformance-pack-aaplmz7xo':
                enforce_ssl_requests(s3_client)

        # Handle compliance results from AWS Security Hub
        compliance_results = event.get('complianceResults', [])

        for result in compliance_results:
            rule_id = result.get('ruleId')
            if result.get('complianceType') == 'NON_COMPLIANT':
                if rule_id == 'securityhub-nacl-no-unrestricted-ssh-rdp-6e2b13b7':
                    remediate_nacl()
                elif rule_id == 'securityhub-s3-lifecycle-policy-check-7c887767':
                    remediate_s3_lifecycle()
                elif rule_id == 'securityhub-s3-default-encryption-kms-c8534b73':
                    remediate_s3_default_encryption()
                elif rule_id == 'securityhub-s3-event-notifications-enabled-2333c5c4':
                    remediate_s3_event_notifications()
                elif rule_id == 'securityhub-secretsmanager-rotation-enabled-check-83a003d1':
                    remediate_secretsmanager_rotation()
                elif rule_id == 'securityhub-secretsmanager-secret-periodic-rotation-f57fb340':
                    remediate_secretsmanager_periodic_rotation()
                elif rule_id == 'securityhub-sns-encrypted-kms-881ece20':
                    remediate_sns_encryption()
                elif rule_id == 'securityhub-service-vpc-endpoint-enabled-9e0ff40a':
                    remediate_vpc_endpoints()
                elif rule_id == 'securityhub-vpc-default-security-group-closed-9dae2b20':
                    remediate_vpc_default_security_group()

        # Additionnal compliance related to securityhub
        if event.get('configRuleName') == 'securityhub-ec2-managedinstance-association-compliance-status-check-068c1c5d':
            remediate_ec2_ssm(event)
        elif event.get('configRuleName') == 'securityhub-eip-attached-21e800ac':
            return remediate_unattached_eips()
        elif event.get('configRuleName') == 'securityhub-guardduty-eks-protection-runtime-enabled-a79f2d2e':
            remediate_eks_runtime_protection(event)
        elif event.get('configRuleName') == 'securityhub-elb-deletion-protection-enabled-72f85c25':
            return remediate_elb_deletion_protection(event)
        elif event.get('configRuleName') == 'securityhub-macie-status-check-c447fedd':
            return remediate_macie_status(event)
        elif event.get('configRuleName') == 'securityhub-iam-customer-policy-blocked-kms-actions-Oe8ab023':
            return remediate_kms_actions(event)
        elif 'securityhub-athena-workgroup-logging-enabled-4529ffdb' in event.get('detail', {}).get('configRuleName', ''):
            check_athena_logging(event)
        elif 'securityhub-autoscaling-launch-template-6b37ac5c' in event.get('detail', {}).get('configRuleName', ''):
            check_launch_template(event)
        elif 'securityhub-cloud-trail-encryption-enabled-95734ec3' in event.get('detail', {}).get('configRuleName', ''):
            check_cloudtrail_encryption(event)
        elif 'securityhub-autoscaling-launchconfig-requires-imdsv2-96f01f87' in event.get('detail', {}).get('configRuleName', ''):
            check_launch_configuration_imdsv2()
        elif 'securityhub-cloud-trail-cloud-watch-logs-enabled-1fa0fc24' in event.get('detail', {}).get('configRuleName', ''):
            check_cloudtrail_logging()
        elif 'securityhub-cw-loggroup-retention-period-check-5c544a32' in event.get('detail', {}).get('configRuleName', ''):
            check_log_group_retention()

        return {
            'statusCode': 200,
            'body': json.dumps('Remediation processes executed successfully.')
        }

    except Exception as e:
        logger.error(f"Error in remediation execution: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps('Remediation process failed.')
        }

# Define your remediation functions below

def enable_key_rotation(client):
   response = kms_client.list_keys()
    keys = response['Keys']
    for key in keys:
        key_id = key['KeyId']
        key_info = kms_client.describe_key(KeyId=key_id)
        key_rotation_enabled = key_info['KeyMetadata']['KeyRotationEnabled']
        if not key_rotation_enabled:
            try:
                kms_client.enable_key_rotation(KeyId=key_id)
                print(f"Enabled key rotation for CMK: {key_id}.")
            except Exception as e:
                print(f"Error enabling key rotation for CMK {key_id}: {str(e)}")

    pass

def check_ec2_volume_inuse(ec2_client):
    volumes = ec2_client.describe_volumes()
    for volume in volumes['Volumes']:
        volume_id = volume['VolumeId']
        state = volume['State']
        if state == 'in-use':
            print(f"Volume {volume_id} is currently in use.")
        else:
            try:
                ec2_client.delete_volume(VolumeId=volume_id)
                print(f"Deleted unused volume: {volume_id}")
            except Exception as e:
                print(f"Failed to delete volume {volume_id}: {str(e)}")

def remove_inline_policies(iam_client):
    users = iam_client.list_users()
    for user in users['Users']:
        user_name = user['UserName']
        inline_policies = iam_client.list_user_policies(UserName=user_name)
        for policy_name in inline_policies['PolicyNames']:
            try:
                iam_client.delete_user_policy(UserName=user_name, PolicyName=policy_name)
                print(f"Removed inline policy {policy_name} from user {user_name}.")
            except Exception as e:
                print(f"Failed to remove inline policy {policy_name} from user {user_name}: {str(e)}")

def move_lambda_to_vpc(lambda_client):
    response = lambda_client.list_functions()
    for function in response['Functions']:
        function_name = function['FunctionName']
        vpc_config = function.get('VpcConfig')
        if not vpc_config or not vpc_config.get('SubnetIds'):
            try:
                lambda_client.update_function_configuration(
                    FunctionName=function_name,
                    VpcConfig={
                        'SubnetIds': ['subnet-0123456789abcdef0'],  # Replace with your Subnet IDs
                        'SecurityGroupIds': ['sg-0123456789abcdef0']  # Replace with your Security Group IDs
                    }
                )
                print(f"Moved Lambda function {function_name} to VPC.")
            except Exception as e:
                print(f"Failed to update Lambda function {function_name} to VPC: {str(e)}")

def remove_user_policies(iam_client):
    users = iam_client.list_users()
    for user in users['Users']:
        user_name = user['UserName']
        attached_policies = iam_client.list_attached_user_policies(UserName=user_name)
        for policy in attached_policies['AttachedPolicies']:
            try:
                iam_client.detach_user_policy(UserName=user_name, PolicyArn=policy['PolicyArn'])
                print(f"Detached policy {policy['PolicyName']} from user {user_name}.")
            except Exception as e:
                print(f"Failed to detach policy {policy['PolicyName']} from user {user_name}: {str(e)}")

def enable_s3_default_lock(s3_client):
    buckets = s3_client.list_buckets()
    for bucket in buckets['Buckets']:
        bucket_name = bucket['Name']
        try:
            response = s3_client.get_object_lock_configuration(Bucket=bucket_name)
            lock_config = response.get('ObjectLockConfiguration')
            if lock_config is None or lock_config['ObjectLockEnabled'] != 'Enabled':
                s3_client.put_object_lock_configuration(
                    Bucket=bucket_name,
                    ObjectLockConfiguration={
                        'ObjectLockEnabled': 'Enabled',
                        'Rule': {
                            'DefaultRetention': {
                                'Mode': 'GOVERNANCE',
                                'Days': 30
                            }
                        }
                    }
                )
                print(f"Enabled default object lock for bucket: {bucket_name}.")
        except s3_client.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ObjectLockConfigurationNotFoundError':
                s3_client.put_object_lock_configuration(
                    Bucket=bucket_name,
                    ObjectLockConfiguration={
                        'ObjectLockEnabled': 'Enabled',
                        'Rule': {
                            'DefaultRetention': {
                                'Mode': 'GOVERNANCE',
                                'Days': 30
                            }
                        }
                    }
                )
                print(f"Enabled default object lock for bucket: {bucket_name}.")
            else:
                print(f"Error checking or enabling object lock for bucket {bucket_name}: {str(e)}")

def enable_s3_logging(s3_client):
    buckets = s3_client.list_buckets()
    for bucket in buckets['Buckets']:
        bucket_name = bucket['Name']
        try:
            logging_status = s3_client.get_bucket_logging(Bucket=bucket_name)
            if 'LoggingEnabled' not in logging_status:
                logging_config = {
                    'LoggingEnabled': {
                        'TargetBucket': 'your-logging-bucket',  # Replace with your logging bucket
                        'TargetPrefix': f"{bucket_name}/logs/"
                    }
                }
                s3_client.put_bucket_logging(Bucket=bucket_name, BucketLoggingStatus=logging_config)
                print(f"Enabled logging for bucket: {bucket_name}.")
        except Exception as e:
            print(f"Failed to enable logging for bucket {bucket_name}: {str(e)}")

def check_s3_bucket_policy(s3_client):
     buckets = s3_client.list_buckets()
    for bucket in buckets['Buckets']:
        bucket_name = bucket['Name']
        try:
            policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(policy_response['Policy'])
            new_statements = []
            for statement in policy['Statement']:
                if 'Principal' in statement:
                    principal = statement['Principal']
                    if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                        print(f"Removing overly permissive statement from bucket: {bucket_name}")
                    else:
                        new_statements.append(statement)
                else:
                    new_statements.append(statement)
            if len(new_statements) != len(policy['Statement']):
                updated_policy = {
                    'Version': policy['Version'],
                    'Statement': new_statements
                }
                s3_client.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(updated_policy))
                print(f"Updated bucket policy for bucket: {bucket_name}.")
        except s3_client.exceptions.NoSuchBucketPolicy:
            print(f"No bucket policy found for bucket: {bucket_name}.")
        except Exception as e:
            print(f"Error checking or updating policy for bucket {bucket_name}: {str(e)}")

def enforce_ssl_requests(s3_client):
    buckets = s3_client.list_buckets()
    for bucket in buckets['Buckets']:
        bucket_name = bucket['Name']
        try:
            policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(policy_response['Policy'])
        except s3_client.exceptions.NoSuchBucketPolicy:
            policy = {
                'Version': '2012-10-17',
                'Statement': []
            }
        except Exception as e:
            print(f"Error getting bucket policy for {bucket_name}: {str(e)}")
            continue

        ssl_policy_statement = {
            'Effect': 'Deny',
            'Principal': '*',
            'Action': 's3:*',
            'Resource': [f'arn:aws:s3:::{bucket_name}/*'],
            'Condition': {
                'Bool': {
                    'aws:SecureTransport': 'false'
                }
            }
        }

        if ssl_policy_statement not in policy['Statement']:
            policy['Statement'].append(ssl_policy_statement)
            s3_client.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))
            print(f"Updated bucket policy to enforce SSL for bucket: {bucket_name}.")

def remediate_nacl():
    nacl_id = 'your-nacl-id'  # Replace with your actual NACL ID
    nacl_entries = ec2.describe_network_acls(NetworkAclIds=[nacl_id])
    
    for acl in nacl_entries['NetworkAcls']:
        for entry in acl['Entries']:
            if entry['Protocol'] == '6':  # TCP
                if entry['PortRange']['From'] <= 22 <= entry['PortRange']['To'] and entry['CidrBlock'] == '0.0.0.0/0':
                    ec2.delete_network_acl_entry(NetworkAclId=nacl_id, RuleNumber=entry['RuleNumber'], Egress=False)
                if entry['PortRange']['From'] <= 3389 <= entry['PortRange']['To'] and entry['CidrBlock'] == '0.0.0.0/0':
                    ec2.delete_network_acl_entry(NetworkAclId=nacl_id, RuleNumber=entry['RuleNumber'], Egress=False)

    # Add restrictive rules for your IP address
    add_restrictive_rule(nacl_id, '22', 'your-ip-address/32')  # Replace with your IP address
    add_restrictive_rule(nacl_id, '3389', 'your-ip-address/32')  # Replace with your IP address

def add_restrictive_rule(nacl_id, port, cidr_block):
    try:
        ec2.create_network_acl_entry(
            NetworkAclId=nacl_id,
            RuleNumber=100,  # Adjust as necessary
            Protocol='tcp',
            PortRange={'From': int(port), 'To': int(port)},
            CidrBlock=cidr_block,
            Egress=False,
            RuleAction='allow'
        )
    except Exception as e:
        print(f"Error adding rule: {str(e)}")

def remediate_s3_lifecycle():
    buckets = s3.list_buckets().get('Buckets', [])
    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        except s3.exceptions.NoSuchLifecycleConfiguration:
            apply_s3_lifecycle_policy(bucket_name)

def apply_s3_lifecycle_policy(bucket_name):
    lifecycle_policy = {
        'Rules': [
            {
                'ID': 'CurrentVersionActions',
                'Status': 'Enabled',
                'Transitions': [
                    {
                        'Days': 90,
                        'StorageClass': 'INTELLIGENT_TIERING'
                    }
                ],
                'Expiration': {
                    'Days': 365
                },
                'NoncurrentVersionExpiration': {
                    'NoncurrentDays': 365,
                    'NewerNoncurrentVersions': 0
                },
                'NoncurrentVersionTransitions': [
                    {
                        'NoncurrentDays': 14,
                        'StorageClass': 'INTELLIGENT_TIERING'
                    }
                ]
            },
            {
                'ID': 'NoncurrentVersionActions',
                'Status': 'Enabled',
                'NoncurrentVersionExpiration': {
                    'NoncurrentDays': 365,
                    'NewerNoncurrentVersions': 0
                },
                'NoncurrentVersionTransitions': [
                    {
                        'NoncurrentDays': 14,
                        'StorageClass': 'INTELLIGENT_TIERING'
                    }
                ]
            }
        ]
    }

    # Apply the lifecycle policy
    s3.put_bucket_lifecycle_configuration(
        Bucket=bucket_name,
        LifecycleConfiguration=lifecycle_policy
    )
    print(f"Lifecycle policy applied to bucket: {bucket_name}")

def remediate_s3_default_encryption():
    buckets = s3.list_buckets().get('Buckets', [])
    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            s3.get_bucket_encryption(Bucket=bucket_name)
        except s3.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                apply_default_kms_encryption(bucket_name)

def apply_default_kms_encryption(bucket_name):
    kms_key_id = 'your-kms-key-id-or-arn'  # Replace with your KMS key ID or ARN
    encryption_configuration = {
        'Rules': [
            {
                'ApplyServerSideEncryptionByDefault': {
                    'SSEAlgorithm': 'aws:kms',
                    'KMSMasterKeyID': kms_key_id
                }
            }
        ]
    }
    
    s3.put_bucket_encryption(Bucket=bucket_name, ServerSideEncryptionConfiguration=encryption_configuration)

def remediate_s3_event_notifications():
    buckets = s3.list_buckets().get('Buckets', [])
    for bucket in buckets:
        bucket_name = bucket['Name']
        notification_config = s3.get_bucket_notification_configuration(Bucket=bucket_name)
        if not has_event_notifications(notification_config):
            apply_event_notifications(bucket_name)

def has_event_notifications(notification_config):
    return (
        'TopicConfigurations' in notification_config or
        'QueueConfigurations' in notification_config or
        'LambdaFunctionConfigurations' in notification_config
    )

def apply_event_notifications(bucket_name):
    sns_topic_arn = 'your-sns-topic-arn'  # Replace with your SNS topic ARN
    notification_configuration = {
        'TopicConfigurations': [
            {
                'Id': 'NewObjectCreated',
                'TopicArn': sns_topic_arn,
                'Events': ['s3:ObjectCreated:*']
            }
        ]
    }
    s3.put_bucket_notification_configuration(Bucket=bucket_name, NotificationConfiguration=notification_configuration)

def remediate_secretsmanager_rotation():
    secrets = secrets_manager.list_secrets().get('SecretList', [])
    for secret in secrets:
        secret_name = secret['Name']
        if not secret.get('RotationEnabled', False):
            enable_secret_rotation(secret_name)

def enable_secret_rotation(secret_name):
    rotation_lambda_arn = 'your-rotation-lambda-arn'  # Replace with your Lambda ARN
    secrets_manager.rotate_secret(SecretId=secret_name, RotationLambdaARN=rotation_lambda_arn, RotationRules={'AutomaticallyAfterDays': 30})

def remediate_secretsmanager_periodic_rotation():
    secrets = secrets_manager.list_secrets().get('SecretList', [])
    for secret in secrets:
        secret_id = secret['ARN']
        try:
            secrets_manager.rotate_secret(SecretId=secret_id, RotationLambdaARN='your-rotation-lambda-arn')  # Replace with your rotation Lambda ARN
            print(f"Set periodic rotation for secret: {secret_id}")
        except Exception as e:
            print(f"Error setting periodic rotation for secret {secret_id}: {str(e)}")

def remediate_sns_encryption():
    topics = sns.list_topics()['Topics']
    for topic in topics:
        topic_arn = topic['TopicArn']
        try:
            sns.set_topic_attributes(
                TopicArn=topic_arn,
                AttributeName='KmsMasterKeyId',
                AttributeValue='your-kms-key-id-or-arn'  # Replace with your KMS key ID or ARN
            )
            print(f"Enabled encryption for topic: {topic_arn}")
        except Exception as e:
            print(f"Error enabling encryption for topic {topic_arn}: {str(e)}")

def remediate_vpc_endpoints():
    vpc_id = 'your-vpc-id'  # Replace with your VPC ID
    service_name = 'com.amazonaws.region.s3'  # Adjust service name as needed

    endpoints = ec2.describe_vpc_endpoints(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['VpcEndpoints']
    if not any(ep['ServiceName'] == service_name for ep in endpoints):
        ec2.create_vpc_endpoint(VpcId=vpc_id, ServiceName=service_name, VpcEndpointType='Interface')
        print(f"Created VPC endpoint for service: {service_name}")

def remediate_vpc_default_security_group():
    default_sg = ec2.describe_security_groups(GroupNames=['default'])
    for sg in default_sg['SecurityGroups']:
        if sg['GroupName'] == 'default':
            for permission in sg['IpPermissions']:
                if permission['FromPort'] == 0 and permission['ToPort'] == 65535 and permission['IpRanges'] == [{'CidrIp': '0.0.0.0/0'}]:
                    ec2.revoke_security_group_ingress(GroupId=sg['GroupId'], IpPermissions=[permission])
                    print(f"Revoked public access for default security group: {sg['GroupId']}")
def remediate_ec2_ssm(event):
    non_compliant_instance_id = event['resourceId']
    logger.info(f"Processing EC2 instance {non_compliant_instance_id}")

    try:
        response = ssm_client.describe_instance_information(
            Filters=[{'Key': 'InstanceIds', 'Values': [non_compliant_instance_id]}]
        )
        
        if response['InstanceInformationList']:
            logger.info(f"Instance {non_compliant_instance_id} is already managed by SSM")
            return
        
        instance = ec2_client.describe_instances(InstanceIds=[non_compliant_instance_id])
        instance_profile = instance['Reservations'][0]['Instances'][0].get('IamInstanceProfile')

        if not instance_profile:
            logger.info(f"Instance {non_compliant_instance_id} does not have an IAM role, assigning...")
            ec2_client.associate_iam_instance_profile(
                IamInstanceProfile={
                    'Arn': 'arn:aws:iam::<account_id>:instance-profile/SSMManagedInstanceRole'
                },
                InstanceId=non_compliant_instance_id
            )

        logger.info(f"Installing SSM agent on instance {non_compliant_instance_id}")
        ssm_client.send_command(
            InstanceIds=[non_compliant_instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={
                "commands": [
                    "sudo yum install -y amazon-ssm-agent",
                    "sudo systemctl start amazon-ssm-agent",
                    "sudo systemctl enable amazon-ssm-agent"
                ]
            },
            TimeoutSeconds=600
        )
        logger.info(f"Successfully remediated non-compliance for instance {non_compliant_instance_id}")

    except Exception as e:
        logger.error(f"Failed to remediate instance {non_compliant_instance_id}: {e}")
        raise

def remediate_unattached_eips():
    try:
        response = ec2_client.describe_addresses()
        eip_list = response['Addresses']
        
        unattached_eips = [eip['PublicIp'] for eip in eip_list if 'InstanceId' not in eip and 'NetworkInterfaceId' not in eip]
        
        for eip in unattached_eips:
            ec2_client.release_address(PublicIp=eip)
            logger.info(f"Released unattached EIP: {eip}")
        
        return {
            'statusCode': 200,
            'body': json.dumps(f"Released {len(unattached_eips)} unattached Elastic IP(s).")
        }

    except Exception as e:
        logger.error(f"Error releasing EIPs: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error releasing EIPs: {str(e)}")
        }

def remediate_eks_runtime_protection(event):
    try:
        detector_id = get_guardduty_detector()
        if not detector_id:
            logger.error("GuardDuty detector not found.")
            return
        
        non_compliant_cluster_name = event['detail']['resourceId']
        logger.info(f"Non-compliant EKS cluster: {non_compliant_cluster_name}")

        if not is_runtime_monitoring_enabled(non_compliant_cluster_name, detector_id):
            logger.info(f"Enabling runtime protection for cluster: {non_compliant_cluster_name}")
            enable_runtime_monitoring(non_compliant_cluster_name, detector_id)
            logger.info(f"Runtime protection enabled for cluster: {non_compliant_cluster_name}")
        else:
            logger.info(f"Runtime protection already enabled for cluster: {non_compliant_cluster_name}")
    
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        raise

def get_guardduty_detector():
    try:
        response = guardduty_client.list_detectors()
        if 'DetectorIds' in response and len(response['DetectorIds']) > 0:
            return response['DetectorIds'][0]
        return None
    except Exception as e:
        logger.error(f"Error retrieving GuardDuty detectors: {str(e)}")
        raise

def is_runtime_monitoring_enabled(cluster_name, detector_id):
    try:
        response = guardduty_client.get_eks_runtime_monitoring(
            DetectorId=detector_id,
            ClusterName=cluster_name
        )
        return response.get('RuntimeMonitoringStatus') == 'ENABLED'
    except Exception as e:
        logger.error(f"Error checking runtime protection: {str(e)}")
        return False

def enable_runtime_monitoring(cluster_name, detector_id):
    try:
        guardduty_client.enable_eks_runtime_monitoring(
            DetectorId=detector_id,
            ClusterName=cluster_name
        )
    except Exception as e:
        logger.error(f"Error enabling runtime monitoring: {str(e)}")
        raise

def remediate_elb_deletion_protection(event):
    non_compliant_elb_arn = json.loads(event['invokingEvent'])['configurationItem']['resourceId']

    try:
        response = elb_client.describe_load_balancer_attributes(
            LoadBalancerArn=non_compliant_elb_arn
        )
        
        deletion_protection_enabled = any(
            attr['Key'] == 'deletion_protection.enabled' and attr['Value'] == 'true'
            for attr in response['Attributes']
        )

        if not deletion_protection_enabled:
            logger.info(f"Enabling deletion protection for ELB: {non_compliant_elb_arn}")
            elb_client.modify_load_balancer_attributes(
                LoadBalancerArn=non_compliant_elb_arn,
                Attributes=[{
                    'Key': 'deletion_protection.enabled',
                    'Value': 'true'
                }]
            )
            return {
                'statusCode': 200,
                'body': json.dumps(f"Deletion protection enabled for ELB: {non_compliant_elb_arn}")
            }
        else:
            return {
                'statusCode': 200,
                'body': json.dumps(f"Deletion protection already enabled for ELB: {non_compliant_elb_arn}")
            }
    except Exception as e:
        logger.error(f"Error modifying ELB attributes: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error modifying ELB attributes: {str(e)}")
        }

def remediate_macie_status(event):
    try:
        logger.info("Updating Macie status...")
        macie_client.enable_macie()
        return {
            'statusCode': 200,
            'body': json.dumps("Macie status updated to enabled.")
        }
    except Exception as e:
        logger.error(f"Error enabling Macie: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error enabling Macie: {str(e)}")
        }

def remediate_kms_actions(event):
    policy_arn = event['resourceId']
    logger.info(f"Checking KMS policy: {policy_arn}")

    try:
        response = iam_client.get_policy(PolicyArn=policy_arn)
        policy_version_id = response['Policy']['DefaultVersionId']
        policy_version = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version_id)

        for statement in policy_version['PolicyVersion']['Document']['Statement']:
            if 'Action' in statement and 'kms:Decrypt' in statement['Action']:
                logger.info(f"Deleting KMS policy statement: {statement}")
                iam_client.delete_policy_version(PolicyArn=policy_arn, VersionId=policy_version_id)

        return {
            'statusCode': 200,
            'body': json.dumps(f"KMS policy {policy_arn} remediated.")
        }
    
    except Exception as e:
        logger.error(f"Error remediating KMS policy {policy_arn}: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error remediating KMS policy: {str(e)}")
        }


def check_athena_logging(event):
    logger.info("Checking Athena workgroup logging...")
    response = athena_client.list_work_groups()
    workgroups = response.get('WorkGroups', [])
    
    for workgroup in workgroups:
        workgroup_name = workgroup['Name']
        logger.info(f"Checking workgroup: {workgroup_name}")

        workgroup_details = athena_client.get_work_group(WorkGroup=workgroup_name)
        logging_enabled = workgroup_details['WorkGroup']['Configuration'].get('ResultConfiguration', {}).get('OutputLocation') is not None

        if not logging_enabled:
            enable_logging(workgroup_name)

def enable_logging(workgroup_name):
    try:
        athena_client.update_work_group(
            WorkGroup=workgroup_name,
            ConfigurationUpdates={
                'ResultConfigurationUpdates': {
                    'OutputLocation': 's3://YOUR_S3_BUCKET_FOR_LOGGING/',
                    'EncryptionConfiguration': {
                        'EncryptionOption': 'SSE_S3'
                    }
                },
                'EnforceWorkGroupConfiguration': True,
                'PublishCloudWatchMetricsEnabled': True
            },
            State='ENABLED'
        )
        logger.info(f"Logging enabled for workgroup: {workgroup_name}")
    except Exception as e:
        logger.error(f"Failed to enable logging for workgroup {workgroup_name}: {str(e)}")

def check_launch_template(event):
    logger.info("Checking launch templates...")
    non_compliant_resources = event['detail']['resourceId']
    
    for resource_id in non_compliant_resources:
        try:
            response = ec2_client.describe_launch_templates(LaunchTemplateIds=[resource_id])
            launch_template = response['LaunchTemplates'][0]

            if not is_compliant(launch_template):
                new_version = create_compliant_launch_template_version(launch_template)
                logger.info(f"Created a compliant version for {resource_id}: {new_version}")

        except Exception as e:
            logger.error(f"Error processing resource {resource_id}: {e}")

def is_compliant(launch_template):
    return True  # Implement compliance checks based on your organization's requirements

def create_compliant_launch_template_version(launch_template):
    new_version_data = {
        'LaunchTemplateId': launch_template['LaunchTemplateId'],
        'VersionDescription': 'Compliant version',
        'LaunchTemplateData': {
            'IamInstanceProfile': {
                'Arn': 'arn:aws:iam::your-account-id:instance-profile/your-instance-profile'
            },
            # Add other necessary fields...
        }
    }

    response = ec2_client.create_launch_template_version(**new_version_data)
    return response['LaunchTemplateVersion']['VersionNumber']

def check_cloudtrail_encryption(event):
    logger.info("Checking CloudTrail encryption...")
    trails = cloudtrail_client.describe_trails()
    
    for trail in trails['trailList']:
        trail_name = trail['Name']
        kms_key_id = trail.get('KmsKeyId')

        if kms_key_id is None:
            logger.info(f"Enabling KMS encryption for trail: {trail_name}")
            cloudtrail_client.update_trail(
                Name=trail_name,
                KmsKeyId='alias/aws/cloudtrail'  # Use the default KMS key for CloudTrail or your own KMS key ARN
            )
            logger.info(f"KMS encryption enabled for trail: {trail_name}")
        else:
            logger.info(f"KMS encryption already enabled for trail: {trail_name}")

def check_launch_configuration_imdsv2():
    logger.info("Checking launch configurations for IMDSv2...")
    launch_configs = ec2_client.describe_launch_configurations()

    for lc in launch_configs['LaunchConfigurations']:
        lc_name = lc['LaunchConfigurationName']

        if lc.get('MetadataOptions', {}).get('HttpTokens') != 'required':
            logger.info(f"Updating Launch Configuration: {lc_name} to use IMDSv2")
            new_lc_name = f"{lc_name}-v2"
            response = ec2_client.create_launch_configuration(
                LaunchConfigurationName=new_lc_name,
                ImageId=lc['ImageId'],
                InstanceType=lc['InstanceType'],
                SecurityGroups=lc.get('SecurityGroups', []),
                KeyName=lc.get('KeyName', None),
                UserData=lc.get('UserData', None),
                IamInstanceProfile=lc.get('IamInstanceProfile', None),
                BlockDeviceMappings=lc.get('BlockDeviceMappings', []),
                InstanceMonitoring=lc.get('InstanceMonitoring', {}),
                SpotPrice=lc.get('SpotPrice', None),
                AssociatePublicIpAddress=lc.get('AssociatePublicIpAddress', None),
                MetadataOptions={
                    'HttpTokens': 'required',
                    'HttpEndpoint': 'enabled',
                    'HttpPutResponseHopLimit': 1,
                    'InstanceMetadataTags': 'enabled'
                }
            )
            logger.info(f"Launch Configuration updated to {new_lc_name}")

def check_cloudtrail_logging():
    logger.info("Checking CloudTrail CloudWatch logging...")
    trail_name = "YOUR_CLOUDTRAIL_NAME"  # Replace with your CloudTrail name
    log_group_name = "/aws/cloudtrail/YOUR_CLOUDTRAIL_NAME"  # Replace with your log group name

    response = cloudtrail_client.describe_trails(trailNameList=[trail_name])
    trails = response['trailList']

    if not trails:
        logger.error("No CloudTrail found with the specified name.")
        return

    trail = trails[0]

    if trail['CloudWatchLogsLogGroupArn'] is None:
        logger.info("CloudWatch Logs not enabled for CloudTrail. Enabling now...")
        cloudtrail_client.start_logging(Name=trail_name)

        try:
            logs_client.create_log_group(logGroupName=log_group_name)
        except logs_client.exceptions.ResourceAlreadyExistsException:
            logger.info(f"Log group {log_group_name} already exists.")

        cloudtrail_client.put_resource_policy(
            ResourcePolicy=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudtrail.amazonaws.com"
                    },
                    "Action": "logs:PutLogEvents",
                    "Resource": log_group_name
                }]
            }),
            Name=trail_name
        )

        logger.info("Successfully enabled CloudWatch Logs for CloudTrail.")
    else:
        logger.info("CloudWatch Logs already enabled for CloudTrail.")

def check_cmk_key_rotation(event):
    logger.info("Checking CMK key rotation...")
    
    for record in event.get('records', []):
        cmk_id = record['configuration']['resourceId']
        logger.info("Checking CMK ID: %s", cmk_id)
        
        try:
            key_info = kms_client.describe_key(KeyId=cmk_id)
            key_metadata = key_info['KeyMetadata']
            
            if not key_metadata.get('KeyRotationEnabled', False):
                logger.info("Enabling key rotation for CMK ID: %s", cmk_id)
                kms_client.enable_key_rotation(KeyId=cmk_id)
                logger.info("Key rotation enabled for CMK ID: %s", cmk_id)
            else:
                logger.info("Key rotation already enabled for CMK ID: %s", cmk_id)

        except Exception as e:
            logger.error(f"Failed to check key rotation for CMK {cmk_id}: {str(e)}")

def check_log_group_retention():
    logger.info("Checking CloudWatch log group retention periods...")
    log_groups = logs_client.describe_log_groups()

    for log_group in log_groups['logGroups']:
        group_name = log_group['logGroupName']
        retention_days = log_group.get('retentionInDays')

        if retention_days is None or retention_days > RETENTION_PERIOD_DAYS:
            logger.info(f"Setting retention period for log group {group_name} to {RETENTION_PERIOD_DAYS} days.")
            logs_client.put_retention_policy(
                logGroupName=group_name,
                retentionInDays=RETENTION_PERIOD_DAYS
            )
            logger.info(f"Retention period set for log group {group_name}.")