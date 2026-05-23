import boto3
import botocore

REGIONS = ["us-east-1", "us-west-2", "eu-west-1"]

LOG_GROUP_NAME = "aws-cloudtrail-logs-257426645494-f702f63c"
NAMESPACE = "CISBenchmark"

METRIC_FILTERS = {
    "UnauthorizedAPICalls": '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }',
    "ConsoleLoginNoMFA": '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") && ($.responseElements.ConsoleLogin = "Success") }',
    "RootLogin": '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }',
    "IAMPolicyChanges": '{ ($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy) }',
    "CloudTrailChanges": '{ ($.eventName = "CreateTrail") || ($.eventName = "UpdateTrail") || ($.eventName = "DeleteTrail") || ($.eventName = "StartLogging") || ($.eventName = "StopLogging") }'
}

ALARM_MAP = {
    "UnauthorizedAPICalls": "CIS-4.3-UnauthorizedAPICalls",
    "ConsoleLoginNoMFA": "CIS-4.4-ConsoleLoginNoMFA",
    "RootLogin": "CIS-4.5-RootLogin",
    "IAMPolicyChanges": "CIS-4.6-IAMPolicyChanges",
    "CloudTrailChanges": "CIS-4.7-CloudTrailChanges"
}

SNS_TOPIC_ARN = "<PUT-YOUR-SNS-TOPIC-ARN-HERE>"


def log_group_exists(region):
    logs = boto3.client("logs", region_name=region)
    try:
        logs.describe_log_groups(logGroupNamePrefix=LOG_GROUP_NAME)
        return True
    except botocore.exceptions.ClientError:
        return False


def create_metric_filters(region):
    logs = boto3.client("logs", region_name=region)

    for name, pattern in METRIC_FILTERS.items():
        try:
            logs.put_metric_filter(
                logGroupName=LOG_GROUP_NAME,
                filterName=name,
                filterPattern=pattern,
                metricTransformations=[
                    {
                        "metricName": name,
                        "metricNamespace": NAMESPACE,
                        "metricValue": "1"
                    }
                ]
            )
            print(f"[{region}] ✔ Metric filter created: {name}")
        except Exception as e:
            print(f"[{region}] ❌ Failed to create metric filter {name}: {e}")


def create_alarms(region):
    cw = boto3.client("cloudwatch", region_name=region)

    for metric, alarm_name in ALARM_MAP.items():
        try:
            cw.put_metric_alarm(
                AlarmName=alarm_name,
                MetricName=metric,
                Namespace=NAMESPACE,
                Statistic="Sum",
                Period=300,
                Threshold=1,
                ComparisonOperator="GreaterThanOrEqualToThreshold",
                EvaluationPeriods=1,
                AlarmActions=[SNS_TOPIC_ARN]
            )
            print(f"[{region}] ✔ Alarm created: {alarm_name}")
        except Exception as e:
            print(f"[{region}] ❌ Failed to create alarm {alarm_name}: {e}")


def enable_config(region):
    config = boto3.client("config", region_name=region)

    try:
        config.put_configuration_recorder(
            ConfigurationRecorder={
                "name": "default",
                "roleARN": "arn:aws:iam::<ACCOUNT-ID>:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
                "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": True}
            }
        )
        config.put_delivery_channel(
            DeliveryChannel={
                "name": "default",
                "s3BucketName": "<PUT-YOUR-S3-BUCKET-HERE>"
            }
        )
        config.start_configuration_recorder(ConfigurationRecorderName="default")
        print(f"[{region}] ✔ AWS Config enabled")
    except Exception as e:
        print(f"[{region}] ❌ Failed to enable AWS Config: {e}")


def main():
    for region in REGIONS:
        print(f"\n=== FIXING REGION: {region} ===")

        if log_group_exists(region):
            print(f"[{region}] ✔ Log group exists — creating CIS 4.x filters + alarms")
            create_metric_filters(region)
            create_alarms(region)
        else:
            print(f"[{region}] ⚠ Log group missing — skipping CIS 4.x filters + alarms")

        enable_config(region)

    print("\n✔ ALL FIXES COMPLETED")


if __name__ == "__main__":
    main()
