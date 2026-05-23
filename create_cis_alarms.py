import boto3

REGIONS = ["us-east-1", "us-west-2", "eu-west-1"]
NAMESPACE = "CISBenchmark"

ALARMS = {
    "CIS-4.3-UnauthorizedAPICalls": "UnauthorizedAPICalls",
    "CIS-4.4-ConsoleLoginNoMFA": "ConsoleLoginNoMFA",
    "CIS-4.5-RootLogin": "RootLogin",
    "CIS-4.6-IAMPolicyChanges": "IAMPolicyChanges",
    "CIS-4.7-CloudTrailChanges": "CloudTrailChanges",
}

def create_alarm(region, alarm_name, metric_name):
    cw = boto3.client("cloudwatch", region_name=region)

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        MetricName=metric_name,
        Namespace=NAMESPACE,
        Statistic="Sum",
        Period=300,
        EvaluationPeriods=1,
        Threshold=1,
        ComparisonOperator="GreaterThanOrEqualToThreshold",
        ActionsEnabled=False,  # no SNS for now
    )

    print(f"[{region}] Created alarm: {alarm_name}")

def main():
    for region in REGIONS:
        print(f"\n=== Region: {region} ===")
        for alarm_name, metric_name in ALARMS.items():
            create_alarm(region, alarm_name, metric_name)

if __name__ == "__main__":
    main()
