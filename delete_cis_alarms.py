import boto3

REGIONS = ["us-east-1", "us-west-2", "eu-west-1"]

ALARMS = [
    "CIS-4.3-UnauthorizedAPICalls",
    "CIS-4.4-ConsoleLoginNoMFA",
    "CIS-4.5-RootLogin",
    "CIS-4.6-IAMPolicyChanges",
    "CIS-4.7-CloudTrailChanges",
]

def delete_alarm(region, alarm_name):
    cw = boto3.client("cloudwatch", region_name=region)

    try:
        cw.delete_alarms(AlarmNames=[alarm_name])
        print(f"[{region}] Deleted alarm: {alarm_name}")
    except Exception as e:
        print(f"[{region}] Could not delete {alarm_name}: {e}")

def main():
    for region in REGIONS:
        print(f"\n=== Region: {region} ===")
        for alarm_name in ALARMS:
            delete_alarm(region, alarm_name)

if __name__ == "__main__":
    main()
