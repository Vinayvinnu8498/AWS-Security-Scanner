import boto3

def scan_config(region):
    findings = []
    client = boto3.client("config")

    try:
        recorders = client.describe_configuration_recorders().get("ConfigurationRecorders", [])
        statuses = client.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])

        if not recorders:
            findings.append("❌ AWS Config is NOT configured in this region.")
            return findings

        recorder = recorders[0]
        status = statuses[0] if statuses else {}

        if not status.get("recording", False):
            findings.append("❌ AWS Config recorder exists but is NOT recording.")
        else:
            findings.append("✔ AWS Config recorder is enabled and recording.")

        if not recorder.get("roleARN"):
            findings.append("⚠ AWS Config recorder has no IAM role assigned.")

        if not recorder.get("recordingGroup", {}).get("allSupported", False):
            findings.append("⚠ AWS Config is not recording all supported resource types.")

    except Exception as e:
        findings.append(f"⚠ Unable to check AWS Config: {e}")

    return findings
