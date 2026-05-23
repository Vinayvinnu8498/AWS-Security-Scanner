import boto3
from botocore.exceptions import ClientError

def scan(region):
    findings = []

    events = boto3.client("events", region_name=region)

    # 1. List event buses
    try:
        buses = events.list_event_buses().get("EventBuses", [])
    except ClientError as e:
        findings.append(f"❌ Unexpected EventBridge error (list_event_buses): {e}")
        return findings

    if not buses:
        findings.append("ℹ No EventBridge event buses found in this region.")
        return findings

    for bus in buses:
        bus_name = bus.get("Name")
        findings.append(f"ℹ Event bus: {bus_name}")

        # 2. Check bus policy (public / cross-account)
        try:
            policy_resp = events.describe_event_bus(Name=bus_name)
            policy = policy_resp.get("Policy", "")
            if '"Principal":"*"' in policy or '"AWS":"*"' in policy:
                findings.append(f"❌ Event bus '{bus_name}' has an overly permissive resource policy (public or wildcard principal).")
            elif policy:
                findings.append(f"✔ Event bus '{bus_name}' has a resource policy without obvious wildcards.")
            else:
                findings.append(f"ℹ Event bus '{bus_name}' has no resource policy (default, private to account).")
        except ClientError as e:
            findings.append(f"⚠ Could not retrieve policy for event bus '{bus_name}': {e}")

        # 3. List rules on this bus
        try:
            next_token = None
            rules = []

            while True:
                if next_token:
                    resp = events.list_rules(EventBusName=bus_name, NextToken=next_token)
                else:
                    resp = events.list_rules(EventBusName=bus_name)

                rules.extend(resp.get("Rules", []))
                next_token = resp.get("NextToken")
                if not next_token:
                    break

        except ClientError as e:
            findings.append(f"⚠ Could not list rules for event bus '{bus_name}': {e}")
            continue

        if not rules:
            findings.append(f"ℹ No rules found on event bus '{bus_name}'.")
            continue

        for rule in rules:
            rule_name = rule.get("Name")
            state = rule.get("State")
            findings.append(f"ℹ Rule: {rule_name} (State: {state})")

            if state != "ENABLED":
                findings.append(f"⚠ Rule '{rule_name}' is not enabled.")

            # 4. Check rule targets
            try:
                targets_resp = events.list_targets_by_rule(
                    EventBusName=bus_name,
                    Rule=rule_name
                )
                targets = targets_resp.get("Targets", [])
            except ClientError as e:
                findings.append(f"⚠ Could not list targets for rule '{rule_name}': {e}")
                continue

            if not targets:
                findings.append(f"⚠ Rule '{rule_name}' has no targets configured.")
                continue

            for t in targets:
                target_arn = t.get("Arn")
                dlq = t.get("DeadLetterConfig", {})
                retry = t.get("RetryPolicy", {})

                findings.append(f"ℹ Target: {target_arn}")

                # DLQ check
                if dlq.get("Arn"):
                    findings.append(f"✔ Target has a dead-letter queue configured: {dlq.get('Arn')}.")
                else:
                    findings.append(f"⚠ Target for rule '{rule_name}' has NO dead-letter queue configured.")

                # Retry policy check
                if retry:
                    findings.append(f"✔ Custom retry policy configured for target.")
                else:
                    findings.append(f"ℹ Using default retry behavior for target.")

    return findings
