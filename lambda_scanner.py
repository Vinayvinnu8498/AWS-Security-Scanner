import boto3
from botocore.exceptions import ClientError

def scan_lambda():
    findings = []

    lambda_client = boto3.client("lambda")

    try:
        paginator = lambda_client.get_paginator("list_functions")
        functions = []

        for page in paginator.paginate():
            functions.extend(page.get("Functions", []))

    except ClientError as e:
        findings.append(f"❌ Unexpected Lambda error: {e}")
        return findings

    if not functions:
        findings.append("ℹ No Lambda functions found in this region.")
        return findings

    for fn in functions:
        fn_name = fn.get("FunctionName")
        findings.append(f"ℹ Lambda Function: {fn_name}")

        # 1. Public Lambda URLs
        try:
            urls = lambda_client.list_function_url_configs(FunctionName=fn_name).get("FunctionUrlConfigs", [])
            for url in urls:
                auth = url.get("AuthType")
                if auth == "NONE":
                    findings.append(f"❌ Lambda URL for {fn_name} is PUBLIC (AuthType=NONE).")
                else:
                    findings.append(f"✔ Lambda URL for {fn_name} requires authentication.")
        except ClientError:
            findings.append(f"✔ No Lambda Function URL configured for {fn_name}.")

        # 2. Environment variable encryption
        env = fn.get("Environment", {}).get("Variables", {})
        if env:
            kms_key = fn.get("KMSKeyArn")
            if kms_key:
                findings.append(f"✔ Environment variables encrypted with KMS key: {kms_key}.")
            else:
                findings.append(f"⚠ Environment variables exist but are NOT encrypted with a customer-managed KMS key.")
        else:
            findings.append(f"✔ No environment variables found.")

        # 3. IAM execution role
        role = fn.get("Role")
        if role:
            findings.append(f"ℹ Execution role: {role}")
        else:
            findings.append(f"❌ No execution role found for {fn_name}.")

        # 4. VPC configuration
        vpc_cfg = fn.get("VpcConfig", {})
        if vpc_cfg and vpc_cfg.get("SubnetIds"):
            findings.append(f"✔ {fn_name} is attached to a VPC.")
        else:
            findings.append(f"⚠ {fn_name} is NOT attached to a VPC (runs publicly).")

        # 5. X-Ray tracing
        tracing = fn.get("TracingConfig", {}).get("Mode")
        if tracing == "Active":
            findings.append(f"✔ X-Ray tracing ENABLED for {fn_name}.")
        else:
            findings.append(f"⚠ X-Ray tracing NOT enabled for {fn_name}.")

        # 6. Concurrency limits
        try:
            conc = lambda_client.get_function_concurrency(FunctionName=fn_name)
            if conc.get("ReservedConcurrentExecutions") is not None:
                findings.append(f"✔ Reserved concurrency set for {fn_name}.")
            else:
                findings.append(f"⚠ No reserved concurrency set for {fn_name}.")
        except ClientError:
            findings.append(f"⚠ No reserved concurrency set for {fn_name}.")

    return findings
