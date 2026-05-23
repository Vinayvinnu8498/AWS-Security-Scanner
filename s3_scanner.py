import boto3

def scan_s3(region):
    findings = []
    s3 = boto3.client('s3')

    buckets = s3.list_buckets()['Buckets']

    for bucket in buckets:
        name = bucket['Name']

        # Check if bucket is public
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl['Grants']:
                if 'AllUsers' in str(grant):
                    findings.append({
                        "service": "S3",
                        "bucket": name,
                        "issue": "Bucket is public",
                        "severity": "Critical"
                    })
        except:
            pass

        # Check if encryption is enabled
        try:
            s3.get_bucket_encryption(Bucket=name)
        except:
            findings.append({
                "service": "S3",
                "bucket": name,
                "issue": "Bucket has no encryption",
                "severity": "High"
            })

    return findings
