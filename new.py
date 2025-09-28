import boto3
import os
from datetime import datetime
from openpyxl import Workbook

# Always use Security Hub in us-east-1
securityhub = boto3.client("securityhub", region_name="us-east-1")
s3 = boto3.client("s3")
sns = boto3.client("sns")
sts = boto3.client("sts")

S3_BUCKET = os.environ.get("S3_BUCKET")
S3_PREFIX = os.environ.get("S3_PREFIX", "reports/")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")

ACCOUNT_ID = sts.get_caller_identity()["Account"]
REGION = "us-east-1"

def lambda_handler(event, context):
    findings = []
    next_token = None

    # Fetch only Security Hub findings (exclude GuardDuty, Macie, etc.)
    while True:
        params = {
            "MaxResults": 50,
            "Filters": {
                "ProductName": [{"Value": "Security Hub", "Comparison": "EQUALS"}],
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
            },
        }
        if next_token:
            params["NextToken"] = next_token

        resp = securityhub.get_findings(**params)
        findings.extend(resp["Findings"])
        next_token = resp.get("NextToken")
        if not next_token:
            break

    # Build Excel workbook
    wb = Workbook()
    ws = wb.active
    ws.title = "SecurityHub Findings"

    ws.append([
        "AccountId",
        "Region",
        "Standard",
        "ControlId",
        "Title",
        "Severity",
        "ComplianceStatus",
        "ResourceType",
        "ResourceId",
        "UpdatedAt"
    ])

    for f in findings:
        control_id = f.get("ProductFields", {}).get("ControlId", "N/A")
        related = f.get("ProductFields", {}).get("RelatedAWSResources:0/name", "")

        # Try to map to known standards
        if "cis-aws-foundations-benchmark" in related.lower():
            standard_name = "CIS AWS Foundations Benchmark"
        elif "pci-dss" in related.lower():
            standard_name = "PCI DSS"
        elif "nist" in related.lower():
            standard_name = "NIST"
        elif "aws-foundational-security-best-practices" in related.lower():
            standard_name = "AWS Foundational Security Best Practices"
        else:
            standard_name = "Unknown"

        ws.append([
            ACCOUNT_ID,
            REGION,
            standard_name,
            control_id,
            f.get("Title", "N/A"),
            f.get("Severity", {}).get("Label", "N/A"),
            f.get("Compliance", {}).get("Status", "N/A"),
            f["Resources"][0].get("Type", "N/A") if f.get("Resources") else "N/A",
            f["Resources"][0].get("Id", "N/A") if f.get("Resources") else "N/A",
            f.get("UpdatedAt", "N/A"),
        ])

    # Save Excel file
    report_key = f"{S3_PREFIX}securityhub_findings_{datetime.utcnow().strftime('%Y-%m-%d_%H-%M-%S')}.xlsx"
    local_path = f"/tmp/{os.path.basename(report_key)}"
    wb.save(local_path)

    # Upload to S3
    s3.upload_file(local_path, S3_BUCKET, report_key)
    report_link = f"s3://{S3_BUCKET}/{report_key}"

    # Notify via SNS
    if SNS_TOPIC_ARN:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="Security Hub Findings Report (us-east-1)",
            Message=(
                f"A new Security Hub findings report has been generated.\n\n"
                f"Account: {ACCOUNT_ID}\nRegion: {REGION}\n"
                f"Findings Count: {len(findings)}\n"
                f"Report: {report_link}"
            ),
        )

    return {
        "statusCode": 200,
        "body": f"Report uploaded to {report_link} with {len(findings)} findings"
    }
