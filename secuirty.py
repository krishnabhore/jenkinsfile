import boto3
import csv
import io
import os
from datetime import datetime

securityhub = boto3.client("securityhub")
s3 = boto3.client("s3")
sns = boto3.client("sns")

# Environment variables
S3_BUCKET = os.environ.get("S3_BUCKET", "my-securityhub-reports")
S3_PREFIX = os.environ.get("S3_PREFIX", "reports/")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")

# Helper: Map ARN → Security Standard
def get_standard_name(control_arn):
    arn = control_arn.lower()
    if "cis-aws-foundations-benchmark" in arn:
        return "CIS AWS Foundations Benchmark"
    elif "pci-dss" in arn:
        return "PCI DSS"
    elif "nist" in arn:
        return "NIST"
    elif "aws-foundational-security-best-practices" in arn:
        return "AWS Foundational Security Best Practices"
    else:
        return "Other/Custom"

def lambda_handler(event, context):
    findings = []
    next_token = None

    # Fetch all active findings
    while True:
        params = {
            "MaxResults": 50,
            "Filters": {
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
            },
        }
        if next_token:
            params["NextToken"] = next_token

        response = securityhub.get_findings(**params)
        findings.extend(response["Findings"])
        next_token = response.get("NextToken")
        if not next_token:
            break

    # Create CSV buffer
    csv_buffer = io.StringIO()
    csv_writer = csv.writer(csv_buffer)
    csv_writer.writerow(
        [
            "Standard",
            "ControlId",
            "ControlTitle",
            "FindingId",
            "Severity",
            "ComplianceStatus",
            "ResourceType",
            "ResourceId",
            "Region",
        ]
    )

    for f in findings:
        control_arn = f.get("ProductFields", {}).get("ControlId", "")
        standard_name = get_standard_name(control_arn)

        csv_writer.writerow(
            [
                standard_name,
                control_arn,
                f.get("Title", "N/A"),
                f.get("Id", "N/A"),
                f.get("Severity", {}).get("Label", "N/A"),
                f.get("Compliance", {}).get("Status", "N/A"),
                f["Resources"][0].get("Type", "N/A")
                if f.get("Resources")
                else "N/A",
                f["Resources"][0].get("Id", "N/A")
                if f.get("Resources")
                else "N/A",
                f.get("Region", "N/A"),
            ]
        )

    # Save report to S3
    report_key = f"{S3_PREFIX}securityhub_report_{datetime.utcnow().strftime('%Y-%m-%d_%H-%M-%S')}.csv"
    s3.put_object(
        Bucket=S3_BUCKET,
        Key=report_key,
        Body=csv_buffer.getvalue(),
        ContentType="text/csv",
    )

    report_link = f"s3://{S3_BUCKET}/{report_key}"

    # Publish SNS notification
    if SNS_TOPIC_ARN:
        message = (
            f"A new AWS Security Hub report has been generated.\n\n"
            f"Report Location: {report_link}\n"
            f"Total Findings: {len(findings)}"
        )
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="Security Hub Report Generated",
            Message=message,
        )

    return {
        "statusCode": 200,
        "body": f"Report uploaded to {report_link} and SNS notification sent.",
    }
