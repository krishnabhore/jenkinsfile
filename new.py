import boto3
import os
from datetime import datetime
from openpyxl import Workbook

securityhub = boto3.client("securityhub")
s3 = boto3.client("s3")
sns = boto3.client("sns")
sts = boto3.client("sts")

S3_BUCKET = os.environ.get("S3_BUCKET")
S3_PREFIX = os.environ.get("S3_PREFIX", "reports/")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")

# Get AWS account ID and region
ACCOUNT_ID = sts.get_caller_identity()["Account"]
REGION = boto3.session.Session().region_name

def lambda_handler(event, context):
    # Get all enabled standards
    standards = securityhub.get_enabled_standards()["StandardsSubscriptions"]

    wb = Workbook()
    ws = wb.active
    ws.title = "SecurityHub Controls"

    # Header row
    ws.append([
        "AccountId",
        "Region",
        "Standard",
        "ControlId",
        "Title",
        "Description",
        "Severity",
        "Status",
        "UpdatedAt",
    ])

    for std in standards:
        std_name = std["StandardsArn"].split("/")[-1]  # e.g. cis-aws-foundations-benchmark/v/1.2.0

        next_token = None
        while True:
            params = {"StandardsSubscriptionArn": std["StandardsSubscriptionArn"]}
            if next_token:
                params["NextToken"] = next_token

            controls_resp = securityhub.describe_standards_controls(**params)

            for control in controls_resp["Controls"]:
                ws.append([
                    ACCOUNT_ID,
                    REGION,
                    std_name,
                    control.get("ControlId", "N/A"),
                    control.get("Title", "N/A"),
                    control.get("Description", "N/A"),
                    control.get("SeverityRating", "N/A"),
                    control.get("ControlStatus", "N/A"),
                    control.get("UpdatedAt", "").strftime("%Y-%m-%d %H:%M:%S") if control.get("UpdatedAt") else "N/A",
                ])

            next_token = controls_resp.get("NextToken")
            if not next_token:
                break

    # Save Excel file
    report_key = f"{S3_PREFIX}securityhub_controls_{datetime.utcnow().strftime('%Y-%m-%d_%H-%M-%S')}.xlsx"
    file_path = f"/tmp/{os.path.basename(report_key)}"
    wb.save(file_path)

    # Upload to S3
    s3.upload_file(file_path, S3_BUCKET, report_key)

    report_link = f"s3://{S3_BUCKET}/{report_key}"

    # Publish SNS
    if SNS_TOPIC_ARN:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="Security Hub Controls Report",
            Message=(
                f"A new Security Hub Controls report has been generated.\n\n"
                f"Account: {ACCOUNT_ID}\nRegion: {REGION}\n"
                f"Report: {report_link}"
            ),
        )

    return {
        "statusCode": 200,
        "body": f"Report uploaded to {report_link} and SNS notification sent."
    }
