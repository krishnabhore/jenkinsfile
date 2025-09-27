import boto3, json, os
from datetime import datetime

region = os.environ['region']
bucket = os.environ['bucket']
snsTopicArn = os.environ['SNSTopic']
csv = ','   # Use comma instead of semicolon
filename = 'findings.csv'
utcDate = datetime.utcnow().strftime('%Y%m%d')
s3Path = utcDate + '/'
fullpath = '/tmp/' + filename

def get_securityhub_findings(region):
    print('get_securityhub_findings STARTED')
    client = boto3.client('securityhub', region_name=region)
    paginator = client.get_paginator('get_findings')
    page_iterator = paginator.paginate(
        Filters={
            'WorkflowStatus': [
                {
                    'Comparison': 'EQUALS',
                    'Value': 'NEW'
                }
            ],
            'RecordState': [
                {
                    'Comparison': 'EQUALS',
                    'Value': 'ACTIVE'
                }
            ]
        },
        SortCriteria=[
            {
                'Field': 'Id',
                'SortOrder': 'asc'
            },
        ],
        MaxResults=10
    )
    return page_iterator

def get_securityhub_findings2csv(region):
    findings_pages = get_securityhub_findings(region)
    findings_csv = ''
    lines = 0

    # Header row
    findings_csv = (
        f'FindingId{csv}'
        f'ProductName{csv}'
        f'ComplianceStatus{csv}'
        f'WorkflowStatus{csv}'
        f'Description{csv}'
        f'Severity{csv}'
        f'Region{csv}'
        f'AccountId{csv}'
        f'ResourceType{csv}'
        f'SecurityControlId{csv}'
        f'SecurityStandard'
        + os.linesep
    )

    # Findings rows
    for page in findings_pages:
        for finding in page['Findings']:
            finding_id = finding.get('Id', '')
            product_name = finding.get('ProductName', '')
            compliance_status = finding.get('Compliance', {}).get('Status', '')
            workflow_status = finding.get('Workflow', {}).get('Status', '')
            description = finding.get('Description', '').replace(',', ' ').replace('\n', ' ')
            severity = finding.get('Severity', {}).get('Label', '')
            region = finding.get('Region', '')
            account_id = finding.get('AwsAccountId', '')
            resource_type = finding.get('Resources', [{}])[0].get('Type', '')

            # Security Control ID
            control_id = finding.get('Compliance', {}).get('SecurityControlId', '')

            # Security Standard (from RelatedRequirements)
            standards = []
            if 'RelatedRequirements' in finding.get('Compliance', {}):
                for req in finding['Compliance']['RelatedRequirements']:
                    if 'CIS' in req:
                        standards.append('CIS')
                    elif 'NIST' in req:
                        standards.append('NIST')
                    elif 'PCI' in req:
                        standards.append('PCI')
                    else:
                        # fallback: first word (e.g. "ISO 27001")
                        standards.append(req.split('/')[0])
            security_standard = ','.join(set(standards)) if standards else ''

            # Row
            finding_csv = (
                f'{finding_id}{csv}'
                f'{product_name}{csv}'
                f'{compliance_status}{csv}'
                f'{workflow_status}{csv}'
                f'{description}{csv}'
                f'{severity}{csv}'
                f'{region}{csv}'
                f'{account_id}{csv}'
                f'{resource_type}{csv}'
                f'{control_id}{csv}'
                f'{security_standard}'
                + os.linesep
            )
            findings_csv += finding_csv
            lines += 1

    print('lines:' + str(lines))
    return findings_csv

def copy_file_to_s3(region, bucket_name, filename):
    s3 = boto3.client('s3', region_name=region)
    tc = boto3.s3.transfer.S3Transfer(client=s3)
    tc.upload_file(fullpath, bucket_name, s3Path + filename, extra_args={'ServerSideEncryption': 'AES256'})
    os.remove(fullpath)

def collection_to_csv(col, filename):
    with open(filename, 'w') as f:
        f.write(col)

def create_s3_preauth_url(region, bucket_name, file_name):
    s3 = boto3.client('s3', region_name=region)
    presigned_url = s3.generate_presigned_url(
        'get_object',
        Params={'Bucket': bucket_name, 'Key': s3Path + file_name},
        ExpiresIn=86400
    )
    print(presigned_url)
    return presigned_url

def send_sns(url):
    snsBody = 'Download AWS Security Hub Findings full report: '
    snsBody += url
    sns_client = boto3.client('sns')
    response = sns_client.publish(TopicArn=snsTopicArn, Message=snsBody)

def lambda_handler(event, context):
    csv_data = get_securityhub_findings2csv(region)
    collection_to_csv(csv_data, fullpath)
    copy_file_to_s3(region, bucket, filename)
    url = create_s3_preauth_url(region, bucket, filename)
    send_sns(url)
    return {
        'statusCode': 200,
        'body': json.dumps('Report: ' + url)
    }
