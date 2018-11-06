#  Copyright 2016 Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
#  This file is licensed to you under the AWS Customer Agreement (the "License").
#  You may not use this file except in compliance with the License.
#  A copy of the License is located at http://aws.amazon.com/agreement/ .
#  This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied.
#  See the License for the specific language governing permissions and limitations under the License.

from __future__ import print_function
import boto3
import traceback
from botocore.vendored import requests
import json


SUCCESS = "SUCCESS"
FAILED = "FAILED"


def send(event, context, response_status, response_data, physical_resource_id):
    response_url = event['ResponseURL']

    print(response_url)

    response_body = dict()
    response_body['Status'] = response_status
    response_body['Reason'] = 'See the details in CloudWatch Log Stream: ' + context.log_stream_name
    response_body['PhysicalResourceId'] = physical_resource_id or context.log_stream_name
    response_body['StackId'] = event['StackId']
    response_body['RequestId'] = event['RequestId']
    response_body['LogicalResourceId'] = event['LogicalResourceId']
    response_body['Data'] = response_data

    json_response_body = json.dumps(response_body)

    print("Response body:\n" + json_response_body)

    headers = {
        'content-type': '',
        'content-length': str(len(json_response_body))
    }

    try:
        response = requests.put(response_url, data=json_response_body, headers=headers)
        print("Status code: " + response.reason)
    except Exception as e:
        print("send(..) failed executing requests.put(..): " + str(e))


def lambda_handler(event, context):
    try:
        print(json.dumps(event))
        if event['RequestType'] == 'Delete':
            s3 = boto3.client('s3')
            # Delete KeyBucket contents
            if "KeyBucket" in event["ResourceProperties"].keys():
                print('Getting KeyBucket objects...')
                s3objects = s3.list_objects_v2(Bucket=event["ResourceProperties"]["KeyBucket"])
                if 'Contents' in s3objects.keys():
                    print('Deleting KeyBucket objects %s...' % str(
                        [{'Key': key['Key']} for key in s3objects['Contents']]))
                    s3.delete_objects(Bucket=event["ResourceProperties"]["KeyBucket"],
                                      Delete={'Objects': [{'Key': key['Key']} for key in s3objects['Contents']]})
                # Delete Output bucket contents and versions
            if "OutputBucket" in event["ResourceProperties"].keys():
                print('Getting OutputBucket objects...')
                objects = []
                versions = s3.list_object_versions(Bucket=event["ResourceProperties"]["OutputBucket"])
                while versions:
                    if 'Versions' in versions.keys():
                        for v in versions['Versions']:
                            objects.append({'Key': v['Key'], 'VersionId': v['VersionId']})
                    if 'DeleteMarkers' in versions.keys():
                        for v in versions['DeleteMarkers']:
                            objects.append({'Key': v['Key'], 'VersionId': v['VersionId']})
                    if versions['IsTruncated']:
                        versions = s3.list_object_versions(Bucket=event["ResourceProperties"]["OutputBucket"],
                                                           VersionIdMarker=versions['NextVersionIdMarker'])
                    else:
                        versions = False
                if objects:
                    s3.delete_objects(Bucket=event["ResourceProperties"]["OutputBucket"], Delete={'Objects': objects})
    except Exception as e:
        print(e)
        traceback.print_exc()
    send(event, context, SUCCESS, {}, '')
