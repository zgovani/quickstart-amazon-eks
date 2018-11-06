from __future__ import print_function
import boto3
from botocore.exceptions import ClientError
import time
import traceback
from botocore.vendored import requests
import json


SUCCESS = "SUCCESS"
FAILED = "FAILED"


ec2 = boto3.client('ec2')


def send(event, context, responseStatus, responseData, physicalResourceId=None, noEcho=False):
    responseUrl = event['ResponseURL']

    print(responseUrl)

    responseBody = {}
    responseBody['Status'] = responseStatus
    responseBody['Reason'] = 'See the details in CloudWatch Log Stream: ' + context.log_stream_name
    responseBody['PhysicalResourceId'] = physicalResourceId or context.log_stream_name
    responseBody['StackId'] = event['StackId']
    responseBody['RequestId'] = event['RequestId']
    responseBody['LogicalResourceId'] = event['LogicalResourceId']
    responseBody['NoEcho'] = noEcho
    responseBody['Data'] = responseData

    json_responseBody = json.dumps(responseBody)

    print("Response body:\n" + json_responseBody)

    headers = {
        'content-type' : '',
        'content-length' : str(len(json_responseBody))
    }

    try:
        response = requests.put(responseUrl,
                                data=json_responseBody,
                                headers=headers)
        print("Status code: " + response.reason)
    except Exception as e:
        print("send(..) failed executing requests.put(..): " + str(e))


def detach_interface(attachment_id):
    ec2.detach_network_interface(AttachmentId=attachment_id, Force=True)
    print('Detached attachment [{0}]'.format(attachment_id))


def delete_interface(interface_id):
    retries = 10

    # We need to retry because the detach can take some time and this will fail if you try too quickly after the detach
    while retries > 0:
        try:
            # Delete the ENI, if successful drop the retry count to 0 so we do not try again
            ec2.delete_network_interface(NetworkInterfaceId=interface_id)
            print('Deleted interface [{0}]'.format(interface_id))
            retries = 0
        except ClientError as delete_error:
            # Get the error code and do not retry on NotFound
            error_code = delete_error.response.get("Error", {}).get("Code", "")

            if error_code == 'InvalidNetworkInterfaceID.NotFound':
                retries = 0
                print('Interface [{0}] has already been deleted'.format(interface_id))
            # Default Case
            else:
                # If we encounter an error decrement the retry count by 1 and retry after sleeping for 5s
                retries -= 1
                print('Failed to delete interface [{0}] - retries remaining [{1}]. Error: {2}'.format(interface_id, retries, delete_error))
                time.sleep(5)


def get_attachment_id_for_eni(eni):
    if 'Attachment' in eni and 'AttachmentId' in eni['Attachment']:
        return eni['Attachment']['AttachmentId']
    return None


def get_eni_id(eni):
    if 'NetworkInterfaceId' in eni:
        return eni['NetworkInterfaceId']
    return None


def clean_up_enis_for_lambda_function(function_name):
    try:
        # Get the associated ENIs
        response = ec2.describe_network_interfaces(
            Filters=[
                {
                    'Name': 'requester-id',
                    'Values': ['*:{0}'.format(function_name)]
                },
                {
                    'Name': 'description',
                    'Values': ['AWS Lambda VPC ENI*']
                }
            ]
        )

        # Check there is any interfaces
        if 'NetworkInterfaces' in response and len(response['NetworkInterfaces']) > 0:
            print('{0} ENIs to clean up for [{1}]'.format(len(response['NetworkInterfaces']), function_name))

            # Get the list of attachments we need to detach
            eni_attachment_ids = filter(lambda eaid: eaid is not None, map(lambda eni: get_attachment_id_for_eni(eni), response['NetworkInterfaces']))

            # Get the list of ENIs
            eni_ids = filter(lambda eid: eid is not None, map(lambda eni: get_eni_id(eni), response['NetworkInterfaces']))

            # Print out what we are going to do
            print('Detaching the following attachments [{0}]'.format(",".join(eni_attachment_ids)))
            print('Deleting the following interfaces [{0}]'.format(",".join(eni_ids)))

            # Detach each ENI
            for eni_attachment_id in eni_attachment_ids:
                detach_interface(eni_attachment_id)

            # Delete each ENI
            for eni_id in eni_ids:
                delete_interface(eni_id)
        else:
            print('No ENIs to clean up for [{0}]'.format(function_name))

    # We would rather let the Custom Resource "Delete" than not clean up. Print the error and continue
    except Exception as clean_up_error:
        print('Failed to cleanup ENIs for function [{0}]. Error: '.format(function_name, clean_up_error))


def lambda_handler(event, context):
    request_type = event['RequestType']
    responseData = {}

    if request_type == 'Delete':
        try:
            function_names = event['ResourceProperties']['LambdaFunctionNames']
            if type(function_names) != list:
                function_names = [function_names]
            for function_name in function_names:
                clean_up_enis_for_lambda_function(function_name)
            send(event, context, SUCCESS, responseData)
        except Exception as e:
            print("ERROR: %S" % e)
            traceback.print_exc()
            send(event, context, FAILED, responseData)
    else:
        send(event, context, SUCCESS, responseData)
