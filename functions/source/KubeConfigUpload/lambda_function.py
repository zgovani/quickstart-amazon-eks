import json
import logging
import threading
from botocore.vendored import requests
import os
import boto3


SUCCESS = "SUCCESS"
FAILED = "FAILED"
KUBECONFIG = """apiVersion: v1
clusters:
- cluster:
    server: {endpoint}
    certificate-authority-data: {ca_data}
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: aws
  name: aws
current-context: aws
kind: Config
preferences: {{}}
users:
- name: aws
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1alpha1
      command: aws-iam-authenticator
      args:
        - "token"
        - "-i"
        - "{cluster_name}"
"""


kms_client = boto3.client('kms')
s3_client = boto3.client('s3')


def send(event, context, response_status, response_data, physical_resource_id, reason=None):
    response_url = event['ResponseURL']
    logging.debug("CFN response URL: " + response_url)
    response_body = dict()
    response_body['Status'] = response_status
    msg = 'See details in CloudWatch Log Stream: ' + context.log_stream_name
    if not reason:
        response_body['Reason'] = msg
    else:
        response_body['Reason'] = str(reason)[0:255] + '... ' + msg
    if physical_resource_id:
        response_body['PhysicalResourceId'] = physical_resource_id
    elif 'PhysicalResourceId' in event:
        response_body['PhysicalResourceId'] = event['PhysicalResourceId']
    else:
        response_body['PhysicalResourceId'] = context.log_stream_name
    response_body['StackId'] = event['StackId']
    response_body['RequestId'] = event['RequestId']
    response_body['LogicalResourceId'] = event['LogicalResourceId']
    if response_data and response_data != {} and response_data != [] and isinstance(response_data, dict):
        response_body['Data'] = response_data
    json_response_body = json.dumps(response_body)
    logging.debug("Response body:\n" + json_response_body)
    headers = {
        'content-type': '',
        'content-length': str(len(json_response_body))
    }
    try:
        response = requests.put(response_url, data=json_response_body, headers=headers)
        logging.info("CloudFormation returned status code: " + response.reason)
    except Exception as e:
        logging.error("send(..) failed executing requests.put(..): " + str(e))
        raise


def timeout(event, context):
    logging.error('Execution is about to time out, sending failure response to CloudFormation')
    send(event, context, FAILED, {}, None)


def create_kubeconfig(endpoint, cluster_name, ca_data):
    return KUBECONFIG.format(endpoint=endpoint, ca_data=ca_data, cluster_name=cluster_name)


def lambda_handler(event, context):
    # make sure we send a failure to CloudFormation if the function is going to timeout
    timer = threading.Timer((context.get_remaining_time_in_millis() / 1000.00) - 0.5, timeout, args=[event, context])
    timer.start()
    print('Received event: %s' % json.dumps(event))
    status = SUCCESS
    try:
        os.environ["PATH"] = "/var/task/bin:" + os.environ.get("PATH")
        endpoint = event['ResourceProperties']['EKSEndpoint']
        cluster_arn = event['ResourceProperties']['EKSArn']
        ca_data = event['ResourceProperties']['EKSCAData']
        kms_key_arn = event['ResourceProperties']['KmsKeyArn']
        s3_bucket_name = event['ResourceProperties']['S3BucketName']
        s3_key = event['ResourceProperties']['S3Key']
        enc_context = {"QSContext": event['ResourceProperties']['EncryptionContext']}
        kube_config = create_kubeconfig(endpoint, cluster_arn.split('/')[1], ca_data)
        if event['RequestType'] == 'Create' or event['RequestType'] == 'Update':
            enc_config = kms_client.encrypt(
                Plaintext=kube_config,
                KeyId=kms_key_arn,
                EncryptionContext=enc_context
            )['CiphertextBlob']
            s3_client.put_object(Body=enc_config, Bucket=s3_bucket_name, Key=s3_key)
        if event['RequestType'] == 'Delete':
            s3_client.delete_object(Bucket=s3_bucket_name, Key=s3_key)
    except Exception as e:
        logging.error('Exception: %s' % e, exc_info=True)
        status = FAILED
    finally:
        timer.cancel()
        send(event, context, status, {}, None)
