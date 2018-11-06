import json
import logging
import threading
from botocore.vendored import requests
import boto3
import subprocess
import shlex
import os


SUCCESS = "SUCCESS"
FAILED = "FAILED"


s3_client = boto3.client('s3')
kms_client = boto3.client('kms')


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


def run_command(command):
    try:
        output = subprocess.check_output(shlex.split(command), stderr=subprocess.STDOUT).decode("utf-8")
        print(output)
    except subprocess.CalledProcessError as exc:
        print("Command failed with exit code %s, stderr: %s" % (exc.returncode, exc.output.decode("utf-8")))
        raise
    return output


def create_kubeconfig(bucket, key, kms_context):
    try:
        os.mkdir("/tmp/.kube/")
    except FileExistsError:
        pass
    enc_config = s3_client.get_object(Bucket=bucket, Key=key)['Body'].read()
    kubeconf = kms_client.decrypt(
        CiphertextBlob=enc_config,
        EncryptionContext=kms_context
    )['Plaintext'].decode('utf8')
    f = open("/tmp/.kube/config", "w")
    f.write(kubeconf)
    f.close()
    os.environ["KUBECONFIG"] = "/tmp/.kube/config"


def lambda_handler(event, context):
    # make sure we send a failure to CloudFormation if the function is going to timeout
    timer = threading.Timer((context.get_remaining_time_in_millis() / 1000.00) - 0.5, timeout, args=[event, context])
    timer.start()
    print('Received event: %s' % json.dumps(event))
    status = SUCCESS
    try:
        os.environ["PATH"] = "/var/task/bin:" + os.environ.get("PATH")
        if not event['ResourceProperties']['KubeConfigPath'].startswith("s3://"):
            raise Exception("KubeConfigPath must be a valid s3 URI (eg.: s3://my-bucket/my-key.txt")
        bucket = event['ResourceProperties']['KubeConfigPath'].split('/')[2]
        key = "/".join(event['ResourceProperties']['KubeConfigPath'].split('/')[3:])
        kms_context = {"QSContext": event['ResourceProperties']['KubeConfigKmsContext']}
        create_kubeconfig(bucket, key, kms_context)
        if event['RequestType'] == 'Create':
            run_command("helm --debug --home /tmp/.helm init --service-account %s --wait" % event['ResourceProperties']['TillerSA'])
        if event['RequestType'] == 'Update':
            pass
        if event['RequestType'] == 'Delete':
            run_command("kubectl delete deployment tiller-deploy -n kube-system ")
    except Exception as e:
        logging.error('Exception: %s' % e, exc_info=True)
        status = FAILED
    finally:
        timer.cancel()
        send(event, context, status, {}, None)
