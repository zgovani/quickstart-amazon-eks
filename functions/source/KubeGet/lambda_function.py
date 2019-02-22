import json
import logging
import threading
from botocore.vendored import requests
import boto3
import subprocess
import shlex
import os
import time
from hashlib import md5

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
        response_body['Reason'] = str(reason)
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
    print("Returning response: %s" % json_response_body)
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
        print("executing command: %s" % command)
        output = subprocess.check_output(shlex.split(command), stderr=subprocess.STDOUT).decode("utf-8")
        print(output)
    except subprocess.CalledProcessError as exc:
        print("Command failed with exit code %s, stderr: %s" % (exc.returncode, exc.output.decode("utf-8")))
        raise Exception(exc.output.decode("utf-8"))
    return output


def create_kubeconfig(bucket, key, kms_context):
    try:
        os.mkdir("/tmp/.kube/")
    except FileExistsError:
        pass
    print("s3_client.get_object(Bucket='%s', Key='%s')" % (bucket, key))
    try:
        enc_config = s3_client.get_object(Bucket=bucket, Key=key)['Body'].read()
    except Exception as e:
        raise Exception("Failed to fetch KubeConfig from S3: %s" % str(e))
    kubeconf = kms_client.decrypt(
        CiphertextBlob=enc_config,
        EncryptionContext=kms_context
    )['Plaintext'].decode('utf8')
    f = open("/tmp/.kube/config", "w")
    f.write(kubeconf)
    f.close()
    os.environ["KUBECONFIG"] = "/tmp/.kube/config"


def get_config_details(event):
    s3_uri_parts = event['ResourceProperties']['KubeConfigPath'].split('/')
    if len(s3_uri_parts) < 4 or s3_uri_parts[0:2] != ['s3:', '']:
        raise Exception("Invalid KubeConfigPath, must be in the format s3://bucket-name/path/to/config")
    bucket = s3_uri_parts[2]
    key = "/".join(s3_uri_parts[3:])
    kms_context = {"QSContext": event['ResourceProperties']['KubeConfigKmsContext']}
    return bucket, key, kms_context


def lambda_handler(event, context):
    # make sure we send a failure to CloudFormation if the function is going to timeout
    timer = threading.Timer((context.get_remaining_time_in_millis() / 1000.00) - 0.5, timeout, args=[event, context])
    timer.start()
    print('Received event: %s' % json.dumps(event))
    status = SUCCESS
    response_data = {}
    physical_resource_id = None
    error_message = ''
    try:
        os.environ["PATH"] = "/var/task/bin:" + os.environ.get("PATH")
        if not event['ResourceProperties']['KubeConfigPath'].startswith("s3://"):
            raise Exception("KubeConfigPath must be a valid s3 URI (eg.: s3://my-bucket/my-key.txt")
        bucket, key, kms_context = get_config_details(event)
        create_kubeconfig(bucket, key, kms_context)
        if "PhysicalResourceId" in event.keys():
            physical_resource_id = event["PhysicalResourceId"]
        if event['RequestType'] in ['Create', 'Update']:
            name = event['ResourceProperties']['Name']
            retry_timeout = 0
            if "Timeout" in event['ResourceProperties']:
                retry_timeout = int(event['ResourceProperties']["Timeout"])
            if retry_timeout > 600:
                retry_timeout = 600
            namespace = event['ResourceProperties']['Namespace']
            json_path = event['ResourceProperties']['JsonPath']
            while True:
                try:
                    outp = run_command('kubectl get %s -o jsonpath="%s" --namespace %s' % (name, json_path, namespace))
                    break
                except Exception as e:
                    if retry_timeout < 1:
                        raise
                    else:
                        logging.error('Exception: %s' % e, exc_info=True)
                        print("retrying until timeout...")
                        time.sleep(5)
                        retry_timeout = retry_timeout - 5
            response_data = {}
            if "ResponseKey" in event['ResourceProperties']:
                response_data[event['ResourceProperties']["ResponseKey"]] = outp
            if len(outp.encode('utf-8')) > 1000:
                outp = 'MD5-' + str(md5(outp.encode('utf-8')).hexdigest())
            physical_resource_id = outp
    except Exception as e:
        logging.error('Exception: %s' % e, exc_info=True)
        status = FAILED
        error_message = str(e)
    finally:
        timer.cancel()
        send(event, context, status, response_data, physical_resource_id, reason=error_message)
