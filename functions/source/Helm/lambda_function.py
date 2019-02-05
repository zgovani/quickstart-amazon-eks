import json
import logging
import threading
from botocore.vendored import requests
import boto3
import subprocess
import shlex
import os
import string
import random
import re


SUCCESS = "SUCCESS"
FAILED = "FAILED"


s3_client = boto3.client('s3')
kms_client = boto3.client('kms')


def rand_string(l):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(l))


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
    print("executing command: %s" % command)
    try:
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


def parse_install_output(output):
    data = {}
    resource_type = ""
    resources_block = False
    for line in output.split('\n'):
        if line.startswith("NAME:"):
                data['Name'] = line.split()[1]
        elif line.startswith("NAMESPACE:"):
            data['Namespace'] = line.split()[1]
        elif line == 'RESOURCES:':
            resources_block = True
        elif line == 'NOTES:':
            resources_block = False
        if resources_block:
            if line.startswith('==>'):
                count = 0
                resource_type = line.split()[1].split('/')[1].replace('(related)', '')
            elif resource_type and not line.startswith('NAME') and line:
                data[resource_type + str(count)] = line.split()[0]
                count += 1
    return data


def get_config_details(event):
    s3_uri_parts = event['ResourceProperties']['KubeConfigPath'].split('/')
    if len(s3_uri_parts) < 4 or s3_uri_parts[0:2] != ['s3:', '']:
        raise Exception("Invalid KubeConfigPath, must be in the format s3://bucket-name/path/to/config")
    bucket = s3_uri_parts[2]
    key = "/".join(s3_uri_parts[3:])
    kms_context = {"QSContext": event['ResourceProperties']['KubeConfigKmsContext']}
    return bucket, key, kms_context


def write_values(manifest, path):
    f = open(path, "w")
    f.write(manifest)
    f.close()


def lambda_handler(event, context):
    # make sure we send a failure to CloudFormation if the function is going to timeout
    timer = threading.Timer((context.get_remaining_time_in_millis() / 1000.00) - 0.5, timeout, args=[event, context])
    timer.start()
    print('Received event: %s' % json.dumps(event))
    status = SUCCESS
    error_message = None
    response_data = {}
    physical_resource_id = None
    try:
        os.environ["PATH"] = "/var/task/bin:" + os.environ.get("PATH")
        if not event['ResourceProperties']['KubeConfigPath'].startswith("s3://"):
            raise Exception("KubeConfigPath must be a valid s3 URI (eg.: s3://my-bucket/my-key.txt")
        bucket, key, kms_context = get_config_details(event)
        create_kubeconfig(bucket, key, kms_context)
        run_command("helm --home /tmp/.helm init --client-only")
        repo_name = event['ResourceProperties']['Chart'].split('/')[0]
        if "PhysicalResourceId" in event.keys():
            physical_resource_id = event["PhysicalResourceId"]
        if "RepoUrl" in event['ResourceProperties'].keys():
            run_command("helm repo add %s %s --home /tmp/.helm" % (repo_name, event['ResourceProperties']["RepoUrl"]))
        if "Namespace" in event['ResourceProperties'].keys():
            namespace = event['ResourceProperties']["Namespace"]
            k8s_context = run_command("kubectl config current-context")
            run_command("kubectl config set-context %s --namespace=%s" % (k8s_context, namespace))
        run_command("helm --home /tmp/.helm repo update")
        if event['RequestType'] == 'Create':
            val_file = ""
            if "ValueYaml" in event['ResourceProperties']:
                write_values(event['ResourceProperties']["ValueYaml"], '/tmp/values.yaml')
                val_file = "-f /tmp/values.yaml"
            set_vals = ""
            if "Values" in event['ResourceProperties']:
                values = event['ResourceProperties']['Values']
                set_vals = " ".join(["--set %s=%s" % (k, values[k]) for k in values.keys()])
            cmd = "helm --home /tmp/.helm install %s %s %s --wait" % (event['ResourceProperties']['Chart'], val_file, set_vals)
            output = run_command(cmd)
            response_data = parse_install_output(output)
            physical_resource_id = response_data["Name"]
        if event['RequestType'] == 'Update':
            pass
        if event['RequestType'] == 'Delete':
            if not re.search(r'^[0-9]{4}\/[0-9]{2}\/[0-9]{2}\/\[\$LATEST\][a-f0-9]{32}$', physical_resource_id):
                run_command("helm delete --home /tmp/.helm --purge %s" % event['PhysicalResourceId'])
            else:
                print("physical_resource_id is not a helm release, assuming there is nothing to delete")
    except Exception as e:
        logging.error('Exception: %s' % e, exc_info=True)
        status = FAILED
        error_message = str(e)
    finally:
        timer.cancel()
        send(event, context, status, response_data, physical_resource_id, reason=error_message)
