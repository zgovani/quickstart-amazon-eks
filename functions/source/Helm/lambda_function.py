import json
import boto3
import subprocess
import shlex
import os
import random
import re
from crhelper import CfnResource
import logging
import string


logger = logging.getLogger(__name__)
helper = CfnResource(json_logging=True, log_level='DEBUG')

try:
    s3_client = boto3.client('s3')
    kms_client = boto3.client('kms')
except Exception as e:
    helper.init_failure(e)


def rand_string(l):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(l))


def run_command(command):
    logger.debug("executing command: %s" % command)
    e = None
    try:
        output = subprocess.check_output(shlex.split(command), stderr=subprocess.STDOUT).decode("utf-8")
        logger.debug(output)
    except subprocess.CalledProcessError as exc:
        logger.debug("Command failed with exit code %s, stderr: %s" % (exc.returncode, exc.output.decode("utf-8")))
        e = Exception(exc.output.decode("utf-8"))
    if e:
        raise e
    else:
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


def truncate(response_data):
    truncated = False
    while len(json.dumps(response_data)) > 3000:
        truncated = True
        response_data.pop(list(response_data.keys())[-1])
    response_data["Truncated"] = truncated
    return response_data


def helm_init(event):
    physical_resource_id = None
    os.environ["PATH"] = "/var/task/bin:" + os.environ.get("PATH")
    if not event['ResourceProperties']['KubeConfigPath'].startswith("s3://"):
        raise Exception("KubeConfigPath must be a valid s3 URI (eg.: s3://my-bucket/my-key.txt")
    bucket, key, kms_context = get_config_details(event)
    create_kubeconfig(bucket, key, kms_context)
    run_command("helm --home /tmp/.helm init --client-only")
    if 'Chart' in event['ResourceProperties'].keys():
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
    return physical_resource_id


def build_flags(properties):
    val_file = ""
    if "ValueYaml" in properties:
        write_values(properties["ValueYaml"], '/tmp/values.yaml')
        val_file = "-f /tmp/values.yaml"
    set_vals = ""
    if "Values" in properties:
        values = properties['Values']
        set_vals = " ".join(["--set %s=%s" % (k, values[k]) for k in values.keys()])
    version = ""
    if "Version" in properties:
        version = "--version %s" % properties['Version']
    name = ""
    if "Name" in properties:
        name = "--name %s" % properties['Name']
    if "ChartBucket" in properties and "ChartKey" in properties:
        properties['Chart'] = '/tmp/chart.tgz'
        chart = s3_client.get_object(Bucket=properties["ChartBucket"], Key=properties["ChartKey"])['Body'].read()
        f = open("/tmp/chart.tgz", "wb")
        f.write(chart)
        f.close()
    return "%s %s %s %s %s" % (properties['Chart'], val_file, set_vals, version, name)


@helper.create
def create(event, context):
    helm_init(event)

    cmd = "helm --home /tmp/.helm install %s" % build_flags(event['ResourceProperties'])
    output = run_command(cmd)
    response_data = parse_install_output(output)
    physical_resource_id = response_data["Name"]
    return physical_resource_id


@helper.update
def update(event, context):
    physical_resource_id = helm_init(event)
    cmd = "helm --home /tmp/.helm upgrade %s %s" % (physical_resource_id, build_flags(event['ResourceProperties']))
    output = run_command(cmd)
    response_data = parse_install_output(output)
    physical_resource_id = response_data["Name"]
    helper.Data.update(response_data)
    return physical_resource_id


@helper.delete
def delete(event, context):
    physical_resource_id = helm_init(event)
    if not re.search(r'^[0-9]{4}\/[0-9]{2}\/[0-9]{2}\/\[\$LATEST\][a-f0-9]{32}$', physical_resource_id):
        try:
            run_command("helm delete --home /tmp/.helm --purge %s" % event['PhysicalResourceId'])
        except Exception as e:
            if 'release: "%s" not found' % event['PhysicalResourceId'] in str(e):
                logger.warning("release already gone, or never existed")
            elif 'invalid release name' in str(e):
                logger.warning("release name invalid, either creation failed, or response not received by CloudFormation")
            else:
                raise
    else:
        logger.warning("physical_resource_id is not a helm release, assuming there is nothing to delete")


@helper.poll_create
@helper.poll_update
def poll_create_update(event, context):
    helm_init(event)
    release_name = helper.Data["PhysicalResourceId"]
    cmd = "helm --home /tmp/.helm status %s" % release_name
    output = run_command(cmd)
    response_data = parse_install_output(output)
    ns = event['ResourceProperties']["Namespace"]
    for t in response_data.keys():
        k8s_type = t.rstrip(string.digits)
        if k8s_type.lower() in ["pod"]:
            k8s_name = response_data[t]
            output = run_command("kubectl get -o json -n %s %s/%s" % (ns, k8s_type, k8s_name))
            logger.debug(output)
            status = json.loads(output)["status"]
            if status['phase'] == 'Pending':
                return None
            if status['phase'] != "Succeeded":
                for s in status["containerStatuses"]:
                    if not s["ready"]:
                        return None
    # Return a resource id or True to indicate that creation is complete. if True is returned an id will be generated
    helper.Data.update(truncate(response_data))
    return release_name


def lambda_handler(event, context):
    helper(event, context)
