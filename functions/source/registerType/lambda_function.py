import boto3
import logging
from crhelper import CfnResource
from time import sleep
import json
import random

logger = logging.getLogger(__name__)
helper = CfnResource(json_logging=True, log_level='DEBUG')
cfn = boto3.client('cloudformation')


def stabilize(token):
    p = cfn.describe_type_registration(RegistrationToken=token)
    while p['ProgressStatus'] == "IN_PROGRESS":
        sleep(5)
        p = cfn.describe_type_registration(RegistrationToken=token)
    if p['ProgressStatus'] == 'FAILED':
        if 'to finish before submitting another deployment request for ' not in p['Description']:
            raise Exception(p['Description'])
        return None
    return p['TypeVersionArn']


@helper.create
@helper.update
def register(event, _):
    logger.error(f"event: {json.dumps(event)}")
    kwargs = {
       "Type": 'RESOURCE',
       "TypeName": event['ResourceProperties']['TypeName'],
       "SchemaHandlerPackage": event['ResourceProperties']['SchemaHandlerPackage'],
        "LoggingConfig": {
            "LogRoleArn": event['ResourceProperties']['LogRoleArn'],
            "LogGroupName": event['ResourceProperties']['LogGroupName']
        },
        "ExecutionRoleArn": event['ResourceProperties']['ExecutionRoleArn']
    }
    retries = 3
    while True:
        try:
            try:
                response = cfn.register_type(**kwargs)
            except cfn.exceptions.CFNRegistryException as e:
                if "Maximum number of versions exceeded" not in str(e):
                    raise
                delete_oldest(event['ResourceProperties']['TypeName'])
                continue
            version_arn = stabilize(response['RegistrationToken'])
            break
        except Exception as e:
            if not retries:
                raise
            retries -= 1
            logger.error(e, exc_info=True)
            sleep(60)
    if version_arn:
        cfn.set_type_default_version(Arn=version_arn)
    return version_arn


def delete_oldest(name):
    versions = cfn.list_type_versions(Type='RESOURCE', TypeName=name)['TypeVersionSummaries']
    if len(versions) < 2:
        return
    try:
        try:
            cfn.deregister_type(Arn=versions[0]['Arn'])
        except cfn.exceptions.CFNRegistryException as e:
            if "is the default version" not in str(e):
                raise
            cfn.deregister_type(Arn=versions[1]['Arn'])
    except cfn.exceptions.TypeNotFoundException:
        print("version already deleted...")


@helper.delete
def delete(event, _):
    if not event['PhysicalResourceId'].startswith("arn:"):
        print("no valid arn to delete")
        return
    retries = 0
    while True:
        try:
            try:
                cfn.deregister_type(Arn=event['PhysicalResourceId'])
            except cfn.exceptions.CFNRegistryException as e:
                if "is the default version" not in str(e):
                    raise
                versions = cfn.list_type_versions(Type='RESOURCE', TypeName=event['ResourceProperties']['TypeName'])
                if len(versions) > 1:
                    versions = [v['Arn'] for v in versions if v['Arn'] != event['PhysicalResourceId']]
                    versions.sort(reverse=True)
                    cfn.set_type_default_version(Arn=versions[0])
                    cfn.deregister_type(Arn=event['PhysicalResourceId'])
                else:
                    cfn.deregister_type(Type='RESOURCE', TypeName=event['ResourceProperties']['TypeName'])
            return
        except cfn.exceptions.TypeNotFoundException:
            print("type already deleted...")
            return
        except Exception as e:
            retries += 1
            if retries > 5:
                raise
            logger.error(e, exc_info=True)
            sleep(random.choice([1, 2, 3, 4, 5]))


def lambda_handler(event, context):
    helper(event, context)
