import boto3
import logging
from crhelper import CfnResource

logger = logging.getLogger(__name__)
helper = CfnResource(json_logging=True, log_level='DEBUG')
lmbd = boto3.client("lambda")


@helper.delete
def delete_handler(event, _):
    security_group_id = event["ResourceProperties"]["SecurityGroupId"]
    paginator = lmbd.get_paginator('list_functions')
    for page in paginator.paginate():
            for func in page['Functions']:
                if "helm-provider-vpc-connector" not in func['FunctionName']:
                    continue
                if "kubernetes-provider-vpc-connector" not in func['FunctionName']:
                    continue
                if "k8s-api-vpc-connector-" not in func['FunctionName']:
                    continue
                if security_group_id not in func.get('VpcConfig', {}).get('SecurityGroupIds', []):
                    continue
                lmbd.update_function_configuration(
                    FunctionName=func['FunctionName'],
                    VpcConfig={
                        'SecurityGroupIds': [],
                        'SubnetIds': []
                    }
                )
                lmbd.delete_function(FunctionName=func['FunctionName'])


def lambda_handler(event, context):
    helper(event, context)
