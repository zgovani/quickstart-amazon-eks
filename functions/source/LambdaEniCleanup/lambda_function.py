import logging
import boto3
from botocore.exceptions import ClientError
import time
from crhelper import CfnResource

logger = logging.getLogger(__name__)
helper = CfnResource(json_logging=True, log_level='DEBUG')

try:
    ec2 = boto3.client('ec2')
except Exception as init_exception:
    helper.init_failure(init_exception)


def detach_interface(attachment_id):
    logger.info("Detaching %s", attachment_id)
    try:
        ec2.detach_network_interface(AttachmentId=attachment_id, Force=True)
        logger.info('Detached attachment [{0}]'.format(attachment_id))
    except Exception as detach_error:
        logger.error(str(detach_error), exc_info=True)


def delete_interface(interface_id):
    logger.info("deleteing %s", interface_id)
    retries = 10

    # We need to retry because the detach can take some time and this will fail if you try too quickly after the detach
    while retries > 0:
        try:
            # Delete the ENI, if successful drop the retry count to 0 so we do not try again
            ec2.delete_network_interface(NetworkInterfaceId=interface_id)
            logger.info('Deleted interface [{0}]'.format(interface_id))
            break
        except ClientError as delete_error:
            logger.error(str(delete_error), exc_info=True)
            # Get the error code and do not retry on NotFound
            error_code = delete_error.response.get("Error", {}).get("Code", "")
            if error_code == 'InvalidNetworkInterfaceID.NotFound':
                logger.info('Interface [{0}] has already been deleted'.format(interface_id))
                break
            else:
                # If we encounter an error decrement the retry count by 1 and retry after sleeping for 5s
                retries -= 1
                logger.info(f'Failed to delete interface [{interface_id}] - retries remaining [{retries}]. '
                            'Error: {delete_error}')
                time.sleep(5)
        except Exception as delete_error:
            logger.error(str(delete_error), exc_info=True)
            break


def get_attachment_id_for_eni(eni):
    try:
        return eni['Attachment']['AttachmentId']
    except KeyError:
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
            logger.info('{0} ENIs to clean up for [{1}]'.format(len(response['NetworkInterfaces']), function_name))

            # Get the list of attachments we need to detach
            eni_attachment_ids = filter(
                lambda eaid: eaid is not None,
                map(lambda eni: get_attachment_id_for_eni(eni), response['NetworkInterfaces'])
            )

            # Get the list of ENIs
            eni_ids = filter(
                lambda eid: eid is not None,
                map(lambda eni: get_eni_id(eni), response['NetworkInterfaces'])
            )

            # Detach each ENI
            for eni_attachment_id in eni_attachment_ids:
                detach_interface(eni_attachment_id)

            # Delete each ENI
            for eni_id in eni_ids:
                delete_interface(eni_id)
        else:
            logger.info('No ENIs to clean up for [{0}]'.format(function_name))

    # We would rather let the Custom Resource "Delete" than not clean up. Print the error and continue
    except Exception as clean_up_error:
        logger.error('Failed to cleanup ENIs for function [{0}]. Error: '.format(function_name, clean_up_error),
                     exc_info=True)


@helper.delete
def delete_handler(event, _):
    function_names = event['ResourceProperties']['LambdaFunctionNames']
    if type(function_names) != list:
        function_names = [function_names]
    for function_name in function_names:
        clean_up_enis_for_lambda_function(function_name)


def lambda_handler(event, context):
    helper(event, context)
