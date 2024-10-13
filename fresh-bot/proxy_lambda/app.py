import json

import requests
from requests.auth import HTTPBasicAuth
import boto3
import base64
from botocore.exceptions import ClientError

# PROXY LAMBDA FUNCTION
def lambda_handler(event, context):
    """Sample pure Lambda function

    Parameters
    ----------
    event: dict, required
        API Gateway Lambda Proxy Input Format

        Event doc: https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html#api-gateway-simple-proxy-for-lambda-input-format

    context: object, required
        Lambda Context runtime methods and attributes

        Context doc: https://docs.aws.amazon.com/lambda/latest/dg/python-context-object.html

    Returns
    ------
    API Gateway Lambda Proxy Output Format: dict

        Return doc: https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
    """

    # try:
    #     ip = requests.get("http://checkip.amazonaws.com/")
    # except requests.RequestException as e:
    #     # Send some context about this error to Lambda Logs
    #     print(e)

    #     raise e
    
    domain_url = event.get("headers").get("user-domain") 
    url="https://"+domain_url+".predev1.in/micro_service/freshbot/createPlan" #choose this based on incoming action
    
    headers = {
        "chargebee-ms-name":"cb-freshbot",
        "chargebee-ms-request-source":"100", 
        "chargebee-ms-request-id": event.get("jwt_payload").get("request_id"), #TODO: check if this should be sent from jwt payload or AWS CONTEXT
        "chargebee-ms-origin-user":event.get("jwt_payload").get("email"),
        "chargebee-ms-origin-ip":"127.0.0.1",
        }
    
    
    data = check_and_remove_null(event.get("data"))
    # data = event.get("data")

    # set site from jwt token
    data["site"] = event.get("jwt_payload").get("domain")
    
    # ms_api_key = get_secret()
    ms_api_key = "__dev__2nxO4ekeAwggxdlaGV9TVIyApv3xRnJJ" #hardcoding now for Freshworks team to test and develop
    auth = HTTPBasicAuth(ms_api_key,'')
    
    response = requests.post(url, headers=headers , auth=auth, data=data)
    return {
        "statusCode": response.status_code,
        "body": {
             "response": response.text
        }
    }

def check_and_remove_null(data):
    return {
      k:v
      for k, v in data.items()
      if (v is not None) and (v != "null")
   }
    
def get_secret():
    print("insideeeee get_secret()")
    secret_name = "dev/us-e1/freshbot/msapi/test"
    region_name = "us-east-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            return get_secret_value_response['SecretString']
        else:
            return base64.b64decode(get_secret_value_response['SecretBinary']).decode('utf-8')
            


