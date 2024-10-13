import json

import requests
from requests.auth import HTTPBasicAuth
import boto3
import base64
from botocore.exceptions import ClientError

# PROXY LAMBDA FUNCTION
def lambda_handler(event, context):

    url="http://376e5cd517f1.ngrok.io/micro_service/freshbot"+event.get("path") #Pointing to mannar-test exposed via ngrok
    
    authorizer_context = event.get("requestContext").get("authorizer")
    
    headers = {
        "chargebee-ms-name":"cb-app",
        "chargebee-ms-request-source":"100", 
        "chargebee-ms-request-id": authorizer_context.get("requestId"), 
        "chargebee-ms-origin-user":authorizer_context.get("userEmail"),
        "chargebee-ms-origin-ip":"127.0.0.1",
        }
    

    # ms_api_key = get_secret()
    ms_api_key = "__dev__opmy47fWHoqSVTKhDBD7cdQvT2xjyvJxG" # hardcoding now for Freshworks team to test and develop
    http_method = event.get("httpMethod")

    if(http_method == "GET"):
        # params = authorizer.get("domain")
        params = {"site": "mannar-test"}
        response = requests.get(url, headers=headers, auth=HTTPBasicAuth(ms_api_key,''), params=params)
    elif(http_method == "POST"):
        data = check_and_remove_null(json.loads(event.get("body")))
        if(not data):
            raise Exception("Request body cannot be empty or contain null values") #ToDO: add exception constants
        # set site from jwt token . harcoding for now
        # data["site"] = event.get("jwt_payload").get("domain")     
        data["site"] = "mannar-test"
        response = requests.post(url, headers=headers , auth=HTTPBasicAuth(ms_api_key,''), data=data)   
    
    # print(response.headers)
    # print(type(response.headers))
    return {
        "isBase64Encoded": "False",
        "headers": {},
        "statusCode": response.status_code,
        "body": response.text
        
    }

def check_and_remove_null(data):
    return {
      k:v
      for k, v in data.items()
      if (v is not None) and (v != "null")
   }
    
def get_secret():
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
            


