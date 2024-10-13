import json

import requests
from requests.auth import HTTPBasicAuth
import boto3
import base64
from botocore.exceptions import ClientError

# PROXY LAMBDA FUNCTION
def lambda_handler(event, context):
    try:
        print("EVEntttt-----")
        print(event)
        # http_method = event.get("jwt_payload").get("http_method")
        http_method = event.get("http_method")
        end_point = ""
        if(event.get("path")):
            end_point = event.get("path").split("/")[-1] 
            
        # elif(event.get("jwt_payload").get("operation_name")): #  fallback to operation name if path is not getting set    
        #     end_point = event.get("jwt_payload").get("operation_name")

        url = "http://e2863d08b044.ngrok.io/micro_service/freshbot/"+end_point #choose this based on incoming action
        
        headers = {
            "chargebee-ms-name":"cb-app",
            "chargebee-ms-request-source":"100", # maintain a map to get resource
            "chargebee-ms-request-id": event.get("jwt_payload").get("request_id"), #TODO: check if this should be sent from jwt payload or AWS CONTEXT
            "chargebee-ms-origin-user":event.get("jwt_payload").get("email"),
            "chargebee-ms-origin-ip":"127.0.0.1",
            }
        
        
        
        secret = "__dev__Os3Wb0Je5mVlZP8ZtYZuAxmujVF2cscuG"
        # secret = get_secret()

        if(http_method == "GET"):
            response = requests.get(url, headers=headers, auth=HTTPBasicAuth(secret,''))
            
        elif(http_method == "POST"):
            data = check_and_remove_null(event.get("data"))
            if(not data):
                raise Exception("Request body cannot be empty or contain null values") #ToDO: add exception constants
                
            # set site from jwt token
            # data["site"] = event.get("jwt_payload").get("domain")     
            response = requests.post(url, headers=headers , auth=HTTPBasicAuth(secret,''), data=data)
        else:
            raise Exception("Invlaid request type")
    
        # print("Response is:")
        # print(response.text) #TEXT/HTML
        # print(response.status_code, response.reason) #HTTP
    
        return {
            "statusCode": response.status_code,
            "body": {
                 "response": response.text
            }
        }
        
    except Exception as error:
        return {
            "statusCode": "400",
            "error": str(error)
        }

def check_and_remove_null(data):
    if(data):
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
            # secretString = json.loads(get_secret_value_response['SecretString'])
            # print(list(secretString.values())[0])
            # return (list(secretString.values())[0])
        else:
            return base64.b64decode(get_secret_value_response['SecretBinary']).decode('utf-8')
            


