import json
import jwt
# import time
import boto3
import base64
from botocore.exceptions import ClientError
from jwt.exceptions import InvalidTokenError

def authorize(event, context):
    try:
        auth_string = ""
        
        if("authorizationToken" in event):
            auth_string = event.get("authorizationToken")
        
        request_id = "" #TODO: assign this any unique data from the decoded jwt??
        
        if(auth_string != None and len(auth_string) != 0):
            payload,is_valid = validate_jwt_token(auth_string)
            if(is_valid):
                return validate_token_and_gen_policy('Allow', payload, request_id)
            else:
                return validate_token_and_gen_policy('Deny', payload, request_id)
        else:
            return validate_token_and_gen_policy('Deny', {}, request_id)
            
    except Exception as e:
        raise e
    

def validate_jwt_token(auth_string):
    try:
        secret = "chargebee-secret" #hardcoding for FW testing
        # secret = get_secret()
        payload = jwt.decode(auth_string, secret, algorithms=['HS256'])
        return payload,True
    except:
        return {},False
 

def validate_token_and_gen_policy(effect, payload, request_id):
        
    policyObj = {
        "principalId": request_id, # The principal user identification associated with the token sent by the client.
        "policyDocument": {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Action': 'execute-api:Invoke',
                    'Effect': effect,
                    'Resource': '*'
                }
            ]
        }
    }
    
    
    # Adding context if payload is not empty (i.e properly decoded)
    if(payload):
        policyObj["context"] = payload
    
    return policyObj

def get_secret():
    print("inside get_secret")
    secret_name = "dev/us-e1/freshbot/test/secret"
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
    except Exception as e:
        raise e

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
            secretString = json.loads(get_secret_value_response['SecretString'])
            return (list(secretString.values())[0])
        else:
            return json.loads(base64.b64decode(get_secret_value_response['SecretBinary']))
            # return base64.b64decode(get_secret_value_response['SecretBinary']).decode('utf-8') #TODO: check this once secret is enabled in mamager

        
    
    