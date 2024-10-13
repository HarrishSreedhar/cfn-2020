import json
from .authorizer import authorize
from .proxy_lambda import lambda_handler

def authorizer_call(event, context):
    return authorize(event, context)

def proxy_call(event, context):
    return lambda_handler(event, context)


