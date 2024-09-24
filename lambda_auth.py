import boto3
import json

cognito = boto3.client('cognito-idp')


def lambda_handler(event, context):
    print(json.dumps(event, indent=2))

    email = event['headers']['user_email']
    password = event['headers']['user_pword']
    client_id = '6i132tjd63jrjpcl991kk0kue9'

    try:
        response_cognito = cognito.initiate_auth(
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': email,
                'PASSWORD': password
            },
            ClientId=client_id
        )

        print(json.dumps(response_cognito, indent=2))

        response = generatePolicy(email, 'Allow', event['methodArn'], email)

    except Exception as error:

        print('Cognito Response ----- : ' + error.__str__())

        response = generatePolicy(email, 'Deny', event['methodArn'], email)

    return json.loads(response)


def generatePolicy(principalid, effect, resource, email):
    authResponse = {}
    authResponse['principalId'] = principalid
    if (effect and resource):
        policyDocument = {}
        policyDocument['Version'] = '2012-10-17'
        policyDocument['Statement'] = []
        statementOne = {}
        statementOne['Action'] = 'execute-api:Invoke'
        statementOne['Effect'] = effect
        statementOne['Resource'] = resource
        policyDocument['Statement'] = [statementOne]
        authResponse['policyDocument'] = policyDocument

    authResponse['context'] = {
        "email_usuario": email
    }

    authResponse_JSON = json.dumps(authResponse)

    return authResponse_JSON
