from chalice import Chalice
from botocore.exceptions import ClientError
import boto3
import hashlib
import binascii
import os

app = Chalice(app_name='testAPI')
app.debug = False

dynamodb = boto3.resource('dynamodb', region_name='us-west-1')
table = dynamodb.Table('User_info')


def authenticate(func):
    def authenticate_and_call(*args, **kwargs):
        try:
            nickname = app.current_request.query_params.get('nickname')
            password = app.current_request.query_params.get('password')
            response = check_authentication(nickname, password)
            if not (response['status'] == 'Authenticated'):
                return {"status": "Not Authenticated"}
        except KeyError:
            return {"status": "Unexpected error - might be missing parameter"}
        return func(*args, **kwargs)
    return authenticate_and_call


def check_authentication(nickname, password):
    try:
        response = table.get_item(
            Key={
                'nickname': nickname
            }
        )
        if 'Item' in response:
            result = response['Item']['encrypted_password']
            encrypted_password = hashlib.sha512(password.encode('utf-8')).hexdigest()
            if encrypted_password == result:
                return {"status": "Authenticated"}
            else:
                return {"status": "Invalid Password"}
        else:
            return {"status": "Invalid Username"}
    except ClientError as e:
        return {"status": "Error: %s" % e.response['Error']['Message']}


@app.route('/login')
def login():
    nickname = app.current_request.query_params.get('nickname')
    password = app.current_request.query_params.get('password')
    return check_authentication(nickname, password)


@app.route('/register/{operation}')
def register(operation):
    if operation == 'create':
        nickname = app.current_request.query_params.get('nickname')
        first_name = app.current_request.query_params.get('first_name')
        last_name = app.current_request.query_params.get('last_name')
        phone_number = app.current_request.query_params.get('phone_number')
        profile_photo_url = app.current_request.query_params.get('profile_photo_url')
        encrypted_pwd = hashlib.sha512(app.current_request.query_params.get('password').encode('utf-8')).hexdigest()

        try:
            table.put_item(
                Item={
                    'nickname': nickname,
                    'first_name': first_name,
                    'last_name': last_name,
                    'phone_number': phone_number,
                    'profile_photo_url': profile_photo_url,
                    'encrypted_password': encrypted_pwd,
                },
                ConditionExpression='attribute_not_exists(nickname)'
            )
            return {"status": "OK"}
        except ClientError as e:
            if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
                return {"status": "Nickname already taken"}
            else:
                return {"status": "Unexpected Error: %s" % e}


@app.route('/create_presigned_url', methods=["GET"])
def create_presigned_url():
    return {"status": "OK", "file": create_presigned_photo_url()}


@app.route('/update_profile_picture')
def update_profile_picture():
    return {"status": "OK", "file": create_presigned_photo_url()}


@app.route('/')
def index():
    return {'hello': 'world'}


@app.route('/update_profile_photo')
@authenticate
def update_profile_photo():
    nickname = app.current_request.query_params.get('nickname')
    profile_photo_url = app.current_request.query_params.get('profile_photo_url')

    response = table.update_item(
        Key={
            'nickname': nickname,
        },
        UpdateExpression="set profile_photo_url=:p",
        ExpressionAttributeValues={
            ':p': profile_photo_url,
        },
        ReturnValues="UPDATED_NEW"
    )
    return {"status": response}


def create_presigned_photo_url():
    fields = {"file_name": (binascii.b2a_hex(os.urandom(32)) + ".jpg").decode("utf-8")}
    fields["file_url"] = "http://d3fjhd6pdkzg07.cloudfront.net/profile_photos/{}".format(fields["file_name"])
    s3_client = boto3.client("s3")
    fields["url"] = s3_client.generate_presigned_url(
        'put_object',
        Params={'Bucket': 'loginappbucket',
                'Key': 'profile_photos/' + fields['file_name'],
                'ACL': 'public-read',
                'ContentType': 'image/jpeg'
                },
        ExpiresIn=1000
    )
    return fields
