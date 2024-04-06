import boto3
from botocore.exceptions import ClientError
import uuid
import logging
import json
from types import SimpleNamespace
from dataclasses import dataclass
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s')
logger = logging.getLogger()
logger.setLevel("INFO")
logger.info("==============Happy Isles Initilization==============")


####
aws_account = os.environ.get('aws_account', "339713150119")
aws_region = os.environ.get('aws_region', 'us-east-1')
application = os.environ.get('application', 'dream')
source_bucket = os.environ.get('source_bucket', 'dream-store-bucket')
destination_bucket = os.environ.get('destination_bucket', 'dream-store-bucket')
user_id = os.environ.get('user_id', 'drem-user-2700')
sns_arn = os.environ.get('sns_arn', 'arn:aws:sns:us-east-1:339713150119:dream-nlp-textract-sns-response')
sns_role_arn = os.environ.get('sns_role_arn', 'arn:aws:iam::339713150119:role/dream-nlp-textract-role')
raw_prefix = 'raw'
####

@dataclass
class S3Object:
    bucket: str = None
    key: str = None
    file_name: str = None
    size: int = None
    etag: str = None
    folder: str = None
    file_name: str= None
    destination_bucket: str =None
    destination_key: str = None
    uuid: str = None


class AWSUtilities:
    def __init__(self, aws_region):
        self.aws_region = aws_region
        self.s3_client = boto3.client('s3', region_name=self.aws_region)
        self.s3_resource = boto3.resource('s3', region_name=self.aws_region)
        self.dynamodb_client = boto3.client('dynamodb', region_name=self.aws_region)
        self.dynamodb_resource = boto3.resource('dynamodb', region_name=self.aws_region)
        self.textract_client = boto3.client('textract', region_name=self.aws_region)
        self.comprehend_medical_client = boto3.client('comprehendmedical', region_name=self.aws_region)
        self.s3_status_table = 's3_status_table'
        self.textract_status_table = 'textract_status_table'
        self.comprehend_status_table = 'comprehend_status_table'
        self.S3Object = S3Object()

        self.aws_account = aws_account
        self.aws_region = aws_region
        self.application = application
        self.source_bucket = source_bucket
        self.destination_bucket = destination_bucket
        self.user_id = user_id
        self.sns_arn = sns_arn
        self.sns_role_arn = sns_role_arn

        self.dream_nlp_file_state_table = self.dynamodb_resource.Table("dream-nlp-file-state-table")

    def store_event(self, event: list):
        try:

            for e in event:
                o = S3Object(**e)
                if o.size >0:
                    uuid = self.generate_uuid()
                    if self.store_s3_status(user_id, o):
                        # processed_key = f'processed/{user_id}/{uuid}/{o.file_name}'
                        # o.destination_bucket = destination_bucket
                        # o.destination_key = processed_key
                        self.transfer_files_s3(o.bucket, o.key, o.destination_bucket,o.destination_key)
                        logger.info(f"Copied File {o.file_name} from {o.bucket}/{o.key} to  {o.destination_bucket} {o.destination_key}")
                        self.store_s3_status(user_id, o)
                        #initiate textract analysis process
                        self.initiate_textract_process(user_id,o)
                    # logger.info(f"Adding S3 record to Dynamodb with UUID {uuid}")
                else:
                    logger.info(f'File/Data size is 0, so not storing and copying, looks to be a folder {o.key}')
        except Exception as e:
            logger.error("Error copying file from source to destination {e}")

    def get_files_s3(self, bucket, key) -> list:
        """
        Get a list of files from S3 bucket with the given key prefix.
        """
        files = []
        try:
            response = self.s3_client.list_objects_v2(Bucket=bucket, Prefix=key)
            if 'Contents' in response:
                files = [obj['Key'] for obj in response['Contents']]
        except ClientError as e:
            logger.info(f"Error getting files from S3: {e}")
        return files

    def read_files_s3(self, bucket, key) :
        """
        Read file content from S3 bucket with the given key.
        """
        try:
            response = self.s3_client.get_object(Bucket=bucket, Key=key)
            return response['Body'].read()
        except ClientError as e:
            logger.info(f"Error reading file from S3: {e}")
            return None

    def save_files_s3(self, data_or_buffer, bucket, key):
        """
        Save file to S3 bucket with the given key.
        """
        try:
            if isinstance(data_or_buffer, bytes):
                self.s3_client.put_object(Bucket=bucket, Key=key, Body=data_or_buffer)
            else:
                self.s3_resource.Object(bucket, key).put(Body=data_or_buffer)
            return True
        except ClientError as e:
            logger.info(f"Error saving file to S3: {e}")
            return False
    def transfer_files_s3(self, source_bucket, source_key, target_bucket, target_key):
        """
        Transfer file from source bucket/key to target bucket/key
        """
        try:
            copy_source = {
                'Bucket': source_bucket,
                'Key': source_key
            }
            bucket = self.s3_resource.Bucket(target_bucket)
            logger.info(f'source {copy_source}, target {target_bucket} {target_key}')
            bucket.copy(copy_source, target_key)
            # self.s3_resource.Object(source_bucket, source_key).delete()
            
            return True
        except ClientError as e:
            logger.info(f"Error transfer file from source bucket/key to target bucket/key: {e}")
            return False
    def generate_uuid(self):
        """
        [Generate random uuid string]
        """
        return f'{uuid.uuid4().hex}'
    def build_json_document(self, source_bucket, source_key, destination_bucket, destination_key, sns_notification_topic_arn = None, sns_notification_topic_role = None):
        """
        [Generate random uuid string]
        """
        application = self.application
        client_token = f'{application}_{self.generate_uuid()}'
        async_json_doc = {"DocumentLocation": {
                    "S3Object": {
                        "Bucket": source_bucket,
                        "Name": source_key
                    }
                }, "ClientRequestToken": client_token , "NotificationChannel": {
                    "SNSTopicArn": sns_notification_topic_arn,
                    "RoleArn": sns_notification_topic_role
                }, "JobTag": client_token,
                   "OutputConfig": {
                    "S3Bucket": destination_bucket,
                    "S3Prefix": destination_key
                }}
        return async_json_doc
    
    def fetch_s3_status(self, user_id, etag):
        status_item = self.s3_status_table.get_item(
            Key={
                'etag': etag,
                'user_id': user_id
            }
        )
        logger.info(status_item)
        if 'Item' in status_item:
            return status_item['Item']
        else:
            return None
    def parse_event(self, event):
        s3_event_list = []
        for event in event['Records']:
            s3_object = event.get('s3', None)
            if s3_object.get('bucket', None):
                bucket_name = s3_object.get('bucket')['name']
                key = s3_object.get('object')['key']
                size = s3_object.get('object')['size']
                etag = s3_object.get('object')['eTag']
                key_split = key.split("/")
                file_name = key_split[-1]
                folder = key_split[-2]
                uuid = self.generate_uuid()
                destination_key = f'processed/{user_id}/{uuid}/{file_name}'
                destination_bucket = self.destination_bucket
                destination_key = destination_key
                object = {
                    'bucket':bucket_name,
                    'key':key,
                    'size': size,
                    'etag': etag,
                    'folder': folder,
                    'file_name': file_name,
                    'destination_bucket': destination_bucket,
                    'destination_key': destination_key,
                    'uuid': uuid
                }
                s3_event_list.append(object)
        return s3_event_list


    def store_s3_status(self, user_id, s3_object: S3Object):

        check_event = self.fetch_s3_status(s3_object.etag, user_id)
        #check if there is an existing entry for the s3 data
        if check_event:
            if s3_object.etag == check_event.get('etag'): # check if etag has changed
                logger.info(f"Got the same file again so not storing, {s3_object}")
                return False
        
        item = {
                'etag': s3_object.etag,
                'user_id': user_id,
                'uuid': s3_object.uuid,
                'bucket': s3_object.bucket,
                'key': s3_object.key,
                'folder': s3_object.folder,
                'file_name': s3_object.file_name,
                'size': s3_object.size,
                'destination_bucket': s3_object.destination_bucket,
                'destination_key': s3_object.destination_key,
                'status': 'completed'
        }

        response = self.dream_nlp_file_state_table.put_item(
            Item = item
        )

        logger.info(f"Status of S3 Event stored to dream_nlp_file_state_table status {response}")
        return True

    def fetch_s3_status(self,etag, user_id):
        response = self.dream_nlp_file_state_table.get_item(
            Key={
                'etag': etag,
                'user_id': user_id
            }
        )
        if 'Item' in response:
            logger.info(response['Item'])
            return response['Item']
        else:
            logger.info('Item not found')
            return None
    def initiate_textract_process(self, user_id, s3_object: S3Object):
        try:
            textract_key = f'textract/{user_id}/{s3_object.uuid}/'
            textract_json = self.build_json_document(s3_object.destination_bucket, s3_object.destination_key,s3_object.destination_bucket, 
                                                     textract_key, self.sns_arn, self.sns_role_arn)
            logger.info(f'textract json {textract_json}')

            response = self.textract_client.start_document_analysis(
                            DocumentLocation=textract_json['DocumentLocation'],
                            FeatureTypes=[
                                'TABLES', 'FORMS',
                            ],
                            ClientRequestToken=textract_json['ClientRequestToken'],
                            JobTag=textract_json['JobTag'],
                            NotificationChannel=textract_json['NotificationChannel'],
                            OutputConfig=textract_json['OutputConfig']
                )
            logger.info(f'Textract Start Document Analysis Response {response}')
        except Exception as e:
            logger.info(f"(initiate_textract_process) failed textract start_document_analysis process: {e}")
            return False

# Example usage:
if __name__ == "__main__":
    aws_region = 'us-east-1'
    bucket_name = 'dream-store-bucket'
    file_key = '/'

    aws_utilities = AWSUtilities(aws_region)

    # Example usage of the methods
    files_list = aws_utilities.get_files_s3(bucket_name, file_key)
    print("Files in S3:", files_list)

    # Read files in S3
    for f in files_list:
        print("Reading")

    # file_content = aws_utilities.read_files_s3(bucket_name, file_key)
    # print("File content:", file_content)

    # file_data = b"Example file content"
    # save_result = aws_utilities.save_files_s3(file_data, bucket_name, file_key)
    # print("File saved successfully:", save_result)
        
    event_s3 = {'Records': [{'eventVersion': '2.1', 'eventSource': 'aws:s3', 'awsRegion': 'us-east-1', 'eventTime': '2024-04-06T01:45:56.726Z', 'eventName': 'ObjectCreated:Put', 'userIdentity': {'principalId': 'AWS:AIDAU6GD3JSTYXPMXYJH5'}, 'requestParameters': {'sourceIPAddress': '68.77.251.225'}, 'responseElements': {'x-amz-request-id': 'WKT238N8JT78453V', 'x-amz-id-2': 'cdPCMWGIGCeqpMmLm5eAdqIwp59KFCDgDpTKbrfs4R8y13pv88cZRXaqdtzuKG8ZRHJ3Ahk91i6NXA3lAWzt2qXxPTh/70HM'}, 's3': {'s3SchemaVersion': '1.0', 'configurationId': 'tf-s3-lambda-20240325151258856000000001', 'bucket': {'name': 'dream-store-bucket', 'ownerIdentity': {'principalId': 'A3BYOZPL9NA0HA'}, 'arn': 'arn:aws:s3:::dream-store-bucket'}, 'object': {'key': 'raw/admin/EHR_Sreeji.pdf', 'size': 21609, 'eTag': '49c5d35f32b328985e1d083f18375c71', 'versionId': 'n7xZaVmik6C0w0WDJHPMtQE23Zu6GSZx', 'sequencer': '006610A9548E864EC1'}}}]}
    event_textract = {'Records': [{'EventSource': 'aws:sns', 'EventVersion': '1.0', 'EventSubscriptionArn': 'arn:aws:sns:us-east-1:339713150119:dream-nlp-textract-sns-response:d6be26f5-dd12-41e5-8759-db0063c31af0', 'Sns': {'Type': 'Notification', 'MessageId': '4747a705-9679-5952-8855-f98f268578a9', 'TopicArn': 'arn:aws:sns:us-east-1:339713150119:dream-nlp-textract-sns-response', 'Subject': None, 'Message': '{"JobId":"dd31dceeb3a0fc352cf2ce8ced2116cefe0a2d8f3aa7ce2025ac5f526b6e0d9d","Status":"SUCCEEDED","API":"StartDocumentAnalysis","JobTag":"dream_a4704609b0d14fe4857f9f0b47e80486","Timestamp":1712369340059,"DocumentLocation":{"S3ObjectName":"processed/drem-user-2700/5bb2379c82ec4a8d97074fe613dcb91b/EHR_Sreeji.pdf","S3Bucket":"dream-store-bucket"}}', 'Timestamp': '2024-04-06T02:09:00.096Z', 'SignatureVersion': '1', 'Signature': 'B3RZNOpR2GXb+jKdJBO8jXfpzpvLpyrRu1aXD5fp5bcEn85IQVxcMtsW5YWdiN/T6i1gZUEhERGcpLps/ekfua3eYb3fJ3Kqd5utiGLniENk6zPt2eDmrlxTcxggtnRo4Rq4Rf01JrePGRKpz9SAjMXAQBq9bcCgrLgHlYUCS3KAMg6PW6i32tFPj3FNrniBw/6ECwPkMyWyjFrhiEzP/xhkgRrfYWvU60majUxKNN1CqO+YuORScZ76GQkrCxxUJI8fSFWoWuHWJJfUo4nhKVnMaodU8zyuY3nbSjV6jSyhfvjRC6NcoqXqDiPUbdvUbwk/1p3EVWpYMPiT5Fp27w==', 'SigningCertUrl': 'https://sns.us-east-1.amazonaws.com/SimpleNotificationService-60eadc530605d63b8e62a523676ef735.pem', 'UnsubscribeUrl': 'https://sns.us-east-1.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-east-1:339713150119:dream-nlp-textract-sns-response:d6be26f5-dd12-41e5-8759-db0063c31af0', 'MessageAttributes': {}}}]}
    s3_event_dict = aws_utilities.parse_event(event_s3)
    aws_utilities.store_event(s3_event_dict)
    # aws_utilities.fetch_s3_status('drem-user-2700','8bd9c5d00a134330afcece380aa12015')

        

def lambda_handler(event, content):
    print(event)
    aws_utilities = AWSUtilities(aws_region)
    s3_event_dict = aws_utilities.parse_event(event)
    aws_utilities.store_event(s3_event_dict)
