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
source_bucket = os.environ.get('source_bucket', 'dream-store-bucket')
destination_bucket = os.environ.get('destination_bucket', 'dream-store-bucket')
user_id = os.environ.get('user_id', 'drem-user-2700')
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
    
        self.dream_nlp_file_state_table = self.dynamodb_resource.Table("dream-nlp-file-state-table")

    def store_event(self, event: list):
        try:

            for e in event:
                o = S3Object(**e)
                if o.size >0:
                    uuid = self.generate_uuid()
                    if self.store_s3_status(user_id, uuid, o ):
                        processed_key = f'processed/{user_id}/{uuid}/{o.file_name}'
                        self.transfer_files_s3(o.bucket, o.key, destination_bucket,processed_key)
                        logger.info(f"Copied File {o.file_name} from {o.bucket}/{o.key} to  {destination_bucket} {processed_key}")
                        self.store_s3_status(user_id, uuid, o )
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
        application = 'mednlp'
        client_token = f'{application}_{self.generate_uuid()}'
        async_json_doc = {"DocumentLocation": {
                    "S3Object": {
                        "Bucket": source_bucket,
                        "Name": source_key
                    }
                }, "ClientRequestToken": client_token , "NotificationChannel": {
                    "SNSTopicArn": "arn:aws:sns:us-east-1:099439818035:law_textract_sns",
                    "RoleArn": "arn:aws:iam::099439818035:role/service-role/AmazonSageMaker-ExecutionRole-20240130T091053"
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
                object = {
                    'bucket':bucket_name,
                    'key':key,
                    'size': size,
                    'etag': etag,
                    'folder': folder,
                    'file_name': file_name
                }
                s3_event_list.append(object)
        return s3_event_list


    def store_s3_status(self, user_id, uuid, s3_object: S3Object):

        check_event = self.fetch_s3_status(s3_object.etag, user_id)
        print(check_event)
        #check if there is an existing entry for the s3 data
        if check_event:
            if s3_object.etag == check_event.get('etag'): # check if etag has changed
                logger.info(f"Got the same file again so not storing, {s3_object}")
                return False
        
        item = {
                'etag': s3_object.etag,
                'user_id': user_id,
                'uuid': uuid,
                'bucket': s3_object.bucket,
                'key': s3_object.key,
                'folder': s3_object.folder,
                'file_name': s3_object.file_name,
                'size': s3_object.size,
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
        
    event = {'Records': [{'eventVersion': '2.1', 'eventSource': 'aws:s3', 'awsRegion': 'us-east-1', 'eventTime': '2024-03-29T14:02:01.341Z', 'eventName': 'ObjectCreated:CompleteMultipartUpload', 'userIdentity': {'principalId': 'A3BYOZPL9NA0HA'}, 'requestParameters': {'sourceIPAddress': '68.77.251.225'}, 'responseElements': {'x-amz-request-id': '8NVVVS5HB664AHZ5', 'x-amz-id-2': 'erRspy73WLNsC9Vsh7HdC1+RN+1GTygIsLGmu1+6wjnTnRvp/E1cgAhIWpnCCD3efWwZyuI3i75SsyrPNRjG7lk/zYm1yzZ8'}, 's3': {'s3SchemaVersion': '1.0', 'configurationId': 'tf-s3-lambda-20240325151258856000000001', 'bucket': {'name': 'dream-store-bucket', 'ownerIdentity': {'principalId': 'A3BYOZPL9NA0HA'}, 'arn': 'arn:aws:s3:::dream-store-bucket'}, 'object': {'key': 'raw/00_afh_full.pdf', 'size': 276335101, 'eTag': 'b2e6a1e0cdd4813ad8e66bb49172d291-17', 'versionId': 'DHKcbBockbLDY52r5eXCFtbsg.tqJR2r', 'sequencer': '006606C9C1436A3AFD'}}}]}

    s3_event_dict = aws_utilities.parse_event(event)
    aws_utilities.store_event(s3_event_dict)
    # aws_utilities.fetch_s3_status('drem-user-2700','8bd9c5d00a134330afcece380aa12015')

        

def lambda_handler(event, content):
    print(event)
    aws_utilities = AWSUtilities(aws_region)
    s3_event_dict = aws_utilities.parse_event(event)
    aws_utilities.store_event(s3_event_dict)
