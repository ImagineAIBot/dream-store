import boto3
from botocore.exceptions import ClientError
import uuid
import logging
import json
from types import SimpleNamespace
from dataclasses import dataclass
import os
import trp

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

#static variables
s3_eventSource = 'aws:s3'   #for event comming from s3 raw key
sns_eventSource = 'aws:sns' #for event comming sns for textract result
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

@dataclass
class TextractObject:
    uuid: str = None
    job_id: str = None
    job_status: str = None
    job_tag: str = None
    job_timestamp: int = None
    source_bucket: str =None
    source_key: str = None
    destination_bucket: str =None
    destination_key: str = None
    user_id:str = None

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
        self.TextractObject = TextractObject

        self.aws_account = aws_account
        self.aws_region = aws_region
        self.application = application
        self.source_bucket = source_bucket
        self.destination_bucket = destination_bucket
        self.user_id = user_id
        self.sns_arn = sns_arn
        self.sns_role_arn = sns_role_arn
        self.uuid = None

        self.dream_nlp_file_state_table = self.dynamodb_resource.Table("dream-nlp-file-state-table")
        self.dream_nlp_textract_state_table = self.dynamodb_resource.Table("dream-nlp-textract-state-table")

    def buildUUID(self, user_id):
        # UUID will be the common field to be mapped between all the services, it should a string 
        # in combinaation of application name, user id, and uuid (generated)
        # ex. dream:user2700:cccf1765b01d4e7b9aaa24897a471a80
        uuid = self.generateUUID()
        return (f'{self.application}:{user_id}:{uuid}', f'{uuid}')
    
    def getUUID(self, uuid):
        uuid_split = uuid.split(":")
        self.application = uuid_split[0]
        self.user_id = uuid_split[1]
        self.uuid = uuid_split[2]
        return (self.application, self.user_id, self.uuid)
    
    def eventSource(self, event):
        for event in event['Records']:
            eventsource = event.get('EventSource', s3_eventSource)
            logger.info(f'Got Event with source {eventsource}')
            return eventsource
        
    def loadTextractOutput(self, bucket, key):
        file_list = self.getFilesS3(bucket, key)
        logger.info(f'File List {file_list} for key {key}')
        if len(file_list) > 0 :
            logger.info('loadTextractOutput: Textract Output File Found, returning to processing ')
            for file in file_list:
                textract_json = self.readFilesS3(bucket, key)
                textract_json = json.loads(textract_json)
                # logger.info(textract_json)
                return textract_json
        return None

    def getTextractDocument(self, textextract_object):
        try:
            job_id = textextract_object.job_id
            textract_bucket = textextract_object.destination_bucket
            textract_key = f'{textextract_object.destination_key}{textextract_object.job_id}/{textextract_object.uuid}.json'
            textract_json = self.loadTextractOutput(textract_bucket,textract_key)

            if textract_json == None:
                logger.info('getTextractDocument: Textract Output Not Found Accessing via the API')
                # Get Textract Document from API only if the JSONN is not stored
                response = self.textract_client.get_document_analysis(JobId=job_id)
                nextToken = None

                if('NextToken' in response):
                    nextToken = response['NextToken']
                while(nextToken):
                    next_response = self.textract_client.get_document_analysis(JobId=job_id, NextToken=nextToken)
                    response['Blocks'].extend(next_response['Blocks'])
                    nextToken = None
                    if('NextToken' in next_response):
                        nextToken = next_response['NextToken']
                logger.info('getTextractDocument: Textract Response JSON Storting to S3')
                self.saveFilesS3(json.dumps(response), textract_bucket, textract_key)
                return response
            else:
                return textract_json
  
        except Exception as e:
            logger.error(f"Error getTextractDocument {e}")
            return None
        
    def processTextractEvent(self, event: list):
        try:
            for e in event:
                o = TextractObject(**e)
                logger.info(f'Got Event with source {o}')
                textract_event = self.fetchTextractStatus(o.job_tag, o.user_id)
                logger.info(f'Textract data from DB {textract_event}')

                ##calling load textract outpout as json
                textextract_object = TextractObject(**textract_event)
                logger.info(f'processTextractEvent: Textract data from object {textextract_object}')
    

                textract_json = self.getTextractDocument(textextract_object)
                doc = trp.Document(textract_json)
        
                for page in doc.pages:
                    print(page)

        except Exception as e:
            logger.error(f"Error processTextractEvent {e}")

    def storeS3Event(self, event: list):
        try:
            for e in event:
                o = S3Object(**e)
                if o.size >0:
                    (uuid, uuid_only) = self.buildUUID(user_id)
                    if self.storeS3Status(user_id, o):
                        # processed_key = f'processed/{user_id}/{uuid}/{o.file_name}'
                        # o.destination_bucket = destination_bucket
                        # o.destination_key = processed_key
                        self.transferFilesS3(o.bucket, o.key, o.destination_bucket,o.destination_key)
                        logger.info(f"Copied File {o.file_name} from {o.bucket}/{o.key} to  {o.destination_bucket} {o.destination_key}")
                        # self.storeS3Status(user_id, o)
                        #initiate textract analysis process
                        textract_status = self.initiateTextractProcess(o)
                        # if textract_status:
                        

        except Exception as e:
            logger.error(f"Error copying file from source to destination {e}")

    def getFilesS3(self, bucket, key) -> list:
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

    def readFilesS3(self, bucket, key) :
        """
        Read file content from S3 bucket with the given key.
        """
        try:
            response = self.s3_client.get_object(Bucket=bucket, Key=key)
            return response['Body'].read()
        except ClientError as e:
            logger.info(f"Error reading file from S3: {e}")
            return None

    def saveFilesS3(self, data_or_buffer, bucket, key):
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
    def transferFilesS3(self, source_bucket, source_key, target_bucket, target_key):
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
    def generateUUID(self):
        """
        [Generate random uuid string]
        """
        return f'{uuid.uuid4().hex}'
    def buildJsonDocument(self, client_token,job_tag, source_bucket, source_key, destination_bucket, destination_key, sns_notification_topic_arn = None, sns_notification_topic_role = None):
        """
        [Generate random uuid string]
        """
        # client_token = f'{application}_{self.generateUUID()}'  # a combination of user_id, application namd and uuid (s3 uuid)
        async_json_doc = {"DocumentLocation": {
                    "S3Object": {
                        "Bucket": source_bucket,
                        "Name": source_key
                    }
                }, "ClientRequestToken": client_token , "NotificationChannel": {
                    "SNSTopicArn": sns_notification_topic_arn,
                    "RoleArn": sns_notification_topic_role
                }, "JobTag": job_tag,
                   "OutputConfig": {
                    "S3Bucket": destination_bucket,
                    "S3Prefix": destination_key
                }}
        return async_json_doc
    
    def fetchS3Status(self, user_id, etag):
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

    def parseEvent(self, event):
        event_list = []
        for event in event['Records']:
            eventsource = event.get('EventSource', s3_eventSource)
            logger.info(f'Got Event with source {eventsource}')
            if eventsource == s3_eventSource:
                s3_object = event.get('s3', None)
                if s3_object.get('bucket', None):
                    (uuid, uuid_only) = self.buildUUID(self.user_id)
                    bucket_name = s3_object.get('bucket')['name']
                    key = s3_object.get('object')['key']
                    size = s3_object.get('object')['size']
                    etag = s3_object.get('object')['eTag']
                    key_split = key.split("/")
                    file_name = key_split[-1]
                    folder = key_split[-2]
                    uuid = uuid
                    destination_key = f'processed/{self.user_id}/{uuid_only}/{file_name}'
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
                    event_list.append(object)
                return event_list
            elif eventsource == sns_eventSource:
                sns_object = event.get('Sns', None)
                sns_message = json.loads(sns_object["Message"])
                logger.info(f'Got sns_message {sns_message} {type(sns_message)}')
                if sns_message:
                    (application, user_id, uuid) = self.getUUID(sns_message['JobTag'])
                    object = {
                        'uuid': uuid,
                        'user_id': user_id,
                        'job_id': sns_message['JobId'],
                        'job_status': sns_message['Status'],
                        'job_tag': sns_message['JobTag'],
                        'job_timestamp': sns_message['Timestamp']
                    }
                    event_list.append(object)
                return event_list
            
    def storeTextractStatus(self, user_id, textract_object: TextractObject):

        check_event = self.fetchTextractStatus(textract_object.uuid, user_id)
        #check if there is an existing entry for the s3 data

        item = {
                'uuid': textract_object.uuid,
                'user_id': user_id,
                'job_id': textract_object.job_id,
                'job_tag': textract_object.job_tag,
                'job_timestamp': textract_object.job_timestamp,
                'source_bucket': textract_object.source_bucket,
                'source_key': textract_object.source_key,
                'destination_bucket': textract_object.destination_bucket,
                'destination_key': textract_object.destination_key,
                'job_status': textract_object.job_status
        }

        response = self.dream_nlp_textract_state_table.put_item(
            Item = item
        )

        logger.info(f"Status of S3 Event stored to dream_nlp_file_state_table status {response}")
        return True

    def fetchTextractStatus(self,uuid, user_id):
        response = self.dream_nlp_textract_state_table.get_item(
            Key={
                'uuid': uuid,
                'user_id': user_id
            }
        )
        if 'Item' in response:
            logger.info(response['Item'])
            return response['Item']
        else:
            logger.info('Item not found')
            return None
        
    def storeS3Status(self, user_id, s3_object: S3Object):

        check_event = self.fetchS3Status(s3_object)
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
                'job_status': 'COMPLETED'
        }

        response = self.dream_nlp_file_state_table.put_item(
            Item = item
        )

        logger.info(f"Status of S3 Event stored to dream_nlp_file_state_table status {response}")
        return True

    def fetchS3Status(self, s3_object: S3Object):
        response = self.dream_nlp_file_state_table.get_item(
            Key={
                'etag': s3_object.etag,
                'uuid': s3_object.uuid
            }
        )
        if 'Item' in response:
            logger.info(response['Item'])
            return response['Item']
        else:
            logger.info('Item not found')
            return None
    def initiateTextractProcess(self, s3_object: S3Object):
        try:
            (application, user_id, uuid) = self.getUUID(s3_object.uuid)
            textract_key = f'textract/{user_id}/{uuid}/'
            client_token = f'{application}-{uuid}'
            textract_json = self.buildJsonDocument(client_token, s3_object.uuid, s3_object.destination_bucket, s3_object.destination_key,s3_object.destination_bucket, 
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
            textract_object = TextractObject()
            textract_object.uuid = s3_object.uuid
            textract_object.job_status = 'STARTED'
            textract_object.source_bucket = s3_object.destination_bucket
            textract_object.source_key = s3_object.destination_key
            textract_object.job_tag = textract_json['JobTag']
            textract_object.destination_bucket = textract_json['OutputConfig']['S3Bucket']
            textract_object.destination_key = textract_json['OutputConfig']['S3Prefix']
            textract_object.job_id = response['JobId']  # this holds the job id from the start_document_analysis API
            self.storeTextractStatus(user_id,textract_object)
            logger.info(f"Textract Start Document Analysis Initiated Success and Stored {textract_object.uuid} ")
            return True
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
    files_list = aws_utilities.getFilesS3(bucket_name, file_key)
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
    event_textract = {'Records': [{'EventSource': 'aws:sns', 'EventVersion': '1.0', 'EventSubscriptionArn': 'arn:aws:sns:us-east-1:339713150119:dream-nlp-textract-sns-response:d6be26f5-dd12-41e5-8759-db0063c31af0', 'Sns': {'Type': 'Notification', 'MessageId': '71b0b25b-8c34-5563-a54c-ecd66f8938c4', 'TopicArn': 'arn:aws:sns:us-east-1:339713150119:dream-nlp-textract-sns-response', 'Subject': None, 'Message': '{"JobId":"9a2ebd8b245477e5c56421f3867fbc1f5c60ad27d584097fc3165a9a1611d32c","Status":"SUCCEEDED","API":"StartDocumentAnalysis","JobTag":"dream:drem-user-2700:c974241ac25a4a54835c16b4e3508ff7","Timestamp":1712578941104,"DocumentLocation":{"S3ObjectName":"processed/drem-user-2700/c974241ac25a4a54835c16b4e3508ff7/EHR_Sreeji.pdf","S3Bucket":"dream-store-bucket"}}', 'Timestamp': '2024-04-08T12:22:21.151Z', 'SignatureVersion': '1', 'Signature': 'EVvSFIOpeuZ+t2iDmPjhQxgR0q9wSveWRWplLPLsoHV7vKVg/qWKZhcxu3b1XN2NycciVcAT/7Ip8gXN5qKGslJL8cou6aORqgoql+Fgc92shufdXzbRPg6dtoi5/qz5dzaO+YWTLGlCfRIxuXLb3e1dGZ73G6IZlZP2xWoEd5wRpo3px+3yhD5oPoYSvxxHWXePxk2yRg6DayQr/KUObzRbEwyglVXNeLlN5FwVeSJBsJ07qtGPOr2lCqe2RM+HSqgbh/RZXfEZNTv9BmAhRGM4O3bWVdp/+tPv/hv+LSb5DHDY5bHcd8CbdbEZdnDLI+7haVlW9+NrFVNCCW1NoA==', 'SigningCertUrl': 'https://sns.us-east-1.amazonaws.com/SimpleNotificationService-60eadc530605d63b8e62a523676ef735.pem', 'UnsubscribeUrl': 'https://sns.us-east-1.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-east-1:339713150119:dream-nlp-textract-sns-response:d6be26f5-dd12-41e5-8759-db0063c31af0', 'MessageAttributes': {}}}]}
    source = aws_utilities.eventSource(event_textract)
    
    if source == s3_eventSource:
        event_dict = aws_utilities.parseEvent(event_s3)
        aws_utilities.storeS3Event(event_dict)
    else:
        event_dict = aws_utilities.parseEvent(event_textract)
        aws_utilities.processTextractEvent(event_dict)
    # aws_utilities.fetch_s3_status('drem-user-2700','8bd9c5d00a134330afcece380aa12015')

        

def lambda_handler(event, content):
    print(event)
    aws_utilities = AWSUtilities(aws_region)
    s3_event_dict = aws_utilities.parseEvent(event)
    aws_utilities.storeEvent(s3_event_dict)
