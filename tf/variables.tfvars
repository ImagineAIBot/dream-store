
aws_region = "us-east-1"
environment = "dev"
deployment_team = "dream-team"
project_tag ="dream-project"
aws_account = "339713150119"
dream_bucket = "dream-store-bucket"
application_name = "dream-nlp"
ddb_file_state_table = "dream-nlp-file-state-table"
ddb_file_state_table_hash_key = "etag"
ddb_file_state_table_range_key = "user_id"
ddb_file_state_table_attribute = {
    "etag" = "S",
    "user_id" = "S"
}
