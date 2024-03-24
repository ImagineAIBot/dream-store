module "dynamodb" {
  source                    = "./modules/dynamodb"
  environment               = var.environment
  aws_account               = var.aws_account
  aws_region                = var.aws_region
  dynamo_name               = var.ddb_file_state_table
  dynamo_hash_key           = var.ddb_file_state_table_hash_key
  dynamo_range_key          = var.ddb_file_state_table_range_key
  dynamo_table_attributes   = var.ddb_file_state_table_attribute
}