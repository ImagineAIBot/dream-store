variable "aws_account" {
  type        = string
  description = "Numerical ID of AWS Account"
}

variable "environment" {
  type = string
}

variable "aws_region" {
  description = "AWS region where the resources will be deployed"
  type        = string
  default     = "us-east-1"
}

variable "deployment_team" {
  type        = string
  description = "Numerical ID of AWS Account"
}

variable "project_tag" {
  type = string
}

variable "application_name" {
  type = string
}


variable "dream_bucket" {
  description = "bucket to store dream nlp application data"
  type = string
  default = "dream-project"
}

variable "ddb_file_state_table" {
  description = "dyanmodb table name"
  type = string
}

variable "ddb_file_state_table_hash_key" {
  description = "dyanmodb table dynamo_hash_key"
  type = string
}

variable "ddb_file_state_table_range_key" {
  description = "dyanmodb table dynamo_range_key"
  type = string
}

variable "ddb_file_state_table_attribute" {
  type = map(string)
}