
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

variable "dynamo_name" {
  description = "dyanmodb table name"
  type = string
  default = "dream-nlp-file-state-table"
}

variable "dynamo_hash_key" {
  description = "dyanmodb table dynamo_hash_key"
  type = string
  default = "dream-nlp-file-state-table"
}

variable "dynamo_range_key" {
  description = "dyanmodb table dynamo_range_key"
  type = string
  default = "dream-nlp-file-state-table"
}

variable "dynamo_table_attributes" {
  type = map(string)
}