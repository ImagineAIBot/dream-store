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

variable "dream_bucket" {
  description = "bucket to store dream nlp application data"
  type = string
  default = "dream-project"
}

variable "text_process_function_arn" {
  type = string
}