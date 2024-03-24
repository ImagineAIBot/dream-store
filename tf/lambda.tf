module "lambda" {
  source                = "./modules/lambda"
  environment           = var.environment
  aws_account           = var.aws_account
  aws_region            = var.aws_region
  dream_bucket          = var.dream_bucket
  application_name      = var.application_name
}