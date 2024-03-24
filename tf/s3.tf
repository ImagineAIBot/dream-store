module "s3" {
  source                = "./modules/s3"
  environment           = var.environment
  aws_account           = var.aws_account
  aws_region            = var.aws_region
  dream_bucket          = var.dream_bucket
}