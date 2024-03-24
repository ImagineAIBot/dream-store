terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.16"
    }
  }

  required_version = ">= 1.2.0"
}

provider "aws" {
  region  = "us-east-1"
  default_tags {
    tags = {
      Project     = var.project_tag
      Environment = var.environment
      Deployment  = "Terraform"
      Team        = var.deployment_team
    }
  }
}

terraform {
  backend "local" {
    path = "state/terraform.tfstate"
  }
}