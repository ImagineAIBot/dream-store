
resource "aws_s3_bucket" "dream_application_bucket" {
  bucket = var.dream_bucket

 
}

resource "aws_s3_bucket_server_side_encryption_configuration" "dream_application_bucket" {
  bucket = aws_s3_bucket.dream_application_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "dream_application_bucket" {
  bucket = aws_s3_bucket.dream_application_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}


resource "aws_s3_bucket_public_access_block" "dream_application_bucket" {
  bucket                  = aws_s3_bucket.dream_application_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}


resource "aws_s3_bucket_notification" "dream_application_bucket_notification" {
  bucket = aws_s3_bucket.dream_application_bucket.id

  lambda_function {
    lambda_function_arn = var.text_process_function_arn
    events              = ["s3:ObjectCreated:*"]
    # filter_prefix       = "/"
    # filter_suffix       = ".log"
  }

  # depends_on = [aws_lambda_permission.dream_application_bucket]
}

output "dream_application_bucket_arn" {
  value = "${aws_s3_bucket.dream_application_bucket.arn}"
}

output "dream_application_bucket_name" {
  value = "${aws_s3_bucket.dream_application_bucket}"
}
