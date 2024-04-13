resource "aws_lambda_layer_version" "lambda_layer" {
  filename   = "${path.root}/../src/lambda/layer/layers/dream-layer.zip"
  layer_name = "dream_layer"

  compatible_runtimes = ["python3.10"]
}
data "archive_file" "text_process_function" {
    type = "zip"
    source_dir = "${path.root}/../src/lambda/text_process_function"
    output_path = "${path.root}/../src/lambda/text_process_function.zip"
}


resource "aws_lambda_function" "text_process_function" {
  # If the file is not in the current working directory you will need to include a 
  # path.module in the filename.
  filename      = "${data.archive_file.text_process_function.output_path}"
  function_name = "${var.application_name}-text-process-function"
  role          = "${aws_iam_role.lambda_role.arn}"
  handler       = "app.lambda_handler"
  layers        = [aws_lambda_layer_version.lambda_layer.arn]
  timeout       = 60

  # The filebase64sha256() function is available in Terraform 0.11.12 and later
  # For Terraform 0.11.11 and earlier, use the base64sha256() function and the file() function:
  # source_code_hash = "${base64sha256(file("lambda_function_payload.zip"))}"
  source_code_hash = filebase64sha256("${data.archive_file.text_process_function.output_path}")

  runtime = "python3.10"

  environment {
    variables = {
      aws_region = var.aws_region
      aws_account = var.aws_account
      source_bucket = var.dream_bucket
      destination_bucket = var.dream_bucket
      sns_role_arn = "${aws_iam_role.textract_role.arn}"
      sns_arn = aws_sns_topic.textract_sns_response.arn
    }
  }
}

output "text_process_function_arn" {
  value = "${aws_lambda_function.text_process_function.arn}"
}