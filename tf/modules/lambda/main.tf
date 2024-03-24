
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


  # The filebase64sha256() function is available in Terraform 0.11.12 and later
  # For Terraform 0.11.11 and earlier, use the base64sha256() function and the file() function:
  # source_code_hash = "${base64sha256(file("lambda_function_payload.zip"))}"
  source_code_hash = filebase64sha256("${data.archive_file.text_process_function.output_path}")

  runtime = "python3.8"

  environment {
    variables = {
      bucket = var.dream_bucket
    }
  }
  

}