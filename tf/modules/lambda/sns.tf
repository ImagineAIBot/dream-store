resource "aws_sns_topic" "textract_sns_response" {
  name = "${var.application_name}-textract-sns-response"
}

resource "aws_lambda_permission" "with_sns" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = "${var.application_name}-text-process-function"
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.textract_sns_response.arn
}


resource "aws_sns_topic_subscription" "textract_sns_response_lampda_target" {
  topic_arn = aws_sns_topic.textract_sns_response.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.text_process_function.arn
}