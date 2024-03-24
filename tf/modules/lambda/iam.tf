resource "aws_iam_role" "lambda_role" {
  name        = "${var.application_name}-lambda-role"
  description = "IAM role for the KDA Application"
  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonKinesisFullAccess",
    "arn:aws:iam::aws:policy/AdministratorAccess"
  ]
  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "lambda.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
EOF

}
output "iam_role_arn" {
  value = "${aws_iam_role.lambda_role.arn}"
}