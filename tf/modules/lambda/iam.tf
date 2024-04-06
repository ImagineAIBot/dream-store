resource "aws_iam_role" "lambda_role" {
  name        = "${var.application_name}-lambda-role"
  description = "IAM role for the Lambda Application"
  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/AmazonS3FullAccess"
  ]
  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
			"Effect": "Allow",
			"Principal": {
				"Service": [
					"lambda.amazonaws.com",
					"s3.amazonaws.com"
				]
			},
			"Action": "sts:AssumeRole"
		}

    ]
}
EOF

}

resource "aws_iam_role" "textract_role" {
  name        = "${var.application_name}-textract-role"
  description = "IAM role for the Textract Application"
  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    "arn:aws:iam::aws:policy/AmazonSNSFullAccess"
  ]
  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
                "Service": [
                    "textract.amazonaws.com"
                ]
            },
            "Action": [
                "sts:AssumeRole"
            ]
        }
    
    ]
}
EOF

}


output "iam_role_arn" {
  value = "${aws_iam_role.lambda_role.arn}"
}

output "textract_role_arn" {
  value = "${aws_iam_role.textract_role.arn}"
}