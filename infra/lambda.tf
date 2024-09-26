data "archive_file" "zip" {
  type        = "zip"
  source_file = "../lambda_auth.py"
  output_path = "../lambda_auth.zip"
}

resource "aws_lambda_function" "fiap_postech_hackathon_lambda_auth" {
  function_name    = var.project_name
  filename         = data.archive_file.zip.output_path
  source_code_hash = filebase64sha256(data.archive_file.zip.output_path)
  role             = var.lab_role_arn
  runtime          = "python3.9"
  handler          = "lambda_auth.lambda_handler"
  timeout          = 10
}

resource "aws_cloudwatch_log_group" "convert_log_group" {
  name = "/aws/lambda/${aws_lambda_function.fiap_postech_hackathon_lambda_auth.function_name}"
}

resource "aws_lambda_function_url" "lambda_url" {
  function_name      = aws_lambda_function.fiap_postech_hackathon_lambda_auth.function_name
  authorization_type = "NONE"
}
