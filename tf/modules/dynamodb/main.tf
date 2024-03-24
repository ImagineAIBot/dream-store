resource "aws_dynamodb_table" "dream_table" {
  name           = "${var.dynamo_name}"
  billing_mode   = "PAY_PER_REQUEST"
  #read_capacity  = var.dynamo_read_capacity
  #write_capacity = var.dynamo_write_capacity
  hash_key       = var.dynamo_hash_key
  range_key      = var.dynamo_range_key

  dynamic "attribute" {
    for_each = var.dynamo_table_attributes
    content {
      name = attribute.key
      type = attribute.value
    }
  }
  # ttl {
  #   attribute_name = var.ttl_att_name
  #   enabled        = var.ttl_enabled
  # }

  tags = {
    Name        = var.dynamo_name
    Environment = var.environment
  }
}
