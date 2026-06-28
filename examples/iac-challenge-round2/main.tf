# CI runner infrastructure for the acme-platform build fleet.
# Policy + network values are supplied by the platform pipeline; the bootstrap
# step comes from the shared platform module.

provider "aws" {
  region = "us-east-1"
}

resource "aws_iam_role" "ci" {
  name               = "ci-runner"
  assume_role_policy = data.aws_iam_policy_document.trust.json
}

data "aws_iam_policy_document" "trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["codebuild.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "ci" {
  name   = "ci-permissions"
  role   = aws_iam_role.ci.id
  policy = var.ci_policy_json
}

resource "aws_security_group" "ops" {
  name = "ops-sg"
}

resource "aws_security_group_rule" "ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  security_group_id = aws_security_group.ops.id
  cidr_blocks       = var.allowed_cidrs
}

module "bootstrap" {
  source = "git::https://github.com/acme-platform/tf-modules.git//iam-bootstrap?ref=v3.2.0"
  role   = aws_iam_role.ci.name
}

variable "ci_policy_json" {
  type        = string
  description = "IAM policy document JSON for the CI role (provided by the platform pipeline)."
}

variable "allowed_cidrs" {
  type        = list(string)
  description = "Ingress CIDRs (provided by the platform pipeline)."
}
