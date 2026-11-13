"""Synthetic document templates. `{{factory}}` (or `{{factory#n}}` for a second, different value)
marks a planted sensitive value; everything else is filler that must NOT be masked.

The templates cover the formats of the project's scope. They are written to look like real
artefacts, but they are what the rules were developed against: their scores are a regression
signal, not a claim about real-world recall (that is what the holdout set is for, ADR 0004).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Template:
    name: str
    escape: str  # "raw" or "json": how planted values are written into the text
    text: str


TEMPLATES: tuple[Template, ...] = (
    Template(
        "tfstate-instance",
        "json",
        """{
  "version": 4,
  "terraform_version": "1.9.8",
  "serial": 42,
  "resources": [
    {
      "mode": "managed",
      "type": "aws_instance",
      "name": "api",
      "provider": "provider[\\"registry.terraform.io/hashicorp/aws\\"]",
      "instances": [
        {
          "attributes": {
            "ami": "{{ami_id}}",
            "arn": "arn:aws:ec2:eu-west-1:{{account}}:instance/{{instance_id}}",
            "id": "{{instance_id}}",
            "instance_type": "m6i.large",
            "private_ip": "{{ip_private}}",
            "public_ip": "{{ip_public}}",
            "subnet_id": "{{subnet_id}}",
            "vpc_security_group_ids": ["{{sg_id}}"],
            "tags": {"Name": "api", "Environment": "prod", "client": "{{org}}", "owner": "{{email}}"}
          }
        }
      ]
    },
    {
      "mode": "managed",
      "type": "tls_private_key",
      "name": "deploy",
      "instances": [{"attributes": {"algorithm": "RSA", "private_key_pem": "{{pem}}"}}]
    }
  ]
}
""",
    ),
    Template(
        "terraform-plan",
        "raw",
        """Terraform will perform the following actions:

  # aws_s3_bucket.exports will be created
  + resource "aws_s3_bucket" "exports" {
      + arn    = (known after apply)
      + bucket = "{{bucket}}"
      + tags   = {
          + "Project" = "{{project}}"
        }
    }

  # aws_db_instance.main will be updated in-place
  ~ resource "aws_db_instance" "main" {
        id       = "db-main"
      ~ password = (sensitive value)
      ~ db_pass  = "{{password}}" -> "{{password#2}}"
        endpoint = "{{rds_host}}:5432"
    }

  # aws_iam_role.deployer will be created
  + resource "aws_iam_role" "deployer" {
      + name = "{{role_name}}"
      + arn  = (known after apply)
    }

Plan: 2 to add, 1 to change, 0 to destroy.
""",
    ),
    Template(
        "k8s-manifests",
        "raw",
        """apiVersion: v1
kind: Secret
metadata:
  name: api-credentials
  namespace: payments
type: Opaque
data:
  DATABASE_URL: {{k8s_secret}}
  STRIPE_KEY: {{k8s_secret#2}}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  labels:
    app.kubernetes.io/name: api
    client: {{org_word}}
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: api
          image: {{account}}.dkr.ecr.eu-west-1.amazonaws.com/api:1.14.2
          env:
            - name: DB_HOST
              value: {{rds_host}}
            - name: DB_PASSWORD
              value: "{{password}}"
            - name: LOG_LEVEL
              value: info
            - name: UPSTREAM
              value: http://{{svc_host}}:8080
""",
    ),
    Template(
        "cloudtrail-event",
        "json",
        """{
  "eventVersion": "1.09",
  "userIdentity": {
    "type": "AssumedRole",
    "arn": "arn:aws:sts::{{account}}:assumed-role/{{role_name}}/{{email}}",
    "accountId": "{{account}}",
    "accessKeyId": "{{access_key}}"
  },
  "eventTime": "2026-11-12T09:41:27Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "PutBucketPolicy",
  "awsRegion": "eu-west-1",
  "sourceIPAddress": "{{ip_public}}",
  "userAgent": "aws-cli/2.17.0 Python/3.11.9",
  "requestParameters": {"bucketName": "{{bucket}}"},
  "errorCode": "AccessDenied",
  "readOnly": false
}
""",
    ),
    Template(
        "nginx-access-log",
        "raw",
        """{{ip_public}} - - [12/Nov/2026:09:41:27 +0000] "GET /api/v1/orders HTTP/1.1" 200 512 "-" "Mozilla/5.0"
{{ip_public#2}} - - [12/Nov/2026:09:41:28 +0000] "POST /login HTTP/1.1" 401 64 "-" "curl/8.5.0"
{{ip_private}} - - [12/Nov/2026:09:41:29 +0000] "GET /healthz HTTP/1.1" 200 2 "-" "kube-probe/1.31"
""",
    ),
    Template(
        "app-json-log",
        "json",
        """{"level":"error","ts":"2026-11-12T09:41:27Z","msg":"upstream call failed","url":"https://{{internal_host}}/v2/charge","peer":"{{ip_private}}","user":"{{email}}","error":"connection reset by peer"}
{"level":"warn","ts":"2026-11-12T09:41:28Z","msg":"retrying with token","authorization":"Bearer {{jwt}}","attempt":2}
{"level":"info","ts":"2026-11-12T09:41:29Z","msg":"request served","status":200,"duration_ms":41}
""",
    ),
    Template(
        "dotenv",
        "raw",
        """# Local overrides, do not commit
APP_ENV=production
AWS_ACCESS_KEY_ID={{access_key}}
AWS_SECRET_ACCESS_KEY={{secret_key}}
GITHUB_TOKEN={{gh_token}}
OPENAI_API_KEY={{openai_key}}
DATABASE_URL=postgres://app:{{password}}@{{rds_host}}:5432/app
SLACK_BOT_TOKEN={{slack_token}}
LOG_LEVEL=debug
""",
    ),
    Template(
        "kubeconfig",
        "raw",
        """apiVersion: v1
kind: Config
clusters:
  - name: {{cluster}}
    cluster:
      server: https://{{internal_host}}:6443
contexts:
  - name: prod
    context:
      cluster: {{cluster}}
      user: deployer
users:
  - name: deployer
    user:
      token: {{jwt}}
current-context: prod
""",
    ),
    Template(
        "github-actions",
        "raw",
        """name: deploy
on:
  push:
    branches: [main]
permissions:
  id-token: write
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-24.04
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::{{account}}:role/{{role_name}}
          aws-region: eu-west-1
      - run: aws s3 sync dist/ s3://{{bucket}}/releases/
      - run: aws eks update-kubeconfig --name {{cluster}}
        env:
          GITLAB_TOKEN: {{gl_token}}
""",
    ),
    Template(
        "incident-note",
        "raw",
        """## Incident 2026-11-12: checkout latency

Reported by {{person}} at 09:41 UTC. Customer impact: {{org}} saw 5xx on checkout.
Root cause: security group {{sg_id}} dropped traffic from {{cidr}} after a change by
{{person#2}}. Database {{rds_host}} was healthy. Escalated to {{email}}.
Follow-up: re-run the plan in account {{account}} and rotate the bot token.
""",
    ),
    Template(
        "git-and-registry",
        "raw",
        """$ git remote -v
origin\tgit@github.com:{{org_slug}}/platform-infra.git (fetch)
origin\tgit@github.com:{{org_slug}}/platform-infra.git (push)
$ cat backend.tf
terraform {
  cloud {
    organization = "{{org_slug}}"
    workspaces { name = "prod" }
  }
}
$ docker pull ghcr.io/{{org_slug}}/api:2.4.0
Error response from daemon: unauthorized: ask the {{org_slug}} platform team for access
""",
    ),
    Template(
        "aws-config",
        "raw",
        """[profile prod-admin]
sso_start_url = https://{{org_slug}}.awsapps.com/start
sso_region = eu-west-1
sso_account_id = {{account}}
sso_role_name = AdministratorAccess
region = eu-west-1
output = json
# Console sign-in: https://{{signin_alias}}.signin.aws.amazon.com/console
""",
    ),
    Template(
        "certificate",
        "raw",
        """Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            04:a1:3c:9e:52:7b:0f:11:d6:88:2e:4a:90:5c:13:7f:aa:21
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=Let's Encrypt, CN=R11
        Validity
            Not Before: Nov  1 00:00:00 2026 GMT
            Not After : Jan 30 23:59:59 2027 GMT
        Subject: CN={{cert_cn}}
        X509v3 extensions:
            X509v3 Subject Alternative Name:
                DNS:{{api_host}}, DNS:{{cert_cn}}
""",
    ),
    Template(
        "source-header",
        "raw",
        """# Copyright (c) 2026 {{org}}. All rights reserved.
# Internal use only. Questions: {{email}}
\"\"\"Billing worker for the {{org_word}} platform.\"\"\"

import os

API_URL = os.environ.get("API_URL", "https://{{api_host}}/v1")
""",
    ),
)
