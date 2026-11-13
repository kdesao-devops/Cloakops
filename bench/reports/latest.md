# Benchmark results

| Corpus | Docs | Recall | Precision | F2 | Leak after detection | Redacted by re-scan | Leak in final output | Blocked |
|---|---|---|---|---|---|---|---|---|
| synthetic | 280 | 95.9% | 100.0% | 0.967 | 40 (14.3%) | 0 | 40 | 0 |
| synthetic (no propagation) | 280 | 88.1% | 100.0% | 0.903 | 120 (42.9%) | 0 | 58 | 62 |
| synthetic (no propagation, --redact) | 280 | 88.1% | 100.0% | 0.903 | 120 (42.9%) | 62 | 80 | 0 |
| dev | 8 | 86.4% | 90.0% | 0.871 | 2 (25.0%) | 0 | 2 | 0 |
| dev (no propagation) | 8 | 86.4% | 100.0% | 0.889 | 2 (25.0%) | 0 | 1 | 1 |
| dev (no propagation, --redact) | 8 | 86.4% | 97.8% | 0.885 | 2 (25.0%) | 1 | 2 | 0 |
| holdout | 0 | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| holdout (no propagation) | 0 | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| holdout (no propagation, --redact) | 0 | n/a | n/a | n/a | n/a | n/a | n/a | n/a |

## synthetic

| Entity type | Planted | Recall | Masked | Precision |
|---|---|---|---|---|
| api_token | 80 | 100.0% | 80 | 100.0% |
| arn | 0 | - | 60 | 100.0% |
| aws_access_key_id | 40 | 100.0% | 40 | 100.0% |
| aws_account_id | 140 | 100.0% | 60 | 100.0% |
| aws_resource_id | 120 | 100.0% | 100 | 100.0% |
| aws_secret_access_key | 20 | 100.0% | 20 | 100.0% |
| bucket_name | 60 | 100.0% | 81 | 100.0% |
| cluster_name | 60 | 100.0% | 60 | 100.0% |
| email | 100 | 100.0% | 80 | 100.0% |
| generic_secret | 40 | 100.0% | 80 | 100.0% |
| hostname | 220 | 100.0% | 220 | 100.0% |
| ip_address | 140 | 100.0% | 140 | 100.0% |
| ip_network | 20 | 100.0% | 20 | 100.0% |
| jwt | 40 | 100.0% | 20 | 100.0% |
| organization | 220 | 98.6% | 220 | 100.0% |
| password | 80 | 100.0% | 60 | 100.0% |
| person | 40 | 0.0% | 0 | - |
| private_key | 20 | 100.0% | 20 | 100.0% |
| resource_name | 100 | 80.0% | 42 | 100.0% |

Missed (leaks):

- organization: 3 in incident-note-002, incident-note-005, incident-note-013
- person: 40 in incident-note-000, incident-note-001, incident-note-002, incident-note-003, incident-note-004, incident-note-005
- resource_name: 20 in terraform-plan-000, terraform-plan-001, terraform-plan-002, terraform-plan-003, terraform-plan-004, terraform-plan-005

## synthetic (no propagation)

| Entity type | Planted | Recall | Masked | Precision |
|---|---|---|---|---|
| api_token | 80 | 100.0% | 80 | 100.0% |
| arn | 0 | - | 60 | 100.0% |
| aws_access_key_id | 40 | 100.0% | 40 | 100.0% |
| aws_account_id | 140 | 100.0% | 60 | 100.0% |
| aws_resource_id | 120 | 100.0% | 100 | 100.0% |
| aws_secret_access_key | 20 | 100.0% | 20 | 100.0% |
| bucket_name | 60 | 100.0% | 58 | 100.0% |
| cluster_name | 60 | 66.7% | 20 | 100.0% |
| email | 100 | 100.0% | 80 | 100.0% |
| generic_secret | 40 | 100.0% | 80 | 100.0% |
| hostname | 220 | 72.7% | 118 | 100.0% |
| ip_address | 140 | 100.0% | 140 | 100.0% |
| ip_network | 20 | 100.0% | 20 | 100.0% |
| jwt | 40 | 100.0% | 0 | - |
| organization | 220 | 80.5% | 97 | 100.0% |
| password | 80 | 100.0% | 56 | 100.0% |
| person | 40 | 0.0% | 0 | - |
| private_key | 20 | 100.0% | 20 | 100.0% |
| resource_name | 100 | 80.0% | 38 | 100.0% |

Missed (leaks):

- cluster_name: 20 in kubeconfig-000, kubeconfig-001, kubeconfig-002, kubeconfig-003, kubeconfig-004, kubeconfig-005
- hostname: 60 in certificate-000, certificate-001, certificate-002, certificate-003, certificate-004, certificate-005
- organization: 43 in git-and-registry-000, git-and-registry-001, git-and-registry-002, git-and-registry-003, git-and-registry-004, git-and-registry-005
- person: 40 in incident-note-000, incident-note-001, incident-note-002, incident-note-003, incident-note-004, incident-note-005
- resource_name: 20 in terraform-plan-000, terraform-plan-001, terraform-plan-002, terraform-plan-003, terraform-plan-004, terraform-plan-005

## synthetic (no propagation, --redact)

| Entity type | Planted | Recall | Masked | Precision |
|---|---|---|---|---|
| api_token | 80 | 100.0% | 80 | 100.0% |
| arn | 0 | - | 60 | 100.0% |
| aws_access_key_id | 40 | 100.0% | 40 | 100.0% |
| aws_account_id | 140 | 100.0% | 60 | 100.0% |
| aws_resource_id | 120 | 100.0% | 100 | 100.0% |
| aws_secret_access_key | 20 | 100.0% | 20 | 100.0% |
| bucket_name | 60 | 100.0% | 60 | 100.0% |
| cluster_name | 60 | 66.7% | 40 | 100.0% |
| email | 100 | 100.0% | 80 | 100.0% |
| generic_secret | 40 | 100.0% | 80 | 100.0% |
| hostname | 220 | 72.7% | 160 | 100.0% |
| ip_address | 140 | 100.0% | 140 | 100.0% |
| ip_network | 20 | 100.0% | 20 | 100.0% |
| jwt | 40 | 100.0% | 20 | 100.0% |
| organization | 220 | 80.5% | 177 | 100.0% |
| password | 80 | 100.0% | 60 | 100.0% |
| person | 40 | 0.0% | 0 | - |
| private_key | 20 | 100.0% | 20 | 100.0% |
| resource_name | 100 | 80.0% | 40 | 100.0% |

Missed (leaks):

- cluster_name: 20 in kubeconfig-000, kubeconfig-001, kubeconfig-002, kubeconfig-003, kubeconfig-004, kubeconfig-005
- hostname: 60 in certificate-000, certificate-001, certificate-002, certificate-003, certificate-004, certificate-005
- organization: 43 in git-and-registry-000, git-and-registry-001, git-and-registry-002, git-and-registry-003, git-and-registry-004, git-and-registry-005
- person: 40 in incident-note-000, incident-note-001, incident-note-002, incident-note-003, incident-note-004, incident-note-005
- resource_name: 20 in terraform-plan-000, terraform-plan-001, terraform-plan-002, terraform-plan-003, terraform-plan-004, terraform-plan-005

## dev

| Entity type | Planted | Recall | Masked | Precision |
|---|---|---|---|---|
| api_token | 3 | 100.0% | 2 | 100.0% |
| arn | 0 | - | 2 | 100.0% |
| aws_account_id | 5 | 100.0% | 2 | 100.0% |
| aws_resource_id | 3 | 100.0% | 3 | 100.0% |
| cluster_name | 2 | 50.0% | 1 | 100.0% |
| email | 3 | 100.0% | 3 | 100.0% |
| generic_secret | 1 | 100.0% | 3 | 100.0% |
| hostname | 8 | 87.5% | 7 | 100.0% |
| ip_address | 10 | 100.0% | 10 | 100.0% |
| ip_network | 3 | 100.0% | 3 | 100.0% |
| organization | 3 | 66.7% | 3 | 66.7% |
| password | 5 | 100.0% | 3 | 100.0% |
| person | 7 | 28.6% | 6 | 33.3% |
| resource_name | 6 | 100.0% | 2 | 100.0% |

Missed (leaks):

- cluster_name: 1 in slack-incident
- hostname: 1 in helm-values
- organization: 1 in slack-incident
- person: 5 in slack-incident

## dev (no propagation)

| Entity type | Planted | Recall | Masked | Precision |
|---|---|---|---|---|
| api_token | 3 | 100.0% | 2 | 100.0% |
| arn | 0 | - | 1 | 100.0% |
| aws_account_id | 5 | 100.0% | 2 | 100.0% |
| aws_resource_id | 3 | 100.0% | 3 | 100.0% |
| cluster_name | 2 | 50.0% | 1 | 100.0% |
| email | 3 | 100.0% | 3 | 100.0% |
| generic_secret | 1 | 100.0% | 2 | 100.0% |
| hostname | 8 | 87.5% | 6 | 100.0% |
| ip_address | 10 | 100.0% | 10 | 100.0% |
| ip_network | 3 | 100.0% | 3 | 100.0% |
| organization | 3 | 66.7% | 2 | 100.0% |
| password | 5 | 100.0% | 2 | 100.0% |
| person | 7 | 28.6% | 2 | 100.0% |
| resource_name | 6 | 100.0% | 2 | 100.0% |

Missed (leaks):

- cluster_name: 1 in slack-incident
- hostname: 1 in helm-values
- organization: 1 in slack-incident
- person: 5 in slack-incident

## dev (no propagation, --redact)

| Entity type | Planted | Recall | Masked | Precision |
|---|---|---|---|---|
| api_token | 3 | 100.0% | 2 | 100.0% |
| arn | 0 | - | 2 | 100.0% |
| aws_account_id | 5 | 100.0% | 2 | 100.0% |
| aws_resource_id | 3 | 100.0% | 3 | 100.0% |
| cluster_name | 2 | 50.0% | 1 | 100.0% |
| email | 3 | 100.0% | 3 | 100.0% |
| generic_secret | 1 | 100.0% | 3 | 100.0% |
| hostname | 8 | 87.5% | 7 | 100.0% |
| ip_address | 10 | 100.0% | 10 | 100.0% |
| ip_network | 3 | 100.0% | 3 | 100.0% |
| organization | 3 | 66.7% | 2 | 100.0% |
| password | 5 | 100.0% | 3 | 100.0% |
| person | 7 | 28.6% | 3 | 66.7% |
| resource_name | 6 | 100.0% | 2 | 100.0% |

Missed (leaks):

- cluster_name: 1 in slack-incident
- hostname: 1 in helm-values
- organization: 1 in slack-incident
- person: 5 in slack-incident
