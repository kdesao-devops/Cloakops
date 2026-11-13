# Benchmark results

| Corpus | Docs | Recall | Precision | F2 | Leak after detection | Redacted by re-scan | Leak in final output | Blocked |
|---|---|---|---|---|---|---|---|---|
| synthetic | 200 | 93.5% | 100.0% | 0.948 | 40 (20.0%) | 0 | 40 | 0 |
| synthetic (no propagation) | 200 | 91.9% | 100.0% | 0.934 | 60 (30.0%) | 22 | 40 | 0 |
| dev | 8 | 84.7% | 91.7% | 0.860 | 3 (37.5%) | 0 | 3 | 0 |
| dev (no propagation) | 8 | 84.7% | 97.8% | 0.871 | 3 (37.5%) | 1 | 3 | 0 |
| holdout | 0 | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| holdout (no propagation) | 0 | n/a | n/a | n/a | n/a | n/a | n/a | n/a |

## synthetic

| Entity type | Planted | Recall | Masked | Precision |
|---|---|---|---|---|
| api_token | 80 | 100.0% | 80 | 100.0% |
| arn | 0 | - | 60 | 100.0% |
| aws_access_key_id | 40 | 100.0% | 40 | 100.0% |
| aws_account_id | 120 | 100.0% | 40 | 100.0% |
| aws_resource_id | 120 | 100.0% | 100 | 100.0% |
| aws_secret_access_key | 20 | 100.0% | 20 | 100.0% |
| bucket_name | 60 | 100.0% | 81 | 100.0% |
| cluster_name | 60 | 100.0% | 60 | 100.0% |
| email | 80 | 100.0% | 60 | 100.0% |
| generic_secret | 40 | 100.0% | 80 | 100.0% |
| hostname | 140 | 100.0% | 140 | 100.0% |
| ip_address | 140 | 100.0% | 140 | 100.0% |
| ip_network | 20 | 100.0% | 20 | 100.0% |
| jwt | 40 | 100.0% | 20 | 100.0% |
| organization | 60 | 66.7% | 40 | 100.0% |
| password | 80 | 100.0% | 60 | 100.0% |
| person | 40 | 0.0% | 0 | - |
| private_key | 20 | 100.0% | 20 | 100.0% |
| resource_name | 80 | 75.0% | 22 | 100.0% |

Missed (leaks):

- organization: 20 in incident-note-000, incident-note-001, incident-note-002, incident-note-003, incident-note-004, incident-note-005
- person: 40 in incident-note-000, incident-note-001, incident-note-002, incident-note-003, incident-note-004, incident-note-005
- resource_name: 20 in terraform-plan-000, terraform-plan-001, terraform-plan-002, terraform-plan-003, terraform-plan-004, terraform-plan-005

## synthetic (no propagation)

| Entity type | Planted | Recall | Masked | Precision |
|---|---|---|---|---|
| api_token | 80 | 100.0% | 80 | 100.0% |
| arn | 0 | - | 60 | 100.0% |
| aws_access_key_id | 40 | 100.0% | 40 | 100.0% |
| aws_account_id | 120 | 100.0% | 40 | 100.0% |
| aws_resource_id | 120 | 100.0% | 100 | 100.0% |
| aws_secret_access_key | 20 | 100.0% | 20 | 100.0% |
| bucket_name | 60 | 100.0% | 60 | 100.0% |
| cluster_name | 60 | 66.7% | 40 | 100.0% |
| email | 80 | 100.0% | 60 | 100.0% |
| generic_secret | 40 | 100.0% | 80 | 100.0% |
| hostname | 140 | 100.0% | 140 | 100.0% |
| ip_address | 140 | 100.0% | 140 | 100.0% |
| ip_network | 20 | 100.0% | 20 | 100.0% |
| jwt | 40 | 100.0% | 20 | 100.0% |
| organization | 60 | 66.7% | 40 | 100.0% |
| password | 80 | 100.0% | 60 | 100.0% |
| person | 40 | 0.0% | 0 | - |
| private_key | 20 | 100.0% | 20 | 100.0% |
| resource_name | 80 | 75.0% | 20 | 100.0% |

Missed (leaks):

- cluster_name: 20 in kubeconfig-000, kubeconfig-001, kubeconfig-002, kubeconfig-003, kubeconfig-004, kubeconfig-005
- organization: 20 in incident-note-000, incident-note-001, incident-note-002, incident-note-003, incident-note-004, incident-note-005
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
| organization | 3 | 33.3% | 1 | 100.0% |
| password | 5 | 100.0% | 3 | 100.0% |
| person | 7 | 28.6% | 6 | 33.3% |
| resource_name | 6 | 100.0% | 2 | 100.0% |

Missed (leaks):

- cluster_name: 1 in slack-incident
- hostname: 1 in helm-values
- organization: 2 in docker-compose, slack-incident
- person: 5 in slack-incident

## dev (no propagation)

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
| organization | 3 | 33.3% | 1 | 100.0% |
| password | 5 | 100.0% | 3 | 100.0% |
| person | 7 | 28.6% | 3 | 66.7% |
| resource_name | 6 | 100.0% | 2 | 100.0% |

Missed (leaks):

- cluster_name: 1 in slack-incident
- hostname: 1 in helm-values
- organization: 2 in docker-compose, slack-incident
- person: 5 in slack-incident
