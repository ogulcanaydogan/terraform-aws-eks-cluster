# terraform-aws-eks-cluster

Terraform module that creates a production-ready AWS EKS (Elastic Kubernetes Service) cluster with managed node groups, IRSA, encryption, and security best practices.

## Features

- **Managed Node Groups** - Auto-scaling EKS managed node groups with Amazon Linux 2023
- **IRSA Support** - IAM Roles for Service Accounts with OIDC provider
- **KMS Encryption** - Envelope encryption for Kubernetes secrets
- **CloudWatch Logging** - Control plane logging with configurable retention
- **Security Groups** - Separate security groups for cluster and nodes
- **EKS Addons** - VPC CNI, CoreDNS, kube-proxy with version management
- **Access Entries** - Native EKS API authentication and RBAC
- **SSM Support** - Node access via AWS Systems Manager

## Usage

### Basic Cluster

```hcl
module "eks" {
  source = "ogulcanaydogan/eks-cluster/aws"

  cluster_name = "my-cluster"
  vpc_id       = "vpc-xxxxxxxx"
  subnet_ids   = ["subnet-aaaaaaaa", "subnet-bbbbbbbb"]

  node_groups = {
    default = {
      instance_types = ["t3.medium"]
      scaling_config = {
        desired_size = 2
        min_size     = 1
        max_size     = 4
      }
    }
  }

  tags = {
    Environment = "production"
  }
}
```

### Production Cluster with Multiple Node Groups

```hcl
module "eks" {
  source = "ogulcanaydogan/eks-cluster/aws"

  cluster_name       = "production-cluster"
  kubernetes_version = "1.29"
  vpc_id             = module.vpc.vpc_id
  subnet_ids         = module.vpc.private_subnet_ids

  # Private cluster with restricted public access
  cluster_endpoint_private_access = true
  cluster_endpoint_public_access  = true
  cluster_endpoint_public_access_cidrs = ["10.0.0.0/8"]

  # Enable encryption
  enable_cluster_encryption = true
  kms_key_enable_rotation   = true

  # CloudWatch logging
  enabled_cluster_log_types = ["api", "audit", "authenticator"]
  cluster_log_retention_days = 90

  # Multiple node groups
  node_groups = {
    general = {
      instance_types = ["m6i.large", "m5.large"]
      capacity_type  = "ON_DEMAND"
      ami_type       = "AL2023_x86_64_STANDARD"

      scaling_config = {
        desired_size = 3
        min_size     = 2
        max_size     = 10
      }

      labels = {
        role = "general"
      }
    }

    spot = {
      instance_types = ["t3.large", "t3.xlarge", "t3a.large"]
      capacity_type  = "SPOT"

      scaling_config = {
        desired_size = 2
        min_size     = 0
        max_size     = 20
      }

      labels = {
        role = "spot-workers"
      }

      taints = [
        {
          key    = "spot"
          value  = "true"
          effect = "NO_SCHEDULE"
        }
      ]
    }
  }

  tags = {
    Environment = "production"
    Team        = "platform"
  }
}
```

### Cluster with Graviton (ARM64) Nodes

```hcl
module "eks" {
  source = "ogulcanaydogan/eks-cluster/aws"

  cluster_name = "graviton-cluster"
  vpc_id       = module.vpc.vpc_id
  subnet_ids   = module.vpc.private_subnet_ids

  node_groups = {
    graviton = {
      instance_types = ["t4g.medium", "t4g.large"]
      ami_type       = "AL2023_ARM_64_STANDARD"

      scaling_config = {
        desired_size = 2
        min_size     = 1
        max_size     = 6
      }
    }
  }

  tags = {
    Environment = "production"
  }
}
```

### Private Cluster (No Public Endpoint)

```hcl
module "eks" {
  source = "ogulcanaydogan/eks-cluster/aws"

  cluster_name = "private-cluster"
  vpc_id       = module.vpc.vpc_id
  subnet_ids   = module.vpc.private_subnet_ids

  # Private only - requires VPN/Direct Connect access
  cluster_endpoint_private_access = true
  cluster_endpoint_public_access  = false

  node_groups = {
    default = {
      instance_types = ["t3.medium"]
      scaling_config = {
        desired_size = 2
        min_size     = 1
        max_size     = 4
      }
    }
  }

  tags = {
    Environment = "production"
  }
}
```

### Cluster with IAM Access Entries

```hcl
module "eks" {
  source = "ogulcanaydogan/eks-cluster/aws"

  cluster_name       = "rbac-cluster"
  kubernetes_version = "1.29"
  vpc_id             = module.vpc.vpc_id
  subnet_ids         = module.vpc.private_subnet_ids

  authentication_mode = "API_AND_CONFIG_MAP"

  access_entries = {
    admin_role = {
      principal_arn = "arn:aws:iam::123456789012:role/AdminRole"
      type          = "STANDARD"

      policy_associations = {
        admin = {
          policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
          access_scope = {
            type = "cluster"
          }
        }
      }
    }

    dev_role = {
      principal_arn = "arn:aws:iam::123456789012:role/DeveloperRole"
      type          = "STANDARD"

      policy_associations = {
        view = {
          policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"
          access_scope = {
            type       = "namespace"
            namespaces = ["development", "staging"]
          }
        }
      }
    }
  }

  node_groups = {
    default = {
      instance_types = ["t3.medium"]
    }
  }

  tags = {
    Environment = "production"
  }
}
```

### Cluster with Custom Addons

```hcl
module "eks" {
  source = "ogulcanaydogan/eks-cluster/aws"

  cluster_name = "addon-cluster"
  vpc_id       = module.vpc.vpc_id
  subnet_ids   = module.vpc.private_subnet_ids

  cluster_addons = {
    vpc-cni = {
      addon_version = "v1.16.0-eksbuild.1"
    }
    coredns = {
      addon_version = "v1.11.1-eksbuild.4"
    }
    kube-proxy = {
      addon_version = "v1.29.0-eksbuild.1"
    }
    aws-ebs-csi-driver = {
      service_account_role_arn = module.ebs_csi_irsa.iam_role_arn
    }
  }

  node_groups = {
    default = {
      instance_types = ["t3.medium"]
    }
  }

  tags = {
    Environment = "production"
  }
}
```

## Inputs

### Required

| Name | Description | Type |
|------|-------------|------|
| `cluster_name` | Name of the EKS cluster | `string` |
| `vpc_id` | VPC ID for the EKS cluster | `string` |
| `subnet_ids` | List of subnet IDs (minimum 2 in different AZs) | `list(string)` |

### Cluster Configuration

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `kubernetes_version` | Kubernetes version | `string` | `"1.29"` |
| `cluster_endpoint_private_access` | Enable private API endpoint | `bool` | `true` |
| `cluster_endpoint_public_access` | Enable public API endpoint | `bool` | `true` |
| `cluster_endpoint_public_access_cidrs` | CIDRs for public API access | `list(string)` | `["0.0.0.0/0"]` |
| `cluster_service_ipv4_cidr` | CIDR for Kubernetes services | `string` | `null` |

### Encryption

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `enable_cluster_encryption` | Enable secrets encryption | `bool` | `true` |
| `kms_key_arn` | Existing KMS key ARN | `string` | `null` |
| `kms_key_deletion_window` | KMS key deletion window (days) | `number` | `30` |
| `kms_key_enable_rotation` | Enable KMS key rotation | `bool` | `true` |

### Logging

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `enabled_cluster_log_types` | Control plane log types | `list(string)` | `["api", "audit", "authenticator", "controllerManager", "scheduler"]` |
| `cluster_log_retention_days` | Log retention in days | `number` | `30` |

### IRSA

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `enable_irsa` | Create OIDC provider for IRSA | `bool` | `true` |

### Node Groups

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `node_groups` | Map of node group configurations | `map(object)` | `{}` |
| `node_group_defaults` | Default values for node groups | `object` | `{}` |

### Node Group Configuration Object

```hcl
node_groups = {
  name = {
    instance_types = ["t3.medium"]      # Instance types
    capacity_type  = "ON_DEMAND"        # ON_DEMAND or SPOT
    disk_size      = 50                 # EBS volume size (GB)
    ami_type       = "AL2023_x86_64_STANDARD"  # AMI type

    scaling_config = {
      desired_size = 2
      min_size     = 1
      max_size     = 4
    }

    update_config = {
      max_unavailable = 1               # Max nodes unavailable during update
    }

    labels = {                          # Kubernetes labels
      role = "worker"
    }

    taints = [                          # Kubernetes taints
      {
        key    = "dedicated"
        value  = "special"
        effect = "NO_SCHEDULE"
      }
    ]

    subnet_ids = []                     # Override cluster subnet_ids
  }
}
```

### AMI Types

| AMI Type | Description |
|----------|-------------|
| `AL2023_x86_64_STANDARD` | Amazon Linux 2023 (x86_64) |
| `AL2023_ARM_64_STANDARD` | Amazon Linux 2023 (ARM64/Graviton) |
| `AL2_x86_64` | Amazon Linux 2 (x86_64) |
| `AL2_ARM_64` | Amazon Linux 2 (ARM64) |
| `BOTTLEROCKET_x86_64` | Bottlerocket (x86_64) |
| `BOTTLEROCKET_ARM_64` | Bottlerocket (ARM64) |

### Addons

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `cluster_addons` | Map of EKS addons | `map(object)` | `{vpc-cni={}, coredns={}, kube-proxy={}}` |

### Access Configuration

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `authentication_mode` | Auth mode (CONFIG_MAP, API, API_AND_CONFIG_MAP) | `string` | `"API_AND_CONFIG_MAP"` |
| `access_entries` | Map of IAM access entries | `map(object)` | `{}` |

### Security Groups

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `cluster_security_group_additional_rules` | Additional cluster SG rules | `map(object)` | `{}` |
| `node_security_group_additional_rules` | Additional node SG rules | `map(object)` | `{}` |

### Tags

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `tags` | Tags for all resources | `map(string)` | `{}` |
| `cluster_tags` | Additional cluster tags | `map(string)` | `{}` |
| `node_group_tags` | Additional node group tags | `map(string)` | `{}` |

## Outputs

### Cluster

| Name | Description |
|------|-------------|
| `cluster_id` | EKS cluster ID |
| `cluster_arn` | EKS cluster ARN |
| `cluster_name` | EKS cluster name |
| `cluster_version` | Kubernetes version |
| `cluster_platform_version` | EKS platform version |
| `cluster_status` | Cluster status |
| `cluster_endpoint` | API server endpoint |
| `cluster_certificate_authority_data` | CA certificate data |

### Security

| Name | Description |
|------|-------------|
| `cluster_security_group_id` | Cluster security group ID |
| `cluster_primary_security_group_id` | EKS-managed cluster security group |
| `node_security_group_id` | Node security group ID |

### IAM

| Name | Description |
|------|-------------|
| `cluster_iam_role_name` | Cluster IAM role name |
| `cluster_iam_role_arn` | Cluster IAM role ARN |
| `node_iam_role_name` | Node IAM role name |
| `node_iam_role_arn` | Node IAM role ARN |
| `oidc_provider_arn` | OIDC provider ARN |
| `oidc_provider_url` | OIDC provider URL |
| `cluster_oidc_issuer_url` | OIDC issuer URL |

### Encryption

| Name | Description |
|------|-------------|
| `kms_key_arn` | KMS key ARN |
| `kms_key_id` | KMS key ID |

### Logging

| Name | Description |
|------|-------------|
| `cloudwatch_log_group_name` | CloudWatch log group name |
| `cloudwatch_log_group_arn` | CloudWatch log group ARN |

### Node Groups

| Name | Description |
|------|-------------|
| `node_groups` | Map of node group details |
| `node_group_arns` | List of node group ARNs |

### Addons

| Name | Description |
|------|-------------|
| `cluster_addons` | Map of addon details |

### Utilities

| Name | Description |
|------|-------------|
| `kubectl_config` | Command to configure kubectl |

## Examples

See [`examples/complete`](./examples/complete) for a full configuration.

## IRSA Usage

After creating the cluster, you can create IAM roles for service accounts:

```hcl
module "s3_irsa" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name = "my-app-s3-role"

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["default:my-app"]
    }
  }

  role_policy_arns = {
    s3 = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
  }
}
```

## kubectl Configuration

After cluster creation, configure kubectl:

```bash
aws eks update-kubeconfig --region us-east-1 --name my-cluster
```

Or use the output:

```bash
$(terraform output -raw kubectl_config)
```
