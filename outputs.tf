# Cluster
output "cluster_id" {
  description = "EKS cluster ID."
  value       = aws_eks_cluster.this.id
}

output "cluster_arn" {
  description = "EKS cluster ARN."
  value       = aws_eks_cluster.this.arn
}

output "cluster_name" {
  description = "EKS cluster name."
  value       = aws_eks_cluster.this.name
}

output "cluster_version" {
  description = "Kubernetes version of the EKS cluster."
  value       = aws_eks_cluster.this.version
}

output "cluster_platform_version" {
  description = "Platform version of the EKS cluster."
  value       = aws_eks_cluster.this.platform_version
}

output "cluster_status" {
  description = "Status of the EKS cluster."
  value       = aws_eks_cluster.this.status
}

# Endpoints
output "cluster_endpoint" {
  description = "Endpoint URL for the EKS cluster API server."
  value       = aws_eks_cluster.this.endpoint
}

output "cluster_certificate_authority_data" {
  description = "Base64 encoded certificate data for cluster authentication."
  value       = aws_eks_cluster.this.certificate_authority[0].data
}

# Security Groups
output "cluster_security_group_id" {
  description = "Security group ID attached to the EKS cluster control plane."
  value       = aws_security_group.cluster.id
}

output "cluster_primary_security_group_id" {
  description = "Cluster security group created by EKS."
  value       = aws_eks_cluster.this.vpc_config[0].cluster_security_group_id
}

output "node_security_group_id" {
  description = "Security group ID attached to the EKS nodes."
  value       = aws_security_group.node.id
}

# IAM
output "cluster_iam_role_name" {
  description = "IAM role name of the EKS cluster."
  value       = aws_iam_role.cluster.name
}

output "cluster_iam_role_arn" {
  description = "IAM role ARN of the EKS cluster."
  value       = aws_iam_role.cluster.arn
}

output "node_iam_role_name" {
  description = "IAM role name of the EKS node groups."
  value       = try(aws_iam_role.node[0].name, null)
}

output "node_iam_role_arn" {
  description = "IAM role ARN of the EKS node groups."
  value       = try(aws_iam_role.node[0].arn, null)
}

# OIDC Provider
output "oidc_provider_arn" {
  description = "ARN of the OIDC provider for IRSA."
  value       = try(aws_iam_openid_connect_provider.cluster[0].arn, null)
}

output "oidc_provider_url" {
  description = "URL of the OIDC provider (without https://)."
  value       = try(replace(aws_iam_openid_connect_provider.cluster[0].url, "https://", ""), null)
}

output "cluster_oidc_issuer_url" {
  description = "OIDC issuer URL of the EKS cluster."
  value       = aws_eks_cluster.this.identity[0].oidc[0].issuer
}

# KMS
output "kms_key_arn" {
  description = "ARN of the KMS key used for cluster encryption."
  value       = var.enable_cluster_encryption ? (var.kms_key_arn != null ? var.kms_key_arn : try(aws_kms_key.cluster[0].arn, null)) : null
}

output "kms_key_id" {
  description = "ID of the KMS key used for cluster encryption."
  value       = try(aws_kms_key.cluster[0].key_id, null)
}

# CloudWatch Logs
output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for cluster logs."
  value       = try(aws_cloudwatch_log_group.cluster[0].name, null)
}

output "cloudwatch_log_group_arn" {
  description = "ARN of the CloudWatch log group for cluster logs."
  value       = try(aws_cloudwatch_log_group.cluster[0].arn, null)
}

# Node Groups
output "node_groups" {
  description = "Map of EKS managed node groups."
  value = {
    for key, ng in aws_eks_node_group.this : key => {
      arn            = ng.arn
      id             = ng.id
      status         = ng.status
      capacity_type  = ng.capacity_type
      instance_types = ng.instance_types
      scaling_config = ng.scaling_config
    }
  }
}

output "node_group_arns" {
  description = "ARNs of all EKS managed node groups."
  value       = [for ng in aws_eks_node_group.this : ng.arn]
}

# Addons
output "cluster_addons" {
  description = "Map of EKS cluster addons."
  value = {
    for key, addon in aws_eks_addon.this : key => {
      arn           = addon.arn
      addon_version = addon.addon_version
    }
  }
}

# Kubectl Configuration
output "kubectl_config" {
  description = "kubectl configuration command."
  value       = "aws eks update-kubeconfig --region ${data.aws_region.current.name} --name ${aws_eks_cluster.this.name}"
}
