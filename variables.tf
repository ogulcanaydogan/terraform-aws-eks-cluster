variable "cluster_name" {
  description = "Name of the EKS cluster."
  type        = string

  validation {
    condition     = length(trimspace(var.cluster_name)) > 0 && length(var.cluster_name) <= 100
    error_message = "cluster_name must be between 1 and 100 characters."
  }

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9-]*$", var.cluster_name))
    error_message = "cluster_name must start with a letter and contain only alphanumeric characters and hyphens."
  }
}

variable "kubernetes_version" {
  description = "Kubernetes version for the EKS cluster."
  type        = string
  default     = "1.29"

  validation {
    condition     = can(regex("^1\\.(2[5-9]|3[0-9])$", var.kubernetes_version))
    error_message = "kubernetes_version must be a valid EKS version (1.25-1.39)."
  }
}

variable "vpc_id" {
  description = "VPC ID where the EKS cluster will be deployed."
  type        = string

  validation {
    condition     = can(regex("^vpc-[a-f0-9]+$", var.vpc_id))
    error_message = "vpc_id must be a valid VPC ID (vpc-xxxxxxxx)."
  }
}

variable "subnet_ids" {
  description = "List of subnet IDs for the EKS cluster (minimum 2 in different AZs)."
  type        = list(string)

  validation {
    condition     = length(var.subnet_ids) >= 2
    error_message = "At least 2 subnet IDs are required for EKS cluster."
  }
}

# Cluster Configuration
variable "cluster_endpoint_private_access" {
  description = "Enable private API server endpoint access."
  type        = bool
  default     = true
}

variable "cluster_endpoint_public_access" {
  description = "Enable public API server endpoint access."
  type        = bool
  default     = true
}

variable "cluster_endpoint_public_access_cidrs" {
  description = "List of CIDR blocks that can access the public API server endpoint."
  type        = list(string)
  default     = ["0.0.0.0/0"]

  validation {
    condition     = alltrue([for cidr in var.cluster_endpoint_public_access_cidrs : can(cidrnetmask(cidr))])
    error_message = "All values must be valid IPv4 CIDR blocks."
  }
}

variable "cluster_service_ipv4_cidr" {
  description = "CIDR block for Kubernetes service IPs."
  type        = string
  default     = null

  validation {
    condition     = var.cluster_service_ipv4_cidr == null || can(cidrnetmask(var.cluster_service_ipv4_cidr))
    error_message = "cluster_service_ipv4_cidr must be a valid IPv4 CIDR block."
  }
}

# KMS Encryption
variable "enable_cluster_encryption" {
  description = "Enable envelope encryption of Kubernetes secrets with KMS."
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "ARN of existing KMS key for secrets encryption. If not provided, a new key will be created."
  type        = string
  default     = null
}

variable "kms_key_deletion_window" {
  description = "Duration in days before KMS key is deleted after destruction."
  type        = number
  default     = 30

  validation {
    condition     = var.kms_key_deletion_window >= 7 && var.kms_key_deletion_window <= 30
    error_message = "kms_key_deletion_window must be between 7 and 30 days."
  }
}

variable "kms_key_enable_rotation" {
  description = "Enable automatic KMS key rotation."
  type        = bool
  default     = true
}

# CloudWatch Logging
variable "enabled_cluster_log_types" {
  description = "List of control plane logging to enable."
  type        = list(string)
  default     = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  validation {
    condition     = alltrue([for log_type in var.enabled_cluster_log_types : contains(["api", "audit", "authenticator", "controllerManager", "scheduler"], log_type)])
    error_message = "enabled_cluster_log_types must only contain: api, audit, authenticator, controllerManager, scheduler."
  }
}

variable "cluster_log_retention_days" {
  description = "Number of days to retain cluster logs in CloudWatch."
  type        = number
  default     = 30

  validation {
    condition     = contains([0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.cluster_log_retention_days)
    error_message = "cluster_log_retention_days must be a valid CloudWatch Logs retention value."
  }
}

# OIDC Provider
variable "enable_irsa" {
  description = "Enable IAM Roles for Service Accounts (IRSA) by creating OIDC provider."
  type        = bool
  default     = true
}

# Node Groups
variable "node_groups" {
  description = "Map of EKS managed node group configurations."
  type = map(object({
    instance_types = optional(list(string), ["t3.medium"])
    capacity_type  = optional(string, "ON_DEMAND")
    disk_size      = optional(number, 50)
    ami_type       = optional(string, "AL2023_x86_64_STANDARD")

    scaling_config = optional(object({
      desired_size = optional(number, 2)
      min_size     = optional(number, 1)
      max_size     = optional(number, 4)
    }), {})

    update_config = optional(object({
      max_unavailable            = optional(number, 1)
      max_unavailable_percentage = optional(number, null)
    }), {})

    labels = optional(map(string), {})
    taints = optional(list(object({
      key    = string
      value  = optional(string)
      effect = string
    })), [])

    subnet_ids = optional(list(string), null)
  }))
  default = {}
}

variable "node_group_defaults" {
  description = "Default values for node groups."
  type = object({
    instance_types = optional(list(string), ["t3.medium"])
    capacity_type  = optional(string, "ON_DEMAND")
    disk_size      = optional(number, 50)
    ami_type       = optional(string, "AL2023_x86_64_STANDARD")
  })
  default = {}
}

# EKS Addons
variable "cluster_addons" {
  description = "Map of EKS cluster addons to enable."
  type = map(object({
    addon_version               = optional(string, null)
    resolve_conflicts_on_create = optional(string, "OVERWRITE")
    resolve_conflicts_on_update = optional(string, "OVERWRITE")
    service_account_role_arn    = optional(string, null)
    configuration_values        = optional(string, null)
  }))
  default = {
    vpc-cni    = {}
    coredns    = {}
    kube-proxy = {}
  }
}

# Security Groups
variable "cluster_security_group_additional_rules" {
  description = "Additional security group rules for the cluster security group."
  type = map(object({
    description                   = string
    type                          = string
    from_port                     = number
    to_port                       = number
    protocol                      = string
    cidr_blocks                   = optional(list(string), null)
    ipv6_cidr_blocks              = optional(list(string), null)
    source_security_group_id      = optional(string, null)
    source_cluster_security_group = optional(bool, false)
  }))
  default = {}
}

variable "node_security_group_additional_rules" {
  description = "Additional security group rules for the node security group."
  type = map(object({
    description                   = string
    type                          = string
    from_port                     = number
    to_port                       = number
    protocol                      = string
    cidr_blocks                   = optional(list(string), null)
    ipv6_cidr_blocks              = optional(list(string), null)
    source_security_group_id      = optional(string, null)
    source_cluster_security_group = optional(bool, false)
    self                          = optional(bool, false)
  }))
  default = {}
}

# Access Configuration
variable "authentication_mode" {
  description = "Authentication mode for the cluster. Valid values: CONFIG_MAP, API, API_AND_CONFIG_MAP."
  type        = string
  default     = "API_AND_CONFIG_MAP"

  validation {
    condition     = contains(["CONFIG_MAP", "API", "API_AND_CONFIG_MAP"], var.authentication_mode)
    error_message = "authentication_mode must be CONFIG_MAP, API, or API_AND_CONFIG_MAP."
  }
}

variable "access_entries" {
  description = "Map of access entries for cluster access."
  type = map(object({
    principal_arn     = string
    kubernetes_groups = optional(list(string), [])
    type              = optional(string, "STANDARD")

    policy_associations = optional(map(object({
      policy_arn = string
      access_scope = object({
        type       = string
        namespaces = optional(list(string), [])
      })
    })), {})
  }))
  default = {}
}

# Tags
variable "tags" {
  description = "Tags to apply to all resources."
  type        = map(string)
  default     = {}
}

variable "cluster_tags" {
  description = "Additional tags for the EKS cluster."
  type        = map(string)
  default     = {}
}

variable "node_group_tags" {
  description = "Additional tags for all node groups."
  type        = map(string)
  default     = {}
}
