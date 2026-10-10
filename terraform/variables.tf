
variable "resource_group_name" {
  description = "Existing Azure resource group for the lab"
  type        = string
  default     = "rg-cloud-security-lab"
}

variable "storage_account_name" {
  description = "Name for a separate Terraform-managed storage account"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]{3,24}$", var.storage_account_name))
    error_message = "The name must be 3-24 characters and contain only lowercase letters and numbers."
  }
}