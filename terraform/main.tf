
terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  features {}
  resource_provider_registrations = "none"
  storage_use_azuread             = true
}

data "azurerm_resource_group" "lab" {
  name = var.resource_group_name
}

resource "azurerm_storage_account" "hardened" {
  name                     = var.storage_account_name
  resource_group_name      = data.azurerm_resource_group.lab.name
  location                 = "northcentralus"
  account_tier             = "Standard"
  account_replication_type = "LRS"

  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = false
  public_network_access_enabled   = false
  default_to_oauth_authentication = true
  local_user_enabled              = false
}