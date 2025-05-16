# azure-keyvault-secrets-sync-action
A GitHub Action and Python tool to copy secrets from one Azure Key Vault to one or more destination Key Vaults.

# Features
* Migrate secrets from a source Key Vault to multiple destination Key Vaults.

* Supports mapping secret names to different names in the destination.

* Can be run locally or as a GitHub Action.


# Prerequisites

1.Azure Service Principal

You need an Azure Service Principal (SP) with the following permissions:


* Key Vault Access Policies (if using access policies):

  * Get and List permissions on secrets for the source Key Vault.

  * Set permissions on secrets for each destination Key Vault.

* Key Vault RBAC (if using Azure RBAC):

  * Key Vault Secrets User role on the source Key Vault (to read secrets).
  * Key Vault Secrets Officer or Key Vault Administrator role on each destination Key Vault (to set secrets).


# Environment Variables:

Set the following environment variables for authentication (if not using managed identity):

```bash
AZURE_CLIENT_ID=" "
AZURE_TENANT_ID=" "
AZURE_CLIENT_SECRET=" "
```
# Python Environment
* Python 3.11+
* Poetry for dependency management


# Setup

* Clone the repository:

```bash
git clone https://github.com/devwithkrishna/azure-keyvault-secrets-sync-action.git
```

```bash
cd azure-keyvault-secrets-sync-action
```

* Install dependencies:

```python
pip install poetry
poetry install
```

# Usage

* --source_keyvault: Name of the source Key Vault.
* --destination_keyvault_names: Space-separated list of destination Key Vault names.
* --secret_names: Space-separated list of secret names to migrate.
* --target_secret_names: (Optional) Comma-separated list of target secret names.

**When `target_secret_names` is not specified, the source secret names will be used as the target names.**

```python
poetry run python keyvault.py \
  --source_keyvault "source-kv-name" \
  --destination_keyvault_names "dest-kv1,dest-kv2" \
  --secret_names "secret1,secret2" \
  --target_secret_names "target1,target2"
```


# GitHub Action

```yaml
- name: Azure KeyVault Secrets Migration
  uses: /devwithkrishna/azure-keyvault-secrets-sync-action@v1 
  with:
    source_keyvault: 'source-kv-name'
    destination_keyvault_names: 'dest-kv1,dest-kv2'
    secret_names: 'secret1,secret2'
    target_secret_names: 'target1,target2' # optional
  env:
    AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
    AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
    AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
```

# Notes
* If using --target_secret_names, provide as a single comma-separated string (e.g., target1,target2).

* The script logs actions and errors to the console and to azure-kv-secret-migration.log if configured.

* Ensure your SP has permissions on all involved Key Vaults

