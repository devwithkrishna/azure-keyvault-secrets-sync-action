import argparse
import logging
from datetime import datetime
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from dotenv import load_dotenv
from setup_logging import setup_logging


def get_keyvault_endpoints(keyvault_names: str | list[str]) -> list[str]:
	"""
	Get the Key Vault endpoints for one or multiple Key Vault names.

	Args:
		keyvault_names (str | list[str]): A single Key Vault name or a list of Key Vault names.

	Returns:
		list[str]: A list of Key Vault endpoint URLs in the format
				   'https://<keyvault_name>.vault.azure.net'.
	"""
	if isinstance(keyvault_names, str):
		keyvault_names = [keyvault_names]
	keyvault_urls = [f"https://{name}.vault.azure.net" for name in keyvault_names[0].split(',')]
	return keyvault_urls


def get_secret_from_keyvault(keyvault_name: str, secret_name: str) -> str:
	"""
	Retrieve secrets from an Azure Key Vault.

	Args:
		keyvault_name (str): The name of the Key Vault to retrieve secrets from.
		secret_name (str): A comma-separated string of secret names to retrieve.

	Returns:
		str: A dictionary containing the secret names as keys and their corresponding values.
			 Returns None if an error occurs during retrieval.
	"""
	logger = logging.getLogger(__name__)
	keyvault_url = get_keyvault_endpoints(keyvault_name)
	credential = DefaultAzureCredential()
	source_kv = ''.join(keyvault_url)
	client = SecretClient(vault_url=source_kv, credential=credential)

	secrets = {}  # Dictionary to store secrets

	for secret in secret_name[0].split(','):
		logging.info(f"Getting secret {secret} from Key Vault {keyvault_name}")
		try:
			kv_secret = client.get_secret(secret)
			secrets[secret] = kv_secret.value
			logging.info(f"Secret {secret} retrieved successfully.")
		except Exception as e:
			logging.error(f"Error retrieving secret {secret} from Key Vault {keyvault_name}: {e}")
			return None

	logger.info(f"All secrets retrieved from Key Vault {keyvault_name}")
	return secrets


def set_secrets_in_keyvault(keyvault_name: list[str], secrets: dict) -> None:
	"""
	Set secrets in an Azure Key Vault.

	Args:
		keyvault_name (str): The name of the Key Vault where the secrets will be set.
		secrets (dict): A dictionary containing secret names as keys and their corresponding values.

	Returns:
		None
	"""
	logger = logging.getLogger(__name__)
	credentials = DefaultAzureCredential()
	keyvault_url = get_keyvault_endpoints(keyvault_name)
	for kv_url in keyvault_url:
		logging.info(f"Setting secrets in Key Vault {kv_url}")
		destination_kv = ''.join(kv_url)
		client = SecretClient(vault_url=destination_kv, credential=credentials)

		now = datetime.now()
		formatted = now.strftime("%Y-%b-%d %H:%M").lower()

		for secret_name, secret_value in secrets.items():
			try:
				description = f"Secret {secret_name} created on {formatted} by kv secrets migration action"
				logger.info(f"Setting secret {secret_name} in Key Vault {keyvault_name}")
				client.set_secret(name=secret_name, value=secret_value, content_type=description)
				logging.info(f"Secret {secret_name} set successfully.")
			except Exception as e:
				logging.error(f"Error setting secret {secret_name} in Key Vault {keyvault_name}: {e}")
				return None


def main():
	"""

	This function parses command-line arguments, retrieves secrets from a source Key Vault,
	and sets them in one or more destination Key Vaults.

	Args:
		None

	Returns:
		None
	"""
	parser = argparse.ArgumentParser(description="KeyVault Secrets Migration Tool...")
	parser.add_argument(
		"--destination_keyvault_names",
		type=str,
		nargs="+",
		help="List of Key Vault names to get endpoints for.",
		required=True
	)
	parser.add_argument(
		"--secret_names",
		type=str,
		nargs="+",
		help="List of secret names to get from Key Vault.",
		required=True
	)
	parser.add_argument(
		"--source_keyvault",
		type=str,
		help="Source Key Vault name to get secrets from.",
		required=True
	)
	parser.add_argument(
		"--target_secret_names",
		type=str,
		nargs="+",
		help="List of secret names to in destination Key Vaults.",
		required=False
	)

	args = parser.parse_args()
	keyvault_names = args.destination_keyvault_names
	secret_names = args.secret_names
	source_keyvault = args.source_keyvault
	target_secret_names = args.target_secret_names

	load_dotenv()
	setup_logging()
	logger = logging.getLogger(__name__)

	logger.info(f"KeyVault names: {keyvault_names}")
	logger.info(f"Secret names: {secret_names}")
	logger.info(f"Source KeyVault: {source_keyvault}")
	logger.info(f"Target secret names: {target_secret_names}")

	secrets = get_secret_from_keyvault(keyvault_name=source_keyvault, secret_name=secret_names)
	logger.info(f"Secrets retrieved from Key Vault successfully.")
	if target_secret_names:
		secrets_to_set = dict(zip(target_secret_names[0].split(','), secrets.values()))
	else:
		secrets_to_set = secrets

	set_secrets_in_keyvault(keyvault_name=keyvault_names, secrets=secrets_to_set)
	logger.info(f"Secrets set in Key Vault {keyvault_names} successfully.")


if __name__ == "__main__":
	main()
