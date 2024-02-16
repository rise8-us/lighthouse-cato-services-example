"""Provides Aqua API functions for the ``tornado_shared_resources`` package."""

from typing import List
from cato_services.pipeline.image_scanner import AssuranceResult, ImageScanner, ImageScannerConfig, Suppression, Vulnerability, Image
import urllib.parse
from datetime import datetime, timedelta
from cato_services.util import utils

def _get_vulns_by_page(aqua_client_config, image_digest, image_name, page):
    """Return vulnerabilities for an image by page."""
    safe_image_name = urllib.parse.quote(image_name, safe="")
    safe_registry= urllib.parse.quote("Ad Hoc Scans", safe="")

    return utils.api_get(
        aqua_client_config,
        "/api/v2/risks/vulnerabilities"
        "?hide_base_image=false"
        "&fix_availability=true"
        f"&digest={image_digest}"
        f"&image_name={safe_image_name}"
        f"&registry_name={safe_registry}"
        f"&page={page}"
    )['result']

def _get_login_token(base_url, username, password, verify=False):
    """Return the login token from the Aqua API."""
    return utils.post(
        f"{base_url}/api/v1/login",
        {'Content-Type': 'application/json'},
        {'id': username, 'password': password},
        verify=verify
    ).json()['token']

def _get_aqua_client_config(base_url, username, password, verify=False):
    """Return the client configuration necessary to authenticate to Aqua.

    :param base_url: The base URL for the Aqua API
    :param username: The username to use to authenticate to the Aqua API
    :param password: The password to use to authenticate to the Aqua API
    :param verify: (optional) Flag indicating whether to verify SSL
                certificate. Defaults to False.
    :return: The Aqua client configuration
    """
    token = _get_login_token(base_url, username, password, verify=verify)
    return utils.get_client_config(
        base_url,
        {"Authorization": f"Bearer {token}"},
        ca_certs=verify
    )

# As of 7/24/2023, this is the only way to get accurate expiration data for suppressions. The suppression endpoint cannot filter by image.
# Instead, you must filter them by image name, and then match up the suppressions with their vulnerabilities by comparing the resource paths,
# which you can see here
def _find_suppression_for_vulnerability(vulnerability: Vulnerability, image_suppressions: List[Suppression]) -> Suppression:
    suppression_match = next(
        (
            s for s in image_suppressions
            if (vulnerability["name"] == s["issue_name"]  # Must match CVE 
                and (s.get('resource_path') == vulnerability["resource"]["path"]  # Must match resource path
                or (s.get('resource_path') is None and vulnerability["resource"]["path"] == "")) # Or both have no resource path
            )
        ),
        None
    )

    if suppression_match is not None:
        return suppression_match
    # There are cases where vulnerability is suppressed, but cannot be found in suppression list.
    # If there's an ack author associated with vulnerability we will consider it to be suppressed
    if vulnerability.get("ack_author") is not None or vulnerability.get("ack_author") != "":
        return {}
    
    return None

def _get_scope(aqua_client_config, scope_name):
    """Return the specified scope from the Aqua API."""
    return utils.api_get(
        aqua_client_config,
        f"/api/v2/access_management/scopes/{scope_name}"
    )

def _create_scope(aqua_client_config, data):
    """Create a new scope in the Aqua API."""
    return utils.api_post(
        aqua_client_config,
        "/api/v2/access_management/scopes",
        data
    )


def _get_role(aqua_client_config, role_name):
    """Return the specified role from the Aqua API."""
    return utils.api_get(
        aqua_client_config,
        f"/api/v2/access_management/roles/{role_name}"
    )

def _create_role(aqua_client_config, data):
    """Create a new role in the Aqua API."""
    return utils.api_post(
        aqua_client_config,
        "/api/v2/access_management/roles",
        data
    )

def _update_role(self, role_name, data):
    """Update the specified role in the Aqua API."""
    return utils.api_put(
        self.client_config,
        f"/api/v2/access_management/roles/{role_name}",
        data
    )


def _get_auth_settings(aqua_client_config):
    """Return the authentication settings from the Aqua API."""
    return utils.api_get(
        aqua_client_config,
        "/api/v1/settings/OIDCSettings/OpenIdSettings"
    )

def _update_auth_settings(aqua_client_config, data):
    """Update the authentication settings in the Aqua API."""
    return utils.api_put(
        aqua_client_config,
        "/api/v1/settings/OIDCSettings/OpenIdSettings",
        data
    )


def _build_secrel_customer_scope(scope_name, owner_email, namespace):
    """Return a SecRel customer scope.

    Builds a dictionary that represents a SecRel customer scope
    which covers image and container scanning for a given repository.

    :param scope_name: The name of the scope.
    :param owner_email: The email of the owner.
    :param namespace: The Kubernetes namespace.
    :return: A dictionary representing the customer scope.
    """
    description = (
        "This scope covers image and container scanning for the "
        f"{scope_name} repository."
    )

    return {
        "name": scope_name,
        "description": description,
        "owner_email": owner_email,
        "categories": {
            "artifacts": {
                "image": {
                    "expression": "v1 && v2",
                    "variables": [
                        {
                            "attribute": "aqua.registry",
                            "value": "*"
                        },
                        {
                            "attribute": "image.repo",
                            "value": f"*/{scope_name}/*"
                        }
                    ]
                }
            },
            "workloads": {
                "kubernetes": {
                    "expression": "v1 && v2",
                    "variables": [
                        {
                            "attribute": "kubernetes.cluster",
                            "value": "ldx-prod-1"
                        },
                        {
                            "attribute": "kubernetes.namespace",
                            "value": namespace
                        }
                    ]
                }
            }
        }
    }

def _build_secrel_customer_role(github_team_name, scope):
    """Return a SecRel customer role."""
    if scope.lower() == "global":
        raise AquaException("Cannot create role with global scope")

    role_name = f"{github_team_name}-vulnerability_operator"
    description = (
        f"This role enables the {github_team_name} team to access and "
        "manage vulnerability scan results for images and containers "
        "that are discovered from all associated Application Scopes"
    )

    return {
        "name": role_name,
        "description": description,
        "permission": "Vulnerability Operator",
        "scopes": [scope]
    }


def _get_all_suppressions(aqua_client_config):
    """Return all suppressions from the Aqua API."""
    return utils.collect_pages(lambda page: _get_suppressions_by_page(aqua_client_config, page))

def _get_suppressions_by_page(aqua_client_config, page):
    """Return suppressions by page from the Aqua API."""
    return utils.api_get(
        aqua_client_config,
        f"/api/v2/risks/acknowledge?order_by=repository&page={page}"
    )['result']

def get_aqua_ui_url(image, registry, aqua_url):
    """Return a URL for the Aqua UI for a given image."""
    image_name, image_tag = image["name"].split(":")
    image_digest = image["id"]
    safe_image_name = urllib.parse.quote(image_name, safe="")
    safe_image_digest = urllib.parse.quote(image_digest, safe="")
    url = (
        f"{aqua_url}/#/images/{registry}/{safe_image_name}:{image_tag}/vulns"
        f"?digest={safe_image_digest}"
    )

    return url

def _add_existing_scopes_to_role_and_update(aqua_client_config, role_name, new_role_data):
    existing_role = _get_role(aqua_client_config, role_name)
    new_role_data["scopes"] += existing_role["scopes"]
    return _update_role(aqua_client_config, role_name, new_role_data)

def format_image_name(image):
    """Return the formatted image name from the provided image name."""
    return image.split("ghcr.io/department-of-veterans-affairs/")[1]

class AquaScanner(ImageScanner):
    def __init__(self, base_url, username, password) -> None:
        self.client_config = _get_aqua_client_config(base_url, username, password)
    
    def get_vulnerabilities_for_image(self, image: Image) -> List[Vulnerability]:
        vulnerabilities = utils.collect_pages(lambda page: _get_vulns_by_page(self.client_config, image["digest"], image["name"], page))
        all_suppressions = _get_all_suppressions(self.client_config)
        vulns_with_suppressions = [v | {"suppression": _find_suppression_for_vulnerability(v, all_suppressions)} for v in vulnerabilities]
        return vulns_with_suppressions

    def get_assurance_results(self, image: Image) -> AssuranceResult:
        safe_image_name = urllib.parse.quote(image["name"], safe="")
        safe_registry= urllib.parse.quote("Ad Hoc Scans", safe="")

        request = utils.api_get(
            self.client_config,
            f"/api/v2/images/{safe_registry}/{safe_image_name}/{image['tag']}"
            f"?digest={image['digest']}"
        )

        return request['assurance_results']


    def onboard_new_customer(self, configuration: ImageScannerConfig):
        github_repo_name = configuration["github-repo-name"]
        va_email_address = configuration["va-email-address"]
        github_team_name = configuration["github-team-name"]
        kubernetes_namespace = github_team_name + "-prod"

        scope = _build_secrel_customer_scope(github_repo_name, va_email_address, kubernetes_namespace)
        utils.handle404(lambda: _create_scope(self.client_config, scope),
                        lambda: print(f"Scope: {scope['name']} already exists"))

        role_name = f"{github_team_name}-vulnerability_operator"
        role_data = _build_secrel_customer_role(github_team_name, scope["name"])
        utils.handle404(lambda: _create_role(self.client_config, role_data),
                        lambda: _add_existing_scopes_to_role_and_update(self.client_config, role_name, role_data))

        existing_auth_settings = _get_auth_settings(self.client_config)
        new_role_mapping = existing_auth_settings["role_mapping"] | {f"{role_name}" : [f"department-of-veterans-affairs/{github_team_name}"]}
        new_auth_settings = existing_auth_settings | {"role_mapping": new_role_mapping}
        _update_auth_settings(self.client_config, new_auth_settings)


class AquaException(Exception):
    """Exception raised for errors in the Aqua API functions."""





