import os
import sys
import logging
import json
from cato_services.util import utils
from .image_scanner import ImageScanner
import re

AQUA_URL = os.environ.get('AQUA_URL')
AQUA_USERNAME = os.environ.get('AQUA_ONBOARDING_USERNAME')
AQUA_PASSWORD = os.environ.get('AQUA_ONBOARDING_PASSWORD')
CRM_FILENAME = os.environ.get('CRM_FILENAME')

def check_filename_for_bad_chars(filename):
    return re.search('\.\./', filename)


def read_crm_file(crm_filename):
    with open(crm_filename, "r") as crm_file:
        crm_data = json.load(crm_file)
    return crm_data



def onboard_to_image_scanner(image_scanner: ImageScanner):
    try:
        certs = "/etc/ssl/certs/ca-certificates.crt"
        aqua_client_config = aqua.get_aqua_client_config(AQUA_URL, AQUA_USERNAME, AQUA_PASSWORD, verify=certs)
        if check_filename_for_bad_chars(CRM_FILENAME) == None:
            crm_data = read_crm_file(CRM_FILENAME)
        else:
            utils.print_and_exit(f"CRM_FILENAME is invalid. {CRM_FILENAME}", 1)


        image_scanner.onboard_new_customer(crm_data)

    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.error("Failed to read CRM file: %s", e)
        sys.exit(1)
    except utils.APIException as e:
        if e.endpoint == "/login":
            utils.print_and_exit(f"Failed to login to aqua API. {e}", 1)
        elif e.endpoint == "/settings/OIDCSettings/OpenIdSettings":
            utils.print_and_exit(f"Failed to update role mappings. {e}", 1)
        elif e.endpoint == "/access_management/roles":
            utils.print_and_exit(f"Failed to create role. {e}", 1)
        utils.print_and_exit(e, 1)
            
    except Exception as e:
        logging.error("Failed to create role and scopes: %s", e)
        sys.exit(1)
