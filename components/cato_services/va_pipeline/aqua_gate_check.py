import sys
import json
import logging
from requests import HTTPError
from cato_services.aqua.aqua_scanner import AquaScanner
from cato_services.github_actions.core import GithubActionsImageScanStep
from cato_services.pipeline.image_gate_check import gate_check_images


AQUA_URL = "http://localhost:8080"
AQUA_USERNAME = "administrator"
AQUA_PASSWORD = "9oCNRJ798&xMZ0Xk"

def main():
    registry = "Ad Hoc Scans"
    images = json.loads(sys.argv[1])
    aqua_scanner = AquaScanner(AQUA_URL, AQUA_USERNAME, AQUA_PASSWORD)
    github_actions_image_scan_step = GithubActionsImageScanStep()
    try:
        gate_check_flag, image_data = gate_check_images(images, aqua_scanner)
        github_actions_image_scan_step.output_image_scan_summary(image_data)
        if gate_check_flag is True:
            sys.exit(99)
    except HTTPError as http_err:
        logging.error("An error occurred during the GET request. %s", http_err)
        sys.exit(1)


if __name__ == "__main__":
    main()
