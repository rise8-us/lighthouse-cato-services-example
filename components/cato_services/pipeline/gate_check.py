from .image_scanner import Image, ImageScanner, Vulnerability, Suppression
from typing import List

def filter_suppressions_by_image(image, suppressions):
    return [
        s for s in suppressions
        if s.get('repository') == image["name"].split(":")[0].split("ghcr.io/")[1]
        or s.get('image') == image["name"]
    ]

def trim_none(values):
    return (v for v in values if v is not None)

def attach_suppression_data_to_vulnerability(vulnerability: Vulnerability, suppression: Suppression):
    return vulnerability | {
        "ack_expiration_days": suppression["expiration_days"],
        "ack_expiration_date": format_suppression_expiration_date(suppression),
        "ack_comment": suppression["comment"]
    }

# As of 7/24/2023, this is the only way to get accurate expiration data for suppressions. The suppression endpoint cannot filter by image.
# Instead, you must filter them by image name, and then match up the suppressions with their vulnerabilities by comparing the resource paths,
# which you can see here
def find_suppression_for_vulnerability(vulnerability: Vulnerability, image_suppressions: List[Suppression]):
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
        return None, attach_suppression_data_to_vulnerability(vulnerability, suppression_match)
    # There are cases where vulnerability is suppressed, but cannot be found in suppression list.
    # If there's an ack author associated with vulnerability we will consider it to be suppressed
    if vulnerability.get("ack_author") is not None or vulnerability.get("ack_author") != "":
        return None, vulnerability
    
    return vulnerability, None

def sort_image_vulnerabilities_by_suppressed(image: Image, image_vulnerabilities: List[Vulnerability], suppressions: List[Suppression]):
    if not image_vulnerabilities:
        return [], []
    image_suppressions = filter_suppressions_by_image(image, suppressions)
    unsuppressed_vulns, suppressed_vulns =  zip(*(find_suppression_for_vulnerability(v, image_suppressions) for v in image_vulnerabilities))
    return trim_none(unsuppressed_vulns), trim_none(suppressed_vulns)

def get_aqua_data(image_scanner: ImageScanner, image: Image):
    fixable_image_vulnerabilities = image_scanner.get_vulnerabilities(image)
    assurance_results = image_scanner.get_assurance_results(image)
    return fixable_image_vulnerabilities, assurance_results

def get_gate_check_data_for_image(image: Image, suppressions: List[Suppression], image_scanner: ImageScanner):
    fixable_image_vulnerabilities, assurance_results = get_aqua_data(image_scanner, image)
    unsuppressed_fixable_vulnerabilities, suppressed_fixable_vulnerabilities = sort_image_vulnerabilities_by_suppressed(image, fixable_image_vulnerabilities, suppressions)
    expiring_suppressed_fixable_vulnerabilities = (
        v for v in suppressed_fixable_vulnerabilities
        if v["ack_expiration_days"] != 0 and v["ack_expiration_days"] <= 31
    )

    return image | {
        "vulnerabilities": list(unsuppressed_fixable_vulnerabilities),
        "suppressed_vulnerabilities": list(expiring_suppressed_fixable_vulnerabilities),
        "assurance_results": assurance_results
    }


def gate_check_images(images: List[Image], image_scanner: ImageScanner):
    suppressions = image_scanner.get_all_suppressions()
    image_data = [get_gate_check_data_for_image(image, suppressions, image_scanner) for image in images]
    gate_check_flag = any(image["assurance_results"]['disallowed'] for image in image_data)
    return gate_check_flag, image_data
