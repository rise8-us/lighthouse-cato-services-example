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

def sort_image_vulnerabilities_by_suppressed(image: Image, image_vulnerabilities: List[Vulnerability], suppressions: List[Suppression]):
    if not image_vulnerabilities:
        return [], []
    image_suppressions = filter_suppressions_by_image(image, suppressions)
    unsuppressed_vulns, suppressed_vulns =  zip(*(find_suppression_for_vulnerability(v, image_suppressions) for v in image_vulnerabilities))
    return trim_none(unsuppressed_vulns), trim_none(suppressed_vulns)

def get_aqua_data(image_scanner: ImageScanner, image: Image):
    fixable_image_vulnerabilities = image_scanner.get_all_vulnerabilities(image)
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
