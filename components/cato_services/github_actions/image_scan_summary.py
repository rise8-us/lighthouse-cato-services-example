from datetime import datetime, timedelta

SUMMARY_TEMPLATE = """
# Aqua Gate Check Summary
**Lighthouse Policy:**
Must remediate vulnerabilities designated as Low or higher severity in order to comply with the cATO policy.

---
<for images>
### **Image: [{{ formatted_image }}]({{ url }})**

*Note: Hyperlink can only be accessed if you are on Citrix or utilizing GFE.*

<if {{ has_no_vulnerabilities }}>
### **No new vulnerabilities or suppressed vulnerabilities need your attention at this time**
</if {{ has_no_vulnerabilities }}>

<if {{ has_vulnerabilities }}>
<if {{ has_non-remediated_vulnerabilities }}>
### **Non-Remediated Vulnerabilities**
*Note: More vulnerabilities may exist in Aqua that have not yet been remedied and acknowledged. The following vulnerabilities have fix versions available and have not yet been acknowledged.*
|Severity|Remediation|Fix Version|Resource Path|Description|Vulnerability Name|
|--------|-----------|-----------|-------------|-----------|------------------|<for {{ vulnerabilities }}>
|{{ severity }}|{{ remediation }}|{{ fix_version }}|{{ resource_path }}|{{ description }}|{{ vulnerability_name }}|</for {{ vulnerabilities }}>
</if {{ has_non-remediated_vulnerabilities }}>
<if {{ has_no_non-remediated_vulnerabilities }}>
*No vulnerabilities with a known fix or no vulnerabilities exist*
</if {{ has_no_non-remediated_vulnerabilities }}>
<if {{ has_suppressed_vulnerabilities }}>
### **Expiring Suppressed Vulnerabilities**
*Note: Suppressed vulnerabilities that expire in the next 31 days and have fix versions available are shown below. More suppressed vulnerabilities may exist in Aqua*
|Severity|Expiration|Who Last Suppressed|Reason for Suppression|Remediation|Fix Version|Resource Path|
|--------|----------|-------------------|----------------------|-----------|-----------|-------------|<for {{ suppressed_vulnerabilities }}>
|{{ severity }}|{{ expiration }}|{{ who_last_suppressed }}|{{ reason_for_suppression }}|{{ remediation }}|{{ fix_version }}|{{ resource_path }}|</for {{ suppressed_vulnerabilities }}>
</if {{ has_suppressed_vulnerabilities }}>
<if {{ has_no_suppressed_vulnerabilities }}>
*No suppressed vulnerabilities need your attention at this time*
</if {{ has_no_suppressed_vulnerabilities }}>
</if {{ has_vulnerabilities }}>

<if {{ failed_aqua_policy }}>
The following Aqua policies failed:
<for {{ assurance_results }}>
Control `{{ control }}` from policy {{ policy }}</for {{ assurance_results }}>
</if {{ failed_aqua_policy }}>
</for images>
---

"""

def image_data_to_template_params(image_data, registry):
    """Convert image data into parameters for the Aqua Gate Check Summary template."""
    vulnerability_params = {
        f"vs-in-{image['name']}": [
            {
                "severity": vuln['aqua_severity'].capitalize(),
                "remediation": vuln['solution'],
                "fix_version": vuln['fix_version'],
                "resource_path": vuln['resource']['path'],
                "description": vuln['description'].replace("\n", " ").replace("\r", " "),
                "vulnerability_name": vuln['name']
            }
            for vuln in image["vulnerabilities"]
        ]
        for image in image_data
    }

    suppressed_vulnerability_params = {
        f"ss-in-{image['name']}": [
            {
                "severity": vuln['aqua_severity'].capitalize(),
                "expiration": f"in {vuln.get('ack_expiration_days')} days on {vuln.get('ack_expiration_date')}",
                "who_last_suppressed": vuln['ack_author'],
                "reason_for_suppression": vuln.get('ack_comment').replace("\n", " ").replace("\r", " ") if vuln.get('ack_comment') is not None else "",
                "remediation": vuln['solution'],
                "fix_version": vuln['fix_version'],
                "resource_path": vuln['resource']['path']
            }
            for vuln in image["suppressed_vulnerabilities"]
        ]
        for image in image_data
    }

    assurance_results_params = {
        f"assurance_results-in-{image['name']}": [
            {
                "control": control['control'],
                "policy": control['policy_name']
            }
            for control in image["assurance_results"]["checks_performed"]
            if control['failed'] and control['blocking']
        ]
        for image in image_data
    }

    top_level_params = {
        "images": [
            {
                "formatted_image": aqua.format_image_name(image["name"]),
                "url": aqua.get_aqua_ui_url(image, registry, AQUA_URL),
                "has_suppressed_vulnerabilities": bool(image["suppressed_vulnerabilities"]),
                "has_non-remediated_vulnerabilities": bool(image["vulnerabilities"]),
                "has_vulnerabilities": bool(image["vulnerabilities"]) or bool(image["suppressed_vulnerabilities"]),
                "has_no_vulnerabilities": not (bool(image["vulnerabilities"]) and bool(image["suppressed_vulnerabilities"])),
                "has_no_non-remediated_vulnerabilities": not bool(image["vulnerabilities"]),
                "has_no_suppressed_vulnerabilities": not bool(image["suppressed_vulnerabilities"]),
                "failed_aqua_policy": image["assurance_results"]["disallowed"],
                "vulnerabilities": f'vs-in-{image["name"]}',
                "suppressed_vulnerabilities": f'ss-in-{image["name"]}',
                "assurance_results": f'assurance_results-in-{image["name"]}',
            }
            for image in image_data
        ]
    }

    return top_level_params | vulnerability_params | suppressed_vulnerability_params | assurance_results_params

def format_suppression_expiration_date(suppression):
    expiry_date = datetime.fromisoformat(suppression["expiration_configured_at"]) + timedelta(days=suppression["expiration_days"])
    return f"{expiry_date.month}/{expiry_date.day}/{expiry_date.year}"