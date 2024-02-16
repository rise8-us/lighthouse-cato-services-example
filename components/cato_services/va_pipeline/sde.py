import sys
import os
import json
from datetime import datetime, timezone
from cato_services.util import utils

SDE_URL = os.environ['SDE_URL']
SDE_TOKEN = os.environ['SDE_TOKEN']
CA_CERTS = os.environ['CA_CERTS']
CRM_DATA = json.loads(os.environ['CRM_DATA'])
BUILD_URL = os.environ['BUILD_URL']
sde_client_config = sde.get_sde_client_config(SDE_URL, SDE_TOKEN, CA_CERTS)

SDE_SUMMARY_TEMPLATE = """
- How do I resolve this gate check failure?
    <p>Each countermeasure must have a status of Complete, Inherited or Not Applicable, 
    and also include a verification status of <b>Pass</b> or <b>Partial Pass</b> from your App Assessor.</p>
- To do this, leverage either Citrix or GFE to access your [SD Elements Project]({{ url }}) directly, or via your backlog tool (eg Jira) if your team has integrated with SD Elements to address any outstanding Countermeasures. 
If you would like to implement an integration between your backlog and SD Elements, contact your App Assessor for assistance.



## SDE Countermeasures Summary for project: {{ project }}
|SD Elements Attribute|Value|
| --- | --- |
|Current Project Risk Policy| {{ risk_policy }} |<if {{ has_expiration }}>
|Risk Policy Start Date| {{ policy_start_date }} |
|Risk Policy Expiration Date| {{ policy_expiration_date }} |
|Days until SDE gate check fails without 100% compliance| {{ days_until_gate_check_failure }} |</if {{ has_expiration }}>
|Gate Check Percentage Completion| {{ gate_check_percent_complete }}% |
|Total Project Countermeasures| {{ total_count }} |
|Incomplete Countermeasures| {{ incomplete_count }} |
|In progress Countermeasures| {{ in_progress_count }} |
|Countermeasures Completed by App Team| {{ done_count }} |
|Countermeasures Missing App Assessor Verification| {{ missing_verification_count }} |
"""

EXPIRATION_LOG_MESSAGE_TEMPLATE = """
cATO Policy warning, your pipeline will become blocked in {{ expiration_days }} days on {{ expiration_date }},
if your SDE Project Compliance is not at 100%.
To avoid this, please ensure all SDE countermeasures that are applicable to your current risk policy have been completed by your team,
and verified by your teams App Assessor. For details on your teams progress, you can either view the SDE gate check summary table at {{ build_url }}, then scroll down and expand the SDE gate check summary table., log in to SD Elements and view your project summary page,
or reach out to your App Assessor to confirm remaining scope.
"""

def get_gate_check_summary_table(project, policy, countermeasure_data, expiration_data={}):
    """Return a gate check summary based on project, policy, and countermeasure data."""
    gate_check_percent_complete = 100 * float(countermeasure_data['done']) / float(countermeasure_data['total'])
    summary = utils.build_string_from_template(
        SDE_SUMMARY_TEMPLATE,
        {
            "url": project['url'],
            "project": project['name'],
            "risk_policy": policy['name'],
            "has_expiration": expiration_data != {},
            "policy_start_date": expiration_data.get('policy_start_date'),
            "policy_expiration_date": expiration_data.get('policy_expiration_date'),
            "days_until_gate_check_failure": expiration_data.get('days_until_gate_check_failure'),
            "gate_check_percent_complete": str(f"{gate_check_percent_complete:.2f}"),
            "total_count": str(countermeasure_data['total']),
            "incomplete_count": str(countermeasure_data['incomplete']),
            "in_progress_count": str(countermeasure_data['in_progress']),
            "done_count": str(countermeasure_data['done']),
            "missing_verification_count": str(countermeasure_data['missing_verification'])
        }
    )

    return summary

def write_summary(summary):
    output_file_path = os.getenv("GITHUB_STEP_SUMMARY")

    with open(output_file_path, 'w', encoding='utf8') as file:
        file.write(summary)

def gate_check(app_id):
    project, policy, countermeasure_summary = get_sde_data(app_id)
    summary, error_code = get_summary_and_error_code(project, policy, countermeasure_summary)
    write_summary(summary)
    sys.exit(error_code)

def get_summary_and_error_code(project, policy, cm_summary):
    error_code = 0
    expiration_data = {}
    if project['risk_policy_compliant']:
        return get_gate_check_summary_table(project, policy, cm_summary, expiration_data), 0
    if policy['name'] == 'Highest Risk Requirements Only':
        utils.write_annotation(f"SD Elements gate check failed. Please access the workflow summary from this latest run at {BUILD_URL}, then scroll down and expand the SDE gate check summary table.")
        return get_gate_check_summary_table(project, policy, cm_summary, expiration_data), 99
    if not policy["name"] == "Requirements Round 2" and not policy["name"] == "Requirements Round 3":
        return get_gate_check_summary_table(project, policy, cm_summary, expiration_data), 0

    # In the edge case where you have a round 2 or 3, but they haven't had their CRM updated with expiration dates yet, send them a table without that info.
    if policy['name'] == 'Requirements Round 2' and CRM_DATA.get("sde-round-2-expiration-date") is None:
        return get_gate_check_summary_table(project, policy, cm_summary, expiration_data), 0
    if policy['name'] == 'Requirements Round 3' and CRM_DATA.get("sde-round-3-expiration-date") is None:
        return get_gate_check_summary_table(project, policy, cm_summary, expiration_data), 0

    if policy['name'] == 'Requirements Round 2':
        policy_expiration_date = datetime.fromisoformat(CRM_DATA["sde-round-2-expiration-date"])
        policy_start_date = datetime.fromisoformat(CRM_DATA["sde-round-2-start-date"])
    else:
        policy_expiration_date = datetime.fromisoformat(CRM_DATA["sde-round-3-expiration-date"])
        policy_start_date = datetime.fromisoformat(CRM_DATA["sde-round-3-start-date"])

    now = datetime.now(timezone.utc)
    policy_expiration_date.strftime("%m/%d/%y")
    is_within_policy_expiration_date = now < policy_expiration_date
    time_until_expiration = policy_expiration_date - now
    if is_within_policy_expiration_date:
        expiration_data =  {"policy_start_date": policy_start_date.strftime("%m/%d/%y"),
                            "policy_expiration_date": policy_expiration_date.strftime("%m/%d/%y"),
                            "days_until_gate_check_failure": time_until_expiration.days}
        warning_message = utils.build_string_from_template(
            EXPIRATION_LOG_MESSAGE_TEMPLATE,
            {"expiration_days": time_until_expiration.days,
              "expiration_date": policy_expiration_date.strftime("%m/%d/%y"),
              "build_url": BUILD_URL})
        utils.write_annotation(warning_message, "warning")
    else:
        expiration_data = {"policy_start_date": policy_start_date.strftime("%m/%d/%y"),
                            "policy_expiration_date": policy_expiration_date.strftime("%m/%d/%y"),
                            "days_until_gate_check_failure": "your risk policy has expired!"}
        utils.write_annotation(f"SD Elements gate check failed. Please access the workflow summary from this latest run at {BUILD_URL}, then scroll down and expand the SDE gate check summary table.")
        error_code = 99
    summary = get_gate_check_summary_table(project, policy, cm_summary, expiration_data)
    return summary, error_code

def get_sde_data(app_id):
    projects = sde.get_projects_by_app_id(sde_client_config, app_id, '-created')
    if len(projects) == 0:
        utils.print_and_exit(f"No project was found in SD Elements associated with app id: {app_id}", 150)
    project = projects[0]
    if not project["survey_complete"]:
        utils.print_and_exit(f"SD Elements project survey for Project {project['name']} is listed as incomplete. Please reach out to your App Assessor teammate and complete your survey together, and then this failure will be mitigated.", 151)
    policy = sde.get_policy_by_id(sde_client_config, project['risk_policy'])
    countermeasures = sde.get_countermeasures(sde_client_config, project['id'])
    cm_summary = sde.get_countermeasure_summary(countermeasures)
    return project, policy, cm_summary


if __name__ == "__main__":
    gate_check(sys.argv[1])
