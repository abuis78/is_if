"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_email_artifact' block
    filter_email_artifact(container=container)

    return

@phantom.playbook_block()
def filter_check_if_artifact_name_is_vault_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_check_if_artifact_name_is_vault_artifact() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "Vault Artifact"]
        ],
        name="filter_check_if_artifact_name_is_vault_artifact:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        checks_zip_or_tar_file_id_password_protected(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def checks_zip_or_tar_file_id_password_protected(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("checks_zip_or_tar_file_id_password_protected() called")

    id_value = container.get("id", None)
    filtered_artifact_0_data_filter_check_if_artifact_name_is_vault_artifact = phantom.collect2(container=container, datapath=["filtered-data:filter_check_if_artifact_name_is_vault_artifact:condition_1:artifact:*.cef.vaultId","filtered-data:filter_check_if_artifact_name_is_vault_artifact:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'checks_zip_or_tar_file_id_password_protected' call
    for filtered_artifact_0_item_filter_check_if_artifact_name_is_vault_artifact in filtered_artifact_0_data_filter_check_if_artifact_name_is_vault_artifact:
        parameters.append({
            "vault_id": filtered_artifact_0_item_filter_check_if_artifact_name_is_vault_artifact[0],
            "container_id": id_value,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="dev/check_if_is_password_protected", parameters=parameters, name="checks_zip_or_tar_file_id_password_protected", callback=decision_1)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["checks_zip_or_tar_file_id_password_protected:custom_function_result.data.protected_status", "==", "yes"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        artifact_update_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    format_email_body_ohne_passwort(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def artifact_update_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("artifact_update_2() called")

    filtered_artifact_0_data_filter_check_if_artifact_name_is_vault_artifact = phantom.collect2(container=container, datapath=["filtered-data:filter_check_if_artifact_name_is_vault_artifact:condition_1:artifact:*.id","filtered-data:filter_check_if_artifact_name_is_vault_artifact:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'artifact_update_2' call
    for filtered_artifact_0_item_filter_check_if_artifact_name_is_vault_artifact in filtered_artifact_0_data_filter_check_if_artifact_name_is_vault_artifact:
        parameters.append({
            "artifact_id": filtered_artifact_0_item_filter_check_if_artifact_name_is_vault_artifact[0],
            "name": None,
            "label": None,
            "severity": None,
            "cef_field": None,
            "cef_value": None,
            "cef_data_type": None,
            "tags": "pwd_protected",
            "overwrite_tags": None,
            "input_json": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_update", parameters=parameters, name="artifact_update_2", callback=format_json_schema)

    return


@phantom.playbook_block()
def format_email_body_ohne_passwort(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_email_body_ohne_passwort() called")

    template = """Hallo,\n\nwir möchten Sie darüber informieren, dass wir eine E-Mail mit einem potenziell verdächtigen Anhang zurückgehalten haben. Es handelt sich um die folgende Datei:\n\nDatei Name: {0}\n\nDer Absender der E-Mail mit dem potenziell verdächtigen Anhang, der an Sie adressiert war, lautet wie folgt:\n\nE-Mail: {1}\n\nFalls Ihnen weitere verdächtige Aktivitäten auffallen sollten, zögern Sie bitte nicht, uns zu kontaktieren. Nach Überprüfung des Inhalts werden wir Sie über die nächsten Schritte informieren.\n\nVielen Dank für Ihre Aufmerksamkeit.\n\nMit freundlichen Grüßen\nIT-Security\n\n\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_check_if_artifact_name_is_vault_artifact:condition_1:artifact:*.cef.fileName",
        "exctract_email_fromemail:custom_function_result.data.*.email_address"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_email_body_ohne_passwort")

    email_subject_no_action(container=container)

    return


@phantom.playbook_block()
def filter_email_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_email_artifact() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "Email Artifact"]
        ],
        name="filter_email_artifact:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        exctract_email_fromemail(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def exctract_email_fromemail(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("exctract_email_fromemail() called")

    filtered_artifact_0_data_filter_email_artifact = phantom.collect2(container=container, datapath=["filtered-data:filter_email_artifact:condition_1:artifact:*.cef.fromEmail","filtered-data:filter_email_artifact:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'exctract_email_fromemail' call
    for filtered_artifact_0_item_filter_email_artifact in filtered_artifact_0_data_filter_email_artifact:
        parameters.append({
            "input_string": filtered_artifact_0_item_filter_email_artifact[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/regex_extract_email", parameters=parameters, name="exctract_email_fromemail", callback=extract_email_toemail)

    return


@phantom.playbook_block()
def format_email_body_mit_passwort(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_email_body_mit_passwort() called")

    template = """Hallo,\n\nwir möchten Sie darüber informieren, dass wir eine E-Mail mit einem potenziell verdächtigen Anhang zurückgehalten haben. Es handelt sich um die folgende Datei:\n\nDatei Name: {0}\n\nBei der ersten Überprüfung wurde festgestellt, dass der Anhang passwortgeschützt ist. Um eine gründliche Prüfung durchführen zu können, bitten wir Sie, uns das Passwort mitzuteilen. Bitte verwenden Sie dafür das sichere Formular, welches Sie über den nachstehenden Link erreichen können.\n\nLink: {2}\n\nDer Absender der E-Mail mit dem potenziell verdächtigen Anhang, der an Sie adressiert war, lautet wie folgt:\n\nE-Mail: {1}\n\nFalls Ihnen weitere verdächtige Aktivitäten auffallen sollten, zögern Sie bitte nicht, uns zu kontaktieren. Nach Überprüfung des Inhalts werden wir Sie über die nächsten Schritte informieren.\n\nVielen Dank für Ihre Aufmerksamkeit.\n\nMit freundlichen Grüßen\nIT-Security\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_check_if_artifact_name_is_vault_artifact:condition_1:artifact:*.cef.fileName",
        "exctract_email_fromemail:custom_function_result.data.*.email_address",
        "create_magic_link:action_result.data.*.web_url"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_email_body_mit_passwort")

    email_subject_action_needed(container=container)

    return


@phantom.playbook_block()
def format_json_schema(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_json_schema() called")

    template = """{\n    \"schema\": {\n        \"title\": \"Archie Passwort\",\n        \"description\": \"\",\n        \"type\": \"object\",\n        \"required\": [\"password\"],\n        \"properties\": {\n            \"password\": {\"type\": \"integer\", \"title\": \"password\", \"minumum\": 0, \"maximum\": 10}\n        }\n    }\n}"""

    # parameter list for template variable replacement
    parameters = []

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_json_schema")

    create_magic_link(container=container)

    return


@phantom.playbook_block()
def create_magic_link(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("create_magic_link() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_json_schema = phantom.get_format_data(name="format_json_schema")

    parameters = []

    if format_json_schema is not None:
        parameters.append({
            "schema": format_json_schema,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("create json prompt", parameters=parameters, name="create_magic_link", assets=["urlprompt"], callback=format_email_body_mit_passwort)

    return


@phantom.playbook_block()
def extract_email_toemail(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("extract_email_toemail() called")

    filtered_artifact_0_data_filter_email_artifact = phantom.collect2(container=container, datapath=["filtered-data:filter_email_artifact:condition_1:artifact:*.cef.toEmail","filtered-data:filter_email_artifact:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'extract_email_toemail' call
    for filtered_artifact_0_item_filter_email_artifact in filtered_artifact_0_data_filter_email_artifact:
        parameters.append({
            "input_string": filtered_artifact_0_item_filter_email_artifact[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/regex_extract_email", parameters=parameters, name="extract_email_toemail", callback=filter_check_if_artifact_name_is_vault_artifact)

    return


@phantom.playbook_block()
def email_subject_no_action(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("email_subject_no_action() called")

    template = """[{0}] - Aktuelle Überprüfung Ihres E-Mail-Anhangs – Status information"""

    # parameter list for template variable replacement
    parameters = [
        "container:id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="email_subject_no_action")

    playbook_send_email_2(container=container)

    return


@phantom.playbook_block()
def email_subject_action_needed(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("email_subject_action_needed() called")

    template = """[{0}] - Aktuelle Überprüfung Ihres E-Mail-Anhangs – Ihre Mitwirkung ist gefragt\n"""

    # parameter list for template variable replacement
    parameters = [
        "container:id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="email_subject_action_needed")

    playbook_send_email_1(container=container)

    return


@phantom.playbook_block()
def playbook_send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_send_email_1() called")

    exctract_email_fromemail_data = phantom.collect2(container=container, datapath=["exctract_email_fromemail:custom_function_result.data.*.email_address"])
    format_email_body_mit_passwort = phantom.get_format_data(name="format_email_body_mit_passwort")
    email_subject_action_needed = phantom.get_format_data(name="email_subject_action_needed")

    exctract_email_fromemail_data___email_address = [item[0] for item in exctract_email_fromemail_data]

    inputs = {
        "email_body": format_email_body_mit_passwort,
        "email_subject": email_subject_action_needed,
        "email_recipient": exctract_email_fromemail_data___email_address,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "is_if/send_email", returns the playbook_run_id
    playbook_run_id = phantom.playbook("is_if/send_email", container=container, name="playbook_send_email_1", inputs=inputs)

    return


@phantom.playbook_block()
def playbook_send_email_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_send_email_2() called")

    exctract_email_fromemail_data = phantom.collect2(container=container, datapath=["exctract_email_fromemail:custom_function_result.data.*.email_address"])
    format_email_body_ohne_passwort = phantom.get_format_data(name="format_email_body_ohne_passwort")
    email_subject_no_action = phantom.get_format_data(name="email_subject_no_action")

    exctract_email_fromemail_data___email_address = [item[0] for item in exctract_email_fromemail_data]

    inputs = {
        "email_body": format_email_body_ohne_passwort,
        "email_subject": email_subject_no_action,
        "email_recipient": exctract_email_fromemail_data___email_address,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "is_if/send_email", returns the playbook_run_id
    playbook_run_id = phantom.playbook("is_if/send_email", container=container, name="playbook_send_email_2", inputs=inputs)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return