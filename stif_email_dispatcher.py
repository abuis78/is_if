"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_check_if_artifact_name_is_vault_artifact' block
    filter_check_if_artifact_name_is_vault_artifact(container=container)

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
            ["checks_zip_or_tar_file_id_password_protected:custom_function_result.data.protected_status", "==", "yew"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        artifact_update_2(action=action, success=success, container=container, results=results, handle=handle)
        return

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

    phantom.custom_function(custom_function="community/artifact_update", parameters=parameters, name="artifact_update_2")

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