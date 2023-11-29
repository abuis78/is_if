"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_url_prompt_artifact' block
    filter_url_prompt_artifact(container=container)

    return

@phantom.playbook_block()
def check_prompt_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("check_prompt_status() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_artifact_0_data_filter_url_prompt_artifact = phantom.collect2(container=container, datapath=["filtered-data:filter_url_prompt_artifact:condition_1:artifact:*.cef.prompt_id","filtered-data:filter_url_prompt_artifact:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'check_prompt_status' call
    for filtered_artifact_0_item_filter_url_prompt_artifact in filtered_artifact_0_data_filter_url_prompt_artifact:
        if filtered_artifact_0_item_filter_url_prompt_artifact[0] is not None:
            parameters.append({
                "id": filtered_artifact_0_item_filter_url_prompt_artifact[0],
                "context": {'artifact_id': filtered_artifact_0_item_filter_url_prompt_artifact[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("check status", parameters=parameters, name="check_prompt_status", assets=["urlprompt"], callback=decission_prompt)

    return


@phantom.playbook_block()
def filter_url_prompt_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_url_prompt_artifact() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "url prompt"]
        ],
        name="filter_url_prompt_artifact:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        check_prompt_status(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def decission_prompt(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decission_prompt() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["check_prompt_status:action_result.data.*.status", "==", "complete"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        filter_file_artifact_with_tag_pwd_protected(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    get_scheduler_artifact(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def filter_file_artifact_with_tag_pwd_protected(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_file_artifact_with_tag_pwd_protected() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["artifact:*.name", "==", "Vault Artifact"],
            ["pwd_protected", "in", "artifact:*.tags"]
        ],
        name="filter_file_artifact_with_tag_pwd_protected:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        unzip_file_pwd_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def playbook_detonate_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_detonate_file_1() called")

    inputs = {}

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "is_if/detonate_file", returns the playbook_run_id
    playbook_run_id = phantom.playbook("is_if/detonate_file", container=container, name="playbook_detonate_file_1", callback=playbook_detonate_file_1_callback, inputs=inputs)

    return


@phantom.playbook_block()
def playbook_detonate_file_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_detonate_file_1_callback() called")

    
    # Downstream End block cannot be called directly, since execution will call on_finish automatically.
    # Using placeholder callback function so child playbook is run synchronously.


    return


@phantom.playbook_block()
def get_scheduler_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_scheduler_artifact() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["artifact:*.name", "==", "scheduled playbook"],
            ["artifact:*.label", "==", "complete"]
        ],
        name="get_scheduler_artifact:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        artifact_update_4(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def artifact_update_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("artifact_update_4() called")

    filtered_artifact_0_data_get_scheduler_artifact = phantom.collect2(container=container, datapath=["filtered-data:get_scheduler_artifact:condition_1:artifact:*.id","filtered-data:get_scheduler_artifact:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'artifact_update_4' call
    for filtered_artifact_0_item_get_scheduler_artifact in filtered_artifact_0_data_get_scheduler_artifact:
        parameters.append({
            "name": None,
            "tags": None,
            "label": "pending",
            "severity": None,
            "cef_field": None,
            "cef_value": None,
            "input_json": None,
            "artifact_id": filtered_artifact_0_item_get_scheduler_artifact[0],
            "cef_data_type": None,
            "overwrite_tags": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_update", parameters=parameters, name="artifact_update_4")

    return


@phantom.playbook_block()
def unzip_file_pwd_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("unzip_file_pwd_1() called")

    id_value = container.get("id", None)
    label_value = container.get("label", None)
    filtered_artifact_0_data_filter_file_artifact_with_tag_pwd_protected = phantom.collect2(container=container, datapath=["filtered-data:filter_file_artifact_with_tag_pwd_protected:condition_1:artifact:*.id","filtered-data:filter_file_artifact_with_tag_pwd_protected:condition_1:artifact:*.id"])
    check_prompt_status_result_data = phantom.collect2(container=container, datapath=["check_prompt_status:action_result.data.0.response.password","check_prompt_status:action_result.parameter.context.artifact_id"], action_results=results)

    filtered_artifact_0__id = [item[0] for item in filtered_artifact_0_data_filter_file_artifact_with_tag_pwd_protected]

    parameters = []

    # build parameters list for 'unzip_file_pwd_1' call
    for check_prompt_status_result_item in check_prompt_status_result_data:
        parameters.append({
            "artifact_id": filtered_artifact_0__id,
            "container_id": id_value,
            "default_tag": "unpacked",
            "default_severity": "Low",
            "default_label": label_value,
            "pwd": check_prompt_status_result_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="is_if/unzip_file_pwd", parameters=parameters, name="unzip_file_pwd_1", callback=playbook_detonate_file_1)

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