"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_unpacked_files' block
    filter_unpacked_files(container=container)

    return

@phantom.playbook_block()
def filter_unpacked_files(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_unpacked_files() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["unpacked", "in", "artifact:*.tags"]
        ],
        name="filter_unpacked_files:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        vt_detonate_file(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def vt_detonate_file(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("vt_detonate_file() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_artifact_0_data_filter_unpacked_files = phantom.collect2(container=container, datapath=["filtered-data:filter_unpacked_files:condition_1:artifact:*.cef.vaultId","filtered-data:filter_unpacked_files:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'vt_detonate_file' call
    for filtered_artifact_0_item_filter_unpacked_files in filtered_artifact_0_data_filter_unpacked_files:
        if filtered_artifact_0_item_filter_unpacked_files[0] is not None:
            parameters.append({
                "vault_id": filtered_artifact_0_item_filter_unpacked_files[0],
                "wait_time": 5,
                "context": {'artifact_id': filtered_artifact_0_item_filter_unpacked_files[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("detonate file", parameters=parameters, name="vt_detonate_file", assets=["virustotal"], callback=filter_get_right_artifact)

    return


@phantom.playbook_block()
def filter_get_right_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_get_right_artifact() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_unpacked_files:condition_1:artifact:*.cef.vaultId", "==", "vt_detonate_file:action_result.parameter.vault_id"]
        ],
        name="filter_get_right_artifact:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_tags(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def debug_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("debug_2() called")

    format_2 = phantom.get_format_data(name="format_2")

    parameters = []

    parameters.append({
        "input_1": format_2,
        "input_2": None,
        "input_3": None,
        "input_4": None,
        "input_5": None,
        "input_6": None,
        "input_7": None,
        "input_8": None,
        "input_9": None,
        "input_10": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_2")

    return


@phantom.playbook_block()
def update_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_artifact() called")

    filtered_artifact_0_data_filter_get_right_artifact = phantom.collect2(container=container, datapath=["filtered-data:filter_get_right_artifact:condition_1:artifact:*.id","filtered-data:filter_get_right_artifact:condition_1:artifact:*.id"])
    filtered_result_0_data_filter_get_right_artifact = phantom.collect2(container=container, datapath=["filtered-data:filter_get_right_artifact:condition_1:vt_detonate_file:action_result.summary.scan_id"])
    format_tags = phantom.get_format_data(name="format_tags")

    parameters = []

    # build parameters list for 'update_artifact' call
    for filtered_artifact_0_item_filter_get_right_artifact in filtered_artifact_0_data_filter_get_right_artifact:
        for filtered_result_0_item_filter_get_right_artifact in filtered_result_0_data_filter_get_right_artifact:
            parameters.append({
                "artifact_id": filtered_artifact_0_item_filter_get_right_artifact[0],
                "name": None,
                "label": None,
                "severity": None,
                "cef_field": "scan_id",
                "cef_value": filtered_result_0_item_filter_get_right_artifact[0],
                "cef_data_type": None,
                "tags": format_tags,
                "overwrite_tags": True,
                "input_json": None,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_update", parameters=parameters, name="update_artifact")

    return


@phantom.playbook_block()
def format_tags(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_tags() called")

    template = """{0}, pending_scan"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_get_right_artifact:condition_1:artifact:*.tags"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_tags")

    update_artifact(container=container)

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