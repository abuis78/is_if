"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_artifacts_pending_scan' block
    filter_artifacts_pending_scan(container=container)

    return

@phantom.playbook_block()
def filter_artifacts_pending_scan(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_artifacts_pending_scan() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["pending_scan", "in", "artifact:*.tags"]
        ],
        name="filter_artifacts_pending_scan:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_scann_report(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def get_scann_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_scann_report() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_artifact_0_data_filter_artifacts_pending_scan = phantom.collect2(container=container, datapath=["filtered-data:filter_artifacts_pending_scan:condition_1:artifact:*.cef.scan_id","filtered-data:filter_artifacts_pending_scan:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'get_scann_report' call
    for filtered_artifact_0_item_filter_artifacts_pending_scan in filtered_artifact_0_data_filter_artifacts_pending_scan:
        if filtered_artifact_0_item_filter_artifacts_pending_scan[0] is not None:
            parameters.append({
                "scan_id": filtered_artifact_0_item_filter_artifacts_pending_scan[0],
                "wait_time": 1,
                "context": {'artifact_id': filtered_artifact_0_item_filter_artifacts_pending_scan[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get report", parameters=parameters, name="get_scann_report", assets=["virustotal"], callback=decision_1)

    return


@phantom.playbook_block()
def artifact_update_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("artifact_update_1() called")

    filtered_result_0_data_filter_status_success = phantom.collect2(container=container, datapath=["filtered-data:filter_status_success:condition_1:get_scann_report:action_result.parameter.context.artifact_id","filtered-data:filter_status_success:condition_1:get_scann_report:action_result.summary.malicious"])

    parameters = []

    # build parameters list for 'artifact_update_1' call
    for filtered_result_0_item_filter_status_success in filtered_result_0_data_filter_status_success:
        parameters.append({
            "artifact_id": filtered_result_0_item_filter_status_success[0],
            "name": None,
            "label": None,
            "severity": None,
            "cef_field": "vt_malicious",
            "cef_value": filtered_result_0_item_filter_status_success[1],
            "cef_data_type": None,
            "tags": " unpacked,scan_successful",
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

    phantom.custom_function(custom_function="community/artifact_update", parameters=parameters, name="artifact_update_1")

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["get_scann_report:action_result.status", "==", "success"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        filter_status_success(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def filter_status_success(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_status_success() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["get_scann_report:action_result.status", "==", "success"],
            ["filtered-data:filter_status_success:condition_1:get_scann_report:action_result.summary.malicious", ">", 0]
        ],
        name="filter_status_success:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        artifact_update_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["get_scann_report:action_result.status", "==", "success"],
            ["filtered-data:filter_status_success:condition_1:get_scann_report:action_result.summary.malicious", "<=", 0]
        ],
        name="filter_status_success:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        artifact_update_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def artifact_update_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("artifact_update_2() called")

    filtered_result_0_data_filter_status_success = phantom.collect2(container=container, datapath=["filtered-data:filter_status_success:condition_2:get_scann_report:action_result.parameter.context.artifact_id"])

    parameters = []

    # build parameters list for 'artifact_update_2' call
    for filtered_result_0_item_filter_status_success in filtered_result_0_data_filter_status_success:
        parameters.append({
            "artifact_id": filtered_result_0_item_filter_status_success[0],
            "name": None,
            "label": None,
            "severity": "low",
            "cef_field": "vt_malicious",
            "cef_value": 0,
            "cef_data_type": None,
            "tags": " unpacked,scan_successful",
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