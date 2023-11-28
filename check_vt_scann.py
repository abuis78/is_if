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

    filtered_result_0_data_filter_status_success = phantom.collect2(container=container, datapath=["filtered-data:filter_status_success:condition_1:get_scann_report:action_result.summary.malicious","filtered-data:filter_status_success:condition_1:get_scann_report:action_result.parameter.context.artifact_id"])
    calculate_the_severity__new_severity = json.loads(_ if (_ := phantom.get_run_data(key="calculate_the_severity:new_severity")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    # build parameters list for 'artifact_update_1' call
    for filtered_result_0_item_filter_status_success in filtered_result_0_data_filter_status_success:
        parameters.append({
            "name": None,
            "tags": " unpacked,scan_successful",
            "label": None,
            "severity": calculate_the_severity__new_severity,
            "cef_field": "vt_malicious",
            "cef_value": filtered_result_0_item_filter_status_success[0],
            "input_json": None,
            "artifact_id": filtered_result_0_item_filter_status_success[1],
            "cef_data_type": None,
            "overwrite_tags": True,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_update", parameters=parameters, name="artifact_update_1", callback=join_noop_4)

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

    # check for 'else' condition 2
    filter_failed_scann(action=action, success=success, container=container, results=results, handle=handle)

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
            ["get_scann_report:action_result.summary.malicious", ">", 0]
        ],
        name="filter_status_success:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        calculate_the_severity(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["get_scann_report:action_result.status", "==", "success"],
            ["get_scann_report:action_result.summary.malicious", "<=", 0]
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
            "name": None,
            "tags": " unpacked,scan_successful",
            "label": None,
            "severity": "low",
            "cef_field": "vt_malicious",
            "cef_value": "no hit",
            "input_json": None,
            "artifact_id": filtered_result_0_item_filter_status_success[0],
            "cef_data_type": None,
            "overwrite_tags": True,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_update", parameters=parameters, name="artifact_update_2", callback=join_noop_4)

    return


@phantom.playbook_block()
def filter_failed_scann(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_failed_scann() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "scheduled playbook"]
        ],
        name="filter_failed_scann:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        artifact_update_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def artifact_update_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("artifact_update_3() called")

    filtered_artifact_0_data_filter_artifacts_pending_scan = phantom.collect2(container=container, datapath=["filtered-data:filter_artifacts_pending_scan:condition_1:artifact:*.id","filtered-data:filter_artifacts_pending_scan:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'artifact_update_3' call
    for filtered_artifact_0_item_filter_artifacts_pending_scan in filtered_artifact_0_data_filter_artifacts_pending_scan:
        parameters.append({
            "name": None,
            "tags": None,
            "label": "pending",
            "severity": None,
            "cef_field": None,
            "cef_value": None,
            "input_json": None,
            "artifact_id": filtered_artifact_0_item_filter_artifacts_pending_scan[0],
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

    phantom.custom_function(custom_function="community/artifact_update", parameters=parameters, name="artifact_update_3")

    return


@phantom.playbook_block()
def calculate_the_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("calculate_the_severity() called")

    filtered_result_0_data_filter_status_success = phantom.collect2(container=container, datapath=["filtered-data:filter_status_success:condition_1:get_scann_report:action_result.summary.malicious"])

    filtered_result_0_summary_malicious = [item[0] for item in filtered_result_0_data_filter_status_success]

    calculate_the_severity__new_severity = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug(filtered_result_0_summary_malicious[0])
    x = filtered_result_0_summary_malicious[0]
    # Überprüfen, ob x > 1 und <= 20
    if 1 < x <= 20:
        phantom.debug("x ist größer als 1 und kleiner oder gleich 20.")
        calculate_the_severity__new_severity = 'medium'
    # Überprüfen, ob x > 20 und < 50
    elif 20 < x < 50:
        phantom.debug("x ist über 20 und unter 50.")
        calculate_the_severity__new_severity = 'high'
    # Überprüfen, ob x >= 50
    elif x >= 50:
        phantom.debug("x ist 50 oder mehr.")
        calculate_the_severity__new_severity = 'critical'
    else:
        phantom.debug("x erfüllt keine der Bedingungen.")
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="calculate_the_severity:new_severity", value=json.dumps(calculate_the_severity__new_severity))

    artifact_update_1(container=container)

    return


@phantom.playbook_block()
def join_noop_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_noop_4() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_noop_4_called"):
        return

    # save the state that the joined function has now been called
    phantom.save_run_data(key="join_noop_4_called", value="noop_4")

    # call connected block "noop_4"
    noop_4(container=container, handle=handle)

    return


@phantom.playbook_block()
def noop_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("noop_4() called")

    parameters = [{}]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="DB_POC_final/noop", parameters=parameters, name="noop_4", callback=playbook_final_check_1)

    return


@phantom.playbook_block()
def playbook_final_check_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_final_check_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "is_if/final_check", returns the playbook_run_id
    playbook_run_id = phantom.playbook("is_if/final_check", container=container, name="playbook_final_check_1", callback=playbook_final_check_1_callback)

    return


@phantom.playbook_block()
def playbook_final_check_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_final_check_1_callback() called")

    
    # Downstream End block cannot be called directly, since execution will call on_finish automatically.
    # Using placeholder callback function so child playbook is run synchronously.


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