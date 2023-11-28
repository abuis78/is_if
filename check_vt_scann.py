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

    phantom.act("get report", parameters=parameters, name="get_scann_report", assets=["virustotal"])

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