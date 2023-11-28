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
        detonate_file_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("debug_1() called")

    filtered_artifact_0_data_filter_unpacked_files = phantom.collect2(container=container, datapath=["filtered-data:filter_unpacked_files:condition_1:artifact:*.id","filtered-data:filter_unpacked_files:condition_1:artifact:*.cef.vaultId","filtered-data:filter_unpacked_files:condition_1:artifact:*.id"])

    filtered_artifact_0__id = [item[0] for item in filtered_artifact_0_data_filter_unpacked_files]
    filtered_artifact_0__cef_vaultid = [item[1] for item in filtered_artifact_0_data_filter_unpacked_files]

    parameters = []

    parameters.append({
        "input_1": filtered_artifact_0__id,
        "input_2": filtered_artifact_0__cef_vaultid,
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

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_1")

    return


@phantom.playbook_block()
def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("file_reputation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.fileHashSha256","artifact:*.id"])

    parameters = []

    # build parameters list for 'file_reputation_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "hash": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("file reputation", parameters=parameters, name="file_reputation_1", assets=["virustotal"])

    return


@phantom.playbook_block()
def detonate_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("detonate_file_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_artifact_0_data_filter_unpacked_files = phantom.collect2(container=container, datapath=["filtered-data:filter_unpacked_files:condition_1:artifact:*.cef.vaultId","filtered-data:filter_unpacked_files:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'detonate_file_1' call
    for filtered_artifact_0_item_filter_unpacked_files in filtered_artifact_0_data_filter_unpacked_files:
        if filtered_artifact_0_item_filter_unpacked_files[0] is not None:
            parameters.append({
                "vault_id": filtered_artifact_0_item_filter_unpacked_files[0],
                "wait_time": "",
                "context": {'artifact_id': filtered_artifact_0_item_filter_unpacked_files[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("detonate file", parameters=parameters, name="detonate_file_1", assets=["virustotal"])

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