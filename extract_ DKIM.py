"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'extract_dkim_signatur' block
    extract_dkim_signatur(container=container)

    return

@phantom.playbook_block()
def extract_dkim_signatur(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("extract_dkim_signatur() called")

    playbook_input_dkim_signatur = phantom.collect2(container=container, datapath=["playbook_input:dkim_signatur"])

    playbook_input_dkim_signatur_values = [item[0] for item in playbook_input_dkim_signatur]

    extract_dkim_signatur__dkim_json = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    def parse_dkim_signature(dkim_signature):
        # Zerlegt die DKIM-Signatur und speichert die Elemente in einem Dictionary
        dkim_parts = {}
        for part in dkim_signature.split("; "):
            if "=" in part:
                key, value = part.split("=", 1)
                dkim_parts[key.strip()] = value.strip()
        return dkim_parts

    dkim_parts = parse_dkim_signature(playbook_input_dkim_signatur_values[0])
    
    phantom.debug(f"dkim_parts: {dkim_parts}")
    
    cef_json = {}
    
    for key, value in dkim_parts.items():
        cef_json[f"{key}"] = f"{value}"
        #phantom.debug(f"{key}: {value}")
        
    phantom.debug(cef_json)
    extract_dkim_signatur__dkim_json = cef_json
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="extract_dkim_signatur:dkim_json", value=json.dumps(extract_dkim_signatur__dkim_json))

    format_json_for_create_artifact(container=container)

    return


@phantom.playbook_block()
def format_json_for_create_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_json_for_create_artifact() called")

    template = """{{ \"cef\": {{ {0} }} }}"""

    # parameter list for template variable replacement
    parameters = [
        "extract_dkim_signatur:custom_function:dkim_json"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_json_for_create_artifact")

    artifact_create_1(container=container)

    return


@phantom.playbook_block()
def artifact_create_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("artifact_create_1() called")

    id_value = container.get("id", None)
    format_json_for_create_artifact = phantom.get_format_data(name="format_json_for_create_artifact")

    parameters = []

    parameters.append({
        "container": id_value,
        "name": "DKIM-Signatur",
        "label": None,
        "severity": None,
        "cef_field": None,
        "cef_value": None,
        "cef_data_type": None,
        "tags": None,
        "run_automation": None,
        "input_json": format_json_for_create_artifact,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_create", parameters=parameters, name="artifact_create_1")

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