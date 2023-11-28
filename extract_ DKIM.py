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

    dkim_parts = parse_dkim_signature(playbook_input_dkim_signatur_values)
    
    phantom.debug(f"dkim_parts: {dkim_parts}")
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="extract_dkim_signatur:dkim_json", value=json.dumps(extract_dkim_signatur__dkim_json))

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