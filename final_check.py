"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'code_1' block
    code_1(container=container)

    return

@phantom.playbook_block()
def code_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("code_1() called")

    id_value = container.get("id", None)

    code_1__count = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    # artifact?_filter_container=72293&_filter_name__icontains="Vault%20Artifact:"&_exclude_severity="low"

    
    u_filter = '?_filter_container='+ str(id_value) +'&_filter_name__icontains="Vault Artifact:"&_exclude_severity="low"'
    
    url = phantom.build_phantom_rest_url('indicator')
    url_filter = url + u_filter
    r = phantom.requests.get(url,verify=False)
    data = r.json()
    phantom.debug(data)
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="code_1:count", value=json.dumps(code_1__count))

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