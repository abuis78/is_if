"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'count_severity' block
    count_severity(container=container)

    return

@phantom.playbook_block()
def count_severity(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("count_severity() called")

    count_severity__count = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    # artifact?_filter_container=72293&_filter_name__icontains="Vault%20Artifact:"&_exclude_severity="low"
    c_id = container['id']    
    
    u_filter = '?_filter_container="'+ str(c_id) +'"&_filter_name__icontains="Vault Artifact:"&_exclude_severity="low"'
    phantom.debug(u_filter)
    
    url = phantom.build_phantom_rest_url('artifact')
    url_filter = url + u_filter
    r = phantom.requests.get(url_filter,verify=False)
    data = r.json()
    phantom.debug(data["count"])
    code_1__count = data["count"]
    
    if data["count"] == 0:
        count_severity__count = "no"
    else:
        count_severity__count = "yes"
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="count_severity:count", value=json.dumps(count_severity__count))

    decision_1(container=container)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["count_severity:custom_function:count", "==", "yes"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        set_severity_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    format_email_subject(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def set_severity_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_severity_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_severity(container=container, severity="high")

    container = phantom.get_container(container.get('id', None))

    promote_to_case_2(container=container)

    return


@phantom.playbook_block()
def format_email_subject(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_email_subject() called")

    template = """[{0}] - [Entwarnung] Überprüfter E-Mail-Anhang – Keine Gefahr Identifiziert\n"""

    # parameter list for template variable replacement
    parameters = [
        "container:id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_email_subject")

    filter_scan_successful(container=container)

    return


@phantom.playbook_block()
def format_email_body(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_email_body() called")

    template = """Sehr geehrte Damen und Herren,\n\nich hoffe, diese Nachricht erreicht Sie wohlbehalten. Ich möchte Sie darüber informieren, dass der kürzlich gemeldete E-Mail-Anhang eingehend untersucht wurde. Insbesondere handelt es sich um die folgenden Dateien:\n\n%%\n{0}\n%%\n\nNach einer gründlichen Analyse durch unser IT-Sicherheitsteam können wir bestätigen, dass beide Anhänge sicher sind und keine schädlichen Inhalte oder Software enthalten.\n\nWir verstehen, dass solche Vorfälle Anlass zur Besorgnis geben können, und möchten Ihnen versichern, dass die Sicherheit unserer Systeme und Daten höchste Priorität hat. Dank Ihrer schnellen Meldung konnten wir umgehend reagieren und sicherstellen, dass keine Gefahr besteht.\n\nZusätzlich möchten wir einige Tipps mit Ihnen teilen, um zukünftig ähnliche Situationen zu vermeiden:\n\nSeien Sie vorsichtig bei unerwarteten Anhängen: Auch wenn dieser Anhang sicher war, empfehlen wir, bei Anhängen aus unbekannten Quellen stets vorsichtig zu sein.\n\nAktualisieren Sie regelmäßig Ihre Antivirensoftware: Eine aktuelle Antivirensoftware kann viele Bedrohungen frühzeitig erkennen und abwehren.\n\nSchulungen zur Cybersicherheit: Wir bieten regelmäßig Schulungen an, um das Bewusstsein und das Wissen über Cybersicherheit zu stärken.\n\nWir danken Ihnen für Ihre Wachsamkeit und Ihr Engagement für die Sicherheit unseres Unternehmens. Bei weiteren Fragen oder Bedenken stehen wir Ihnen jederzeit zur Verfügung.\n\nMit freundlichen Grüßen,\nIT-Sicherheit\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_scan_successful:condition_1:artifact:*.cef.filename"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_email_body")

    filter_fromemail(container=container)

    return


@phantom.playbook_block()
def filter_fromemail(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_fromemail() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "fromEmail"]
        ],
        name="filter_fromemail:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        playbook_send_email_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def playbook_send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_send_email_1() called")

    filtered_artifact_0_data_filter_fromemail = phantom.collect2(container=container, datapath=["filtered-data:filter_fromemail:condition_1:artifact:*.cef.fromEmail"])
    format_email_body = phantom.get_format_data(name="format_email_body")
    format_email_subject = phantom.get_format_data(name="format_email_subject")

    filtered_artifact_0__cef_fromemail = [item[0] for item in filtered_artifact_0_data_filter_fromemail]

    inputs = {
        "email_body": format_email_body,
        "email_subject": format_email_subject,
        "email_recipient": filtered_artifact_0__cef_fromemail,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "is_if/send_email", returns the playbook_run_id
    playbook_run_id = phantom.playbook("is_if/send_email", container=container, name="playbook_send_email_1", callback=playbook_send_email_1_callback, inputs=inputs)

    return


@phantom.playbook_block()
def playbook_send_email_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_send_email_1_callback() called")

    
    # Downstream End block cannot be called directly, since execution will call on_finish automatically.
    # Using placeholder callback function so child playbook is run synchronously.


    return


@phantom.playbook_block()
def filter_scan_successful(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_scan_successful() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["scan_successful", "in", "artifact:*.tags"]
        ],
        name="filter_scan_successful:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_email_body(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def promote_to_case_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("promote_to_case_2() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.promote()

    container = phantom.get_container(container.get('id', None))

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