import json
import requests
import base64
from os import path
import datetime


def get_ct_information(end_cert):
    """Get information regarding SCTs included in certificate

    Extracts the SCT extension from the certificate and matches it
    against a fetched CT log list. The timestamp of each SCT is checked
    and all relevant information is extracted from both the SCT object
    and the CT log list

    Args:
        end_cert (Cert_repr): Certificate including SCT list extension

    Returns:
        tuple(bool, list): If cert includes CT info and
            list of ct_information objects or failure message
    """
    ct_information = []

    sct_ext = end_cert.extensions.get("signedCertificateTimestampList", None)
    if sct_ext is None:
        print("CT: No SCT was found in end certificate")
        return (False, "No SCT was found in end-certificate")

    log_list = get_ct_log_list()

    for sct in sct_ext["value"]:
        sct_info = {"valid": True}

        # Checking if the SCT timestamp is in the future
        if datetime.datetime.now() < sct["timestamp"]:
            sct_info["message"] = "Timestamp is greater than current time"
            sct_info["valid"] = False
            print(
                f"{sct_info['description']} timestamp is greater than current time")

        # Getting the CT log id to the same encoding as in the log list
        sct_log_id = base64.b64encode(
            bytes.fromhex(sct['log_id'])).decode("utf-8")
        result = get_log_list_entry(log_list, sct_log_id)

        if result is not None:
            operator, log_info = result
            sct_info["operator"] = operator["name"]
            sct_info["email"] = operator["email"][0]
            sct_info["description"] = log_info["description"]
            sct_info["version"] = sct["version"]
            sct_info["log_id"] = sct['log_id']
            sct_info["url"] = log_info["url"]
            sct_info["mmd"] = log_info["mmd"]
            state = next(iter(log_info["state"]))
            sct_info["state"] = (state, log_info["state"][state]["timestamp"])
            sct_info["timestamp"] = sct["timestamp"].ctime()
            # Setting timestamp in extension to ctime
            sct["timestamp"] = sct["timestamp"].ctime()
            sct_info["entry_type"] = sct["entry_type"]
            ct_information.append(sct_info)

    return (True, ct_information)


def get_ct_log_list():
    """Fetch the CT log list from a URI

    This function fetches the CT log list from the given URI and
    parses it from JSON to a python dictionary. If the fetching fails,
    it will try to use a local cached version.

    Returns:
        (dict): The parsed CT log list 
        or
        None if fetching fails

    """
    endpoint = "https://www.gstatic.com/ct/log_list/v2/log_list.json"

    ct_list_file = None
    default_path = "ct_log_list.json"

    try:
        ct_list_file = requests.get(endpoint).content

    except Exception:
        print(f"NOTICE: Failed while fetching CT_log_list from {endpoint}\n"
              f"Using cached CT log {default_path} with possibly outdated information\n")
        if path.exists(default_path):
            with open(default_path) as ll:
                ct_list_file = ll.read()

        else:
            print(f"ERROR: No default CT_log_list found in {default_path}\n")
            return None

    json_log_list = json.loads(ct_list_file)
    with open(default_path, "w") as f:
        json.dump(json_log_list, f)

    return json_log_list


def get_log_list_entry(log_list, sct_log_id):
    for operator in log_list["operators"]:
        for log in operator["logs"]:
            if sct_log_id == log['log_id']:
                return (operator, log)

    return None
