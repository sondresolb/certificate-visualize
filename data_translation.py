import textwrap
import copy
import locale
from datetime import datetime
from collections import OrderedDict
from PyQt5 import QtCore, QtWidgets, QtGui
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtCore import Qt


def getDuration(then, now=datetime.now(), interval="default"):

    # Returns a duration as specified by variable interval
    # Functions, except totalDuration, returns [quotient, remainder]

    duration = then - now  # For build-in functions
    duration_in_s = duration.total_seconds()

    def years():
        return divmod(duration_in_s, 31536000)  # Seconds in a year=31536000.

    def days(seconds=None):
        # Seconds in a day = 86400
        return divmod(seconds if seconds != None else duration_in_s, 86400)

    def hours(seconds=None):
        # Seconds in an hour = 3600
        return divmod(seconds if seconds != None else duration_in_s, 3600)

    def minutes(seconds=None):
        # Seconds in a minute = 60
        return divmod(seconds if seconds != None else duration_in_s, 60)

    def seconds(seconds=None):
        if seconds != None:
            return divmod(seconds, 1)
        return duration_in_s

    def totalDuration():
        y = years()
        d = days(y[1])
        h = hours(d[1])
        m = minutes(h[1])
        s = seconds(m[1])

        return (f"{int(y[0])} years {int(d[0])} days "
                f"{int(h[0])} hours {int(m[0])} minutes")

    return {
        'years': int(years()[0]),
        'days': int(days()[0]),
        'hours': int(hours()[0]),
        'minutes': int(minutes()[0]),
        'seconds': int(seconds()),
        'default': totalDuration()
    }[interval]


def translate_connection_details(scan_result):
    connection_details = {}

    connection_details["ip"] = str(scan_result["connection"]["ip"])
    connection_details["server_name"] = str(
        scan_result["connection"]["server_name"])
    connection_details["tls_versions"] = scan_result["connection"]["tls_versions"]

    connection_details["protocol"] = str(scan_result["connection"]["protocol"])
    connection_details["cipher"] = str(scan_result["connection"]["cipher"])
    connection_details["hsts"] = "Supported" if scan_result["hsts"] else "Not supported"

    staple, staple_valid = scan_result["staple"]
    if staple:
        if staple_valid:
            connection_details["staple"] = "Supported"
        else:
            connection_details["staple"] = "Invalid staple"
    else:
        connection_details["staple"] = "Not supported"

    caa_support, _ = scan_result["caa"]
    connection_details["caa"] = "Supported" if caa_support else "Not supported"
    connection_details["certs_served"] = str(scan_result["certs_served"])

    return connection_details


def translate_certificate_path(cert_path):
    new_path = {}

    new_path["End-user Certificate"] = stringify_certificate(
        cert_path["end_cert"])
    new_path["Intermediate Certificates"] = [stringify_certificate(
        cert) for cert in cert_path["intermediates"]]
    new_path["Root Certificate"] = stringify_certificate(cert_path["root"])

    return {"Validation path": new_path}


def translate_failed_path(cert_path):
    new_path = {}

    new_path["End-user Certificate"] = stringify_certificate(
        cert_path["end_cert"])
    if cert_path["issuer"] is not None:
        new_path["Issuer"] = stringify_certificate(cert_path["issuer"])

    return {"Validation path": new_path}


def translate_all_keyusages(key_usages):
    return {"Key usages": key_usages}


def stringify_certificate(cert):
    locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
    certificate = {}
    certificate["subject"] = cert.subject
    certificate["issuer"] = cert.issuer
    certificate["serial_number"] = str(cert.serial_number)
    certificate["fingerprint"] = {
        "SHA1": str(cert.fingerprint["SHA1"]),
        "SHA2": str(cert.fingerprint["SHA256"])}
    certificate["signature_algorithm"] = str(cert.signature_algorithm)
    certificate["signature_hash"] = {
        "name": str(cert.signature_hash[0]),
        "bits": str(cert.signature_hash[1])}
    certificate["version"] = str(cert.version)
    certificate["expired"] = str(cert.has_expired)
    certificate["ct_poison"] = str(cert.ct_poison)
    certificate["must_staple"] = str(cert.must_staple)

    certificate["validity_period"] = {
        "not_before": cert.validity_period[0].strftime("%a %b %d %Y"),
        "not_after": cert.validity_period[1].strftime("%a %b %d %Y")}

    if cert.has_expired:
        expired = getDuration(datetime.now(), cert.validity_period[1])
        certificate["validity_period"]["has_expired"] = expired
    else:
        expires = getDuration(cert.validity_period[1])
        certificate["validity_period"]["expires"] = expires

    certificate["certificate_type"] = cert.certificate_type

    # Public keys
    if cert.public_key["type"] == 'RSA':
        certificate["public_key"] = {
            "type": cert.public_key["type"],
            "size": str(cert.public_key["size"]),
            "exponent": str(cert.public_key["exponent"]),
            "modulus": str(cert.public_key["modulus"])
        }
    elif cert.public_key["type"] == 'DSA':
        certificate["public_key"] = {
            "type": cert.public_key["type"],
            "size": str(cert.public_key["size"]),
            "y": str(cert.public_key["y"]),
            "modulus": str(cert.public_key["modulus"]),
            "sub_group_order": str(cert.public_key["sub-group-order"]),
            "generator": str(cert.public_key["generator"])
        }
    elif cert.public_key["type"] == 'EllipticCurve':
        certificate["public_key"] = {
            "type": cert.public_key["type"],
            "size": str(cert.public_key["size"]),
            "curve": str(cert.public_key["curve"])
        }
    else:
        certificate["public_key"] = {
            "type": cert.public_key["type"],
            "hash": str(cert.public_key["hash"]),
            "curve": str(cert.public_key["curve"])
        }

    # Certificate extensions
    certificate["extensions"] = {}
    for ext in cert.extensions.values():
        certificate["extensions"][ext["name"]] = {
            "description": textwrap.fill(ext["doc"], 50),
            "critical": str(ext["critical"]),
            "OID": str(ext["OID"]),
            "content": stringify_extension_value(ext["value"])
        }

    return certificate


def translate_ocsp(ocsp_support, ocsp_data):
    if not ocsp_support:
        no_supp = {
            "not_supported": ocsp_data}
        return {"Online Certificate Status Protocol": no_supp}

    for ocsp_endpoint in ocsp_data:
        verfi_res = ocsp_endpoint.get("verification_result", None)
        if verfi_res != None:
            if verfi_res["cert_match"]["passed"]:
                del verfi_res["cert_match"]

            if verfi_res["next_update"]["passed"]:
                del verfi_res["next_update"]

            if verfi_res["this_update"]["passed"]:
                del verfi_res["this_update"]

            if verfi_res["responder_cert"]["passed"]:
                del verfi_res["responder_cert"]
        else:
            ocsp_endpoint["verification_result"] = "Could not verify"

        ocsp_resp_msg = ocsp_endpoint.get("response_message", None)
        if ocsp_resp_msg:
            ocsp_endpoint["response_message"] = textwrap.fill(
                ocsp_resp_msg, 50)

    if len(ocsp_data) == 1:
        ocsp_data = ocsp_data[0]

    return {"Online Certificate Status Protocol": stringify_extension_value(ocsp_data)}


def translate_crl(crl_support, crl_data):
    if crl_support:
        data = []

        for item in crl_data:
            crl_item = {}
            crl_item["issuer"] = item["issuer"]
            crl_item["endpoint"] = item["endpoint"]
            crl_item["is_delta"] = item["is_delta"]
            crl_item["crl_number"] = item["crl_number"]
            crl_item["signature_algorithm"] = item["signature_algorithm"]
            crl_item["signature_hash"] = {
                "name": item["hash_algorithm"][0], "bits": item["hash_algorithm"][1]}
            crl_item["last_update"] = item["last_update"].ctime()
            crl_item["next_update"] = item["next_update"].ctime()
            crl_item["contains_revoked"] = item["has_revoked"]
            if item["has_revoked"]:
                crl_item["revocation_info"] = item["revocation_info"]

            data.append(crl_item)

    else:
        data = {"not_supported": crl_data["no_crl"]}

    return {"Certificate Revocation Lists": stringify_extension_value(data)}


def translate_certificate_transparency(ct_support, ct_data):
    if not ct_support:
        no_supp = {
            "not_supported": "No Signed Certificate Timestamps (SCTs)\nfound in End-user Certificate"}
        return {"Certificate Transparency": no_supp}

    data = []

    for item in ct_data:
        if "not_found" in item:
            data.append({"not_found": item["not_found"],
                         "log_id": item["log_id"]})
            continue

        sct_item = {}
        sct_item["version"] = item["version"]
        sct_item["valid"] = item["valid"]

        err_msg = item.get("message", None)
        if err_msg is not None:
            sct_item["error_message"] = err_msg

        sct_item["submitted"] = item["timestamp"].ctime()
        sct_item["entry_type"] = item["entry_type"]

        log_item = {}
        log_item["name"] = item["description"]
        log_item["operator"] = item["operator"]
        log_item["log_state"] = {"log_state": item["state"]
                                 [0], "timestamp": item["state"][1].ctime()}
        log_item["log_id"] = item["log_id"]
        log_item["mmd"] = item["mmd"]
        log_item["uri"] = item["url"]
        log_item["email"] = item["email"]

        data.append({"sct": sct_item, "log": log_item})

    return {"Certificate Transparency": stringify_extension_value(data)}


def translate_caa(caa_support, caa_data):
    if not caa_support:
        no_supp = {
            "not_supported": "No DNS CAA data found for domain"}
        return {"Certificate Authority Authorization": no_supp}

    return {"Certificate Authority Authorization": stringify_extension_value(caa_data)}


def translate_proto_cipher(pc_support, pc_data):
    if not pc_support:
        no_supp = {"not_supported": textwrap.fill(pc_data, 50)}
        return {"Cipher suites": no_supp}

    new_data = copy.deepcopy(pc_data)

    try:
        for protocol, ciphers in pc_data.items():
            unknown_ciphers = {}
            for cipher, cipher_info in ciphers.items():
                if cipher_info == "unknown":
                    unknown_ciphers[cipher] = new_data[protocol].pop(cipher)

            new_data[protocol] = dict(OrderedDict(
                sorted(new_data[protocol].items())))
            unknown_ciphers = {"unknown": dict(
                OrderedDict(sorted(unknown_ciphers.items())))}

            if len(unknown_ciphers["unknown"]) > 0:
                new_data[protocol].update(unknown_ciphers)

    except Exception as e:
        print(str(e))

    return {"Cipher suites": new_data}


def translate_revoked(cert_revoked, crl_support, ocsp_support):
    is_revoked = "Yes" if cert_revoked else "No"
    crl = "Supported" if crl_support else "Not supported"
    ocsp = "Supported" if ocsp_support else "Not supported"

    support = {"is_revoked": is_revoked,
               "CRL": crl, "OCSP": ocsp}
    return {"Revoked": support}


def translate_validation_res(validation_res):
    if validation_res[0]:
        return {"Path validation": "Successful"}
    else:
        reason = textwrap.fill(validation_res[2]["reason"], 60)
        details = textwrap.fill(validation_res[2]["details"], 60)
        res = {"status": "Failed", "Reason": reason, "Details": details}
        return {"Path validation": res}


def translate_evaluation(evaluation_tree):
    return {"Evaluation": stringify_extension_value(evaluation_tree)}


def set_evaluation_result(evaluation_score, ui):
    light_path = "qt_files/color_lights/"
    status_lights = {
        "red": f"{light_path}red_light.svg",
        "yellow": f"{light_path}yellow_light.svg",
        "green": f"{light_path}green_light.svg"
    }

    gui_score = evaluation_score

    if evaluation_score == -1 or 0 < evaluation_score < 40:
        ui.status_light.setPixmap(QtGui.QPixmap(status_lights["red"]))
        gui_score = 0

    elif 40 <= evaluation_score < 60:
        ui.status_light.setPixmap(QtGui.QPixmap(status_lights["yellow"]))

    elif 60 <= evaluation_score:
        ui.status_light.setPixmap(QtGui.QPixmap(status_lights["green"]))

    ui.score.setText(f"{round(gui_score, 1)}/100")


def stringify_extension_value(extension_value):
    value_type = type(extension_value)

    if value_type is dict:

        for key, value in extension_value.items():
            extension_value[key] = stringify_extension_value(value)

        return extension_value

    elif value_type is list:

        for index, value in enumerate(extension_value):
            extension_value[index] = stringify_extension_value(value)

        return extension_value

    else:
        if isinstance(extension_value, datetime):
            return extension_value.ctime()

        else:
            return str(extension_value)


def fill_connection_details(connection_details, data):
    _translate = QtCore.QCoreApplication.translate

    for index, key in enumerate(data):
        item = QtWidgets.QTableWidgetItem()
        connection_details.setItem(index, 0, item)
        item = connection_details.item(index, 0)
        item.setText(_translate("Form", str(data[key])))


def create_data_model(display, parent):
    data_model = QStandardItemModel(0, 2, parent)
    data_model.setHeaderData(0, Qt.Horizontal, "Name")
    data_model.setHeaderData(1, Qt.Horizontal, "Value")
    display.data_view.setModel(data_model)
    return data_model


def create_metric_model(display, parent):
    data_model = QStandardItemModel(0, 2, parent)
    data_model.setHeaderData(0, Qt.Horizontal, "Name")
    data_model.setHeaderData(1, Qt.Horizontal, "Value")
    display.metric_tree.setModel(data_model)
    return data_model


def fill_data_model(parent, data):
    value_type = type(data)

    if value_type is dict:

        for key, value in data.items():
            custom_row(parent, key, value)

    elif value_type is list:

        for index, value in enumerate(data):
            key = index
            custom_row(parent, key, value)


def custom_row(parent, key, value):
    if type(value) is str:
        item = custom_item_layout(parent, key, value, True)
        parent.appendRow(item)

    else:
        item = custom_item_layout(parent, key, value, False)
        parent.appendRow(item)
        fill_data_model(item[0], value)


def custom_item_layout(parent, key, value, is_string):
    if is_string:
        item = [QStandardItem(str(key)), QStandardItem(value)]
    else:
        item = [QStandardItem(str(key)), QStandardItem()]

    fn_name = f"{key}_layout"
    try:
        module = __import__('data_translation')
        layout_function = getattr(module, fn_name)
        fn_result = layout_function(value, item)
        if fn_result is not None:
            item[1] = fn_result

        return item

    except Exception as e:
        if parent.text() == "Certificate Revocation Lists":
            if type(value) is not str:
                item[0].setText("endpoint")
                item[1] = QStandardItem(value["endpoint"])
                del value["endpoint"]

        elif parent.text() == "extensions":
            item[0].setToolTip(textwrap.fill(value["description"], 50))
            extension_item = extension_layout(value, item)
            item[1] = extension_item

        elif "TLSv" in parent.text():
            if type(value) is not str and value.get("security") == 'insecure':
                item[1] = QStandardItem("Not secure")
            elif type(value) is not str and value.get("security") == 'recommended':
                item[1] = QStandardItem("PFS")

        elif parent.text() == "unknown":
            item[1] = QStandardItem()

        elif key == "Revoked":
            item[0].setToolTip("End-user certificate revoked?")
            item[1] = QStandardItem(value["is_revoked"])
            del value["is_revoked"]

        elif key == "Path validation":
            if type(value) is not str:
                item[1] = QStandardItem(value["status"])
                del value["status"]

        elif parent.text() == "Path validation" and key == "Details":
            msg = item[1].text()
            item[1].clearData()
            item[0].insertRow(0, [QStandardItem(), QStandardItem(msg)])

        elif key == "Key usages":
            item[1] = QStandardItem(str(len(value)))

        elif parent.text() == "Evaluation":
            item[1] = QStandardItem(value["total"])
            del value["total"]

        return item


def subject_layout(value, item_list):
    return QStandardItem(value["commonName"])


def issuer_layout(value, item_list):
    return QStandardItem(value["commonName"])


def signature_hash_layout(value, item_list):
    return QStandardItem(f"{value['name']} ({value['bits']})")


def validity_period_layout(value, item_list):
    if value.get("expires", None):
        msg = f"Expires in:  {value['expires']}"
        del value["expires"]
    else:
        msg = f"Expired for:  {value['has_expired']}"
        del value["has_expired"]

    return QStandardItem(msg)


def expired_layout(value, item_list):
    msg = "Yes" if value == "True" else "No"
    item_list[1].setText(msg)


def fingerprint_layout(value, item_list):
    msg = f"{value['SHA1']} (sha1)"
    return QStandardItem(msg)


def must_staple_layout(value, item_list):
    return QStandardItem("Yes") if value == 'True' else QStandardItem("No")


def ct_poison_layout(value, item_list):
    return QStandardItem("Yes") if value == 'True' else QStandardItem("No")


def log_layout(value, item_list):
    name = value["name"]
    del value["name"]
    return QStandardItem(name)


def sct_layout(value, item_list):
    item_list[0].setToolTip("Signed Certificate Timestamp")
    return QStandardItem(value["submitted"])


def mmd_layout(value, item_list):
    description = (
        """Maximum Merge Delay
        The maximum amount of time that can pass
        before the certificate is included in the public log"""
    )
    item_list[0].setToolTip(description)


def log_state_layout(value, item_list):
    log_state = value["log_state"]
    del value["log_state"]
    return QStandardItem(log_state)


def kex_algorithm_layout(value, item_list):
    item_list[0].setToolTip("Key Exchange algorithm")


def auth_algorithm_layout(value, item_list):
    item_list[0].setToolTip("Authentication algorithm")


def enc_algorithm_layout(value, item_list):
    item_list[0].setToolTip("Encryption algorithm")


def verification_result_layout(value, item_list):
    msg = value["message"]
    del value["message"]
    return QStandardItem(msg)


def public_key_layout(value, item_list):
    if value['type'] == 'RSA':
        return QStandardItem(f"{value['type']} {value['size']} ({value['exponent']})")
    elif value['type'] == 'DSA':
        return QStandardItem(f"{value['type']} ({value['size']})")
    elif value['type'] == 'EllipticCurve':
        return QStandardItem(f"{value['type']} {value['size']} ({value['curve']})")
    else:
        return QStandardItem(f"{value['type']} {value['hash']} ({value['curve']})")


def end_cert_layout(value, item_list):
    return QStandardItem("X509 Certificate")


def intermediates_layout(value, item_list):
    return QStandardItem("X509 Certificate List")


def root_layout(value, item_list):
    return QStandardItem("X509 Certificate")


def extension_layout(value, item_list):
    return QStandardItem(value["OID"])


def description_layout(value, item_list):
    item_list[1].clearData()
    item_list[0].appendRow([QStandardItem(), QStandardItem(value)])
