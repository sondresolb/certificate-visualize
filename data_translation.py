import textwrap
from datetime import datetime
from PyQt5 import QtCore, QtWidgets
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtCore import Qt


def translate_connection_details(scan_result):
    connection_details = {}

    connection_details["ip"] = str(scan_result["connection"]["ip"])
    connection_details["server_name"] = str(
        scan_result["connection"]["server_name"])

    proto_c_support, proto_ciphers = scan_result["proto_cipher"]
    if proto_c_support:
        connection_details["tls_versions"] = ", ".join(
            list(proto_ciphers.keys()))
    else:
        connection_details["tls_versions"] = "N/A"

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

    new_path["end_cert"] = stringify_certificate(cert_path["end_cert"])
    new_path["intermediates"] = [stringify_certificate(
        cert) for cert in cert_path["intermediates"]]
    new_path["root"] = stringify_certificate(cert_path["root"])

    return new_path


def stringify_certificate(cert):
    certificate = {}
    certificate["subject"] = cert.subject
    certificate["issuer"] = cert.issuer
    certificate["version"] = str(cert.version)
    certificate["serial_number"] = str(cert.serial_number)
    certificate["fingerprint"] = {
        "SHA1": str(cert.fingerprint["SHA1"]),
        "SHA2": str(cert.fingerprint["SHA256"])}
    certificate["signature_algorithm"] = str(cert.signature_algorithm)
    certificate["signature_hash"] = {
        "name": str(cert.signature_hash[0]),
        "bits": str(cert.signature_hash[1])}
    certificate["expired"] = str(cert.has_expired)
    certificate["validity_period"] = {
        "not_before": str(cert.validity_period[0]),
        "not_after": str(cert.validity_period[1])}

    # Public keys
    if cert.public_key["type"] == 'RSA':
        certificate["public_key"] = {
            "type": cert.public_key["type"],
            "bit_size": str(cert.public_key["size"]),
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
    display.cert_chain_treeView.setModel(data_model)
    return data_model


def fill_data_model(parent, cert_path):
    value_type = type(cert_path)

    if value_type is dict:

        for key, value in cert_path.items():
            custom_row(parent, key, value)

    elif value_type is list:

        for index, value in enumerate(cert_path):
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
        item = [QStandardItem(str(key))]

    fn_name = f"{key}_layout"
    try:
        module = __import__('data_translation')
        layout_function = getattr(module, fn_name)
        if layout_function is not None:
            fn_result = layout_function(value, item)
            if fn_result is not None:
                item.append(fn_result)

        return item

    except Exception as e:
        # Possibly remove index from tree
        # if type(key) is int:
        #     remove index here if parent == something

        if parent.text() == "extensions":
            item[0].setToolTip(textwrap.fill(value["description"], 50))
            extension_item = extension_layout(value, item)
            item.append(extension_item)

        return item


def subject_layout(value, item_list):
    return QStandardItem(value["commonName"])


def issuer_layout(value, item_list):
    return QStandardItem(value["commonName"])


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
