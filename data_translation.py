from datetime import datetime


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
            "description": ext["doc"],
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
