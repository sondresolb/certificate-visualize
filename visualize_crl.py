import requests
import datetime
from urllib.parse import urlsplit
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from requests.exceptions import HTTPError
import visualize_exceptions as c_ex


def check_crl(end_cert, issuer):
    """
    1.  If the issuer of end-cert is the issuer of the crl,
        then only the distribution-endpoint is present.

        If the certificate issuer is not the CRL
        issuer, then the cRLIssuer field MUST be present and contain the Name
        of the CRL issuer

    2. Full name has http url to fetch revocation list
    3. If there is no distribution point extention. then no crl info given

    CHECK: If CRLs provide Delta crls**

    crl_list = [{endpoint: http://somecrl.crl, crl_number: 534, deltas: [{endpoint: ..., crl_number: 534}]}, {}]

    steps:
        - Extract crls from certificate (with crl number)
        - Extract deltas from certificate (with crl number)
        - Match certificate_deltas against certificate_crls
        - send crls with deltas to validation
        - append certificate deltas to list of all deltas before validation
        - Validate all delta crls
        - validate crl
        - return list of complete crl with all valid deltas

    """
    crl_list = []
    # List over CRLs referenced inside certificate
    certificate_crl_list = []

    # Get CRL extension from end-certificate
    crl_dist_points = end_cert.extensions.get("cRLDistributionPoints", None)

    if crl_dist_points:
        # Extract HTTP CRL endpoints from CRL extention ([strings])
        certificate_crl_endpoints = get_certificate_crl_enpoints(
            crl_dist_points)

        # Check if any HTTP CRL enpoints was found
        if not certificate_crl_endpoints:
            return (False, {"no_crl": "No HTTP CRL enpoints was found"})

        # Fetch CRLs mentioned in the certificate and store with CRL number
        certificate_crl_list = get_certificate_crls(certificate_crl_endpoints)

        # Fetch delta CRLs mentioned in certificate
        certificate_delta_crls = get_delta_crls(end_cert.crypto_cert)

        # Compare CRL number in cert CRLs and delta CRLs and include if match
        include_delta_crls(certificate_crl_list, certificate_delta_crls)

        # Extract and include delta CRLs inside CRLs
        for crl_info in certificate_crl_list:
            crl_delta_crls = get_delta_crls(crl_info["crl"])
            include_delta_crls(crl_info, crl_delta_crls)

        print(certificate_crl_list)

        # Do validation here ...
        # Do revocation checking on validated CRLs here ...

    else:
        return (False, {"no_crl": "Certificate does not include CRL information"})


def validate_crl(end_cert, issuer, complete_crl):
    # If CRL has freshest CRL extension, get delta crl and do check below
    # 1. Check that current time is before the value of the CRL next_update field
    # 2. Validate signature of complete and possible delta CRL info
    #       - can use Authority Information Access extention in crl to get issuer
    # 3. If no crl could be validated, return status as False

    validation_result = {"valid": False, "valid_crls": [], "delta": False}
    delta_crls = []

    # TODO: The end_cert can also contain the FreshestCRL extension. CHECK THERE ALSO
    # Look for delta CRL enpoints and fetch them
    try:
        delta_endpoints = []
        delta_ext = complete_crl.extensions.get_extension_for_class(
            x509.FreshestCRL)
        for delta in delta_ext.value:
            if delta.full_name:
                delta_endpoints.append(delta.full_name)

        # Delta is true even if fetching fails
        validation_result["delta"] = bool(delta_endpoints)

        delta_crls.extend(fetch_all_crls(delta_endpoints))

    except x509.ExtensionNotFound:
        print("Found no delta CRL information")

    for crl_item in delta_crls:
        valid = do_crl_validation(crl_item, issuer.crypto_cert.public_key())
        if valid["valid"]:
            validation_result["valid_crls"].append(crl_item)

    complete_valid = do_crl_validation(
        complete_crl, issuer.crypto_cert.public_key())

    if not complete_valid["valid"]:
        print("Complete CRL is not valid")
        # If signature of complete CRL is invalid. Do not use
        if complete_valid["reason"] == "signature":
            return validation_result
        # If it is old, check if there are any valid delta crls
        elif validation_result["valid_crls"]:
            validation_result["valid_crls"].append(complete_crl)
        else:
            return validation_result
    else:
        validation_result["valid_crls"].append(complete_crl)
        validation_result["valid"] = True

    return validation_result


def do_crl_validation(crl, issuer_key):
    valid = {"valid": False, "reason": ""}
    if datetime.datetime.now() > crl.next_update:
        valid["reason"] = "next_update"
        return valid

    # Verify signature of CRL using issuer of certificate
    valid_sig = crl.is_signature_valid(issuer_key)
    if not valid_sig:
        valid["reason"] = "signature"
        return valid

    valid["valid"] = True
    return valid


def fetch_crl(crl_endpoint):
    try:
        response = requests.get(crl_endpoint)
        response.raise_for_status()
        return x509.load_der_x509_crl(response.content, default_backend())

    except HTTPError as http_err:
        print(
            f"HTTP error occurred while requesting crl from {crl_endpoint}")
    except Exception as e:
        print(
            f"Unhandled exception occured while requesting crl from {crl_endpoint}")

    return None


def include_delta_crls(crls, deltas):
    if deltas is not None:
        for crl in crls:
            for delta in deltas:
                if delta["crl_number"] == crl["crl_number"]:
                    crl["deltas"].append(delta)


def get_delta_crls(crypto_object):
    delta_crls = []
    delta_endpoints = []

    try:
        delta_extention = crypto_object.extensions.get_extension_for_class(
            x509.FreshestCRL)

        for dist_point in delta_extention:
            if dist_point.full_name is not None:
                for name_item in dist_point.full_name:
                    if urlsplit(name_item).scheme == "http":
                        delta_endpoints.append(name_item)

        for delta_endpoint in delta_endpoints:
            delta_crl = fetch_crl(delta_endpoint)
            if delta_crl is not None:
                crl_number = get_crl_number(delta_crl)
                delta_crls.append(
                    {"endpoint": delta_endpoint, "crl": delta_crl, "crl_number": crl_number})

        if not delta_crls:
            return None
        else:
            return delta_crls

    except x509.ExtensionNotFound:
        return None


def get_certificate_crls(certificate_crl_endpoints):
    crl_list = []

    for crl_endpoint in certificate_crl_endpoints:
        certificate_crl = fetch_crl(crl_endpoint)
        if certificate_crl is not None:
            crl_number = get_crl_number(certificate_crl)
            crl_list.append(
                {"endpoint": crl_endpoint, "crl": certificate_crl,
                 "crl_number": crl_number, "deltas": []})

    return crl_list


def get_certificate_crl_enpoints(crl_dist_points):
    crl_endpoints = []

    for crl_enpoint in crl_dist_points["value"]:
        full_name = crl_enpoint.get("full_name", None)
        if full_name is not None:
            for name_item in full_name:
                if urlsplit(name_item).scheme == "http":
                    crl_endpoints.append(name_item)

    return crl_endpoints


def get_crl_number(crl):
    try:
        number_ext = crl.extensions.get_extension_for_class(x509.CRLNumber)
        print(number_ext)
        return number_ext.value.crl_number

    except x509.ExtensionNotFound:
        print("Failed to get CRL number")
        return None
