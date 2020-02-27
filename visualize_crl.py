import requests
import datetime
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


    """
    if end_cert.extensions.get('cRLDistributionPoints', None):
        # Only extracting full_name crl enpoints
        crl_list = fetch_all_crls([crl["full_name"][0]
                                   for crl in end_cert.extensions['cRLDistributionPoints']['value']])

        if not crl_list:
            return (False, {"no_crl": "Not able to fetch CRLs given in certificate"})

        for crl in crl_list:
            validation_result = validate_crl(end_cert, issuer, crl)
            if validation_result["valid"]:
                # add to list of valid CRLs
                pass

        # Do revocation checking on validated CRLs ...

    else:
        return (False, {"no_crl": "No CRL endpoints found in certificate"})


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
        if delta_endpoints:
            validation_result["delta"] = True

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
            validation_result.append(complete_crl)
        else:
            return validation_result

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


def fetch_all_crls(crl_endpoints):
    crls = []

    for crl_endpoint in crl_endpoints:
        try:
            response = requests.get(crl_endpoint)

            response.raise_for_status()
            crls.append(x509.load_der_x509_crl(
                response.content, default_backend()))

        except HTTPError as http_err:
            print(
                f"HTTP error occurred while requesting crl from {crl_endpoint}")
        except Exception as e:
            print(
                f"Unhandled exception occured while requesting crl from {crl_endpoint}")

    return crls
