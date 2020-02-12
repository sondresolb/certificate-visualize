import requests
from requests.exceptions import HTTPError

from urllib.parse import urlsplit

from cryptography import x509 as cryptography_x509
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives import serialization

import visualize_exceptions as c_ex
import visualize_tools as vis_tools


def check_ocsp(cert, issuer):
    """Check OCSP response for a single certificate

    Takes in a <cert> to be checked and the <issuer> of <cert>.
    <cert> is checked for OCSP endpoints, then included as an
    argument to the OCSPRequest builder together with <issuer>.
    The last argument to OCSPRequest builder is the hash function
    used to hash specific fields in the request (eg. issuerNameHash, issuerKeyHash).
    The request is encoded to DER/ASN.1 and sent together with a header to 
    indicate the content type as an OCSP request. If the request was successful,
    the OCSP response is verified and relevant information is extracted.

    The OCSP response can be signed by:
        1.  The issuer of the certificate beeing checked
        2.  A certificate which is signed by the same issuer as the certificate beeing checked
        3.  A certificate issued by the OCSP responder certificate

        (https://www.ibm.com/support/knowledgecenter/SSFKSJ_9.1.0/com.ibm.mq.explorer.doc/e_auth_info_ocsp.htm)

    Args:
        cert (cert_repr): The certificate beeing checked
        issuer (cert_repr): The issuer of <cert>

    Returns:
        tuple(bool, list): 
            First element indicating if ocsp is supported. Second element is the
            list of results (dict) for each enpoint found

    Raises:
        cert_visualize_exceptions.OCSPRequestBuildError():
            Raised if build_ocsp_request() fails
    """
    ocsp_responses = []
    ocsp_endpoints = []

    # Check AIA extension for OCSP enpoints
    if cert.extensions.get("authorityInfoAccess", None):
        for info in cert.extensions["authorityInfoAccess"]["value"]:
            if "OCSP" in info["access_method"]:
                ocsp_endpoint = info["access_location"]
                host = urlsplit(ocsp_endpoint).netloc
                ocsp_endpoints.append((host, ocsp_endpoint))

    else:
        return (False, [{"no_ocsp": "No OCSP enpoint was found"}])

    req = build_ocsp_request(cert, issuer)

    for endpoint in ocsp_endpoints:
        host, ocsp_endpoint = endpoint[0], endpoint[1]

        endpoint_res = {"endpoint": ocsp_endpoint}

        try:
            ocsp_response = get_ocsp_response(host, ocsp_endpoint, req)
        except c_ex.OCSPRequestResponseError as orre:
            endpoint_res["no_response"] = f"Failed to fetch OCSP response: {str(orre)}"
            ocsp_responses.append(endpoint_res)
            continue

        endpoint_res["response_status"] = ocsp_response.response_status.name
        print(f"OCSP Response status: {endpoint_res['response_status']}")

        if endpoint_res["response_status"] == 'SUCCESSFUL':

            # Verify ocsp response signature
            endpoint_res["verification_result"] = validate_ocsp_response(
                host, ocsp_response, issuer)

            print(
                f"OCSP Certificate status: {ocsp_response.certificate_status.name}")
            if endpoint_res["verification_result"]["valid"]:
                print("OCSP Signature: VALID")
            else:
                print("OCSP Signature: INVALID")
            print(
                f"OCSP Signature key can sign: {endpoint_res['verification_result']['can_sign']}\n")

            endpoint_res["certificate_status"] = ocsp_response.certificate_status.name
            endpoint_res["certificate_status_msg"] = get_res_message(
                endpoint_res["certificate_status"])
            endpoint_res["certificate_serial"] = ocsp_response.serial_number
            endpoint_res["signature_algorithm"] = ocsp_response.signature_algorithm_oid._name
            endpoint_res["produced_at"] = ocsp_response.produced_at
            endpoint_res["this_update"] = ocsp_response.this_update
            endpoint_res["next_update"] = ocsp_response.next_update

            if endpoint_res["certificate_status"] == 'REVOKED':
                endpoint_res["revocation_time"] = ocsp_response.revocation_time
                endpoint_res["revocation_reason"] = ocsp_response.revocation_reason

        else:
            endpoint_res["response_message"] = get_res_message(
                endpoint_res["response_status"])

        ocsp_responses.append(endpoint_res)

    return (True, ocsp_responses)


def get_ocsp_response(host, ocsp_endpoint, req_encoded):
    headers = {'Host': host,
               'Content-Type': 'application/ocsp-request'}

    try:
        response = requests.post(
            ocsp_endpoint, data=req_encoded, headers=headers)

        response.raise_for_status()
        return cryptography_x509.ocsp.load_der_ocsp_response(response.content)

    except HTTPError as http_err:
        raise c_ex.OCSPRequestResponseError(
            'HTTP error occurred while requesting ocsp response') from http_err

    except Exception as e:
        raise c_ex.OCSPRequestResponseError(
            'Unhandled exception occured while requesting ocsp response') from e


def validate_ocsp_response(host, ocsp_response, issuer):
    tbs_bytes = ocsp_response.tbs_response_bytes
    signature_bytes = ocsp_response.signature
    sig_hash_algo = ocsp_response.signature_hash_algorithm
    issuer_cert = issuer.crypto_cert
    key_certs = [issuer_cert]

    # Check for certificate chain passed with response
    if ocsp_response.certificates:
        delegate_end = ocsp_response.certificates[0]

        # Try validating delegate signature with issuer key
        verifi_res = vis_tools.signature_verification([issuer_cert], delegate_end.signature,
                                                      delegate_end.tbs_certificate_bytes,
                                                      delegate_end.signature_hash_algorithm)
        if verifi_res[0]:
            key_certs.append(delegate_end)
            print("OCSP: Response signed by delegate and validated with issuer key")

        else:
            # Try validating certificate chain of delegate issued by responder
            delegate_validation_res = vis_tools.validate_certificate_chain(
                host, ocsp_response.certificates)

            if delegate_validation_res[0]:
                key_certs.append(delegate_end)
                print("OCSP: Response signed by delegate and validated by external key")

    valid, cert = vis_tools.signature_verification(
        key_certs, signature_bytes, tbs_bytes, sig_hash_algo)

    validation_result = {"valid": valid,
                         "validation_cert": cert, "can_sign": False}

    if valid:
        # OCSP signing delegation must be explicit with id-kp-OCSPSigning extension
        if issuer.serial_number != cert.serial_number:
            ext_keyusage_oid = cryptography_x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
            try:
                extended_keyusage = cert.extensions.get_extension_for_oid(
                    ext_keyusage_oid).value
            except cryptography_x509.extensions.ExtensionNotFound:
                return validation_result

            if any(keyusage.dotted_string == ("1.3.6.1.5.5.7.3.9")
                   for keyusage in extended_keyusage):
                validation_result["can_sign"] = True

        else:
            validation_result["can_sign"] = True

    return validation_result


def build_ocsp_request(cert, issuer):
    try:
        builder = cryptography_x509.ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(
            cert.crypto_cert, issuer.crypto_cert, SHA1())

        req = builder.build()
        return req.public_bytes(serialization.Encoding.DER)

    except Exception as e:
        raise c_ex.OCSPRequestBuildError(
            f"Failed to build OCSP request") from e


def get_res_message(response_status):
    # Responder response statuses
    if response_status == 'MALFORMED_REQUEST':
        return "OCSP responder may be unable to parse a given request"
    elif response_status == 'INTERNAL_ERROR':
        return "OCSP responder may be currently experiencing operational problems."
    elif response_status == 'TRY_LATER':
        return "OCSP responder may be overloaded."
    elif response_status == 'SIG_REQUIRED':
        return "OCSP responder requires signed OCSP requests"
    elif response_status == 'UNAUTHORIZED':
        return ("OCSP responder may be unaware of queried certificate or an issuer "
                "for which the responder is not authoritative")

    # Certificate statuses
    elif response_status == "GOOD":
        return "The certificate is not revoked"
    elif response_status == "REVOKED":
        return "The certificate being checked is revoked"
    elif response_status == "UNKNOWN":
        return "The certificate being checked is not known to the OCSP responder"
    else:
        return "Uknown"
