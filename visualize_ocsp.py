import requests
import datetime
from requests.exceptions import HTTPError

from urllib.parse import urlsplit

from cryptography import x509 as cryptography_x509
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

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

        https://tools.ietf.org/html/rfc6960#page-6 (page 6)

    Args:
        cert (cert_repr): The certificate beeing checked
        issuer (cert_repr): The issuer of <cert>

    Returns:
        tuple(bool, list): 
            First element indicating if ocsp is supported. Second element is the
            list of results (dict) for each enpoint found

    Raises:
        (cert_visualize_exceptions.OCSPRequestBuildError):
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

    if not ocsp_endpoints:
        return (False, [{"no_ocsp": "No OCSP enpoint was found"}])

    req = build_ocsp_request(cert, issuer)

    for endpoint in ocsp_endpoints:
        host, ocsp_endpoint = endpoint[0], endpoint[1]

        endpoint_res = {"endpoint": ocsp_endpoint}

        try:
            ocsp_response = get_ocsp_response(host, ocsp_endpoint, req)
        except c_ex.RequestResponseError as orre:
            endpoint_res["no_response"] = f"Failed to fetch OCSP response: {str(orre)}"
            ocsp_responses.append(endpoint_res)
            continue

        endpoint_res["response_status"] = ocsp_response.response_status.name
        if endpoint_res["response_status"] == 'SUCCESSFUL':

            # Verify ocsp response signature
            endpoint_res["verification_result"] = validate_ocsp_response(
                host, ocsp_response, issuer, cert.serial_number)

            endpoint_res["certificate_status"] = ocsp_response.certificate_status.name
            endpoint_res["certificate_status_msg"] = get_res_message(
                endpoint_res["certificate_status"])
            endpoint_res["certificate_serial"] = ocsp_response.serial_number
            endpoint_res["signature_algorithm"] = ocsp_response.signature_algorithm_oid._name
            endpoint_res["produced_at"] = ocsp_response.produced_at.ctime()
            endpoint_res["this_update"] = ocsp_response.this_update.ctime()
            endpoint_res["next_update"] = ocsp_response.next_update.ctime()

            if endpoint_res["certificate_status"] == 'REVOKED':
                endpoint_res["revocation_time"] = ocsp_response.revocation_time
                endpoint_res["revocation_reason"] = ocsp_response.revocation_reason
        else:
            endpoint_res["response_message"] = get_res_message(
                endpoint_res["response_status"])

        ocsp_responses.append(endpoint_res)

    return (True, ocsp_responses)


def get_ocsp_response(host, ocsp_endpoint, req_encoded):
    """Function for requesting ocsp response

    Function for requesting ocsp response from ocsp responder.
    A header is created where the host field is the ocsp responder
    address and content type is set to be a ocsp request. The response
    is encoded to a cryptography ocsp response object.

    Args:
        host (str): Address of ocsp responder (E.g., ocsp.digicert.com)
        ocsp_endpoint (str): Address with protocol (E.g., http://ocsp.digicert.com)
        req_encoded (bytes): DER encoded ocsp request as bytes

    Returns:
        (cryptography ocsp response object): The encoded response from the responder

    Raises:
        (cert_visualize_exceptions.RequestResponseError):
            If an exception occured while fetching response
    """
    headers = {'Host': host,
               'Content-Type': 'application/ocsp-request'}

    try:
        response = requests.post(
            ocsp_endpoint, data=req_encoded, headers=headers)

        response.raise_for_status()
        return cryptography_x509.ocsp.load_der_ocsp_response(response.content)

    except HTTPError as http_err:
        raise c_ex.RequestResponseError(
            'HTTP error occurred while requesting ocsp response'
            f'from {ocsp_endpoint})') from http_err

    except Exception as e:
        raise c_ex.RequestResponseError(
            'Unhandled exception occured while requesting ocsp'
            f'response from {ocsp_endpoint}') from e


def validate_ocsp_response(host, ocsp_response, issuer, cert_serial_number):
    """Validation of the ocsp response

    A function for validating the ocsp response. All relevant information like
    tbs_bytes, signature_bytes and hash algorithm is extracted. It then checks if:
        -   The certificate beeing checked is the same as the one indicated in the response
        -   next_update and this_update are adequate
        -   Responder certificate chain is valid
        https://tools.ietf.org/html/rfc6960#page-10 (page 9-10)

    Any certificates included in the response (delegates) are verified using the
    issuer of the certificate beeing checked and added to the list of certificates
    used in the verification process of the response signature. The signature is then
    verified. If a delegate was used to verify the signature, an explicit check
    is carried out to ensure it includes the id-kp-OCSPSigning extension. If the
    extension is not present, the certificate is not authorized to sign the response.
    The information is compiled into a dictionary and returned. The <valid> field
    inside validation_result is only True if all checks passed and the signature
    was successfully verified.

    Args:
        host (str): The address of the ocsp responder
        ocsp_response (cryptography ocsp object): The ocsp response
        issuer (cryptography x509 certificate): The issuer of the checked certificate
        cert_serial_number (int): Serial number of the checked certificate

    Returns:
        validation_result (dict): Result of the validation
    """
    tbs_bytes = ocsp_response.tbs_response_bytes
    signature_bytes = ocsp_response.signature
    sig_hash_algo = ocsp_response.signature_hash_algorithm
    issuer_cert = issuer.crypto_cert
    key_certs = [issuer_cert]
    validation_result = {
        "valid": False, "verification_cert": None, "can_sign": False, "message": ""}

    checks_passed = True

    # Check that the certificate in question is the same as in the ocsp response
    validation_result["cert_match"] = {"passed": True, "message": ""}
    if ocsp_response.serial_number != cert_serial_number:
        checks_passed = False
        validation_result["cert_match"]["passed"] = False
        validation_result["cert_match"]["message"] = (
            "Certificate beeing checked does not match certificate in response")

    # Check that the current time is greater than next_update field in the response
    validation_result["next_update"] = {"passed": True, "message": ""}
    if datetime.datetime.now() > ocsp_response.next_update:
        checks_passed = False
        validation_result["next_update"]["passed"] = False
        validation_result["next_update"]["message"] = (
            "OCSP next_update is earlier than local system time")

    # Check that the current time is less than this_update field in the response
    validation_result["this_update"] = {"passed": True, "message": ""}
    if datetime.datetime.now() < ocsp_response.this_update:
        checks_passed = False
        validation_result["this_update"]["passed"] = False
        validation_result["this_update"]["message"] = (
            "OCSP this_update is greater than local system time")

    # Validate the OCSP responder certificate chain
    validation_result["responder_cert"] = {"passed": True, "message": ""}
    responder_valid, responder_res = validate_ocsp_responder(host)
    if not responder_valid:
        checks_passed = False
        validation_result["responder_cert"]["passed"] = False
        validation_result["responder_cert"]["message"] = (
            f"OCSP responder certificate could not be validated: {responder_res}")

    # Check that the OCSP responder name or key_hash is the one intended for the request
    # if ocsp_response.responder_name != host:
    #     print(ocsp_response.responder_name)
    #     if ocsp_response.responder_name is None:

    #         digest = hashes.Hash(
    #             SHA1(), backend=default_backend())

    #         digest.update(responder_cert.public_key().public_bytes(
    #             serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    #         key_cert_hash = digest.finalize()
    #         if ocsp_response.responder_key_hash != key_cert_hash:
    #             print(ocsp_response.responder_key_hash)
    #             print(key_cert_hash)
    #             validation_result["message"] = "OCSP responder name or key_hash does not match intended responder"
    #             return validation_result

    #     else:
    #         validation_result["message"] = "OCSP responder name or key_hash does not match intended responder"
    #         return validation_result

    # Check for certificate chain passed with response
    if ocsp_response.certificates:
        delegate_end = ocsp_response.certificates[0]

        # Try validating delegate signature with issuer key
        verifi_res = vis_tools.signature_verification([issuer_cert], delegate_end.signature,
                                                      delegate_end.tbs_certificate_bytes,
                                                      delegate_end.signature_hash_algorithm)
        if verifi_res[0]:
            key_certs.append(delegate_end)

    valid, cert = vis_tools.signature_verification(
        key_certs, signature_bytes, tbs_bytes, sig_hash_algo)

    validation_result["signature_verified"] = valid
    validation_result["verification_cert"] = cert

    # OCSP signing delegation must be explicit with id-kp-OCSPSigning extension
    if cert is not None:
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

    validation_result["valid"] = valid and checks_passed and validation_result["can_sign"]

    if validation_result["valid"]:
        validation_result["message"] = "OCSP response successfully validated"
    else:
        validation_result["message"] = "OCSP response validation failed"

    return validation_result


def build_ocsp_request(cert, issuer):
    """Function for building the ocsp request

    The cryptography ocsp request builder takes in the certificate
    to be checked and the issuer of that certificate. The request
    is then hashed using the SHA1 algorithm.

    Args:
        cert (cert_repr): The certificate to be checked
        issuer (cert_repr): The issuer of the certificate in question

    Returns:
        (cryptography request object): The ocsp request, DER serialized

    Raises:
        (visualize_exceptions.OCSPRequestBuildError):
            If any error occured during request building
    """
    try:
        builder = cryptography_x509.ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(
            cert.crypto_cert, issuer.crypto_cert, SHA1())

        req = builder.build()
        return req.public_bytes(serialization.Encoding.DER)

    except Exception as e:
        raise c_ex.OCSPRequestBuildError(
            f"Failed to build OCSP request") from e


def validate_ocsp_responder(host):
    """Validate the certificate chain of the ocsp responder

    Fetches the ocsp responder certificate chain and validates it.
    The fingerprint of the end entity certificate is added to the
    whitelist to avoid hostname matching. 

    Args:
        host (str): Address of ocsp responder

    Returns:
        tuple(bool, str):
            (bool): If validation was successful
            (str): The result message
    """
    try:
        responder_cert_chain = [cert_obj.crypto_cert
                                for cert_obj in vis_tools.fetch_certificate_chain(host)]

    except c_ex.CertificateFetchingError as cfe:
        return (False, str(cfe))
    except c_ex.NoCertificatesError as nce:
        return (False, str(nce))

    # Avoiding TLS hostname matching of end-certificate
    responder_whitelist = [
        responder_cert_chain[0].fingerprint(hashes.SHA1()).hex()]
    responder_validation = vis_tools.validate_certificate_chain(
        host, responder_cert_chain, responder_whitelist)

    if responder_validation[0]:
        return (True, responder_cert_chain[0])
    else:
        return (False, f"{responder_validation[1]}: {responder_validation[2]}")


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
