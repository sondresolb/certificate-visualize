import idna
import requests
from socket import socket
from OpenSSL import SSL
from cert_repr import cert_repr
from requests.exceptions import HTTPError

from cryptography import x509
from cryptography.hazmat.primitives.hashes import SHA1, SHA256
from cryptography.hazmat.primitives import serialization
from urllib.parse import urlsplit

from cryptography.hazmat.backends import default_backend
from certvalidator import CertificateValidator, ValidationContext
from certvalidator import errors as cert_errors
import certifi
import pem

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

import cert_visualize_exceptions as c_ex


TRUST_STORE = None


def main():
    global TRUST_STORE
    TRUST_STORE = get_trust_store()

    domain = "www.google.com"
    cert_chain = [cert_repr(cert) for cert in fetch_certificate_chain(domain)]
    validate_certificate_chain(domain, cert_chain)

    end_cert, issuer_cert = cert_chain[0], cert_chain[1]

    try:
        ocsp_responses = check_ocsp(end_cert, issuer_cert)

    except c_ex.OCSPRequestBuildError as orbe:
        print(str(orbe))


def fetch_certificate_chain(domain):
    certificates = []

    hostname = idna.encode(domain)
    # SSL.TLSv1_2_METHOD, SSL.SSLv23_METHOD
    context = SSL.Context(SSL.SSLv23_METHOD)
    context.verify_mode = SSL.VERIFY_NONE

    print(f'Connecting to {domain} to get certificate chain...')

    try:
        s = socket()
        conn = SSL.Connection(context, s)
        conn.set_connect_state()
        # Server name indicator support (SNI)
        conn.set_tlsext_host_name(hostname)
        conn.connect((hostname, 443))
        conn.do_handshake()
        certificates = conn.get_peer_cert_chain()

    except Exception as e:
        print(f"Exception: {e}")
        exit()
    finally:
        s.close()
        conn.close()

    return certificates


def validate_certificate_chain(domain, cert_chain, whitelist=None):
    """Validates the certificate path given a certificate chain

    Validates the certificate path, checks that the certificate is valid for the
    hostname provided and that the certificate is valid for the purpose of a TLS connection

    Args:
        domain (str): The host address
        cert_chain (list): List of cert_repr objects
        whitelist (list): List of hex encoded SHA-1 certificate fingerprint strings

    Returns:
        tuple(bool, ValidationPath):
            bool: If the validation was successful
            ValidationPath: Iterable of certificate objects representing the path
    """
    try:
        der_certs = [cert.crypto_cert.public_bytes(
            serialization.Encoding.DER) for cert in cert_chain]

        valid_context = ValidationContext(
            trust_roots=TRUST_STORE, whitelisted_certs=whitelist)

        cert_validator = CertificateValidator(
            end_entity_cert=der_certs[0], intermediate_certs=der_certs[1:], validation_context=valid_context)

        result = cert_validator.validate_tls(domain)

        # for res in result:
        #     print(res.subject.human_friendly)

        return (True, result)

    except cert_errors.PathBuildingError as pbe:
        print(f"{type(pbe)}: {str(pbe)}")
        ex = "Unable to find the necessary root certificate to build the validation path"
        return (False, ex, str(pbe))
    except cert_errors.PathValidationError as pve:
        print(f"{type(pve)}: {str(pve)}")
        ex = "An error occured while validating the certificate path"
        return (False, ex, str(pve))
    except cert_errors.InvalidCertificateError as ice:
        print(f"{type(ice)}: {str(ice)}")
        ex = "Certificate is not valid"
        return (False, ex, str(ice))
    except Exception as e:
        print(f"{type(e)}: {str(e)}")
        ex = f"Unhandled exception raised: {str(e)}"
        return (False, ex, str(e))


def check_ocsp(cert, issuer):
    """Check OCSP response for a single certificate

    Takes in a <cert> to be checked and the <issuer> of <cert>.
    <cert> is checked for OCSP endpoints, then included as an
    argument to the OCSPRequest builder, together with <issuer>.
    The last argument to OCSPRequest builder is the hash function
    used to hash specific fields in the request (eg. issuerNameHash, issuerKeyHash).
    The request is encoded to ASN.1 and sent together with a header to 
    indicate the content type as an OCSP request.

    The OCSP response can be signed by:
        1.  The issuer of the certificate beeing checked
        2.  A certificate which is signed by the same issuer as the certificate beeing checked
        3.  A certificate issued by the OCSP responder certificate
        (https://www.ibm.com/support/knowledgecenter/SSFKSJ_9.1.0/com.ibm.mq.explorer.doc/e_auth_info_ocsp.htm)

    Args:
        cert (cryptography.x509.Certificate): The one beeing checked
        issuer (cryptography.x509.Certificate): The issuer of <cert>

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

        # Validate responder certificate (move into response validation)
        endpoint_res["responder_result"] = validate_ocsp_responder(host)
        print(f"Responder valid: {endpoint_res['responder_result']['valid']}")

        # Validate ocsp response signature
        if validate_ocsp_response(ocsp_response, issuer.crypto_cert.public_key()):
            endpoint_res["valid_signature"] = True
            print("OCSP response signature is valid")
        else:
            endpoint_res["valid_signature"] = False
            ocsp_responses.append(endpoint_res)
            print("OCSP response invalid signature")
            continue

        endpoint_res["response_status"] = ocsp_response.response_status.name
        print(endpoint_res["response_status"])

        if endpoint_res["response_status"] == 'SUCCESSFUL':
            endpoint_res["certificate_status"] = ocsp_response.certificate_status.name
            endpoint_res["certificate_status_msg"] = get_res_message(
                endpoint_res["certificate_status"])
            endpoint_res["certificate_serial"] = ocsp_response.serial_number
            endpoint_res["signature_algorithm"] = ocsp_response.signature_algorithm_oid._name
            endpoint_res["produced_at"] = ocsp_response.produced_at
            endpoint_res["this_update"] = ocsp_response.this_update
            endpoint_res["next_update"] = ocsp_response.next_update
            endpoint_res["response_raw"] = ocsp_response.public_bytes(
                serialization.Encoding.DER)

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
        return x509.ocsp.load_der_ocsp_response(response.content)

    except HTTPError as http_err:
        raise c_ext.OCSPRequestResponseError(
            'HTTP error occurred while requesting ocsp response') from http_err

    except Exception as e:
        raise c_ext.OCSPRequestResponseError(
            'Unhandled exception occured while requesting ocsp response') from e


def validate_ocsp_response(ocsp_response, issuer_key):
    tbs_bytes = ocsp_response.tbs_response_bytes
    response_signature = ocsp_response.signature
    sig_hash_algo = ocsp_response.signature_hash_algorithm
    responder_key = issuer_key

    # Valid padding types for RSA -->
    # res_padding = padding.PSS(mgf=padding.MGF1(
    #     SHA256()), salt_length=padding.PSS.MAX_LENGTH)
    res_padding = padding.PKCS1v15()

    try:
        responder_key.verify(response_signature, tbs_bytes,
                             res_padding, sig_hash_algo)

    except InvalidSignature as ivs:
        return False

    # raise c_ex.OCSPInvalidSignature('') from ivs
    return True


def validate_ocsp_responder(host):
    """Validate OCSP responder certificate chain

    Takes in an OCSP endpoint found in the AuthorityInfoAccess
    certificate extension and fetches the certificate chain
    of the responder. The chain is validated and returns a
    dictionary describing the validation result. If validation
    fails, content will contain the failure message

    Args:
        host (str): Host address of ocsp responder

    Returns:
        result (dict): {
            valid (bool): If validation was successful
            content (ValidationPath): Iterable object of certificate path
        }
    """
    responder_certs = [cert_repr(c)
                       for c in fetch_certificate_chain(host)]

    # Avoiding TLS hostname matching of end-certificate
    whitelist = [responder_certs[0].fingerprint["SHA1"]]

    validation_result = validate_certificate_chain(
        host, responder_certs, whitelist)

    valid = validation_result[0]
    result = {
        "valid": valid,
        "content": validation_result[1] if valid else validation_result[1]
    }

    return result


def build_ocsp_request(cert, issuer):
    try:
        builder = x509.ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(
            cert.crypto_cert, issuer.crypto_cert, SHA1())

        req = builder.build()
        return req.public_bytes(serialization.Encoding.DER)

    except Exception as e:
        raise c_ex.OCSPRequestBuildError(
            f"Failed to build OCSP request") from e


def get_trust_store():
    pem_certs = pem.parse_file(certifi.where())

    return [pem_cert.as_bytes() for pem_cert in pem_certs]


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


def rep_cert(cert_obj):
    print(f"\nSubject: {cert_obj.subject}\n")
    print(f"Issuer: {cert_obj.issuer}\n")
    print(f"Version: {cert_obj.version}\n")
    print(f"Serial number: {cert_obj.serial_number}\n")
    print(f"Signature algo: {cert_obj.signature_algorithm}\n")
    print(f"Signature hash: {cert_obj.signature_hash}\n")
    print(f"Expired: {cert_obj.has_expired}\n")
    print(f"Validity period: {cert_obj.validity_period}\n")
    print(f"Public key: {cert_obj.public_key}\n")
    print(f"Fingerprint: {cert_obj.fingerprint}\n")
    print("Extensions: ")
    for ext in cert_obj.extensions.values():
        print(
            f"Name: {ext['name']}, Critical: {ext['critical']}, OID: {ext['OID']}")
        print(f"{ext['value']}\n")


if __name__ == "__main__":
    main()
