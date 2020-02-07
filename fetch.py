import idna
import requests
from socket import socket
from OpenSSL import SSL
from OpenSSL.crypto import x509 as py_x509
from cert_repr import cert_repr
from requests.exceptions import HTTPError

from cryptography import x509 as cryptography_x509
from cryptography.hazmat.primitives.hashes import SHA1, SHA256
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import asymmetric
from urllib.parse import urlsplit

from cryptography.hazmat.backends import default_backend
from certvalidator import CertificateValidator, ValidationContext
from certvalidator import errors as cert_errors
import certifi
import pem

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

import cert_visualize_exceptions as c_ex

# stress test
import json


TRUST_STORE = None


def main():
    global TRUST_STORE
    TRUST_STORE = get_trust_store()

    # Stress test
    uni_domains = []
    with open("uni_domains.json") as json_file:
        uni_json = json.load(json_file)
        for item in uni_json:
            uni_domains.extend([urlsplit(i).netloc for i in item["web_pages"]])

    for domain in uni_domains:
        # domain = "king.edu"
        cert_chain = [cert_repr(cert)
                        for cert in fetch_certificate_chain(domain)]

        if len(cert_chain) <= 1:
            continue

        validation_res = validate_certificate_chain(
            domain, [c.crypto_cert for c in cert_chain])
        if not validation_res[0]:
            print(
                f"Certificate chain provided by {domain} could not be validated!")

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
        print(f"Unable to fetch certificate chain for {domain}: {e}")
        # exit()
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
        cert_chain (list): List of cryptography.x509.Certificate
        whitelist (list): List of hex encoded SHA-1 certificate fingerprint strings

    Returns:
        tuple(bool, ValidationPath):
            bool: If the validation was successful
            ValidationPath: Iterable of certificate objects representing the path
    """
    try:
        der_certs = [cert.public_bytes(
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
        ex = "Unable to find the necessary certificates to build the validation path"
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
                f"OCSP Signing extension: {endpoint_res['verification_result']['sig_ext']}\n")

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
        return cryptography_x509.ocsp.load_der_ocsp_response(response.content)

    except HTTPError as http_err:
        raise c_ext.OCSPRequestResponseError(
            'HTTP error occurred while requesting ocsp response') from http_err

    except Exception as e:
        raise c_ext.OCSPRequestResponseError(
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
        verifi_res = signature_verification([issuer_cert], delegate_end.signature,
                                            delegate_end.tbs_certificate_bytes,
                                            delegate_end.signature_hash_algorithm)
        if verifi_res[0]:
            key_certs.append(delegate_end)
            print("OCSP: Issuer signed response")

        else:
            # Try validating certificate chain of unknown delegate
            delegate_validation_res = validate_certificate_chain(
                host, ocsp_response.certificates)

            if delegate_validation_res[0]:
                key_certs.append(delegate_end)
                print("OCSP: Unknown signed response")

    valid, cert = signature_verification(
        key_certs, signature_bytes, tbs_bytes, sig_hash_algo)

    validation_result = {"valid": valid,
                         "validation_cert": cert, "sig_ext": False}

    # Checking if certificate contains the OCSPSigning extension
    if cert is not None:
        policy_oid = cryptography_x509.oid.ExtensionOID.CERTIFICATE_POLICIES
        try:
            policy_ext = cert.extensions.get_extension_for_oid(policy_oid).value
        except cryptography_x509.extensions.ExtensionNotFound:
            return validation_result

        if any(policy.policy_identifier.dotted_string in
               ("1.3.6.1.5.5.7.3.9", "2.5.29.32.0") for policy in policy_ext):
            validation_result["sig_ext"] = True

    return validation_result


def signature_verification(key_certs, signature_bytes, tbs_bytes, sig_hash_algo):
    # Try validating signature for each available key
    for pub_cert in key_certs:
        if isinstance(pub_cert.public_key(), asymmetric.rsa.RSAPublicKey):
            pss_padding = padding.PSS(mgf=padding.MGF1(
                SHA256()), salt_length=padding.PSS.MAX_LENGTH)

            for pad in (padding.PKCS1v15(), pss_padding):
                if verify_signature(pub_cert.public_key(), signature_bytes,
                                    tbs_bytes, pad, sig_hash_algo):
                    return (True, pub_cert)

        elif isinstance(pub_cert.public_key(), asymmetric.ec.EllipticCurvePublicKey):
            if verify_signature(pub_cert.public_key(), signature_bytes,
                                tbs_bytes, asymmetric.ec.ECDSA(sig_hash_algo)):
                return (True, pub_cert)

        elif isinstance(pub_cert.public_key(), asymmetric.dsa.DSAPublicKey):
            if verify_signature(pub_cert.public_key(), signature_bytes,
                                tbs_bytes, sig_hash_algo):
                return (True, pub_cert)
        else:
            if verify_signature(pub_cert.public_key(), signature_bytes, tbs_bytes):
                return (True, pub_cert)
    else:
        return (False, None)


def verify_signature(pub_key, *verify_args):
    try:
        pub_key.verify(*verify_args)

    except InvalidSignature as ivs:
        return False

    return True


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
