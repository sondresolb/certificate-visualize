import idna
import requests
from socket import socket
from OpenSSL import SSL
from cert_repr import cert_repr
from requests.exceptions import HTTPError

from cryptography import x509
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives import serialization
from urllib.parse import urlsplit

from cryptography.hazmat.backends import default_backend
from certvalidator import CertificateValidator, ValidationContext
import certifi
import pem


def main():
    trust_store = get_trust_store()

    domain = "www.github.com"
    cert_list = [cert_repr(cert) for cert in fetch_certificate_chain(domain)]

    ocsp_res = [res for res in get_ocsp_response(cert_list)]

    validate_certificate_chain(domain, cert_list, trust_store, ocsp_res)


def fetch_certificate_chain(domain):
    certificates = []

    hostname = idna.encode(domain)
    # SSL.TLSv1_2_METHOD, SSL.SSLv23_METHOD
    context = SSL.Context(SSL.SSLv23_METHOD)
    context.verify_mode = SSL.VERIFY_NONE

    print(f'Connecting to {domain} to get certificate...')

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


def validate_certificate_chain(domain, cert_list, trust_store, ocsp_res):
    try:
        ocsp_raw_response_list = [ocsp_raw["response_raw"]
                                  for ocsp_raw in ocsp_res]

        der_certs = [cert.crypto_cert.public_bytes(
            serialization.Encoding.DER) for cert in cert_list]

        valid_context = ValidationContext(
            trust_roots=trust_store, ocsps=ocsp_raw_response_list, revocation_mode="hard-fail")

        cert_validator = CertificateValidator(
            end_entity_cert=der_certs[0], intermediate_certs=der_certs[1:], validation_context=valid_context)

        result = cert_validator.validate_tls(domain)

    except certvalidator.errors.PathValidationError:
        print("Exception: An error occured while validating the certificate path")
        return False
    except certvalidator.errors.RevokedError:
        print("Exception: A certificate in the path has been revoked")
        return False
    except certvalidator.errors.InvalidCertificateError:
        print("Exception: Certificate is not valid")
        return False
    except Exception as e:
        print(f"Unhandled exception raised: {str(e)}")
        return False

    for res in result:
        print(res.subject.human_friendly)


def get_ocsp_response(cert_list):
    ocsp_responses = []
    ocsp_endpoints = []

    cert = cert_list[0]
    issuer = cert_list[1]

    if cert.extensions.get("authorityInfoAccess", None):
        for info in cert.extensions["authorityInfoAccess"]["value"]:
            if "OCSP" in info["access_method"]:
                ocsp_endpoint = info["access_location"]
                host = urlsplit(ocsp_endpoint).netloc
                ocsp_endpoints.append((host, ocsp_endpoint))

    # OCSP not supported
    if not ocsp_endpoints:
        print("No OCSP enpoint found")
        return None

    builder = x509.ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(
        cert.crypto_cert, issuer.crypto_cert, SHA1())
    req = builder.build()
    req_encoded = req.public_bytes(serialization.Encoding.DER)

    for endpoint in ocsp_endpoints:
        endpoint_res = {}
        headers = {'Host': endpoint[0],
                   'Content-Type': 'application/ocsp-request'}

        try:
            response = requests.post(
                endpoint[1], data=req_encoded, headers=headers)

            response.raise_for_status()
        except HTTPError as http_err:
            print(f"HTTP error occurred: {http_err}")
            continue
        except Exception as e:
            print(f'Unhandled exception:\n{e}')
            continue

        ocsp_response = x509.ocsp.load_der_ocsp_response(response.content)
        endpoint_res["endpoint"] = endpoint[1]
        endpoint_res["response_status"] = ocsp_response.response_status.name

        if endpoint_res["response_status"] == 'SUCCESSFUL':
            endpoint_res["certificate_status"] = ocsp_response.certificate_status.name
            endpoint_res["certificate_status_msg"] = get_res_message(
                endpoint_res["certificate_status"])
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

    return ocsp_responses


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
