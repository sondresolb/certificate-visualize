import os
import idna

from socket import socket
from OpenSSL import SSL
from cert_repr import cert_repr

import requests
from cryptography.x509 import ocsp
from cryptography import x509
from cryptography.hazmat.primitives.hashes import SHA1, SHA224, SHA256, SHA384, SHA512
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
from urllib.parse import urlsplit


def main():
    cert_list = []

    for cert in fetch_certificate_chain("www.google.com"):
        cert_list.append(cert_repr(cert))

    for res in get_ocsp_response(cert_list[0], cert_list[1]):
        print(res)


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


def get_ocsp_response(cert, issuer):
    ocsp_responses = []
    ocsp_endpoints = []

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

    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(
        cert.crypto_cert, issuer.crypto_cert, SHA1())
    req = builder.build()
    req_encoded = req.public_bytes(serialization.Encoding.DER)

    for endpoint in ocsp_endpoints:
        endpoint_res = {}
        headers = {'Host': endpoint[0],
                   'Content-Type': 'application/ocsp-request'}

        response = requests.post(
            endpoint[1], data=req_encoded, headers=headers)

        ocsp_response = ocsp.load_der_ocsp_response(response.content)
        endpoint_res["endpoint"] = endpoint[1]
        endpoint_res["response_status"] = ocsp_response.response_status.name
        endpoint_res["certificate_status"] = ocsp_response.certificate_status.name
        endpoint_res["signature_algorithm"] = ocsp_response.signature_algorithm_oid._name
        endpoint_res["produced_at"] = ocsp_response.produced_at
        endpoint_res["this_update"] = ocsp_response.this_update
        endpoint_res["next_update"] = ocsp_response.next_update
        # None if request was successful
        endpoint_res["revocation_time"] = ocsp_response.revocation_time
        endpoint_res["revocation_reason"] = ocsp_response.revocation_reason
        ocsp_responses.append(endpoint_res)

    return ocsp_responses


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
