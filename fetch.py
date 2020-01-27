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
    # (NOTICE) Certificates not always in order
    cert_list = []

    for cert in fetch_certificate_chain("www.google.com"):
        cert_list.append(cert_repr(cert))

    r = check_ocsp_status(cert_list[0], cert_list[1])


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


def check_ocsp_status(cert, issuer):
    ocsp_endpoints = []

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
        headers = {'Host': endpoint[0],
                   'Content-Type': 'application/ocsp-request'}

        response = requests.post(
            endpoint[1], data=req_encoded, headers=headers)

        print(f"Request status: {response.status_code}")

        ocsp_response = ocsp.load_der_ocsp_response(response.content)
        response_status = ocsp_response.response_status
        certificate_status = ocsp_response.certificate_status
        print(f"response_status: {response_status}")
        print(f"certificate_status: {certificate_status}")

    return None


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
    # host_string, port = 'www.fronter.com', 443

    # hostname = idna.encode(host_string)

    # # SSL.TLSv1_2_METHOD, SSL.SSLv23_METHOD
    # context = SSL.Context(SSL.SSLv23_METHOD)
    # context.verify_mode = SSL.VERIFY_NONE

    # print(f'Connecting to {host_string} to get certificate...')
    # cert_list = []

    # try:
    #     s = socket()
    #     conn = SSL.Connection(context, s)
    #     conn.set_connect_state()
    #     # Server name indicator support (SNI)
    #     conn.set_tlsext_host_name(hostname)

    #     conn.connect((hostname, port))
    #     conn.do_handshake()
    #     # print(conn.get_protocol_version_name())
    #     # print(conn.get_servername.get_components())
    #     cert_list = conn.get_peer_cert_chain()

    # except Exception as e:
    #     print(f"Exception: {e}")
    #     exit()
    # finally:
    #     s.close()
    #     conn.close()

    # obj_list = []
    # for cert in cert_list:
    #     obj_list.append(cert_repr(cert))

    # for info in obj_list[0].extensions["authorityInfoAccess"]["value"]:
    #     if "OCSP" in info["access_method"]:
    #         ocsp_endpoint = info["access_location"]
    #         host = urlsplit(ocsp_endpoint).netloc

    # builder = ocsp.OCSPRequestBuilder()
    # builder = builder.add_certificate(
    #     obj_list[0].crypto_cert, obj_list[1].crypto_cert, SHA1())
    # req = builder.build()
    # req_encoded = req.public_bytes(serialization.Encoding.DER)

    # headers = {'Host': host,
    #            'Content-Type': 'application/ocsp-request'}

    # response = requests.post(
    #     ocsp_endpoint, data=req_encoded, headers=headers)

    # print(response.status_code)

    # ocsp_response = ocsp.load_der_ocsp_response(response.content)
    # status = ocsp_response.response_status
    # print(status)
