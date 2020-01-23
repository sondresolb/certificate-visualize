import os
import idna

from socket import socket
from OpenSSL import SSL
from cert_repr import cert_repr


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
    for ext in cert_obj.extensions:
        print(
            f"Name: {ext['name']}, Critical: {ext['critical']}, OID: {ext['OID']}")
        print(f"{ext['value']}\n")


if __name__ == "__main__":
    host_string, port = 'www.fronter.com', 443

    hostname = idna.encode(host_string)

    # SSL.TLSv1_2_METHOD, SSL.SSLv23_METHOD
    context = SSL.Context(SSL.SSLv23_METHOD)
    context.verify_mode = SSL.VERIFY_NONE

    print(f'Connecting to {host_string} to get certificate...')
    cert_list = []

    try:
        s = socket()
        conn = SSL.Connection(context, s)
        conn.set_connect_state()
        # Server name indicator support (SNI)
        conn.set_tlsext_host_name(hostname)

        conn.connect((hostname, port))
        conn.do_handshake()
        # print(conn.get_protocol_version_name())
        # print(conn.get_servername.get_components())
        cert_list = conn.get_peer_cert_chain()

    except Exception as e:
        print(f"Exception: {e}")
        exit()
    finally:
        s.close()
        conn.close()

    for cert in cert_list:
        cert_obj = cert_repr(cert)
        rep_cert(cert_obj)
