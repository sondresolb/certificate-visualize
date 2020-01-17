import os
import idna

from socket import socket
from OpenSSL import SSL
from cert_repr import cert_repr


if __name__ == "__main__":
    host_string, port = 'www.github.com', 443
    cert_path = 'certificates'

    hostname = idna.encode(host_string)
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
        break
