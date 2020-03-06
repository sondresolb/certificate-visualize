import idna
from socket import socket
from OpenSSL import SSL, crypto


def get_server_information(domain, timeout=300):
    transport_protocols = {
        "SSLv23": SSL.SSLv23_METHOD,
        "TLSv1.0": SSL.TLSv1_METHOD,
        "TLSv1.1": SSL.TLSv1_1_METHOD,
        "TLSv1.2": SSL.TLSv1_2_METHOD
    }

    hostname = idna.encode(domain)

    for name, protocol in transport_protocols.items():

        context = SSL.Context(protocol)
        context.set_timeout(timeout)
        context.verify_mode = SSL.VERIFY_NONE

        print(f'Connecting to {domain} to get server information...')

        s = socket()

        try:
            conn = SSL.Connection(context, s)
            conn.set_connect_state()
            conn.set_tlsext_host_name(hostname)
            conn.connect((hostname, 443))
            conn.do_handshake()

            print(
                f"\nServer name: {conn.get_servername().decode('utf-8')}")
            print(f"Server IP: {s.getpeername()[0]}")
            print(
                f"\nProtocol version name: {conn.get_protocol_version_name()}")
            print(f"\nProtocol verison: {conn.get_protocol_version()}")
            print(f"\nCipher name: {conn.get_cipher_name()}")
            print(f"\nCipher version: {conn.get_cipher_version()}")
            print(f"\nCipher bits: {conn.get_cipher_bits()}")
            print(f"\nCipher List:\n{conn.get_cipher_list()}")

            conn.shutdown()

        except Exception as e:
            print(f"Failed. Protocol {name}: {str(e)}")
        finally:
            s.close()
