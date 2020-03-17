import idna
import subprocess
from socket import socket
from OpenSSL import SSL, crypto
import visualize_ciphers as vis_ciphers
import visualize_exceptions as vis_ex


def check_hsts(domain):
    """Check http strict transport security

    Function checking if a server supports sending 
    a hsts header when connecting to it. It uses
    curl in a subprocess to fetch the header data,
    and grep to look for the 'strict-transport-security'
    keyword. If it is included, it is supported.

    Args:
        domain (str): The domain you want to check

    Returns:
        (bool): Indicating if it is supported.
    """
    try:
        s_domain = f"https://{domain}"
        hsts_result = subprocess.run(
            ["curl", "-s", "-D-", s_domain], capture_output=True, timeout=300, text=True)

        grep_result = subprocess.run(
            ["grep", "-i", "Strict"], input=hsts_result.stdout, capture_output=True, timeout=300, text=True)

        if grep_result.stdout:
            items = grep_result.stdout.split(" ")[:2]
            if items[0] != 'strict-transport-security:':
                return False

            hsts = items[0].replace(':', "")
            max_age = items[1].split('=')[1].replace(';', "").replace("\n", "")
            result = {hsts: max_age}

            return True

        else:
            return False

    except Exception:
        return False


def get_supported_proto_ciphers(domain, ip):
    """Determine enabled ciphers on server

    Function for determining the enabled ciphers for each
    TLS protocol on a server. It uses the systems openssl
    in a subprocess to call the server for each cipher for each
    protocol and determines if it is enabled by checking the return
    code. A complete cipher list is extracted from openssl to use when
    testing each cipher.
    The method was adapted to python from this resource:
    https://www.ise.io/using-openssl-determine-ciphers-enabled-server/

    Args:
        domain (str): domain to check
        ip (address): ipv4 address

    Returns:
        proto_cipher_support (dict): Every cipher supported for each protocol

    Raises:
        vis_ex.CipherFetchingError: If an error occures during fetching
    """
    str_ip = str(ip)
    supported_protocols = {}
    proto_cipher_support = {}
    connection_info = get_connection_information(domain)

    # pyopenssl to openssl protocols
    protocol_map = {
        "TLSv1.0": "tls1",
        "TLSv1.1": "tls1_1",
        "TLSv1.2": "tls1_2",
        "TLSv1.3": "tls1_3"
    }

    for info in connection_info:
        if info["supported"] and info["protocol"] in protocol_map:
            supported_protocols[info["protocol"]
                                ] = protocol_map[info["protocol"]]
            proto_cipher_support[info["protocol"]] = {}

    try:
        cipher_info = vis_ciphers.get_cipher_suite_info()
        cipher_list = subprocess.run(
            ["openssl", "ciphers", "ALL:eNULL"], capture_output=True, text=True)

        all_ciphers = cipher_list.stdout.split(":")
        all_ciphers[-1] = all_ciphers[-1].replace("\n", "")

        for p_protocol, o_protocol in supported_protocols.items():
            for cipher in all_ciphers:
                try:
                    call = (
                        f"openssl s_client -connect {str_ip}:443 -cipher {cipher} "
                        f"-{o_protocol} < /dev/null > /dev/null 2>&1")

                    proto_cipher = subprocess.run(
                        call, timeout=3, capture_output=True, shell=True, text=True)

                    if proto_cipher.returncode == 0:
                        security = vis_ciphers.evaluate_cipher(
                            cipher, cipher_info)
                        proto_cipher_support[p_protocol][cipher] = security

                except subprocess.TimeoutExpired:
                    pass

        return proto_cipher_support

    except Exception as e:
        raise vis_ex.CipherFetchingError(
            "Failed while processing proto-cipher list") from e


def get_connection_information(domain, timeout=300):
    """Get information about possible connection

    Checks which TLS protocols are supported by the
    server hosting the domain. The checking is done with
    pyOpenSSL by trying to connect with each TLS protocol.
    New versions of OpenSSL does no longer support SSLv2 and
    SSLv3, so no checks were done for those protocols.

    Args:
        domain (str): Domain hosted by a server
        timeout (int): The time in seconds before 
            connection gets closed

    Returns:
        tuple(server_ip, server_info):
            server_ip describes the ip of the server (IPv4)
            server_info is a list of dicts containing server info
    """
    connection_info = []

    transport_protocols = {
        "TLSv1.0": SSL.TLSv1_METHOD,
        "TLSv1.1": SSL.TLSv1_1_METHOD,
        "TLSv1.2": SSL.TLSv1_2_METHOD,
        "TLSv1.3": SSL.SSLv23_METHOD
    }

    hostname = idna.encode(domain)

    for name, protocol in transport_protocols.items():
        proto_spec_info = {}
        s = socket()

        try:
            context = SSL.Context(protocol)
            context.set_timeout(timeout)
            context.verify_mode = SSL.VERIFY_NONE

            conn = SSL.Connection(context, s)
            conn.set_connect_state()
            conn.set_tlsext_host_name(hostname)
            conn.connect((hostname, 443))
            conn.do_handshake()

            protocol_v_name = conn.get_protocol_version_name()
            proto_spec_info["protocol"] = name

            if name == "TLSv1.3":
                if protocol_v_name != "TLSv1.3":
                    proto_spec_info["supported"] = False
                    connection_info.append(proto_spec_info)
                    conn.shutdown()
                    continue

            proto_spec_info["supported"] = True
            connection_info.append(proto_spec_info)

            conn.shutdown()

        except Exception as e:
            proto_spec_info["protocol"] = name
            proto_spec_info["supported"] = False
            connection_info.append(proto_spec_info)

        finally:
            s.close()

    return connection_info
