import idna
import pem
import certifi
from socket import socket
from OpenSSL import SSL

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import asymmetric, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

from certvalidator import CertificateValidator, ValidationContext
from certvalidator import errors as cert_errors


TRUST_STORE = None


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


def set_trust_store():
    global TRUST_STORE

    pem_certs = pem.parse_file(certifi.where())
    TRUST_STORE = [pem_cert.as_bytes() for pem_cert in pem_certs]
