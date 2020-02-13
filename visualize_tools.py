import idna
import pem
import requests
import certifi
from socket import socket
from OpenSSL import SSL, crypto

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import asymmetric, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

from certvalidator import CertificateValidator, ValidationContext
from certvalidator import errors as cert_errors
from visualize_exceptions import CertificateFetchingError, NoCertificatesError
from visualize_exceptions import IntermediateFetchingError
from visualize_certificate import Cert_repr


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

        if len(certificates) == 0:
            raise NoCertificatesError(
                f"No certificates found for domain: {domain}")

        cert_chain = [Cert_repr(cert) for cert in certificates]

        if len(cert_chain) == 1:
            inter_cert = fetch_intermediate_cert(cert_chain[0])
            cert_chain.append(inter_cert)

        return cert_chain

    except CertificateFetchingError as cfe:
        raise cfe
    except NoCertificatesError as nce:
        raise nce
    except IntermediateFetchingError as ife:
        print("Failed to fetch intermediate")
        return cert_chain
    except Exception as e:
        raise CertificateFetchingError(
            f"Error occured while getting certificates for: {domain}: {e}") from e
    finally:
        s.close()
        conn.close()


def fetch_intermediate_cert(end_cert):
    intermediate_cert = None
    aia_ext = end_cert.extensions["authorityInfoAccess"]["value"]

    for endpoint in aia_ext:
        if endpoint["access_method"] == "caIssuers":
            intermediate_cert = endpoint["access_location"]
            break

    if intermediate_cert is None:
        raise IntermediateFetchingError("No intermediate certificate found")

    try:
        response = requests.get(intermediate_cert)
        response.raise_for_status()
        return Cert_repr(crypto.load_certificate(crypto.FILETYPE_ASN1, response.content))

    except Exception as e:
        raise IntermediateFetchingError(
            f"Failed to get intermediate certificate: {str(e)}") from e


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
        ex = "Unable to find the necessary certificates to build the validation path"
        return (False, ex, str(pbe))
    except cert_errors.PathValidationError as pve:
        ex = "An error occured while validating the certificate path"
        return (False, ex, str(pve))
    except cert_errors.InvalidCertificateError as ice:
        ex = "Certificate is not valid"
        return (False, ex, str(ice))
    except Exception as e:
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
