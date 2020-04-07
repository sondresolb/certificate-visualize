import idna
import pem
import requests
import certifi
from socket import socket

import visualize_exceptions as vis_ex
from visualize_certificate import Cert_repr

from OpenSSL import SSL, crypto

from cryptography import x509
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import asymmetric, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from certvalidator import errors as cert_errors
from certvalidator import CertificateValidator, ValidationContext


TRUST_STORE = None


def ocsp_callback(connection, ocsp_data, data):
    try:
        ocsp_staple = x509.ocsp.load_der_ocsp_response(ocsp_data)
        data["ocsp_staple"] = ocsp_staple
        return True
    except ValueError:
        data["ocsp_staple"] = None
        return True


def fetch_certificate_chain(domain, timeout=300):
    """Connect to a server and ask for certificate chain

    Takes in a domain which gets idna encoded, connects to the
    server using SSL v2 or v3 and asks for the certificate chain of
    the server. The chain is then sorted. If the chain only contains one
    certificate, it will try to check the AIA extension for a refrence to
    an intermedia certificate.

    Args:
        domian (str): The domain you want the certificate chain for

    Returns:
        cert_chain (list): sorted list of cert_repr objects

    Raises:
        (visualize_exceptions.NoCertificatesError):
            If no certificates were given by the server

        (visualize_exceptions.IntermediateFetchingError):
            If fetching of intermediate certificate failed

        (visualize_exceptions.CertificateFetchingError):
            If the connection failed, parsing failed or any other
            exception occured during the fetching.
    """
    certificates = []
    conn_details = {}

    hostname = idna.encode(domain)
    # SSL.TLSv1_2_METHOD, SSL.SSLv23_METHOD
    context = SSL.Context(SSL.SSLv23_METHOD)
    context.set_timeout(timeout)
    context.verify_mode = SSL.VERIFY_NONE
    context.set_ocsp_client_callback(ocsp_callback, data=conn_details)

    print(f'Connecting to {domain} to get certificate chain...')

    try:
        s = socket()
        conn = SSL.Connection(context, s)
        conn.set_connect_state()
        # Server name indicator support (SNI)
        conn.set_tlsext_host_name(hostname)
        conn.connect((hostname, 443))
        ocsp_staple_data = conn.request_ocsp()
        conn.do_handshake()
        certificates = conn.get_peer_cert_chain()

        # Connection details
        conn_details["server_name"] = conn.get_servername().decode('utf-8')
        conn_details["ip"] = s.getpeername()[0]
        conn_details["protocol"] = conn.get_protocol_version_name()
        conn_details["cipher"] = conn.get_cipher_name()

        if len(certificates) == 0:
            raise vis_ex.NoCertificatesError(
                f"No certificates found for domain: {domain}")

        cert_chain = [Cert_repr(cert) for cert in certificates]

        if len(cert_chain) == 1:
            inter_cert = fetch_intermediate_cert(cert_chain[0])
            cert_chain.append(inter_cert)

        try:
            cert_chain = sort_chain(cert_chain, domain)
        except vis_ex.InvalidCertificateChain as icc:
            print(str(icc))

        return cert_chain, conn_details

    except vis_ex.IntermediateFetchingError as ife:
        print(f"Failed to fetch intermediate certificate: {str(ife)}")
        return cert_chain, conn_details
    except Exception as e:
        raise vis_ex.CertificateFetchingError(
            f"Error occured while getting certificates for {domain}: {type(e)}: {e}") from e
    finally:
        s.close()


def fetch_intermediate_cert(end_cert):
    """Get intermediate certificate if only one was served by the server

    Takes in an end entity certificate of a chain and looks up the
    Authority information access extension to fetch the intermediate
    certificate. The fetched certificate is encoded into a crypto.x509
    certificate object and then parsed into a cert_repr object.

    Args:
        end_cert (cert_repr): The end entity certificate

    Returns:
        (cert_repr): The parsed intermediate certificate

    Raises:
        (visualize_exceptions.IntermediateFetchingError):
            If there is no AIA extension or the fetching failed
    """
    intermediate_cert = None
    cert_ext = end_cert.extensions
    aia_ext = cert_ext.get("authorityInfoAccess", None)
    if aia_ext is None:
        raise vis_ex.IntermediateFetchingError(
            "No intermediate AIA certificate info found")

    aia_ext = aia_ext["value"]

    for endpoint in aia_ext:
        if endpoint["access_method"] == "caIssuers":
            intermediate_cert = endpoint["access_location"]
            break

    if intermediate_cert is None:
        raise vis_ex.IntermediateFetchingError(
            "No intermediate certificate found")

    try:
        response = requests.get(intermediate_cert)
        response.raise_for_status()
        return Cert_repr(crypto.load_certificate(crypto.FILETYPE_ASN1, response.content))

    except Exception as e:
        raise vis_ex.IntermediateFetchingError(
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
            (bool): If the validation was successful
            (ValidationPath): Iterable of certificate objects representing the path
    """
    try:
        der_certs = [cert.public_bytes(
            serialization.Encoding.DER) for cert in cert_chain]

        valid_context = ValidationContext(
            trust_roots=TRUST_STORE, whitelisted_certs=whitelist, allow_fetching=True)

        cert_validator = CertificateValidator(
            end_entity_cert=der_certs[0], intermediate_certs=der_certs[1:], validation_context=valid_context)

        result = cert_validator.validate_tls(domain)

        # for res in result:
        #     print(res.subject.human_friendly)

        return (True, result)

    except cert_errors.PathBuildingError as pbe:
        ex = "Unable to find the necessary certificates to build the validation path"
        return (False, ex, str(pbe))
    except cert_errors.RevokedError as re:
        ex = "The certificate or a certificate in the chain has been revoked"
        return (False, ex, str(re))
    except cert_errors.PathValidationError as pve:
        ex = "An error occured while validating the certificate path"
        return (False, ex, str(pve))
    except cert_errors.InvalidCertificateError as ice:
        ex = "Certificate is not valid for TLS or the hostname does not match"
        return (False, ex, str(ice))
    except Exception as e:
        ex = f"Unhandled exception raised: {str(e)}"
        return (False, ex, str(e))


def signature_verification(key_certs, signature_bytes, tbs_bytes, sig_hash_algo):
    """Verify the signature given a public key and some bytes

    A function for verifying the signature of some data given the public
    key that signed the data, the signature, the bytes that was signed and
    the hash algorithm used. The function will run over a list of certificates
    and extract the public key for each. It will check the type of the key and
    try to verify the signature. If the key is of type RSAPublicKey, two
    different padding schemes will be tested. The return value is a tuple where
    the first value indicates if the verification was successful, and the second
    contains the certificate that verified the signaure or None.

    Args:
        key_certs (list): List of possible certificates that signed the data
        signature_bytes (bytes): The signature as bytes
        tbs_bytes (bytes): The data that was signed to produce signature_bytes
        sig_hash_algo (cryptography.hazmat.primitives.hashes.HashAlgorithm): Hash used

    Returns:
        tuple(bool, cryptography.x509 certificate OR None):
            (bool): If the signature could be verified
            (certificate): The certificate used to sign the data
    """
    # Try validating signature for each available key
    for pub_cert in key_certs:
        if isinstance(pub_cert.public_key(), asymmetric.rsa.RSAPublicKey):
            pss_padding = asymmetric.padding.PSS(mgf=asymmetric.padding.MGF1(
                SHA256()), salt_length=asymmetric.padding.PSS.MAX_LENGTH)

            for pad in (asymmetric.padding.PKCS1v15(), pss_padding):
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
    """Wrapper function around cryptography's verify

    A function that wrappes around the cryptography public key
    verification function. This enables the verification function
    to be used regardless of the type of key used. (E.g., The RSA
    key must take in padding as an additional argument to verify()).
    The verify function raises InvalidSignature if the verification
    failed.

    Args:
        pub_key (cryptography public key): The key used for verification
        *verify_args (list): List of additional arguments passed to verify

    Returns:
        (bool): If the verification was successful or not
    """
    try:
        pub_key.verify(*verify_args)

    except InvalidSignature as ivs:
        return False

    return True


def set_trust_store():
    """Set custom trusted root store

    If called, this function will set the currently active
    trust store to be the one provided by the certifi package.
    Certifi is a carefully curated collection of Root Certificates
    for validating the trustworthiness of SSL certificates while
    verifying the identity of TLS hosts. It has been extracted from
    the python Requests project.
    """
    global TRUST_STORE
    pem_certs = pem.parse_file(certifi.where())
    TRUST_STORE = [pem_cert.as_bytes() for pem_cert in pem_certs]


def get_full_validation_path(validation_path):
    parsed_list = []

    try:
        for v_cert in validation_path:
            parsed_cert = Cert_repr(crypto.X509.from_cryptography(x509.load_der_x509_certificate(
                v_cert.dump(), default_backend())))

            parsed_list.append(parsed_cert)

    except Exception as e:
        parsed_list.append("Failed to parse")

    parsed_list.reverse()

    cert_path = {
        "end_cert": parsed_list[0],
        "intermediates": parsed_list[1:-1],
        "root": parsed_list[-1]
    }

    return cert_path


def sort_chain(cert_chain, domain):
    """Sort certificate chain

    Takes in a certificate chain and checks if the order
    is correct. If not, then it sorts them in the 
    correct order. Duplicates are removed from the chain.

    Args:
        cert_chain (list): List of cert_repr objects

    Returns:
        (list): Either the original list or a new chain

    Raises:
        (visualize_exceptions.InvalidCertificateChain):
            If chain could not be sorted correctly
    """
    final_cert = None
    new_chain = []

    # Check if order is correct
    for index, cert in enumerate(cert_chain):
        if index == len(cert_chain)-1:
            return cert_chain
        elif cert.issuer != cert_chain[index+1].subject:
            break

    # Extract all subjects to determine the last certificate
    all_subjects = [cert.subject for cert in cert_chain]

    for cert in cert_chain:
        if cert.issuer not in all_subjects or cert.issuer == cert.subject:
            final_cert = cert
            break

    if final_cert is None:
        raise vis_ex.InvalidCertificateChain(
            f"Certificate chain for {domain} is not a correct chain:\n"
            f"{[(c.subject['commonName'], c.issuer['commonName']) for c in cert_chain]}")

    # Map out issuers and remove duplicates
    # key: issuer(str), value: subject(obj)
    issuer_map = {cert.issuer["commonName"]:
                  cert for cert in cert_chain if cert.subject != final_cert.subject}

    try:
        current_cert = issuer_map[final_cert.subject["commonName"]]
        new_chain.append(final_cert)
        new_chain.insert(0, current_cert)

        for _ in range(len(issuer_map)-1):
            current_cert = issuer_map[current_cert.subject["commonName"]]
            new_chain.insert(0, current_cert)

        return new_chain

    except KeyError:
        raise vis_ex.InvalidCertificateChain(
            f"Certificate chain for {domain} is not a correct chain:\n"
            f"{[(c.subject['commonName'], c.issuer['commonName']) for c in cert_chain]}")


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
