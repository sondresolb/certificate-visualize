import sys

from visualize_exceptions import EvaluationFailureError


def score_results(end_cert, results):
    total_score = {}

    try:

        total_score["certificate"] = score_end_certificate(end_cert)

        # After everything is evaluated. apply weights and sum up
        print(total_score)
        return None

    except EvaluationFailureError as efe:
        print(str(efe))
        return str(efe)


def score_end_certificate(cert):
    """Evaluate a complete certificate

    Signature hash
    - only md2, md5 and the sha-family can sign certificates
    - Source: https://tools.ietf.org/html/rfc3279 (page 3)

    - Evaluation:
        - md2, md5:                 (raise error)
        - SHA2                      : 80
        - SHA3 etc.                 : 100

    Public key (in bits)
    - Source: https://tools.ietf.org/html/rfc4492#page-3
    - Source: https://tools.ietf.org/html/rfc8032#page-3
    - Evaluation:
        - RSA/DSA
            - x < 1024              : 0
            - 1024 <= x < 2048      : 50
            - 2048 <= x < 4096      : 80
            - 4096 <= x             : 100

        - EllipticCurve
            - x < 163               : 0
            - 163 <= x < 233        : 50
            - 233 <= x < 384        : 90
            - 384 <= x              : 100

        - EdDSA
            - EdDSA25519            : 80
            - EdDSA448              : 100

    Certificate type
    - Evaluation:
        - Not indicated             : 60
        - Domain-validated          : 70
        - Individual-validated      : 80
        - Organization-validated    : 80
        - Extended-validation       : 100

    Must-staple
    - Evaluation:
        - true                      : 100
        - false                     : 0

    Evaluation failure (raise error)
    - Use of (md2, md5)
    - No revocation information
    - Includes CTpoison extension
    - Certificate is expired

    Weights
    - signature_hash                : 35%
    - public_key                    : 55%
    - certificate_type              : 5%
    - must_staple                   : 5%
    - version                       : raise
    - ct_poison                     : raise
    - has_expired                   : raise
    """
    cert_score = {}

    try:
        evaluate_certificate_version(cert)
        evaluate_has_expired(cert)
        evaluate_ct_poison(cert)

        cert_score["signature_hash"] = evaluate_signature_hash(cert)*0.35

        cert_score["public_key"] = evaluate_public_key(cert)*0.55

        cert_score["certificate_type"] = evaluate_certificate_type(
            cert)*0.05

        cert_score["must_staple"] = evaluate_must_staple(cert)*0.05

    except EvaluationFailureError as efe:
        raise EvaluationFailureError(
            f"Certificate evaluation failure.\n{str(efe)}")

    return (cert_score, sum(cert_score.values()))


def evaluate_certificate_version(cert):
    """x.509 Certificate Version

    Version 3 is the only certificate version that should be
    seen in practise. 
    """
    version = cert.version

    if cert.version != "v3":
        raise EvaluationFailureError(f"Use of incorrect version {version} "
                                     f"in certificate: {cert.subject['commonName']}")


def evaluate_signature_hash(cert):
    """Signature hash evaluation

    The list of hashes in the deprecated list is no longer
    secure, and should not be used to sign a certificate.
    It is still common to see root certificates with long
    validity periods signed with sha1. They are excluded from
    this check.
    SHA1 has proven to be insecure and should not be used
    to sign new certificates. end-user certificates signed with this
    hash will be given a score of 0.
    The other NIST approved hashes for end-user certificate
    signing differ little in tangible security benefit. For this
    reason, they all recieve a score of 100. 
    """
    deprecated = ["md2", "md5"]

    sig_hash = cert.signature_hash

    if sig_hash[0] in deprecated:
        raise EvaluationFailureError(f"Deprecated hash {sig_hash} used "
                                     f"to sign certificate: {cert.subject['commonName']}")

    if sig_hash == "sha1":
        return 0
    else:
        return 100


def evaluate_has_expired(cert):
    has_expired = cert.has_expired

    if has_expired:
        raise EvaluationFailureError(
            f"The certificte {cert.subject['commonName']} has expired")


def evaluate_ct_poison(cert):
    ct_poison = cert.ct_poison

    if ct_poison:
        raise EvaluationFailureError(f"Certificate {cert.subject['commonName']} "
                                     "contains the ct_poison flag and should "
                                     "not be used as a complete certificate")


def evaluate_certificate_type(cert):
    """Evaluate certificate type

    A certificate type is obtained by going through an audit process
    with the Certificate Authority that will issue the final certificate.
    The thoroughness of this process is dependent on the certificate type
    applied for. The scores are meant to reflect this.
    """
    cert_type = cert.certificate_type

    if cert_type == "Not indicated":
        return 60
    elif cert_type == "Domain-validated":
        return 70
    elif cert_type == "Individual-validated":
        return 80
    elif cert_type == "Organization-validated":
        return 80
    elif cert_type == "Extended-validation":
        return 100


def evaluate_must_staple(cert):
    """Evaluate must-staple

    The must-staple flag indicates that the server must serve the 
    certificate with a ocsp response. This significantly improves
    the privacy of the client. Must-staple is not commenly seen
    in the wild.
    """
    must_staple = cert.must_staple

    if must_staple:
        return 100
    else:
        return 0


def evaluate_public_key(cert):
    """Public key evaluation

    Evaluating the security provided by the public key by looking
    at the type and number of bits. Modeled around the symetric
    key security level. 

    RSA, DSA, EC evaluation:
        - source: https://tools.ietf.org/html/rfc4492#page-3

    EdDSA evaluation:
        - source: https://tools.ietf.org/html/rfc8032#page-3
    """
    public_key = cert.public_key

    key_type = public_key["type"]

    if key_type == "RSA" or key_type == "DSA":
        key_size = public_key["size"]

        if key_size < 1024:
            return 0

        elif 1024 <= key_size < 2048:
            return 50

        elif 2048 <= key_size < 4096:
            return 80

        elif 4096 <= key_size:
            return 100

    elif key_type == "EllipticCurve":
        key_size = public_key["size"]

        if key_size < 163:
            return 0

        elif 163 <= key_size < 233:
            return 50

        elif 233 <= key_size < 384:
            return 90

        elif 384 <= key_size:
            return 100

    # Around 128 bit security level
    elif key_type == "EdDSA25519":
        return 80

    # Around 224 bit security level
    elif key_type == "EdDSA448":
        return 100
