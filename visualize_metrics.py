import sys
from datetime import timedelta

from visualize_exceptions import EvaluationFailureError


def evaluate_results(end_cert, results, validation_res):
    """Evaluation process

    Each element of the scan process is broken down into different categories:
        - The end-entity certificate                    : 35%
        - Certificate Revocation List (CRL)             : 12%
        - Online Certificate Status Protocol (OCSP)     : 12%
        - Certificate Transparency (CT)                 : 5%
        - Certificate Authority Authorization (CAA)     : 3%
        - OCSP-Staple                                   : 2%
        - HTTPS Strict Transport Security (HSTS)        : 8.5%
        - Protocol and cipher support                   : 22.5%

    Each category is then broken down into its most important elements where
    each elements is given a score from 0-100. Each elements is also weighted
    with a percentage that adds up to 100%. When each category has been assigned
    a score, the weigths for each category (seen above) are applied and the result
    is summed up. This is the total score of the certificate/SSL security.

    There are several conditions that have to be met in order to assign a complete score.
    If they are not met, an exception is raised with an explanation of why it failed.
    If this is the case, the score will be 0.

    If certificate validation has already failed, then the score is also 0.
    """
    weighted_score = {
        "certificate":  {"weight": 0.35},
        "crl":          {"weight": 0.12},
        "ocsp":         {"weight": 0.12},
        "ct":           {"weight": 0.05},
        "caa":          {"weight": 0.03},
        "staple":       {"weight": 0.02},
        "hsts":         {"weight": 0.085},
        "pc":           {"weight": 0.225}
    }

    evaluation_result = {}

    if not validation_res:
        raise EvaluationFailureError("Certificate validation failure")

    # Certificate
    certificate_dict, certificate_score = score_end_certificate(
        end_cert, results)
    evaluation_result["certificate"] = certificate_dict
    weighted_score["certificate"]["score"] = certificate_score

    # CRL
    crl_dict, crl_score = score_crl(results)
    evaluation_result["crl"] = crl_dict
    weighted_score["crl"]["score"] = crl_score

    # OCSP
    ocsp_dict, ocsp_score = score_ocsp(results)
    evaluation_result["ocsp"] = ocsp_dict
    weighted_score["ocsp"]["score"] = ocsp_score

    # After everything is evaluated. apply weights and sum up
    print(evaluation_result)
    print(weighted_score)

    return (None, None)


def score_end_certificate(cert, results):
    """Evaluate a complete certificate

    Signature hash
    - only md2, md5 and the sha-family can sign certificates
    - Source: https://tools.ietf.org/html/rfc3279 (page 3)

    - Evaluation:
        - md2, md5:                 (raise error)
        - SHA1                      : 0
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
        - Not indicated             : 50
        - Domain-validated          : 70
        - Individual-validated      : 80
        - Organization-validated    : 80
        - Extended-validation       : 100

    Revocation_support
    - Evaluation:
        - CRL and OCSP              : 100
        - OCSP                      : 80
        - CRL                       : 50
        - None                      : raise

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
    - signature_hash                : 30%
    - public_key                    : 45%
    - certificate_type              : 3%
    - revocation_support            : 17% or raise
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

        cert_score["signature_hash"] = evaluate_cert_signature_hash(cert)*0.30

        cert_score["public_key"] = evaluate_public_key(cert)*0.45

        cert_score["certificate_type"] = evaluate_certificate_type(
            cert)*0.03

        cert_score["revocation_support"] = evaluate_revocation_support(
            cert, results)*0.17

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


def evaluate_cert_signature_hash(cert):
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


def evaluate_revocation_support(cert, results):
    """Evaluate revocation support

    Online Certificate Protocol (OCSP) and Certificate Revocation List (CRL)
    are the two methods of revocation found in an end-entity certificate.
    Having both methods available are good for availability of revocation
    information. OCSP is the best way to verify that a certificate is not revoked
    given that it provides timely revocation info and is updated quickly and
    regularly. CRL is a good alternative, but falls short of the two points above
    and can get very large. Making the process slower and demanding more resources.
    The evaluation will fail if there is no revocation methods in the certificate.
    If that is the case, there is no way to verify if the certificate is safe to use.
    """
    crl_support = results["crl"][0]
    ocsp_support = results["ocsp"][0]

    if crl_support and ocsp_support:
        return 100
    elif ocsp_support:
        return 80
    elif crl_support:
        return 50
    else:
        raise EvaluationFailureError(
            f"No revocation methods found in certificate {cert.subject['commonName']}")


def evaluate_has_expired(cert):
    """Evaluate if the certificate is expired

    The evaluation fails if the certificate is expired. An expired certificate can
    no longer provide any security guarantees and should never be used to secure
    a connection to a server.
    """
    has_expired = cert.has_expired

    if has_expired:
        raise EvaluationFailureError(
            f"The certificte {cert.subject['commonName']} has expired")


def evaluate_ct_poison(cert):
    """Evaluate if certificate contains ct-poison flag

    The evaluation fails if the certificate contains the ct-poison flag. The
    flag signals that the certificate is actually a pre-certificate used to
    obtain a complete certificate from a CA or to obtain a Signed Certificate
    timestamp from a Certificate Transparency log. 
    """
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
        return 50
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


def score_crl(results):
    """Evaluate CRL results from end-entity certificate

    The largest publication interval for a crl in 1 week
        - source: https://tools.ietf.org/html/rfc5280#page-14

    Number of endpoints (more than one)
    - Evaluation:
        - one endpoint                          : 50
        - two or more                           : 100

    Signature hash
    - Evaluation:
        - md2, md5:                             : 0
        - SHA2                                  : 80
        - SHA3 etc.                             : 100

    Update iterval (next_update - last_update)
    - Evaluation:
        - Less or equal to 1 week               : 100
        - More than 1 week                      : 0

    Weights
    - endpoints                                 : 90%
    - reliability                               : 10%
    """
    crl_support, _, crl_data = results["crl"]

    if not crl_support:
        return ({"not_supported": 0}, 0)

    crl_score = {}

    endpoint_dict, endpoint_score = evaluate_crl_endpoints(crl_data)
    crl_score["endpoints"] = endpoint_dict
    endpoint_score = endpoint_score*0.90

    crl_score["reliability"] = evaluate_crl_reliability(crl_data)*0.10

    return (crl_score, sum((endpoint_score, crl_score["reliability"])))


def evaluate_crl_reliability(crl_data):
    if len(crl_data) >= 2:
        return 100
    else:
        return 50


def evaluate_crl_endpoints(crl_data):
    """Evaluate crl endpoints

    Assign a score for each crl endpoint and apply weights. Combine them into
    one score by caluculating the mean.

    Weights
    - Signature hash                            : 80%
    - Update interval                           : 20%
    """
    endpoint_scores = {}

    for endpoint in crl_data:
        end_p = endpoint["endpoint"]
        endpoint_scores[end_p] = {}
        endpoint_scores[end_p]["signature_hash"] = evaluate_revocation_hash(
            endpoint)*0.80
        endpoint_scores[end_p]["update_interval"] = evaluate_update_interval(
            endpoint)*0.20

    total_score = 0
    for endpoint in endpoint_scores.values():
        for item in endpoint.values():
            total_score += item

    total_score = total_score / len(crl_data)

    return (endpoint_scores, total_score)


def evaluate_revocation_hash(revocation_data):
    deprecated = ["md2", "md5"]

    revocation_hash = revocation_data["hash_algorithm"]

    if revocation_hash in deprecated:
        return 0

    if revocation_hash == "sha1":
        return 50
    else:
        return 100


def evaluate_update_interval(crl_data):
    update_interval = crl_data["next_update"] - crl_data["last_update"]

    if update_interval <= timedelta(days=7):
        return 100
    else:
        return 0


def score_ocsp(results):
    """Evaluate OCSP results from end-entity certificate

    If the response status is not SUCCESSFUL, an exception is raised and 
    ocsp is assigned a score of 0.

    Response status
    - Evaluation:
        - Not SUCCESSFUL                        : (raise)

    Verification result
    - If valid is false, but only responder_cert fails, it still passes. If 
      verification_result['valid'] is False and responder_cert is True, look
      for the test that failed and raise exception.

    - Evaluation:
        - Verification failed                   : (raise)

    Signature hash
    - Evaluation:
        - md2, md5:                             : 0
        - SHA2                                  : 80
        - SHA3 etc.                             : 100

    Weights
    - Response status                           : raise
    - Verification result                       : raise
    - Signature hash                            : 100%
    """

    ocsp_support, _, ocsp_data = results["ocsp"]
    # Only one ocsp endpoint is ever given
    ocsp_data = ocsp_data[0]

    if not ocsp_support:
        return ({"not_supported": 0}, 0)

    ocsp_score = {}

    try:
        evaluate_ocsp_response_status(ocsp_data)
        evaluate_verification_result(ocsp_data)
        ocsp_score["signature_hash"] = evaluate_revocation_hash(ocsp_data)

        return (ocsp_score, sum(ocsp_score.values()))

    except EvaluationFailureError as efe:
        return ({"not_evaluated": str(efe)}, 0)


def evaluate_ocsp_response_status(ocsp_data):
    if ocsp_data["response_status"] != "SUCCESSFUL":
        raise EvaluationFailureError(
            "OCSP responder failed to serve a response")


# Easier access to verification elements
def get_ocsp_verification_elements(data):
    elements = {}
    elements["can_sign"] = data["can_sign"]
    elements["cert_match"] = data["cert_match"]["passed"]
    elements["next_update"] = data["next_update"]["passed"]
    elements["this_update"] = data["this_update"]["passed"]
    elements["responder_cert"] = data["responder_cert"]["passed"]
    elements["signature_verified"] = data["signature_verified"]
    return elements


def identify_ocsp_failure(data, skip_keys):
    for key, value in data.items():
        if not value and key not in skip_keys:
            reason = get_ocsp_failure_reason(key)
            raise EvaluationFailureError(reason)


def evaluate_verification_result(ocsp_data):
    if ocsp_data["verification_result"]["valid"]:
        return

    verf = ocsp_data["verification_result"]
    verf_elements = get_ocsp_verification_elements(verf)
    identify_ocsp_failure(verf_elements, ["responder_cert"])


def get_ocsp_failure_reason(failure_key):
    reasons = {
        "can_sign":
        """A certificate was delegated to sign the OCSP response
without containing an explicit id-kp-OCSPSigning extension""",

        "cert_match":
        """The certificate serial number in the OCSP response does
not match the serial number of the certificate beeing checked""",

        "next_update":
        """The current time is greater than the next_update field""",

        "this_update":
        """The this_update field is greater than the current time """,

        "signature_verified":
        """The signature contained in the OCSP response could not be
verified using any provided verification certificates"""}

    return reasons.get(failure_key, "Unknown")
