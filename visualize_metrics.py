import sys
from datetime import timedelta

from visualize_exceptions import EvaluationFailureError


def evaluate_results(results, proto_cipher_result):
    """Evaluation process

    Each element of the scan process is broken down into different categories:
        - The end-entity certificate                    : 32%
        - Certificate Revocation List (CRL)             : 5%
        - Online Certificate Status Protocol (OCSP)     : 5%
        - Certificate Transparency (CT)                 : 12%
        - Certificate Authority Authorization (CAA)     : 10%
        - OCSP-Staple                                   : 2%
        - HTTPS Strict Transport Security (HSTS)        : 14%
        - Protocols and ciphers support                 : 20%

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
        "Certificate":      {"weight": 0.32},
        "CRL":              {"weight": 0.05},
        "OCSP":             {"weight": 0.05},
        "CT":               {"weight": 0.12},
        "CAA":              {"weight": 0.10},
        "OCSP_staple":      {"weight": 0.02},
        "HSTS":             {"weight": 0.14},
        "Proto_ciphers":    {"weight": 0.20}
    }

    evaluation_result = {}

    if not results["validation_path"][0]:
        raise EvaluationFailureError("Certificate validation failure")

    # Certificate
    evaluation_result["Certificate"], certificate_score = score_end_certificate(
        results)
    evaluation_result["Certificate"]["total"] = certificate_score
    weighted_score["Certificate"]["score"] = certificate_score

    # CRL
    evaluation_result["CRL"], crl_score = score_crl(results)
    evaluation_result["CRL"]["total"] = crl_score
    weighted_score["CRL"]["score"] = crl_score

    # OCSP
    evaluation_result["OCSP"], ocsp_score = score_ocsp(results)
    evaluation_result["OCSP"]["total"] = ocsp_score
    weighted_score["OCSP"]["score"] = ocsp_score

    # CT
    evaluation_result["CT"], ct_score = score_ct(results)
    evaluation_result["CT"]["total"] = ct_score
    weighted_score["CT"]["score"] = ct_score

    # CAA
    evaluation_result["CAA"], caa_score = score_caa(results)
    evaluation_result["CAA"]["total"] = caa_score
    weighted_score["CAA"]["score"] = caa_score

    # Staple
    evaluation_result["OCSP_staple"], staple_score = score_staple(results)
    evaluation_result["OCSP_staple"]["total"] = staple_score
    weighted_score["OCSP_staple"]["score"] = staple_score

    # HSTS
    evaluation_result["HSTS"], hsts_score = score_hsts(results)
    evaluation_result["HSTS"]["total"] = hsts_score
    weighted_score["HSTS"]["score"] = hsts_score

    # PC (Proto-Cipher)
    evaluation_result["Proto_ciphers"], pc_score = score_pc(
        results, proto_cipher_result)
    evaluation_result["Proto_ciphers"]["total"] = pc_score
    weighted_score["Proto_ciphers"]["score"] = pc_score

    # After everything is evaluated. apply weights and sum up
    evaluation_total = 0
    for category, metrics in weighted_score.items():
        evaluation_total += metrics["score"]*metrics["weight"]

    return (make_percentage(evaluation_result), evaluation_total)


def score_end_certificate(results):
    """Evaluate a complete certificate

    Signature hash
    - only md2, md5 and the sha-family can sign certificates
    - Source: https://tools.ietf.org/html/rfc3279 (page 3)

    - Evaluation:
        - md2, md5, SHA1:           (raise error)

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
            - EdDSA25519            : 85
            - EdDSA448              : 100

    Certificate type (end-certificate)
    - Evaluation:
        - Not indicated             : 0
        - Domain-validated          : 50
        - Individual-validated      : 70
        - Organization-validated    : 70
        - Extended-validation       : 100

    Revocation_support
    - Evaluation:
        - CRL and OCSP              : 100
        - OCSP                      : 60
        - CRL                       : 40
        - None                      : raise

    Must-staple
    - Evaluation:
        - true                      : 100
        - false                     : 0

    Evaluation failure (raise error)
    - Use of (md2, md5, sha1) by end or intermediate cert
    - Certificate not V3
    - No revocation information
    - Includes CTpoison extension
    - Certificate is expired

    Weights
    - public_key                    : 55%
    - certificate_type              : 5%
    - revocation_support            : 30% or raise
    - must_staple                   : 10%
    - signature_hash                : raise
    - version                       : raise
    - ct_poison                     : raise
    - has_expired                   : raise
    - intermediate_SHA1_signature   : raise
    """
    cert_weight = {
        "public_key":           0.55,
        "certificate_type":     0.05,
        "revocation_support":   0.30,
        "must_staple":          0.10
    }

    cert_score = {}

    validation_path = results["validation_path"][1]
    cert = validation_path["end_cert"]

    try:
        evaluate_certificate_version(cert)
        evaluate_has_expired(cert)
        evaluate_ct_poison(cert)
        evaluate_cert_signature_hash(cert)
        evaluate_intermediate_signature(validation_path["intermediates"])

        cert_score["public_key"] = evaluate_public_key(cert)

        cert_score["certificate_type"] = evaluate_certificate_type(
            cert)

        cert_score["revocation_support"] = evaluate_revocation_support(
            cert, results)

        cert_score["must_staple"] = evaluate_must_staple(cert)

    except EvaluationFailureError as efe:
        raise EvaluationFailureError(
            f"Certificate evaluation failure.\n{str(efe)}")

    # Apply weights and calculate score
    evaluation_total = 0
    for category, metric in cert_score.items():
        evaluation_total += metric*cert_weight[category]

    return (cert_score, evaluation_total)


def evaluate_intermediate_signature(intermediates):
    deprecated = ["md2", "md5", "sha1"]

    for intermediate in intermediates:
        inter_hash = intermediate.signature_hash[0]
        if inter_hash in deprecated:
            raise EvaluationFailureError(f"{inter_hash} hash algorithm used to sign intermediate "
                                         f"certificate: {intermediate.subject['commonName']}")


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
    to sign new certificates.
    The other NIST approved hashes for end-user certificate
    signing differ little in tangible security benefit. For this
    reason, a non-deprecated hash will not affect the certificate score.
    """
    deprecated = ["md2", "md5", "sha1"]

    sig_hash = cert.signature_hash

    if sig_hash[0] in deprecated:
        raise EvaluationFailureError(f"Deprecated hash {sig_hash} used "
                                     f"to sign certificate: {cert.subject['commonName']}")


def evaluate_revocation_support(cert, results):
    """Evaluate revocation support

    Online Certificate Protocol (OCSP) and Certificate Revocation List (CRL)
    are the two methods of revocation found in an end-entity certificate.
    Having both methods available are good for availability of revocation
    information. OCSP is the best way to verify that a certificate is not revoked
    given that it provides timely revocation info and is updated quickly and
    regularly. CRL is a good alternative, but falls short of the two points above.
    It can get very large and make the process slower while demanding more resources.
    The evaluation will fail if there is no revocation methods in the certificate.
    If that is the case, there is no way to verify if the certificate is safe to use.
    """
    crl_support = results["crl"][0]
    ocsp_support = results["ocsp"][0]

    if crl_support and ocsp_support:
        return 100
    elif ocsp_support:
        return 60
    elif crl_support:
        return 40
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
        return 0
    elif cert_type == "Domain-validated":
        return 50
    elif cert_type == "Individual-validated":
        return 70
    elif cert_type == "Organization-validated":
        return 70
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
        return 85

    # Around 224 bit security level
    elif key_type == "EdDSA448":
        return 100


def score_crl(results):
    """Evaluate CRL results from end-entity certificate

    The largest publication interval for a crl is 1 week
        - source: https://tools.ietf.org/html/rfc5280#page-14

    Reliability (Number of endpoints)
    - Evaluation:
        - one endpoint                          : 50
        - two or more                           : 100

    Signature hash (inside endpoint)
    - Evaluation:
        - md2, md5:                             : 0
        - SHA1                                  : 50
        - SHA2, SHA3 etc.                       : 100

    Update iterval (next_update - last_update)(inside endpoint)
    - Evaluation:
        - Less or equal to 1 week               : 100
        - More than 1 week                      : 0

    Weights
    - endpoints                                 : 90%
    - reliability                               : 10%
    """
    crl_weights = {
        "endpoints":        0.90,
        "reliability":      0.10
    }

    crl_support, _, crl_data = results["crl"]

    if not crl_support:
        return ({"not_supported": 0}, 0)

    crl_score = {}

    crl_score["endpoints"], endpoint_score = evaluate_crl_endpoints(crl_data)
    endpoint_score = endpoint_score*crl_weights["endpoints"]

    crl_score["reliability"] = evaluate_crl_reliability(crl_data)
    reliability_score = crl_score["reliability"]*crl_weights["reliability"]

    return (crl_score, sum((endpoint_score, reliability_score)))


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
    endpoint_weights = {
        "signature_hash":       0.80,
        "update_interval":      0.20
    }

    endpoint_scores = {}

    for endpoint in crl_data:
        end_p = endpoint["endpoint"]
        endpoint_scores[end_p] = {}
        endpoint_scores[end_p]["signature_hash"] = evaluate_revocation_hash(
            endpoint)
        endpoint_scores[end_p]["update_interval"] = evaluate_update_interval(
            endpoint)

    total_score = 0
    for endpoint in endpoint_scores.values():
        for name, value in endpoint.items():
            total_score += value*endpoint_weights[name]

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
        - SHA1                                  : 50
        - SHA2, SHA3 etc.                       : 100

    Weights
    - No weights
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
        return ({"failed_evaluation": str(efe)}, 0)


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


def score_ct(results):
    """Evaluate Certificate Transparency

    If Certificate Transparency is not supported, it will receive a score
    of 0. If a log is retired, then the SCT timestamp must
    be less than the log timestamp (SCT issued before log retired).
    Google chrome requires a one year certificate to include SCT-proof
    from two independent logs. A two year certificate must include proof
    from 3 independent logs. More logs improves the overall reliability when
    auditing certificates in CT-logs and limits impact in the case that a
    CA would be hacked or go rogue.
    https://www.digicert.com/certificate-transparency/status-background.htm

    usable/readonly/retired logs
    - Evaluation:
        - No usable/readonly/retired logs           : 0
        - Less than minimum number of logs          : 25
        - More or equal to minimum number of logs   : 100

    - Weight
        No weights
    """
    end_cert = results["validation_path"][1]["end_cert"]
    ct_support, ct_data = results["ct"]

    if not ct_support:
        return ({"not_supported": 0}, 0)

    ct_score = {}

    ct_score["sct_logs"], sct_logs_score = evaluate_sct(ct_data, end_cert)

    return (ct_score, sct_logs_score)


def evaluate_sct(ct_data, end_cert):
    good_states = ["usable", "readonly", "retired"]
    num_operational = 0
    total_score = 0
    sct_score = {}

    for sct in ct_data:
        log = sct["description"]

        if sct["valid"]:
            operation_state, timestamp = sct["state"]
            if operation_state in good_states:

                if operation_state == "retired":
                    if sct["timestamp"] > timestamp:
                        sct_score[log] = "SCT was issued after log retirement"
                        continue

                sct_score[log] = "Good"
                num_operational += 1

            else:
                sct_score[log] = "Log is currently not qualified or rejected"

        else:
            sct_score[log] = "SCT is not valid"

    not_before, not_after = end_cert.validity_period
    cert_age = not_after - not_before

    if cert_age <= timedelta(398):
        min_logs = 2
    else:
        min_logs = 3

    if num_operational == 0:
        total_score = 0

    elif num_operational < min_logs:
        total_score = 25

    elif num_operational >= min_logs:
        total_score = 100

    return (sct_score, total_score)


def score_caa(results):
    """Evaluate Certificate Authority Authorization

    If CAA is not supported or the record does not contain an
    issue or issuewild tag, the score is 0. Else, the score is
    100.
    """
    caa_support, caa_data = results["caa"]

    if not caa_support:
        return ({"not_supported": 0}, 0)

    tags = ["issue", "issuewild"]
    for entry in caa_data:
        if entry["tag"] in tags:
            return ({"supported": 100}, 100)

    else:
        msg = "CAA record does not contain an issue or wildcard tag"
        return ({"failed_evaluation": msg}, 0)


def score_staple(results):
    """Evaluate OCSP-Staple

    If OCSP-Staple is not supported or the staple is not valid, the
    score is 0. Else, the score is 100.
    """
    staple_support, valid_staple = results["staple"]

    if not staple_support:
        return ({"not_supported": 0}, 0)

    else:
        if valid_staple:
            return ({"supported": 100}, 100)
        else:
            msg = "Staple could not be validated"
            return ({"failed_evaluation": msg}, 0)


def score_hsts(results):
    """Evaluate HTTP Strict Transport Security

    If hsts is not supported, the score is 0. Else, the score
    is 100.
    """
    hsts_support = results["hsts"]

    if hsts_support:
        return ({"supported": 100}, 100)
    else:
        return ({"not_supported": 0}, 0)


def score_pc(results, proto_cipher_result):
    """Evaluate protocol and cipher support

    Supported protocols
    - Evaluation:
        - TLSv1.0                               : 0
        - TLSv1.1                               : 30
        - TLSv1.2                               : 80
        - TLSv1.3                               : 100

    Enabled ciphers
    - Evaluation:
        - Source: https://ciphersuite.info/page/faq/

        - insecure:                             : 0
            These ciphers are very old and shouldn't be used under any circumstances.
            Their protection can be broken with minimal effort nowadays.

        - weak:                                 : 50
            These ciphers are old and should be disabled if you are setting up a
            new server for example. Make sure to only enable them if you have a 
            special use case where support for older operating systems, browsers or 
            applications is required.

        - secure:                               : 80
            Secure ciphers are considered state-of-the-art and if you want to
            secure your web server you should certainly choose from this set.
            Only very old operating systems, browsers or applications are unable
            to handle them.

        - recommended:                          : 100
            All 'recommended' ciphers are 'secure' ciphers by definition.
            Recommended means that these ciphers also support
            PFS (Perfect Forward Secrecy) and should be your first choice if you
            want the highest level of security. However, you might run into some
            compatibility issues with older clients that do not support PFS
            ciphers.

    - Weights
        - protocol_support                      : 70%
        - ciphersuite_support                   : 30%
    """
    pc_weights = {
        "protocol_support":     0.70,
        "ciphersuite_support":  0.30
    }

    pc_support, pc_data = results["proto_cipher"]

    pc_score = {}

    if not pc_support:
        if len(proto_cipher_result.keys()) > 0:
            pc_score["protocol_support"], protocol_score = evaluate_supported_protocols(
                proto_cipher_result)
            protocol_score = protocol_score*pc_weights["protocol_support"]
            return (pc_score, protocol_score)
        else:
            return ({"not_supported": 0}, 0)

    pc_score["protocol_support"], protocol_score = evaluate_supported_protocols(
        pc_data)
    protocol_score = protocol_score*pc_weights["protocol_support"]

    pc_score["ciphersuite_support"], cipher_score = evaluate_ciphersuites(
        pc_data)
    cipher_score = cipher_score*pc_weights["ciphersuite_support"]

    total_score = protocol_score + cipher_score

    return (pc_score, total_score)


def evaluate_supported_protocols(pc_data):
    protocol_values = {
        "TLSv1.0": 0,
        "TLSv1.1": 30,
        "TLSv1.2": 80,
        "TLSv1.3": 100
    }

    protocols = {}

    for protocol in pc_data.keys():
        protocols[protocol] = protocol_values[protocol]

    min_protocol = min(protocols, key=protocols.get)
    max_protocol = max(protocols, key=protocols.get)

    protocol_score = (protocols[max_protocol] + protocols[min_protocol])/2

    protocol_result = {
        f"Min: {min_protocol}": protocols[min_protocol],
        f"Max: {max_protocol}": protocols[max_protocol]
    }

    return (protocol_result, protocol_score)


def evaluate_ciphersuites(pc_data):
    cipher_values = {
        "insecure":     0,
        "weak":         50,
        "secure":       80,
        "recommended":  100
    }

    ciphersuites = {}
    for protocol, ciphers in pc_data.items():
        for name, value in ciphers.items():
            if value != "unknown":
                ciphersuites[name] = cipher_values[value["security"]]

    min_cipher = min(ciphersuites, key=ciphersuites.get)
    max_cipher = max(ciphersuites, key=ciphersuites.get)

    cipher_score = (ciphersuites[max_cipher] + ciphersuites[min_cipher])/2

    cipher_result = {
        f"Min: {min_cipher}": ciphersuites[min_cipher],
        f"Max: {max_cipher}": ciphersuites[max_cipher]
    }

    return (cipher_result, cipher_score)


def make_percentage(score):
    if isinstance(score, dict):
        for name, value in score.items():
            score[name] = make_percentage(value)

    if isinstance(score, (int, float)):

        return f"{float(score)}%"

    return score
