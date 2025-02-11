import sys
import time

import visualize_metrics as metrics
import visualize_tools as vis_tools
import visualize_ocsp as vis_ocsp
import visualize_crl as vis_crl
import visualize_ct as vis_ct
import visualize_caa as vis_caa
import visualize_connection as vis_conn
import visualize_exceptions as c_ex
from visualize_certificate import Cert_repr


# Enables run without signal and fixes gui problem
def signal_wrap(signal, percent, text):
    try:
        signal.emit(percent, text)
    except Exception:
        pass


def certificate_scan(domain, signal):
    signal_wrap(signal, 1, "initializing analysis...")

    vis_tools.set_trust_store()     # Set custom trust-store
    scan_result = {}

    try:
        signal_wrap(signal, 6, "fetching certificate chain")
        cert_chain, conn_details = vis_tools.fetch_certificate_chain(domain)
        end_cert = cert_chain[0]
        issuer_cert = cert_chain[1]

        print(f"\nConnection details: {conn_details}")
        print(f"\nCertificates served: {len(cert_chain)}")

        scan_result["connection"] = conn_details
        scan_result["certs_served"] = len(cert_chain)

        vis_tools.rep_cert(end_cert)
    except c_ex.CertificateFetchingError as cfe:
        cfe_msg = f"{str(cfe)}\n\nMake sure you typed the domain correctly"
        raise(c_ex.CertificateFetchingError(cfe_msg))
    except c_ex.NoCertificatesError as nce:
        print(str(nce))
        raise(c_ex.NoCertificatesError(str(nce)))
    except c_ex.InvalidCertificateChain as icc:
        print(str(icc))
        raise(c_ex.InvalidCertificateChain(str(icc)))
    except c_ex.IntermediateFetchingError as ife:
        ife_args = ife.args
        print(ife_args[0])
        cert_chain = ife_args[1]
        conn_details = ife_args[2]
        end_cert = cert_chain[0]
        scan_result["connection"] = conn_details
        scan_result["certs_served"] = len(cert_chain)
        issuer_cert = None

    signal_wrap(signal, 12, "validating certificate path")
    # *Certificate path validation*
    validation_res = vis_tools.validate_certificate_chain(
        domain, [c.crypto_cert for c in cert_chain])

    if validation_res[0]:
        # Get full validation path structure
        scan_result["validation_path"] = (True, vis_tools.get_full_validation_path(
            validation_res[1]))
    else:
        # This is a complete failure
        cert_path = {"end_cert": end_cert, "issuer": issuer_cert}

        path_error = {
            "reason": validation_res[1], "details": validation_res[2]}

        error_string = (
            f"Chain validation for {domain} failed: {validation_res[1]}"
            f"\n\nDetails: {validation_res[2]}")

        scan_result["validation_path"] = (False, cert_path, path_error)
        print(error_string)

    signal_wrap(signal, 20, "processing CRL data")
    # *CRL*
    crl_revoked, crl_result = vis_crl.check_crl(end_cert, issuer_cert)
    crl_support = True if crl_revoked is not None else False
    scan_result["crl"] = (crl_support, crl_revoked, crl_result)
    print(f"\nCRL support: {crl_support}, "
          f"Certificate revoked: {crl_revoked}\n{crl_result}")

    signal_wrap(signal, 30, "processing OCSP data")
    # *OCSP*
    try:
        ocsp_support, ocsp_revoked, ocsp_results = vis_ocsp.check_ocsp(
            end_cert, issuer_cert)
        scan_result["ocsp"] = (ocsp_support, ocsp_revoked, ocsp_results)
        print(f"\nOCSP support: {ocsp_support}, "
              f"Revoked: {ocsp_revoked}\n{ocsp_results}")
    except c_ex.OCSPRequestBuildError as orbe:
        scan_result["ocsp"] = (
            False, False, f"\nFailed while building OCSP request: {str(orbe)}")
        print(f"\nFailed while building OCSP request: {str(orbe)}")

    signal_wrap(signal, 40, "gathering CT information")
    # *CT*
    ct_support, ct_result = vis_ct.get_ct_information(end_cert)
    scan_result["ct"] = (ct_support, ct_result)
    print(f"\nCT support: {ct_support}\n{ct_result}")

    signal_wrap(signal, 46, "querying for CAA record")
    # *CAA*
    caa_support, caa_result = vis_caa.check_caa(domain)
    scan_result["caa"] = (caa_support, caa_result)
    print(f"\nDNS CAA support: {caa_support}\n{caa_result}")

    # *CT poison*
    print(f"\nIncludes CTPoison extension: {end_cert.ct_poison}")

    signal_wrap(signal, 60, "requesting OCSP-staple data")
    # *OCSP staple (improved privacy)*
    staple_support, valid_staple = vis_ocsp.check_ocsp_staple(
        conn_details["ocsp_staple"], issuer_cert, end_cert)
    scan_result["staple"] = (staple_support, valid_staple)
    print(f"\nOCSP staple support: {staple_support}, Valid: {valid_staple}")

    # *OCSP must-staple*
    print(f"\nOCSP Must-staple support: {end_cert.must_staple}")

    # *Certificate type*
    print(f"\nEnd-Certificate type: {end_cert.certificate_type}")

    signal_wrap(signal, 72, "checking HSTS support")
    # *HSTS*
    hsts_support = vis_conn.check_hsts(domain)
    scan_result["hsts"] = hsts_support
    print(f"\nHSTS support: {hsts_support}")

    signal_wrap(signal, 84, "analysing protocol and cipher-suite support")
    # *Protocol and cipher support*
    try:
        proto_cipher_result = vis_conn.get_supported_proto_ciphers(
            domain, conn_details["ip"], (signal, 84))
        scan_result["proto_cipher"] = (True, proto_cipher_result)
        print(f"\nProto_ciphers:\n{proto_cipher_result}")
    except c_ex.CipherFetchingError as cfe:
        proto_c_err, proto_cipher_result = cfe.args
        scan_result["proto_cipher"] = (False, proto_c_err)
        print(str(cfe))

    # Add list of supported protocols to connection details
    scan_result["connection"]["tls_versions"] = ", ".join(
        list(proto_cipher_result.keys()))

    # Indicator if certificate is revoked
    scan_result["cert_revoked"] = crl_revoked or ocsp_revoked

    # All keyusages
    try:
        total_keyusage = []
        total_keyusage.extend(end_cert.extensions["keyUsage"]["value"])
        total_keyusage.extend(end_cert.extensions["extendedKeyUsage"]["value"])
        scan_result["total_keyusage"] = total_keyusage
    except Exception as e:
        # Skip if there are no extended keyusage
        pass

    # Evaluate results
    try:
        scan_result["evaluation_result"] = metrics.evaluate_results(
            scan_result, proto_cipher_result)
    except c_ex.EvaluationFailureError as efe:
        scan_result["evaluation_result"] = (str(efe), -1)

    print(f"\nEVALUATION TOTAL: {scan_result['evaluation_result'][1]}")

    signal_wrap(signal, 100, "analysis completed")
    time.sleep(1)

    return scan_result


def run_stress_test(in_data, out_file):
    import json
    import signal as test_sig
    from urllib.parse import urlsplit
    domains = []

    if in_data == "uni":
        print("\nRunning university domains")
        with open("uni_domains.json") as json_file:
            uni_json = json.load(json_file)
            for item in uni_json:
                domains.extend([urlsplit(i).netloc for i in item["web_pages"]])

    elif in_data == "top":
        print("\nRunning top million domains")
        with open("top-1m_tranco.json") as json_file:
            domains_json = json.load(json_file)
            domains = domains_json["endpoints"]

    elif type(in_data) is list:
        domains = in_data

    else:
        domains.append(in_data)

    # test_sig.signal(test_sig.SIGALRM, test_handler)

    domain_scores = {}
    for index, domain in enumerate(domains):
        if index > 110:
            return domain_scores

        print(f"\nCURRENT DOMAIN NUM: {index}\n")
        # test_sig.alarm(240)

        try:
            res = certificate_scan(domain, None)

            if not res["proto_cipher"][0]:
                raise Exception("Cipher scan failed")
            else:
                domain_scores[domain] = extract_table_data(res)

        except Exception as e:
            domain_scores[domain] = f"Failure: {str(e)}"

        if out_file:
            print(f"\nWriting to: {out_file}")
            with open(out_file, 'w') as fp:
                json.dump(domain_scores, fp)

    return domain_scores


def extract_table_data(result):
    import visualize_ciphers as vis_ciphers

    if not result["validation_path"][0]:
        raise Exception(result["validation_path"][2]["details"])
    elif result["evaluation_result"][1] == -1:
        raise Exception(result["evaluation_result"][0])

    data = {}
    data["score"] = round(result["evaluation_result"][1], 1)
    cert = result["validation_path"][1]["end_cert"]
    public_key = cert.public_key
    data["public_key"] = f"{public_key['type']} {public_key['size']} bit"
    data["cert_type"] = cert.certificate_type
    data["crl"] = result["crl"][0]
    data["ocsp"] = result["ocsp"][0]
    data["must_staple"] = cert.must_staple
    good_logs = 0
    if result["ct"][0]:
        for log in result["evaluation_result"][0]["CT"]["sct_logs"].values():
            if log == "Good":
                good_logs += 1
        data["ct"] = good_logs
    else:
        data["ct"] = 0
    data["caa"] = result["caa"][0]
    data["staple"] = result["staple"][0]
    data["hsts"] = result["hsts"]

    pc_data = result["evaluation_result"][0]["Proto_ciphers"]
    protocol = list(pc_data["protocol_support"].keys())
    cipher = list(pc_data["ciphersuite_support"].keys())
    cipher_min = cipher[0].split(" ")[1]
    cipher_max = cipher[1].split(" ")[1]
    cipher_info = vis_ciphers.get_cipher_suite_info()
    min_security = vis_ciphers.evaluate_cipher(cipher_min, cipher_info)
    max_security = vis_ciphers.evaluate_cipher(cipher_max, cipher_info)
    data["min_protocol"] = protocol[0].split(" ")[1]
    data["max_protocol"] = protocol[1].split(" ")[1]
    data["min_cipher"] = min_security['security']
    data["max_cipher"] = max_security['security']
    return data


# time out stalled calls to improve testing
def test_handler(signum, frame):
    raise Exception("test timeout")


def sort_decending(data):
    return {k: v for k, v in sorted(data.items(), key=lambda item: item[1], reverse=True)}


if __name__ == "__main__":
    import argparse
    text = 'Scan a domain or list of domains and get a summary outputted to JSON'

    parser = argparse.ArgumentParser(description=text)
    parser.add_argument("--domain", "-d", help="Domain to scan")
    parser.add_argument(
        "--top", help="List of Tranco top 1 million domains", action="store_true")
    parser.add_argument(
        "--uni", help="List of US university domains", action="store_true")
    parser.add_argument(
        "--file", "-f", help="Output file: <file_name>.json", default=None)
    args = parser.parse_args()

    if args.domain:
        in_data = args.domain
    elif args.top:
        in_data = "top"
    elif args.uni:
        in_data = "uni"
    else:
        parser.print_help()
        sys.exit()

    scores = run_stress_test(in_data, args.file)
    print(f"\n\n{scores}")
