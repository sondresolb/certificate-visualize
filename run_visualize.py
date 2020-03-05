import sys
from visualize_certificate import Cert_repr
import visualize_tools as vis_tools
import visualize_ocsp as vis_ocsp
import visualize_crl as vis_crl
import visualize_ct as vis_ct
import visualize_exceptions as c_ex


def main():
    vis_tools.set_trust_store()     # Set custom trust store for validation
    # run_stress_test()               # Run a stress test

    certificate_result = {}
    domain = "www.google.com"

    try:
        cert_chain = vis_tools.fetch_certificate_chain(domain)
        end_cert = cert_chain[0]
        issuer_cert = cert_chain[1]

    except c_ex.CertificateFetchingError as cfe:
        print(str(cfe))
        sys.exit()
    except c_ex.NoCertificatesError as nce:
        print(str(nce))
        sys.exit()
    except c_ex.InvalidCertificateChain as icc:
        print(str(icc))
        sys.exit()
    except IndexError as ie:
        issuer_cert = None

    # *Certificate path validation*
    validation_res = vis_tools.validate_certificate_chain(
        domain, [c.crypto_cert for c in cert_chain])

    if not validation_res[0]:
        # This is a complete failure
        print(f"Chain validation for {domain} failed: {validation_res[1]}")
        print(f"Details: {validation_res[2]}")

    # # *CRL*
    # crl_status, crl_result = vis_crl.check_crl(end_cert, issuer_cert)
    # print(f"\nCert revoked in any CRL: {crl_status}, {crl_result}")

    # # *OCSP*
    # try:
    #     ocsp_support, ocsp_results = vis_ocsp.check_ocsp(
    #         end_cert, issuer_cert)
    #     print(f"\nOCSP support: {ocsp_support}\nOCSP result: {ocsp_results}")
    # except c_ex.OCSPRequestBuildError as orbe:
    #     print(str(orbe))

    # *CT*
    ct_support, ct_result = vis_ct.get_ct_information(end_cert)
    print(f"\nCertificate transparency result:\n{ct_result}")

    # *CAA*
    # .....

    # Check for CT poison extension
    poison_res = vis_tools.has_ct_poison(end_cert)
    print(f"\nIncludes CTPoison extension: {poison_res[0]}")

    # Check for OCSP must staple extension
    # If cryptography.x509.TLSFeature extension is embedded in certificate:
    # The TLS Feature extension is defined in RFC 7633 and is used in certificates
    # for OCSP Must-Staple. The object is iterable to get every element.
    # This feature type is defined in RFC 6066 and, when embedded in an X.509 certificate,
    # signals to the client that it should require a stapled OCSP response in the TLS handshake.
    # Commonly known as OCSP Must-Staple in certificates.


def run_stress_test():
    import json
    from urllib.parse import urlsplit
    domains = []
    # with open("uni_domains.json") as json_file:
    #     uni_json = json.load(json_file)
    #     for item in uni_json:
    #         domains.extend([urlsplit(i).netloc for i in item["web_pages"]])

    with open("top-1m.json") as json_file:
        domains_json = json.load(json_file)
        domains = domains_json["endpoints"]

    for domain in domains:
        try:
            cert_chain = vis_tools.fetch_certificate_chain(domain)
            end_cert = cert_chain[0]
            issuer_cert = cert_chain[1]

        except c_ex.CertificateFetchingError as cfe:
            print(str(cfe))
            continue
        except c_ex.NoCertificatesError as nce:
            print(str(nce))
            sys.exit()
        except c_ex.InvalidCertificateChain as icc:
            print(str(icc))
            sys.exit()
        except IndexError as ie:
            issuer_cert = None

        # Certificate path validation
        validation_res = vis_tools.validate_certificate_chain(
            domain, [c.crypto_cert for c in cert_chain])

        if not validation_res[0]:
            # This is a complete failure
            print(f"Chain validation for {domain} failed: {validation_res[1]}")
            print(f"Details: {validation_res[2]}")

        # # CRL Checking
        # crl_status, crl_info = vis_crl.check_crl(end_cert, issuer_cert)
        # print(f"Cert revoked in CRL: {crl_status}, {crl_info}")

        # # OCSP Checking
        # try:
        #     ocsp_support, ocsp_results = vis_ocsp.check_ocsp(
        #         end_cert, issuer_cert)
        #     print(f"OCSP support: {ocsp_support}\nOCSP result: {ocsp_results}")

        # except c_ex.OCSPRequestBuildError as orbe:
        #     print(str(orbe))

        # *CT*
        ct_result = vis_ct.get_ct_information(end_cert)
        print(f"\nCertificate transparency result:\n{ct_result}")

        print("\n")

    sys.exit()


if __name__ == "__main__":
    main()
