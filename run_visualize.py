import sys
from visualize_certificate import Cert_repr
import visualize_tools as vis_tools
import visualize_ocsp as vis_ocsp
import visualize_crl as vis_crl
import visualize_exceptions as c_ex


def main():
    vis_tools.set_trust_store()     # Set custom trust store for validation
    # run_stress_test()               # Run a stress test

    certificate_result = {}
    domain = "www.github.com"

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

    # *CRL*
    crl_status, crl_info = vis_crl.check_crl(end_cert, issuer_cert)
    print(f"\nCert revoked in any CRL: {crl_status}, {crl_info}")

    # *OCSP*
    try:
        ocsp_support, ocsp_results = vis_ocsp.check_ocsp(
            end_cert, issuer_cert)
        # print(f"\nOCSP support: {ocsp_support}\nOCSP result: {ocsp_results}")
    except c_ex.OCSPRequestBuildError as orbe:
        print(str(orbe))


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

        # CRL Checking
        crl_status, crl_info = vis_crl.check_crl(end_cert, issuer_cert)
        print(f"Cert revoked in CRL: {crl_status}, {crl_info}")

        # OCSP Checking
        try:
            ocsp_support, ocsp_results = vis_ocsp.check_ocsp(
                end_cert, issuer_cert)
            print(f"OCSP support: {ocsp_support}\nOCSP result: {ocsp_results}")

        except c_ex.OCSPRequestBuildError as orbe:
            print(str(orbe))

        print("\n")

    sys.exit()


if __name__ == "__main__":
    main()
