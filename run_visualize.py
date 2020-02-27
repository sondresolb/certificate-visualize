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

    except c_ex.CertificateFetchingError as cfe:
        print(str(cfe))
        sys.exit()
    except c_ex.NoCertificatesError as nce:
        print(str(nce))
        sys.exit()
    except c_ex.InvalidCertificateChain as icc:
        print(str(icc))
        sys.exit()

    # Certificate path validation
    validation_res = vis_tools.validate_certificate_chain(
        domain, [c.crypto_cert for c in cert_chain])

    if not validation_res[0]:
        print(f"Chain validation for {domain} failed: {validation_res[1]}")
        print(f"Details: {validation_res[2]}")

    end_cert = cert_chain[0]

    # CRL Checking ...
    vis_crl.check_crl(end_cert, cert_chain[1])
    sys.exit()

    # OCSP Checking
    try:
        if len(cert_chain) > 1:
            issuer_cert = cert_chain[1]
            ocsp_responses = vis_ocsp.check_ocsp(end_cert, issuer_cert)

            if ocsp_responses[0]:
                ocsp_list = ocsp_responses[1]
                print(ocsp_list)

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
    uni_domains = []
    with open("uni_domains.json") as json_file:
        uni_json = json.load(json_file)
        for item in uni_json:
            uni_domains.extend([urlsplit(i).netloc for i in item["web_pages"]])

    for domain in uni_domains:
        try:
            cert_chain = vis_tools.fetch_certificate_chain(domain)

        except c_ex.CertificateFetchingError as cfe:
            print(str(cfe))
            continue
        except c_ex.NoCertificatesError as nce:
            print(str(nce))
            continue

        validation_res = vis_tools.validate_certificate_chain(
            domain, [c.crypto_cert for c in cert_chain])

        if not validation_res[0]:
            print(f"Chain validation for {domain} failed: {validation_res[1]}")

        end_cert = cert_chain[0]

        # CRL Checking ...
        vis_crl.check_crl(end_cert)
        print("\n")
        continue

        try:
            if len(cert_chain) > 1:
                issuer_cert = cert_chain[1]
                ocsp_responses = vis_ocsp.check_ocsp(end_cert, issuer_cert)

                if ocsp_responses[0]:
                    ocsp_list = ocsp_responses[1]
                    print(ocsp_list)

        except c_ex.OCSPRequestBuildError as orbe:
            print(str(orbe))

        print("\n")

    sys.exit()


if __name__ == "__main__":
    main()
