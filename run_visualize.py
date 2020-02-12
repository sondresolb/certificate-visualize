import visualize_tools as vis_tools
import visualize_ocsp as vis_ocsp
from visualize_certificate import Cert_repr
from visualize_exceptions import OCSPRequestBuildError


def main():
    vis_tools.set_trust_store()     # Set custom trust store for validation
    run_stress_test()               # Run a stress test

    domain = "tmall.com"
    cert_chain = [Cert_repr(cert)
                  for cert in vis_tools.fetch_certificate_chain(domain)]

    if len(cert_chain) <= 1:
        print("Only end-certificate provided by server")

    validation_res = vis_tools.validate_certificate_chain(
        domain, [c.crypto_cert for c in cert_chain])

    if not validation_res[0]:
        print(
            f"Certificate chain provided by {domain} could not be validated!")

    if len(cert_chain) > 1:
        end_cert, issuer_cert = cert_chain[0], cert_chain[1]

        try:
            ocsp_responses = vis_ocsp.check_ocsp(end_cert, issuer_cert)

        except OCSPRequestBuildError as orbe:
            print(str(orbe))

    else:
        print("OCSP: No check without intermediate certificates")


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
    import sys
    import json
    from urllib.parse import urlsplit
    uni_domains = []
    with open("uni_domains.json") as json_file:
        uni_json = json.load(json_file)
        for item in uni_json:
            uni_domains.extend([urlsplit(i).netloc for i in item["web_pages"]])

    for domain in uni_domains:
        # Certificate parsing
        cert_chain = [Cert_repr(cert)
                      for cert in vis_tools.fetch_certificate_chain(domain)]

        # Certificate chain validation
        validation_res = vis_tools.validate_certificate_chain(
            domain, [c.crypto_cert for c in cert_chain])

        if not validation_res[0]:
            print(
                f"Certificate chain provided by {domain} could not be validated!")

        # OCSP
        if len(cert_chain) > 1:
            end_cert, issuer_cert = cert_chain[0], cert_chain[1]

            try:
                ocsp_responses = vis_ocsp.check_ocsp(end_cert, issuer_cert)

            except OCSPRequestBuildError as orbe:
                print(str(orbe))
        else:
            print("OCSP: No check without intermediates")

        # CRL

    sys.exit()


if __name__ == "__main__":
    main()
