import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from requests.exceptions import HTTPError
import visualize_exceptions as c_ex


def check_crl(end_cert):
    """
    1.  If the issuer of end-cert is the issuer of the crl,
        then only the distribution-endpoint is present.

        If the certificate issuer is not the CRL
        issuer, then the cRLIssuer field MUST be present and contain the Name
        of the CRL issuer

    2. Full name has http url to fetch revocation list
    3. If there is no distribution point extention. then no crl info given


    """

    if end_cert.extensions.get('cRLDistributionPoints', None):
        for crl in end_cert.extensions['cRLDistributionPoints']['value']:
            print(crl)

    else:
        print("Has no crl information")

    # crls = fetch_all_crls(crl_endpoints)


# def fetch_all_crls(crl_endpoints):

#     try:
#         response = requests.post(crl_endpoint)

#         response.raise_for_status()
#         crl = x509.load_pem_x509_crl(response.content, default_backend)

#     except HTTPError as http_err:
#         raise c_ex.RequestResponseError(
#             'HTTP error occurred while requesting crl from {crl_endpoint}') from http_err

#     except Exception as e:
#         raise c_ex.RequestResponseError(
#             'Unhandled exception occured while requesting crl from {crl_endpoint}') from e
