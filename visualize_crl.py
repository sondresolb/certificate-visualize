import requests
import datetime
from urllib.parse import urlsplit
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID as ext_oid
from requests.exceptions import HTTPError
import visualize_exceptions as c_ex


def check_crl(end_cert, issuer):
    """Check if the end_cert is included in any CRL found

    The function checks if there is an issuer given. All
    HTTP certificate revocation lists (CRLs) mentioned in
    the end_cert are extracted from the crlDistributionPoints
    extension, fetched and parsed into a crl_info dict containing
    the endpoint string (e.g. http://crl3.digicert.com/some_crl.crl),
    the CRL cryptography object and the CRL number (int). The
    delta CRLs are then extracted from the freshestCrl extension
    in the certificate, and in the CRLs mentioned in the certificate,
    and goes through the same process. All the CRLs are then validated
    and verified, excluding the CRLs that fails. If no CRLs were found
    or no complete CRLs passed the validation, the CRL checking fails.
    The end_cert is then matched against each CRL by serial number.
    The revocation information and all other relevant information is
    then collected and stored for each CRL.
    The information is sourced from: https://tools.ietf.org/html/rfc5280#page-92
    6.3.3. CRL Processing

    Args:
        end_cert (cert_repr): The certificate to be checked
        issuer (cert_repr): The issuer of the end_cert

    Returns:
        tuple(None or bool, dict or list):
            If the CRL checking fails, the function will return a tuple
            with None and a message why it failed. 
            If the CRL checking is successful, the function will return
            a tuple with a bool where True indicates the certificate was
            found to be revoked or False if it is not revoked. The second
            element will be a list of dict objects containing information
            about each CRL endpoint, including if the CRL is a delta CRL
            or not.
    """
    # Check for issuer certificate
    if issuer is None:
        return (None, {"no_crl": "Can not validate CRL information "
                       "without the issuer certificate"})

    # Fetch CRLs mentioned in the certificate and store with CRL number
    certificate_crls = get_crls(
        end_cert.crypto_cert, ext_oid.CRL_DISTRIBUTION_POINTS)
    if not certificate_crls:
        return (None, {"no_crl": "Unable to get CRL information from certificate"})

    # Extract and include delta CRLs inside CRLs
    delta_crls = []
    for crl_info in certificate_crls:
        delta_crls.extend(get_crls(crl_info["crl"], ext_oid.FRESHEST_CRL))

    # Fetch delta CRLs mentioned in certificate
    delta_crls.extend(get_crls(
        end_cert.crypto_cert, ext_oid.FRESHEST_CRL))

    valid_crls = []
    # Validate all complete CRLs found
    for crl_info in certificate_crls:
        if validate_crl(crl_info["crl"], issuer.crypto_cert):
            valid_crls.append(crl_info)

    # Can only run revocation checking if there is a complete CRL
    if not valid_crls:
        return (None, {"no_crl": "Could not validate any given CRL"})

    # Validate all delta CRLs found
    for delta_info in delta_crls:
        if valid_crls(delta_info["crl"], issuer.crypto_cert):
            valid_crls.append(crl_info)

    certificate_revoked = False
    for crl_info in valid_crls:
        crl_info["issuer"] = crl_info["crl"].issuer.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME)[0].value
        # Add delta CRL indicator to all CRLs
        crl_info["is_delta"] = is_delta(crl_info["crl"])
        hash_algo = crl_info["crl"].signature_hash_algorithm
        crl_info["hash_algorithm"] = (hash_algo.name, hash_algo.digest_size*8)
        crl_info["signature_algorithm"] = crl_info["crl"].signature_algorithm_oid._name
        crl_info["next_update"] = crl_info["crl"].next_update.ctime()
        crl_info["last_update"] = crl_info["crl"].last_update.ctime()

        # Do revocation checking of end_cert for all CRLs
        revoked, revocation_info = is_revoked(
            crl_info["crl"], end_cert.serial_number)

        crl_info["has_revoked"] = revoked
        if revoked:
            # If revoked, include all relevant revocation info
            certificate_revoked = True
            crl_info["revocation_info"] = revocation_info

    return (certificate_revoked, valid_crls)


def validate_crl(crl, issuer):
    """Validation of a CRL

    This function does a partial validation of a CRL.
    It checks if the issuer of the CRL is the
    same entity as the one who signed the certificate
    beeing checked. It then checks if the current system
    time is greater than the next_update field in the CRL.
    The last check is to verify that the CRL signature using
    the public key of the certificate issuer.

    Args:
        crl (cryptography.x509.CertificateRevocationList): CRL to validate
        issuer (cryptography.x509.Certificate): Issuer of the end certificate

    Returns:
        (bool): True if the validation was successfull, or False if it was not
    """
    # Check that crl issuer matches certificate issuer
    if not issuer.subject == crl.issuer:
        print("CRL: crl issuer does not match cert issuer")
        return False

    # Check if current system time is greater than the crl next_update
    if datetime.datetime.now() > crl.next_update:
        print("CRL: Current time is greater than the crl next_update")
        return False

    # Verify signature of CRL using issuer of certificate
    return crl.is_signature_valid(issuer.public_key())


def is_revoked(crl, serial_number):
    """Check if a certificate is mentioned in a CRL

    This function checks if a certificate given by it's serial
    number is included in a given CRL. If the certificate is
    found in the CRL, then all relevant information is extracted,
    including the revocation reason, if any is given.

    Args:
        crl (cryptography.x509.CertificateRevocationList): CRL
        serial_number (int): Serial number of the certificate to check

    Returns:
        tuple(bool, dict or None):
            The certificate is revoked if the bool is True.
            If revoked, the second element includes the revocation
            information or None if the bool is False.
    """
    result = crl.get_revoked_certificate_by_serial_number(serial_number)

    if result is not None:
        revocation_info = {"serial_number": result.serial_number,
                           "revocation_date": result.revocation_date}

        try:
            reason_ext = crl.extensions.get_extension_for_class(x509.CRLReason)
            reason_name = reason_ext.value.reason.name
            revocation_info["reason"] = f"{reason_name}: {get_reason_message(reason_name)}"

        except x509.ExtensionNotFound:
            revocation_info["reason"] = "No reason specified"

        return (True, revocation_info)

    else:
        return (False, None)


def is_delta(crl):
    """Checks if a CRL is a delta-CRL

    Takes in a CRL and checks if it includes the deltaCrlIndicator
    extension.

    Args:
        crl (cryptography.x509.CertificateRevocationList): CRL

    Returns:
        (bool): True if it includes the extension, or false if not.
    """
    try:
        crl.extensions.get_extension_for_class(x509.DeltaCRLIndicator)
        return True

    except x509.ExtensionNotFound:
        return False


def fetch_crl(crl_endpoint):
    """Function for fetching a CRL given an endpoint

    Takes in a CRL endpoint string and fetches the DER encoded
    CRL data. The data is then parsed into a cryptography.x509.
    CertificateRevocationList object.

    Args:
        crl_endpoint (str): The HTTP endpoint string of the CRL

    Returns:
        (cryptography.x509.CertificateRevocationList): parsed CRL
    """
    try:
        response = requests.get(crl_endpoint)
        response.raise_for_status()
        return x509.load_der_x509_crl(response.content, default_backend())

    except HTTPError as http_err:
        print(
            f"HTTP error occurred while requesting crl from {crl_endpoint}")
    except Exception as e:
        print(
            f"Unhandled exception occured while requesting crl from {crl_endpoint}")

    return None


def get_crl_endpoints(crypto_obj, oid):
    """Extract CRL endpoints from cryptography object

    Takes in a cryptography object (certificate or CRL)
    and extracts an extension with a list of
    distribution points for a given oid. It then extracts
    the full_name enpoint from each DP and checks that it
    uses HTTP.

    Args:
        crypto_obj (cryptography.x509...): The object to extract extension from
        oid (cryptography.x509.oid.ExtensionOID): Extension object identifier

    Returns:
        (list): List of str endpoints or an empty list
    """
    endpoints = []

    try:
        extension = crypto_obj.extensions.get_extension_for_oid(oid)

        for dist_point in extension.value:
            if dist_point.full_name is not None:
                for name_item in dist_point.full_name:
                    if urlsplit(name_item.value).scheme == "http":
                        endpoints.append(name_item.value)

        return endpoints

    except x509.ExtensionNotFound:
        return []


def get_crls(crypto_obj, extension_oid):
    """Function for getting CRLs for a given crypto object

    This function extracts all CRL endpoints from a crypto object,
    fetches the CRLs from each endpoint, extracts the CRL number
    from each CRL and returns it as a list of dictionaries.

    Args:
        crypto_obj (cryptography.x509...): Object to extract CRLs from
        extension_oid (cryptography.x509.oid.ExtensionOID): Extension oid

    Returns:
        (list): List of dictionaries or an empty list
    """
    crl_list = []

    # Extract HTTP CRL endpoints from CRL extention
    crl_endpoints = get_crl_endpoints(
        crypto_obj, extension_oid)

    for crl_endpoint in crl_endpoints:
        crl = fetch_crl(crl_endpoint)
        if crl is not None:
            crl_number = get_crl_number(crl)
            crl_list.append(
                {"endpoint": crl_endpoint, "crl": crl, "crl_number": crl_number})

    return crl_list


def get_crl_number(crl):
    """Extract CRL number from CRL

    Extracts the CRLNumber extension from the given CRL and
    returns the value, or None if the extension is not present.

    Args:
        crl (cryptography.x509.CertificateRevocationList): CRL

    Returns:
        crl_number (int): The CRL number of the given CRL
        or
        None if the extension is not present
    """
    try:
        number_ext = crl.extensions.get_extension_for_class(x509.CRLNumber)
        return number_ext.value.crl_number

    except x509.ExtensionNotFound:
        print("Failed to get CRL number")
        return None


def get_reason_message(reason):
    """Look up the reason string for a reason flag

    Takes in a reason flag for a revocation object found
    in a CRL and returns the meaning.

    Args:
        reason (str): The reason flag

    Returns:
        (str): The reason string for the revocation
    """
    if reason == "key_compromise":
        reason_msg = "The private key was compromised"
    elif reason == "ca_compromise":
        reason_msg = "The CA that issued the certificate was compromised"
    elif reason == "affiliation_changed":
        reason_msg = "The subject’s name or other information has changed"
    elif reason == "superseded":
        reason_msg = "The certificate has been superseded"
    elif reason == "cessation_of_operation":
        reason_msg = "The certificate is no longer in operation"
    elif reason == "certificate_hold":
        reason_msg = "The certificate is currently on hold"
    elif reason == "privilege_withdrawn":
        reason_msg = "The privilege granted by this certificate have been withdrawn"
    elif reason == "aa_compromise":
        reason_msg = "The relevant attribute authority has been compromised"
    else:
        reason_msg = "Uknown reason"

    return reason_msg
