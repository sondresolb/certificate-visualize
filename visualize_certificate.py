from OpenSSL import crypto

from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.x509 import InvalidVersion

from cryptography.hazmat.primitives import asymmetric, hashes


# Decorator for creating safe function reference
def func_ref(func):
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs, me=func)
    return wrapper


class Cert_repr:
    def __init__(self, cert_obj):
        self.py_cert = cert_obj
        self.crypto_cert = None
        self.subject = None
        self.issuer = None
        self.version = None
        self.serial_number = None
        self.signature_algorithm = None
        self.signature_hash = None
        self.has_expired = None
        self.validity_period = None
        self.public_key = None
        self.extensions = None
        self.fingerprint = None
        self.certificate_type = None
        self.must_staple = None
        self.ct_poison = None
        self.initilize_cert()

    def initilize_cert(self):
        self.crypto_cert = self.py_cert.to_cryptography()
        self.subject = self.set_dn(self.crypto_cert.subject)
        self.issuer = self.set_dn(self.crypto_cert.issuer)
        self.version = self.set_version()
        self.serial_number = self.set_serialnumber()
        self.signature_algorithm = self.set_signature_algorithm()
        self.signature_hash = self.set_signature_hash()
        self.has_expired = self.set_has_expired()
        self.validity_period = self.set_validity_period()
        self.public_key = self.set_public_key()
        self.extensions = self.set_extensions()
        self.fingerprint = self.set_fingerprint()
        self.certificate_type = self.set_certificate_type()
        self.must_staple = self.set_ocsp_must_staple()
        self.ct_poison = self.set_ct_poison()

    # Distinguished Name from x.509.Name object as a dict
    def set_dn(self, cert_name):
        return {item.oid._name: item.value for item in cert_name}

    def set_version(self):
        try:
            return self.crypto_cert.version.name

        except InvalidVersion as invalid:
            print(f"Invalid version: {invalid.parsed_version}")
            return None

    def set_serialnumber(self):
        return self.crypto_cert.serial_number

    def set_signature_algorithm(self):
        return self.crypto_cert.signature_algorithm_oid._name

    # If None, same as specified in signature_algorithm
    def set_signature_hash(self):
        signature_hash = self.crypto_cert.signature_hash_algorithm
        if signature_hash:
            return (signature_hash.name, signature_hash.digest_size*8)

        return None

    def set_has_expired(self):
        return self.py_cert.has_expired()

    # Returns tuple(not_valid_before, not_valid_after)
    def set_validity_period(self):
        not_before = self.crypto_cert.not_valid_before
        not_after = self.crypto_cert.not_valid_after
        return (not_before, not_after)

    def set_public_key(self):
        pub_key = {}
        key_obj = self.crypto_cert.public_key()

        if isinstance(key_obj, asymmetric.rsa.RSAPublicKey):
            pub_key["type"] = "RSA"
            pub_key["size"] = key_obj.key_size
            pub_numbers = key_obj.public_numbers()
            pub_key["modulus"] = pub_numbers.n
            pub_key["exponent"] = pub_numbers.e

        elif isinstance(key_obj, asymmetric.dsa.DSAPublicKey):
            pub_key["type"] = "DSA"
            pub_key["size"] = key_obj.key_size
            pub_numbers = key_obj.public_numbers()
            pub_key["y"] = pub_numbers.y
            param_numbers = pub_numbers.parameter_numbers
            pub_key["modulus"] = param_numbers.p
            pub_key["sub-group-order"] = param_numbers.q
            pub_key["generator"] = param_numbers.g

        elif isinstance(key_obj, asymmetric.ec.EllipticCurvePublicKey):
            pub_key["type"] = "EllipticCurve"
            curve_obj = key_obj.public_numbers().curve
            pub_key["size"] = curve_obj.key_size
            pub_key["curve"] = curve_obj.name

        elif isinstance(key_obj, asymmetric.ed25519.Ed25519PublicKey):
            pub_key["type"] = "EdDSA25519"
            pub_key["hash"] = "sha512"
            pub_key["curve"] = "curve25519"

        elif isinstance(key_obj, asymmetric.ed448.Ed448PublicKey):
            pub_key["type"] = "EdDSA448"
            pub_key["hash"] = "SHAKE256"
            pub_key["curve"] = "curve448"

        return pub_key

    def set_fingerprint(self):
        fingerprint = {}
        fingerprint["SHA1"] = self.crypto_cert.fingerprint(hashes.SHA1()).hex()
        fingerprint["SHA256"] = self.crypto_cert.fingerprint(
            hashes.SHA256()).hex()

        return fingerprint

    # Checking policy oids for a match agains type oids
    def set_certificate_type(self):
        policy_ext = self.extensions.get("certificatePolicies", None)
        if policy_ext is None:
            return 'Not indicated'

        if '2.23.140.1.2.3' in policy_ext["value"]:
            return 'Individual-validated'
        elif '2.23.140.1.2.1' in policy_ext["value"]:
            return 'Domain-validated'
        elif '2.23.140.1.2.2' in policy_ext["value"]:
            return 'Organization-validated'
        elif '2.23.140.1.1' in policy_ext["value"]:
            return 'Extended-validation'
        else:
            return 'Not indicated'

    # Checking if the TLSFeature extension is present
    def set_ocsp_must_staple(self):
        tls_feature = self.extensions.get("TLSFeature", None)
        return tls_feature is not None

    def set_ct_poison(self):
        """Check if a certificate includes the ctPoison extension

        If a certificate includes the ctPoison extension, it should not
        be used for any purposed carried out by a complete x509 certificate.
        A certificate including this extension is a pre-certificate meant to
        be issued to a certificate transparency log.

        Args:
            self (Cert_repr): The certificate to check for extension in

        Returns:
            (bool): Indicates if the extension is present or not
        """
        poison_ext = self.extensions.get("ctPoison", None)
        return poison_ext is not None

    def set_extensions(self):
        extensions = {}

        try:
            for ext in self.crypto_cert.extensions:
                try:
                    fn = getattr(self, ext.oid._name)
                    extensions[ext.oid._name] = fn(ext)

                except AttributeError:
                    if isinstance(ext, x509.UnrecognizedExtension):
                        extensions[ext.oid._name] = self.unrecognizedExtension(
                            ext)
                    else:
                        print(f"Failed to parse extension: {ext.oid._name}")

        except x509.DuplicateExtension as dup:
            print(str(dup))
        except x509.UnsupportedGeneralNameType as unsupp:
            print(str(unsupp))
        except UnicodeError as uni:
            print(str(uni))
        except Exception as e:
            print(str(e))

        return extensions

    # x.509 Certificate extensions ---->

    @func_ref
    def keyUsage(self, ext, me):
        """
        The key usage extension defines the purpose of the key contained in
        the certificate. The usage restriction might be employed when a key
        that could be used for more than one operation is to be restricted.
        """
        ext_obj = {}
        ext_obj["name"] = ext.oid._name
        ext_obj["critical"] = ext.critical
        ext_obj["doc"] = self.get_documentation(me)
        ext_obj["OID"] = ext.oid.dotted_string
        ext_obj["value"] = []

        val = ext.value
        ext_obj["value"].append(
            "content_commitment") if val.content_commitment else None
        ext_obj["value"].append(
            "data_encipherment") if val.data_encipherment else None
        ext_obj["value"].append(
            "digital_signature") if val.digital_signature else None
        ext_obj["value"].append(
            "key_encipherment") if val.key_encipherment else None
        ext_obj["value"].append("crl_sign") if val.crl_sign else None
        ext_obj["value"].append("key_cert_sign") if val.key_cert_sign else None
        ext_obj["value"].append("key_agreement") if val.key_agreement else None

        if val.key_agreement:
            ext_obj["value"].append(
                "encipher_only") if val.encipher_only else None
            ext_obj["value"].append(
                "decipher_only") if val.decipher_only else None

        return ext_obj

    @func_ref
    def basicConstraints(self, ext, me):
        """
        Basic constraints is an X.509 extension type that defines whether a
        given certificate is allowed to sign additional certificates and what
        path length restrictions may exist.
        """
        extension_obj = {}
        extension_obj["name"] = ext.oid._name
        extension_obj["critical"] = ext.critical
        extension_obj["doc"] = self.get_documentation(me)
        extension_obj["OID"] = ext.oid.dotted_string
        extension_obj["value"] = {"CA": ext.value.ca,
                                  "path_length": ext.value.path_length}

        return extension_obj

    @func_ref
    def extendedKeyUsage(self, ext, me):
        """
        This extension indicates one or more purposes for which the certified
        public key may be used, in addition to or in place of the basic
        purposes indicated in the key usage extension.
        """
        extension_obj = {}
        extension_obj["name"] = ext.oid._name
        extension_obj["critical"] = ext.critical
        extension_obj["doc"] = self.get_documentation(me)
        extension_obj["OID"] = ext.oid.dotted_string
        extension_obj["value"] = [oid._name for oid in ext.value]

        return extension_obj

    @func_ref
    def TLSFeature(self, ext, me):
        """
        The TLS Feature extension is defined in RFC 7633 and is used in
        certificates for OCSP Must-Staple.
        """
        extension_obj = {}
        extension_obj["name"] = ext.oid._name
        extension_obj["critical"] = ext.critical
        extension_obj["doc"] = self.get_documentation(me)
        extension_obj["OID"] = ext.oid.dotted_string
        extension_obj["value"] = []

        for item in ext.value:
            extension_obj["value"].append(item.name)

        return extension_obj

    @func_ref
    def nameConstraints(self, ext, me):
        """
        The name constraints extension, which only has meaning in a CA
        certificate, defines a name space within which all subject names in
        certificates issued beneath the CA certificate must (or must not) be in.
        """
        extension_obj = {}
        extension_obj["name"] = ext.oid._name
        extension_obj["critical"] = ext.critical
        extension_obj["doc"] = self.get_documentation(me)
        extension_obj["OID"] = ext.oid.dotted_string
        extension_obj["value"] = {}

        extension_obj["value"]["permitted_subtrees"] = [
            val.value for val in ext.permitted_subtrees]
        extension_obj["value"]["excluded_subtrees"] = [
            val.value for val in ext.excluded_subtrees]

        return extension_obj

    @func_ref
    def authorityKeyIdentifier(self, ext, me):
        """
        The authority key identifier extension provides a means of identifying
        the public key corresponding to the private key used to sign this certificate.
        This extension is also typically used to assist in determining the appropriate
        certificate chain.
        """
        extension_obj = {}
        extension_obj["name"] = ext.oid._name
        extension_obj["critical"] = ext.critical
        extension_obj["doc"] = self.get_documentation(me)
        extension_obj["OID"] = ext.oid.dotted_string
        extension_obj["value"] = ext.value.key_identifier.hex()

        return extension_obj

    @func_ref
    def subjectKeyIdentifier(self, ext, me):
        """
        The subject key identifier extension provides a means of uniquely
        identifying the public key contained in this certificate.
        """
        extension_obj = {}
        extension_obj["name"] = ext.oid._name
        extension_obj["critical"] = ext.critical
        extension_obj["doc"] = self.get_documentation(me)
        extension_obj["OID"] = ext.oid.dotted_string
        extension_obj["value"] = ext.value.digest.hex()

        return extension_obj

    @func_ref
    def subjectAltName(self, ext, me):
        """
        Subject alternative name is an X.509 extension that provides a set
        of identities for which the certificate is valid.
        """
        extension_obj = {}
        extension_obj["name"] = ext.oid._name
        extension_obj["critical"] = ext.critical
        extension_obj["doc"] = self.get_documentation(me)
        extension_obj["OID"] = ext.oid.dotted_string
        extension_obj["value"] = ext.value.get_values_for_type(x509.DNSName)

        return extension_obj

    @func_ref
    def issuerAltName(self, ext, me):
        """
        Issuer alternative name is an X.509 extension that provides a set
        of identities for the certificate issuer.
        """
        extension_obj = {}
        extension_obj["name"] = ext.oid._name
        extension_obj["critical"] = ext.critical
        extension_obj["doc"] = self.get_documentation(me)
        extension_obj["OID"] = ext.oid.dotted_string
        extension_obj["value"] = ext.value.get_values_for_type(x509.DNSName)

        return extension_obj

    @func_ref
    def signedCertificateTimestampList(self, ext, me):
        """
        This extension contains Signed Certificate Timestamps which were
        issued for the pre-certificate corresponding to this certificate.
        These can be used to verify that the certificate is included in a
        public Certificate Transparency log.
        """
        extension_obj = {}
        extension_obj["name"] = ext.oid._name
        extension_obj["critical"] = ext.critical
        extension_obj["doc"] = self.get_documentation(me)
        extension_obj["OID"] = ext.oid.dotted_string
        extension_obj["value"] = []

        for item in ext.value:
            sct = {}
            sct["version"] = item.version.name
            sct["log_id"] = item.log_id.hex()
            sct["timestamp"] = item.timestamp
            sct["entry_type"] = item.entry_type.name
            extension_obj["value"].append(sct)

        return extension_obj

    @func_ref
    def ctPoison(self, ext, me):
        """
        This extension indicates that the certificate should not be treated
        as a certificate for the purposes of validation, but is instead for
        submission to a certificate transparency log in order to obtain SCTs
        which will be embedded in a Precertificate SCTs extension on the
        final certificate. This certificate is not safe to use for any purposes
        carried out by a complete x509 certificate.
        """
        extension_obj = {}
        extension_obj["name"] = ext.oid._name
        extension_obj["critical"] = ext.critical
        extension_obj["doc"] = self.get_documentation(me)
        extension_obj["OID"] = ext.oid.dotted_string

        return extension_obj

    # TODO: Remove this CRL extension
    @func_ref
    def deltaCRLIndicator(self, ext, me):
        """
        The delta CRL indicator is a CRL extension that identifies a CRL as
        being a delta CRL. Delta CRLs contain updates to revocation information
        previously distributed, rather than all the information that would appear
        in a complete CRL.
        """
        extension_obj = {}
        extension_obj["name"] = ext.oid._name
        extension_obj["critical"] = ext.critical
        extension_obj["doc"] = self.get_documentation(me)
        extension_obj["OID"] = ext.oid.dotted_string
        extension_obj["value"] = {"crl_number": ext.value.crl_number}

        return extension_obj

    @func_ref
    def authorityInfoAccess(self, ext, me):
        """
        The authority information access extension indicates how to access
        information and services from the issuer of the certificate in which
        the extension appears. Information and services may include online
        validation services (such as OCSP) and issuer data.
        """
        extension_obj = {}
        extension_obj["name"] = ext.oid._name
        extension_obj["critical"] = ext.critical
        extension_obj["doc"] = self.get_documentation(me)
        extension_obj["OID"] = ext.oid.dotted_string
        extension_obj["value"] = []

        for item in ext.value:
            auth_info = {}
            # Either OCSP or CA_ISSUERS
            auth_info["access_method"] = item.access_method._name
            auth_info["access_location"] = item.access_location.value
            extension_obj["value"].append(auth_info)

        return extension_obj

    # TODO: Remove this CRL extension
    @func_ref
    def freshestCRL(self, ext, me):
        """
        The freshest CRL extension (also known as Delta CRL Distribution Point)
        identifies how delta CRL information is obtained
        """
        extension_obj = {}
        extension_obj["name"] = ext.oid._name
        extension_obj["critical"] = ext.critical
        extension_obj["doc"] = self.get_documentation(me)
        extension_obj["OID"] = ext.oid.dotted_string
        extension_obj["value"] = []

        for item in ext.value:
            pass

        return extension_obj

    @func_ref
    def cRLDistributionPoints(self, ext, me):
        """
        The CRL distribution points extension identifies how CRL information
        is obtained.
        """
        extension_obj = {}
        extension_obj["name"] = ext.oid._name
        extension_obj["critical"] = ext.critical
        extension_obj["doc"] = self.get_documentation(me)
        extension_obj["OID"] = ext.oid.dotted_string
        extension_obj["value"] = []

        for item in ext.value:
            crl_dist = {}

            if item.full_name:
                crl_dist["full_name"] = [fn.value for fn in item.full_name]

            if item.relative_name:
                crl_dist["relative_name"] = item.relative_name.rfc4514_string()

            if item.crl_issuer:
                crl_dist["crl_issuer"] = [ci.value for ci in item.crl_issuer]

            if item.reasons:
                crl_dist["reasons"] = [reason.name for reason in item.reasons]

            extension_obj["value"].append(crl_dist)

        return extension_obj

    @func_ref
    def inhibitAnyPolicy(self, ext, me):
        """
        The inhibit anyPolicy extension indicates that the special OID ANY_POLICY,
        is not considered an explicit match for other CertificatePolicies except
        when it appears in an intermediate self-issued CA certificate. The value
        indicates the number of additional non-self-issued certificates that may
        appear in the path before ANY_POLICY is no longer permitted. For example,
        a value of one indicates that ANY_POLICY may be processed in certificates
        issued by the subject of this certificate, but not in additional
        certificates in the path.
        """
        extension_obj = {}
        extension_obj["name"] = ext.oid._name
        extension_obj["critical"] = ext.critical
        extension_obj["doc"] = self.get_documentation(me)
        extension_obj["OID"] = ext.oid.dotted_string
        extension_obj["value"] = {"skip_certs": ext.value.skip_certs}

        return extension_obj

    @func_ref
    def policyConstraints(self, ext, me):
        """
        The policy constraints extension is used to inhibit policy mapping or
        require that each certificate in a chain contain an acceptable policy
        identifier. For more information about the use of this extension see
        RFC 5280.
        """
        extension_obj = {}
        extension_obj["name"] = ext.oid._name
        extension_obj["critical"] = ext.critical
        extension_obj["doc"] = self.get_documentation(me)
        extension_obj["OID"] = ext.oid.dotted_string
        extension_obj["value"] = None

        constraints = {}

        constraints["require_explicit_policy"] = ext.value.require_explicit_policy
        constraints["inhibit_policy_mapping"] = ext.value.inhibit_policy_mapping
        extension_obj["value"] = constraints

        return extension_obj

    @func_ref
    def certificatePolicies(self, ext, me):
        """
        The certificate policies extension is a list containing one or
        more policies.
        """
        extension_obj = {}
        extension_obj["name"] = ext.oid._name
        extension_obj["critical"] = ext.critical
        extension_obj["doc"] = self.get_documentation(me)
        extension_obj["OID"] = ext.oid.dotted_string
        extension_obj["value"] = []

        for policy in ext.value:
            extension_obj["value"].append(
                policy.policy_identifier.dotted_string)

        return extension_obj

    @func_ref
    def unrecognizedExtension(self, ext, me):
        """
        Generic extension holding the raw value of an extension that
        the underlying cryptography library does not know how to parse.
        """
        extension_obj = {}
        extension_obj["name"] = ext.oid._name
        extension_obj["critical"] = ext.critical
        extension_obj["doc"] = self.get_documentation(me)
        extension_obj["OID"] = ext.oid.dotted_string
        extension_obj["value"] = ext.value

        return extension_obj

    def get_documentation(self, func):
        return " ".join(func.__doc__.split())
