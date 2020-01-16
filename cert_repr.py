from OpenSSL import crypto

from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.x509 import ExtensionNotFound
from cryptography.x509 import InvalidVersion

from cryptography.hazmat.primitives import asymmetric


class cert_repr:
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
        print(self.public_key)

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

    def set_extensions(self):
        for ext in self.crypto_cert.extensions:
            print(ext)

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
        not_before = self.crypto_cert.not_valid_before.ctime()
        not_after = self.crypto_cert.not_valid_after.ctime()
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
            print("EC")
        elif isinstance(key_obj, asymmetric.ed25519.Ed25519PublicKey):
            print("ED2")
        elif isinstance(key_obj, asymmetric.ed448.Ed448PublicKey):
            print("ED4")

        return pub_key

    def dump_certificates(self, host, cert_path, certs):
        try:
            for index, cert in enumerate(certs):
                # DN possibly not unique in different regions
                tmp_path = os.path.join(cert_path, host)
                path = f"{tmp_path}_{index}.pem"

                with open(path, 'w+') as out:
                    out.write((crypto.dump_certificate
                               (crypto.FILETYPE_PEM, cert).decode('utf-8')))

        except IOError:
            print(f'Exception:  {IOError.strerror}')
