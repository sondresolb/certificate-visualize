from OpenSSL import crypto

from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.x509 import ExtensionNotFound
from cryptography.x509 import InvalidVersion


class cert_repr:
    def __init__(self, cert_obj):
        self.py_cert = cert_obj
        self.crypto_cert = None

        self.subject = None
        self.issuer = None
        self.version = None
        self.has_expired = None
        self.serial_number = None
        self.signature_algorithm = None

        self.initilize_cert()

    def initilize_cert(self):
        self.crypto_cert = self.py_cert.to_cryptography()
        self.subject = self.set_dn(self.crypto_cert.subject)
        self.issuer = self.set_dn(self.crypto_cert.issuer)
        self.version = self.set_version()

    # Distinguished Name from x.509.Name object as a dict
    def set_dn(self, cert_name):
        return {item.oid._name: item.value for item in cert_name}

    def set_version(self):
        try:
            return self.crypto_cert.version.name

        except InvalidVersion as invalid:
            print(f"Invalid version: {invalid.parsed_version}")
            return None

    def set_extensions(self):
        for ext in self.crypto_cert.extensions:
            print(ext)

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
