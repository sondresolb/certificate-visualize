from cryptography import x509
from OpenSSL.crypto import X509 as pyx509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
import visualize_certificate as vis_cert


def build_test_certificate():
    one_day = datetime.timedelta(1, 0, 0)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'solbakken.io'),
    ]))

    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'solbakken.io'),
    ]))

    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(
        datetime.datetime.today() + (one_day * 30))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)

    builder = builder.add_extension(
        x509.SubjectAlternativeName(
            [x509.DNSName(u'solbakken.io')]),
        critical=False
    )

    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )

    builder = builder.add_extension(
        x509.TLSFeature([x509.TLSFeatureType.status_request,
                         x509.TLSFeatureType.status_request_v2]), critical=True
    )

    certificate = builder.sign(
        private_key=private_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    return vis_cert.Cert_repr(pyx509.from_cryptography(certificate))
