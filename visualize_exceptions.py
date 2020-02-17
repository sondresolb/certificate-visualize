class InvalidCertificateChain(Exception):
    pass


class NoCertificatesError(Exception):
    pass


class IntermediateFetchingError(Exception):
    pass


class CertificateFetchingError(Exception):
    pass


class OCSPRequestBuildError(Exception):
    pass


class OCSPRequestResponseError(Exception):
    pass
