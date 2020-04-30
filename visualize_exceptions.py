class InvalidCertificateChain(Exception):
    pass


class NoCertificatesError(Exception):
    pass


class IntermediateFetchingError(Exception):
    pass


class CertificateFetchingError(Exception):
    pass


class CipherFetchingError(Exception):
    pass


class OCSPRequestBuildError(Exception):
    pass


class RequestResponseError(Exception):
    pass


class ScanFailureError(Exception):
    pass


class EvaluationFailureError(Exception):
    pass
