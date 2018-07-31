class CertAPIError(Exception):
    pass


class InvalidParamError(CertAPIError):
    pass


class InvalidSessionError(CertAPIError):
    pass


class InvalidAuthStateError(CertAPIError):
    pass
