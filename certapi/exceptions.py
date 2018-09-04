class CertAPIError(Exception):
    pass


class CertAPIClientError(CertAPIError):
    pass


class ClientDataError(CertAPIClientError):
    pass


class ClientAuthError(CertAPIClientError):
    pass


class InvalidParamError(ClientDataError):
    pass


class CertAPISystemError(CertAPIError):
    pass


class InvalidSessionError(CertAPISystemError):
    pass


class InvalidAuthStateError(CertAPISystemError):
    pass


class AuthStateMissing(Exception):
    pass
