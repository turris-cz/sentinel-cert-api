class CertAPIError(Exception):
    pass


class RequestConsistencyError(CertAPIError):
    pass


class RequestProcessError(CertAPIError):
    pass


class CertAPISystemError(CertAPIError):
    pass


class InvalidRedisDataError(CertAPISystemError):
    pass
