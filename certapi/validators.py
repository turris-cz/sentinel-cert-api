from .crypto import AVAIL_HASHES, get_common_names, csr_from_str
from .exceptions import RequestConsistencyError, InvalidRedisDataError

AVAIL_REQUEST_TYPES = {"get_cert", "auth"}
AVAIL_FLAGS = {"renew"}
AVAIL_STATES = {"ok", "fail", "error"}

SESSION_PARAMS = {
    "auth_type",
    "nonce",
    "digest",
    "csr_str",
    "flags",
}
AUTH_STATE_PARAMS = {
    "status",
    "message",
}
GENERAL_REQ_PARAMS = {
    "type",
    "auth_type",
    "sid",
    "sn",
}
GET_CERT_REQ_PARAMS = {
    "csr",
    "flags",
}
AUTH_REQ_PARAMS = {
    "digest",
}


def validate_sn_atsha(sn):
    if len(sn) != 16:
        raise RequestConsistencyError("SN has invalid length.")
    if sn[0:5] != "00000":
        raise RequestConsistencyError("SN has invalid format.")
    try:
        sn_value = int(sn, 16)
    except ValueError:
        raise RequestConsistencyError("SN has invalid format.")
    if sn_value % 11 != 0:
        raise RequestConsistencyError("SN has invalid format.")


sn_validators = {
    "atsha204": validate_sn_atsha,
}


def validate_csr_common_name(csr, identity):
    common_names = get_common_names(csr)
    if len(common_names) != 1:
        raise RequestConsistencyError("CSR has not exactly one CommonName")

    common_name = common_names[0].value
    if common_name != identity:
        raise RequestConsistencyError("CSR CommonName ({}) does not match desired identity".format(common_name))


def validate_csr_hash(csr):
    h = csr.signature_hash_algorithm.name
    if h not in AVAIL_HASHES:
        raise RequestConsistencyError("CSR is signed with not allowed hash ({})".format(h))


def validate_csr_signature(csr):
    if not csr.is_signature_valid:
        raise RequestConsistencyError("Request signature is not valid")


def validate_csr(csr, sn):
    csr = csr_from_str(csr)
    validate_csr_common_name(csr, sn)
    validate_csr_hash(csr)
    validate_csr_signature(csr)


def validate_flags(flags):
    for flag in flags:
        if flag not in AVAIL_FLAGS:
            raise RequestConsistencyError("Flag not available: {}".format(flag))


def validate_req_type(req_type):
    if req_type not in AVAIL_REQUEST_TYPES:
        raise RequestConsistencyError("Invalid request type: {}".format(req_type))


def validate_sid(sid):
    if sid == "":
        return
    if (len(sid) != 64 or not sid.islower()):
        raise RequestConsistencyError("Bad format of sid: {}".format(sid))
    try:
        sid = int(sid, 16)
    except ValueError:
        raise RequestConsistencyError("Bad format of sid: {}".format(sid))


def validate_digest(digest):
    if len(digest) != 64:
        raise RequestConsistencyError("Bad format of digest: {}".format(digest))
    try:
        digest = int(digest, 16)
    except ValueError:
        raise RequestConsistencyError("Bad format of digest: {}".format(digest))


def validate_auth_type(auth_type):
    if auth_type not in sn_validators:
        raise RequestConsistencyError("Invalid auth type: {}".format(auth_type))


def check_session(session):
    if type(session) is not dict:
        raise InvalidRedisDataError("Must be a dict!")
    for param in SESSION_PARAMS:
        if param not in session:
            raise InvalidRedisDataError("Parameter {} missing".format(param))


def validate_auth_state(auth_state):
    if type(auth_state) is not dict:
        raise InvalidRedisDataError("Must be a dict!")
    for param in AUTH_STATE_PARAMS:
        if param not in auth_state:
            raise InvalidRedisDataError("Parameter {} missing".format(param))
    if auth_state["status"] not in AVAIL_STATES:
        raise InvalidRedisDataError("Invalid status '{}'".format(auth_state["status"]))


def check_params_exist(req, params):
    for param in params:
        if param not in req:
            raise RequestConsistencyError("'{}' is missing in the request".format(param))


def check_request(req):
    if type(req) is not dict:
        raise RequestConsistencyError("Request not a valid JSON with correct content type")
    check_params_exist(req, GENERAL_REQ_PARAMS)
    validate_req_type(req["type"])
    validate_auth_type(req["auth_type"])
    validate_sn = sn_validators[req["auth_type"]]
    validate_sn(req["sn"])
    validate_sid(req["sid"])

    if req["type"] == "get_cert":
        check_params_exist(req, GET_CERT_REQ_PARAMS)
        validate_csr(req["csr"], req["sn"])
        validate_flags(req["flags"])

        if "renew" in req["flags"] and req["sid"]:
            raise RequestConsistencyError("Renew allowed only in the first request")

    elif req["type"] == "auth":
        check_params_exist(req, AUTH_REQ_PARAMS)
        validate_digest(req["digest"])
