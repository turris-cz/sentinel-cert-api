from .crypto import AVAIL_HASHES, get_common_names, csr_from_str
from .exceptions import InvalidParamError, InvalidAuthStateError, InvalidSessionError, ClientDataError

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
        raise InvalidParamError("SN has invalid length.")
    if sn[0:5] != "00000":
        raise InvalidParamError("SN has invalid format.")
    try:
        sn_value = int(sn, 16)
    except ValueError:
        raise InvalidParamError("SN has invalid format.")
    if sn_value % 11 != 0:
        raise InvalidParamError("SN has invalid format.")


sn_validators = {
    "atsha204": validate_sn_atsha,
}


def validate_csr_common_name(csr, identity):
    common_names = get_common_names(csr)
    if len(common_names) != 1:
        raise InvalidParamError("CSR has not exactly one CommonName")

    common_name = common_names[0].value
    if common_name != identity:
        raise InvalidParamError("CSR CommonName ({}) does not match desired identity".format(common_name))


def validate_csr_hash(csr):
    h = csr.signature_hash_algorithm.name
    if h not in AVAIL_HASHES:
        raise InvalidParamError("CSR is signed with not allowed hash ({})".format(h))


def validate_csr_signature(csr):
    if not csr.is_signature_valid:
        raise InvalidParamError("Request signature is not valid")


def validate_csr(csr, sn):
    csr = csr_from_str(csr)
    validate_csr_common_name(csr, sn)
    validate_csr_hash(csr)
    validate_csr_signature(csr)


def validate_flags(flags):
    for flag in flags:
        if flag not in AVAIL_FLAGS:
            raise InvalidParamError("Flag not available: {}".format(flag))


def validate_req_type(req_type):
    if req_type not in AVAIL_REQUEST_TYPES:
        raise InvalidParamError("Invalid request type: {}".format(req_type))


def validate_sid(sid):
    if sid == "":
        return
    if (len(sid) != 64 or not sid.islower()):
        raise InvalidParamError("Bad format of sid: {}".format(sid))
    try:
        sid = int(sid, 16)
    except ValueError:
        raise InvalidParamError("Bad format of sid: {}".format(sid))


def validate_digest(digest):
    if len(digest) != 64:
        raise InvalidParamError("Bad format of digest: {}".format(digest))
    try:
        digest = int(digest, 16)
    except ValueError:
        raise InvalidParamError("Bad format of digest: {}".format(digest))


def validate_auth_type(auth_type):
    if auth_type not in sn_validators:
        raise InvalidParamError("Invalid auth type: {}".format(auth_type))


def check_session(session):
    if type(session) is not dict:
        raise InvalidSessionError("Must be a dict!")
    for param in SESSION_PARAMS:
        if param not in session:
            raise InvalidSessionError("{} missing in session".format(param))


def check_auth_state(auth_state):
    for param in AUTH_STATE_PARAMS:
        if param not in auth_state:
            raise InvalidAuthStateError("{} missing in auth_state".format(param))
    if auth_state["status"] not in AVAIL_STATES:
        raise InvalidAuthStateError("Invalid status ({}) in auth_state".format(auth_state["status"]))


def check_params_exist(req, params):
    for param in GENERAL_REQ_PARAMS:
        if param not in req:
            raise ClientDataError("'{}' is missing in the request".format(param))


def check_request(req):
    if type(req) is not dict:
        raise ClientDataError("Request not a valid JSON with correct content type")
    check_params_exist(req, GENERAL_REQ_PARAMS)
    validate_req_type(req["type"])
    validate_auth_type(req["auth_type"])
    validate_sn = sn_validators[req["auth_type"]]
    validate_sn(req["sn"])
    validate_sid(req["sid"])

    if req["type"] == "get_cert":
        if len(req) > (len(GENERAL_REQ_PARAMS) + len(GET_CERT_REQ_PARAMS)):
            raise ClientDataError("Too much parameters in request")
        check_params_exist(req, AUTH_REQ_PARAMS)
        validate_csr(req["csr"], req["sn"])
        validate_flags(req["flags"])

        if "renew" in req["flags"] and req["sid"]:
            raise InvalidParamError("Renew allowed only in the first request")

    elif req["type"] == "auth":
        if len(req) > (len(GENERAL_REQ_PARAMS) + len(AUTH_REQ_PARAMS)):
            raise ClientDataError("Too much parameters in request")
        check_params_exist(req, GET_CERT_REQ_PARAMS)
        validate_digest(req["digest"])
