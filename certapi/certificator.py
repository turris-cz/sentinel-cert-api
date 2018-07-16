#!/usr/bin/env python
import json
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography import x509

from certapi import app

DELAY_GET_SESSION_EXISTS = 10
DELAY_AUTH = 10
DELAY_AUTH_AGAIN = 10

AVAIL_REQUEST_TYPES = {"get_cert", "auth"}
AVAIL_FLAGS = {"renew"}
AVAIL_HASHES = {
    hashes.SHA224,
    hashes.SHA256,
    hashes.SHA384,
    hashes.SHA512,
}

SESSION_PARAMS = {
    "auth_type",
    "nonce",
    "digest",
    "csr_str",
    "flags",
}


class InvalidParamError(Exception):
    pass


class InvalidSessionError(Exception):
    pass


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
    common_names = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if len(common_names) != 1:
        raise InvalidParamError("CSR has not exactly one CommonName")

    common_name = common_names[0].value
    if common_name != identity:
        raise InvalidParamError("CSR CommonName ({}) does not match desired identity".format(common_name))


def validate_csr_hash(csr):
    h = csr.signature_hash_algorithm
    if type(h) not in AVAIL_HASHES:
        raise InvalidParamError("CSR is signed with not allowed hash ({})".format(h.name))


def validate_csr_signature(csr):
    if not csr.is_signature_valid:
        raise InvalidParamError("Request signature is not valid")


def csr_from_str(csr_str):
    try:
        # construct x509 request from PEM string
        csr_data = bytes(csr_str, encoding='utf-8')
        csr = x509.load_pem_x509_csr(
                data=csr_data,
                backend=default_backend()
        )
    except (UnicodeEncodeError, ValueError):
        raise InvalidParamError("Invalid CSR format")

    return csr


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
    if (len(sid) != 64 or not sid.islower):
        raise InvalidParamError("Bad format of sid : {}".format(sid))
    try:
        sid = int(sid, 16)
    except ValueError:
        raise InvalidParamError("Bad format of sid : {}".format(sid))


def validate_digest(digest):
    if (len(digest) != 64 or not digest.islower):
        raise InvalidParamError("Bad format of digest : {}".format(digest))
    try:
        digest = int(digest, 16)
    except ValueError:
        raise InvalidParamError("Bad format of digest : {}".format(digest))


def validate_auth_type(auth_type):
    if auth_type not in sn_validators:
        raise InvalidParamError("Invalid auth type: {}".format(auth_type))


def create_random_nonce():
    return os.urandom(32).hex()


def create_random_sid():
    return os.urandom(32).hex()


def get_session_key(sn, sid):
    return "session:{}:{}".format(sn, sid)


def get_auth_state_key(sn, sid):
    return "auth_state:{}:{}".format(sn, sid)


def get_cert_key(sn):
    return "certificate:{}".format(sn)


def check_session(session):
    for param in SESSION_PARAMS:
        if param not in session:
            raise InvalidSessionError(param)


def generate_nonce(sn, sid, csr_str, flags, auth_type, r):
    """ Certificate with matching private key not found in redis
    """
    app.logger.debug("Starting authentication for sn=%s", sn)
    sid = create_random_sid()
    nonce = create_random_nonce()
    session = {
        "auth_type": auth_type,
        "nonce": nonce,
        "digest": "",
        "csr_str": csr_str,
        "flags": flags,
    }
    r.setex(get_session_key(sn, sid),
            app.config["REDIS_SESSION_TIMEOUT"],
            json.dumps(session))
    return {
        "status": "authenticate",
        "sid": sid,
        "nonce": nonce,
    }


def key_match(cert_bytes, csr_bytes):
    """ Compare public keys of two cryptographic objects and return True if
    they are the same, otherwise return False.
    """
    cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
    csr = x509.load_pem_x509_csr(csr_bytes, default_backend())
    return cert.public_key().public_numbers() == csr.public_key().public_numbers()


def process_req_get(sn, sid, csr_str, flags, auth_type, r):
    app.logger.debug("Processing GET request, sn=%s, sid=%s", sn, sid)
    if "renew" in flags:  # when renew is flagged we ignore cert in redis
        return generate_nonce(sn, sid, csr_str, flags, auth_type, r)
    authenticated = False
    if r.exists(get_session_key(sn, sid)):
        auth_state = r.get(get_auth_state_key(sn, sid))
        if auth_state is not None:
            auth_state = json.loads(auth_state.decode("utf-8"))
            try:
                if auth_state["status"] == "ok":
                    authenticated = True
                elif auth_state["status"] == "failed":
                    return {"status": "auth_failed"}
                else:
                    app.logger.error("auth_state invalid value in session sn=%s, sid=%s", sn, sid)
                    return {"status": "error"}
            except KeyError as e:
                app.logger.error("Value missing in Redis session (%s) sn=%s, sid=%s", e, sn, sid)
                return {"status": "error"}
        else:
            app.logger.debug("Certificate creation in progress, sn=%s, sid=%s", sn, sid)
            return {
                "status": "wait",
                "delay": DELAY_GET_SESSION_EXISTS
            }

    cert_bytes = r.get(get_cert_key(sn))
    if cert_bytes is not None:
        app.logger.debug("Certificate found in redis, sn=%s", sn)

        # cert and csr public key match
        if key_match(cert_bytes, csr_str.encode("utf-8")):
            app.logger.debug("Certificate restored from redis, sn=%s", sn)
            return {
                "status": "ok",
                "cert": cert_bytes.decode("utf-8")
            }
        else:
            if authenticated:
                app.logger.warning("Auth OK but certificate key does not match, sn=%s", sn)
            else:
                app.logger.debug("Certificate key does not match, sn=%s", sn)
            return generate_nonce(sn, sid, csr_str, flags, auth_type, r)
    else:
        if authenticated:
            app.logger.warning("Auth OK but certificate not in redis, sn=%s", sn)
        else:
            app.logger.debug("Certificate not in redis, sn=%s", sn)
        return generate_nonce(sn, sid, csr_str, flags, auth_type, r)


def get_auth_session(sn, sid, r):
    """ Get state of client session from Redis. If the session is broken
    or missing, return fail info.
    """
    session_json = r.get(get_session_key(sn, sid))
    if not session_json:  # authentication session open / certificate creation in progress
        app.logger.debug("Authentication session not found, sn=%s, sid=%s", sn, sid)
        return (None, {"status": "fail"})

    try:
        session = json.loads(session_json.decode("utf-8"))
    except UnicodeDecodeError:
        app.logger.error("UnicodeDecodeError for session sn=%s, sid=%s", sn, sid)
        return (None, {"status": "error"})
    except json.decoder.JSONDecodeError:
        app.logger.error("JSONDecodeError for session sn=%s, sid=%s", sn, sid)
        return (None, {"status": "error"})

    try:
        check_session(session)
    except InvalidSessionError as e:
        app.logger.error("Value missing in Redis session (%s) sn=%s, sid=%s", e, sn, sid)
        return (None, {"status": "error"})

    return (session, None)


def push_csr(sn, sid, session, digest, r):
    """ Push csr to the queue in Redis and add digest to the auth session
    """
    session["digest"] = digest
    pipe = r.pipeline(transaction=True)
    pipe.delete(get_session_key(sn, sid))
    pipe.setex(get_session_key(sn, sid),
               app.config["REDIS_SESSION_TIMEOUT"],
               json.dumps(session))
    request = {
        "sn": sn,
        "sid": sid,
        "nonce": session['nonce'],
        "digest": digest,
        "csr_str": session['csr_str'],
        "flags": session["flags"],
        "auth_type": session["auth_type"],
    }
    pipe.lpush('csr', json.dumps(request))
    pipe.execute()


def process_req_auth(sn, sid, digest, auth_type, r):
    app.logger.debug("Processing AUTH request, sn=%s, sid=%s", sn, sid)

    (session, status) = get_auth_session(sn, sid, r)
    if not session:
        return status

    app.logger.debug("Authentication session found open for sn=%s, sid=%s", sn, sid)

    if session["auth_type"] != auth_type:
        app.logger.debug("Authentication type does not match, sn=%s, sid=%s", sn, sid)
        return {"status": "fail"}

    if session["digest"]:  # certificate creation in progress
        app.logger.debug("Digest already saved for sn=%s, sid=%s", sn, sid)
        return {"status": "fail"}

    # start certificate creation (CA will check the digest first)
    app.logger.debug("Saving digest for sn=%s, sid=%s", sn, sid)
    push_csr(sn, sid, session, digest, r)

    return {
        "status": "accepted",
        "delay": DELAY_AUTH,
    }


def process_request(req_json, r):
    if type(req_json) is not dict:
        app.logger.warning("Request failure: not a valid json")
        return {"status": "error"}
    try:
        validate_req_type(req_json["type"])
        validate_auth_type(req_json["auth_type"])
        validate_sn = sn_validators[req_json["auth_type"]]
        validate_sn(req_json["sn"])
        validate_sid(req_json["sid"])

        if req_json["type"] == "get_cert":
            validate_csr(req_json["csr"], req_json["sn"])
            validate_flags(req_json["flags"])
        elif req_json["type"] == "auth":
            validate_digest(req_json["digest"])

    except KeyError as e:
        app.logger.warning("Request failure: parameter missing: %s", e)
        return {"status": "error"}
    except InvalidParamError as e:
        app.logger.warning("Request failure: %s", e)
        return {"status": "error"}

    if req_json["type"] == "get_cert":
        # renew flag may be sent only before the auth session starts
        if "renew" in req_json["flags"]:
            if req_json["sid"]:
                return {"status": "fail"}

        reply = process_req_get(req_json["sn"],
                                req_json["sid"],
                                req_json["csr"],
                                req_json["flags"],
                                req_json["auth_type"],
                                r)
        return reply

    elif req_json["type"] == "auth":
        reply = process_req_auth(req_json["sn"],
                                 req_json["sid"],
                                 req_json["digest"],
                                 req_json["auth_type"],
                                 r)
        return reply
