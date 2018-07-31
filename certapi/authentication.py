import json

from certapi import app
from certapi.crypto import create_random_sid, create_random_nonce, key_match
from certapi.exceptions import InvalidAuthStateError, InvalidSessionError, InvalidParamError
from certapi import validators

DELAY_GET_SESSION_EXISTS = 10
DELAY_AUTH = 10
DELAY_AUTH_AGAIN = 10


def get_session_key(sn, sid):
    return "session:{}:{}".format(sn, sid)


def get_auth_state_key(sn, sid):
    return "auth_state:{}:{}".format(sn, sid)


def get_cert_key(sn):
    return "certificate:{}".format(sn)


def create_auth_session(sn, sid, csr_str, flags, auth_type, r):
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


def get_auth_state(sn, sid, r):
    """ Get state of client authentication from Redis. If the state is failed
    or missing, return fail info.
    """
    auth_state = r.get(get_auth_state_key(sn, sid))
    if not auth_state:
        app.logger.debug("Certificate creation in progress, sn=%s, sid=%s", sn, sid)
        status = {
            "status": "wait",
            "delay": DELAY_GET_SESSION_EXISTS
        }
        return (False, status)

    try:
        auth_state = json.loads(auth_state.decode("utf-8"))
    except UnicodeDecodeError:
        app.logger.error("UnicodeDecodeError for auth_state sn=%s, sid=%s", sn, sid)
        return (False, {"status": "error"})
    except json.decoder.JSONDecodeError:
        app.logger.error("JSONDecodeError for auth_state sn=%s, sid=%s", sn, sid)
        return (False, {"status": "error"})

    try:
        validators.check_auth_state(auth_state)
    except InvalidAuthStateError:
        app.logger.error("Auth state ivalid for sn=%s, sid=%s", sn, sid)
        return (False, {"status": "error"})

    if auth_state["status"] == "ok":
        return (True, None)
    elif auth_state["status"] == "failed":
        return (False, {"status": "auth_failed"})
    else:
        app.logger.error("auth_state invalid value in session sn=%s, sid=%s", sn, sid)
        return (False, {"status": "error"})


def process_req_get(sn, sid, csr_str, flags, auth_type, r):
    app.logger.debug("Processing GET request, sn=%s, sid=%s", sn, sid)
    if "renew" in flags:  # when renew is flagged we ignore cert in redis
        return create_auth_session(sn, sid, csr_str, flags, auth_type, r)
    authenticated = False

    # We care about authentication only when session exists
    if r.exists(get_session_key(sn, sid)):
        (authenticated, status) = get_auth_state(sn, sid, r)
        if not authenticated:
            return status

    cert_bytes = r.get(get_cert_key(sn))
    if not cert_bytes:
        if authenticated:
            app.logger.warning("Auth OK but certificate not in redis, sn=%s", sn)
        else:
            app.logger.debug("Certificate not in redis, sn=%s", sn)
        return create_auth_session(sn, sid, csr_str, flags, auth_type, r)

    app.logger.debug("Certificate found in redis, sn=%s", sn)

    # cert and csr public key match
    if not key_match(cert_bytes, csr_str.encode("utf-8")):
        if authenticated:
            app.logger.warning("Auth OK but certificate key does not match, sn=%s", sn)
        else:
            app.logger.debug("Certificate key does not match, sn=%s", sn)
        return create_auth_session(sn, sid, csr_str, flags, auth_type, r)

    app.logger.debug("Certificate restored from redis, sn=%s", sn)
    return {
        "status": "ok",
        "cert": cert_bytes.decode("utf-8")
    }


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
        validators.check_session(session)
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
        validators.validate_req_type(req_json["type"])
        validators.validate_auth_type(req_json["auth_type"])
        validators.validate_sn = validators.sn_validators[req_json["auth_type"]]
        validators.validate_sn(req_json["sn"])
        validators.validate_sid(req_json["sid"])

        if req_json["type"] == "get_cert":
            validators.validate_csr(req_json["csr"], req_json["sn"])
            validators.validate_flags(req_json["flags"])
        elif req_json["type"] == "auth":
            validators.validate_digest(req_json["digest"])

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
