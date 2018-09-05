"""
Note on exceptions:
    - CertAPISystemError should be used for sentinel-internal errors
    - RequestConsistencyError should be used for client request that cant be
      processed
    - RequestProcessError should be used for client request that can be processed,
      but the provided data is invalid, including checker/CA authentication
      failure
Note on logging:
    - RequestConsistencyError and RequestProcessError should be logged on it's
      first occurence with levels 'debug', 'info' and 'warning' for most severe
      cases
    - CertAPISystemError should be logged centrally in one place with levels
      'error' for most cases and 'critical' when the application needs to stop
"""
import json

from flask import current_app

from .crypto import create_random_sid, create_random_nonce, key_match
from .exceptions import RequestConsistencyError, RequestProcessError, CertAPISystemError, \
                        InvalidRedisDataError
from .validators import check_request, validate_auth_state, check_session

DELAY_GET_SESSION_EXISTS = 10
DELAY_AUTH = 10
DELAY_AUTH_AGAIN = 10


class AuthStateMissing(Exception):
    pass


def build_reply_auth_accepted(delay=DELAY_AUTH):
    return {
        "status": "accepted",
        "delay": delay,
        "message": "Certification process started, wait for {} sec before"
                   " sending next 'get_cert' request".format(delay),
    }


def build_reply_get_wait(delay=DELAY_GET_SESSION_EXISTS):
    return {
        "status": "wait",
        "delay": delay,
        "message": "Certification process still running, wait for"
                   " {} sec before sending another 'get_cert'"
                   " request".format(delay),
    }


def build_reply_get_ok(cert_bytes):
    return {
        "status": "ok",
        "cert": cert_bytes.decode("utf-8"),
        "message": "Authentication succesful, requested certificate provided",
    }


def build_reply(status, msg=""):
    return {"status": status, "message": msg}


def get_session_key(sn, sid):
    return "session:{}:{}".format(sn, sid)


def get_auth_state_key(sn, sid):
    return "auth_state:{}:{}".format(sn, sid)


def get_cert_key(sn):
    return "certificate:{}".format(sn)


def create_auth_session(sn, sid, csr_str, flags, auth_type, r):
    """ Certificate with matching private key not found in redis
    """
    current_app.logger.debug("Starting authentication for sn=%s", sn)
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
            current_app.config["REDIS_SESSION_TIMEOUT"],
            json.dumps(session))
    return {
        "status": "authenticate",
        "sid": sid,
        "nonce": nonce,
        "message": "Authenticate yourself by sending digest and auth_type in 'auth' request"
    }


def check_auth_state(sn, sid, r):
    """ Get state of client authentication from Redis. If the state is broken,
    fail, error or missing raise an exception. If everything is OK, do nothing
    """
    auth_state = r.get(get_auth_state_key(sn, sid))
    if not auth_state:
        raise AuthStateMissing()

    try:
        auth_state = json.loads(auth_state.decode("utf-8"))
        validate_auth_state(auth_state)
    except (UnicodeDecodeError, json.decoder.JSONDecodeError, InvalidRedisDataError) as e:
        raise CertAPISystemError("{} for auth_state sn={}, sid={}".format(e, sn, sid))

    if auth_state["status"] == "error":
        raise CertAPISystemError("error status for auth_state sn={}, sid={},"
                                 " (message={})".format(sn, sid, auth_state["message"]))
    if auth_state["status"] == "fail":
        current_app.logger.debug("fail status for auth_state sn=%s, sid=%s,"
                                 " (message=%s)", sn, sid, auth_state["message"])
        raise RequestProcessError(auth_state["message"])


def process_req_get(sn, sid, csr_str, flags, auth_type, r):
    current_app.logger.debug("Processing GET request, sn=%s, sid=%s", sn, sid)
    if "renew" in flags:  # when renew is flagged we ignore cert in redis
        return create_auth_session(sn, sid, csr_str, flags, auth_type, r)
    authenticated = False

    # We care about authentication only when session exists
    if r.exists(get_session_key(sn, sid)):
        try:
            check_auth_state(sn, sid, r)
        except AuthStateMissing:
            return build_reply_get_wait()
        authenticated = True

    cert_bytes = r.get(get_cert_key(sn))
    if not cert_bytes:
        if authenticated:
            current_app.logger.warning("Auth OK but certificate not in redis, sn=%s", sn)
        else:
            current_app.logger.debug("Certificate not in redis, sn=%s", sn)
        return create_auth_session(sn, sid, csr_str, flags, auth_type, r)

    current_app.logger.debug("Certificate found in redis, sn=%s", sn)

    # cert and csr public key match
    if not key_match(cert_bytes, csr_str.encode("utf-8")):
        if authenticated:
            current_app.logger.warning("Auth OK but certificate key does not match, sn=%s", sn)
        else:
            current_app.logger.debug("Certificate key does not match, sn=%s", sn)
        return create_auth_session(sn, sid, csr_str, flags, auth_type, r)

    current_app.logger.debug("Certificate restored from redis, sn=%s", sn)
    return build_reply_get_ok(cert_bytes)


def get_auth_session(sn, sid, r):
    """ Get state of client session from Redis. If the session is broken
    or missing, return fail info.
    """
    session_json = r.get(get_session_key(sn, sid))
    if not session_json:  # authentication session open / certificate creation in progress
        current_app.logger.debug("Authentication session not found, sn=%s, sid=%s", sn, sid)
        raise RequestProcessError("Auth session not found. Did you send 'get_cert' request?")

    try:
        session = json.loads(session_json.decode("utf-8"))
        check_session(session)
    except (UnicodeDecodeError, json.decoder.JSONDecodeError, InvalidRedisDataError) as e:
        raise CertAPISystemError("{} for sn={}, sid={}".format(e, sn, sid))

    return session


def push_csr(sn, sid, session, digest, r):
    """ Push csr to the queue in Redis and add digest to the auth session
    """
    session["digest"] = digest
    pipe = r.pipeline(transaction=True)
    pipe.delete(get_session_key(sn, sid))
    pipe.setex(get_session_key(sn, sid),
               current_app.config["REDIS_SESSION_TIMEOUT"],
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
    current_app.logger.debug("Processing AUTH request, sn=%s, sid=%s", sn, sid)

    session = get_auth_session(sn, sid, r)

    current_app.logger.debug("Authentication session found open for sn=%s, sid=%s", sn, sid)
    if session["auth_type"] != auth_type:
        current_app.logger.debug("Authentication type does not match, sn=%s, sid=%s", sn, sid)
        raise RequestProcessError("Auth type does not match the original one")

    if session["digest"]:  # certificate creation in progress
        current_app.logger.debug("Digest already saved for sn=%s, sid=%s", sn, sid)
        raise RequestProcessError("Digest already saved")

    # start certificate creation (CA will check the digest first)
    current_app.logger.debug("Saving digest for sn=%s, sid=%s", sn, sid)
    push_csr(sn, sid, session, digest, r)

    return build_reply_auth_accepted()


def process_request(req, r):
    try:
        check_request(req)
        if req["type"] == "get_cert":
            return process_req_get(req["sn"],
                                   req["sid"],
                                   req["csr"],
                                   req["flags"],
                                   req["auth_type"],
                                   r)
        elif req["type"] == "auth":
            return process_req_auth(req["sn"],
                                    req["sid"],
                                    req["digest"],
                                    req["auth_type"],
                                    r)
    except RequestProcessError as e:
        return build_reply("fail", str(e))
    except RequestConsistencyError as e:
        return build_reply("error", str(e))
    except CertAPISystemError as e:
        current_app.logger.error(str(e))
        return build_reply("error", "Sentinel error. Please, restart the process")
