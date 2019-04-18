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

QUEUE_NAME_MAILPASS = "mpr"
QUEUE_NAME_CERTS = "csr"

CERTS_EXTRA_PARAMS = ("csr_str",)

ACTION_CERTS = "certs"
ACTION_MAILPASS = "mailpass"


class AuthStateMissing(Exception):
    pass


def build_reply_auth_accepted(delay=DELAY_AUTH):
    return {
        "status": "accepted",
        "delay": delay,
        "message": "Certification process started, wait for {} sec before"
                   " sending next 'get' request".format(delay),
    }


def build_reply_auth_start(sid, nonce):
    return {
        "status": "authenticate",
        "sid": sid,
        "nonce": nonce,
        "message": "Authenticate yourself by sending digest and auth_type in 'auth' request"
    }


def build_reply_get_wait(delay=DELAY_GET_SESSION_EXISTS):
    return {
        "status": "wait",
        "delay": delay,
        "message": "Certification process still running, wait for"
                   " {} sec before sending another 'get'"
                   " request".format(delay),
    }


def build_reply_get_ok(cert_bytes):
    return {
        "status": "ok",
        "cert": cert_bytes.decode("utf-8"),
        "message": "Authentication succesful, requested certificate provided",
    }


def build_reply_get_mailpass_ok(secret):
    return {
        "status": "ok",
        "secret": secret,
        "message": "Authentication succesful, requested secret provided",
    }


def build_reply(status, msg=""):
    return {"status": status, "message": msg}


def get_session_key(sn, sid):
    return "session:{}:{}".format(sn, sid)


def get_auth_state_key(sn, sid):
    return "auth_state:{}:{}".format(sn, sid)


def get_cert_key(sn):
    return "certificate:{}".format(sn)


def get_mailpass_key(sn):
    return "mailpass:{}".format(sn)


def create_auth_session(req, action, r, extra_params=()):
    """ This function is called in case of `certs` when no certificate with
        matching private key is found in redis or in case of `mailpass` at
        the beginning of each session.

        Parameters "sn", "flags", "auth_type" and extra_params are required in
        the req dictionary
    """
    current_app.logger.debug("Starting authentication for sn=%s", req["sn"])
    sid = create_random_sid()
    nonce = create_random_nonce()

    params = ("flags", "auth_type") + extra_params
    session = {i: req[i] for i in params}
    session.update({"action": action, "nonce": nonce, "digest": ""})

    r.setex(get_session_key(req["sn"], sid),
            current_app.config["REDIS_SESSION_TIMEOUT"],
            json.dumps(session))
    return build_reply_auth_start(sid, nonce)


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


def process_req_get_cert(req, r):
    """ Parameters "sn", "sid", "cert_str", "auth_type" and "flags" are
        required in the req dictionary.
    """
    current_app.logger.debug("Processing cert GET request, sn=%s, sid=%s", req["sn"], req["sid"])
    if "renew" in req["flags"]:  # when renew is flagged we ignore cert in redis
        return create_auth_session(req, ACTION_CERTS, r, CERTS_EXTRA_PARAMS)
    authenticated = False

    # We care about authentication only when session exists
    if r.exists(get_session_key(req["sn"], req["sid"])):
        try:
            check_auth_state(req["sn"], req["sid"], r)
        except AuthStateMissing:
            return build_reply_get_wait()
        authenticated = True

    cert_bytes = r.get(get_cert_key(req["sn"]))
    if not cert_bytes:
        if authenticated:
            current_app.logger.warning("Auth OK but certificate not in redis, sn=%s", req["sn"])
        else:
            current_app.logger.debug("Certificate not in redis, sn=%s", req["sn"])
        return create_auth_session(req, ACTION_CERTS, r, CERTS_EXTRA_PARAMS)

    current_app.logger.debug("Certificate found in redis, sn=%s", req["sn"])

    # cert and csr public key match
    if not key_match(cert_bytes, req["csr_str"].encode("utf-8")):
        if authenticated:
            current_app.logger.warning("Auth OK but certificate key does not match, sn=%s", req["sn"])
        else:
            current_app.logger.debug("Certificate key does not match, sn=%s", req["sn"])
        return create_auth_session(req, ACTION_CERTS, r, CERTS_EXTRA_PARAMS)

    current_app.logger.debug("Certificate restored from redis, sn=%s", req["sn"])
    return build_reply_get_ok(cert_bytes)


def process_req_get_mailpass(req, r):
    """ Parameters "sn", "sid", "auth_type" and "flags" are
        required in the req dictionary.
    """
    current_app.logger.debug("Processing mailpass GET request, sn=%s, sid=%s", req["sn"], req["sid"])

    # Authentication is mandatory here - we do not cache passwords
    if r.exists(get_session_key(req["sn"], req["sid"])):
        try:
            check_auth_state(req["sn"], req["sid"], r)
        except AuthStateMissing:
            return build_reply_get_wait()
    else:
        return create_auth_session(req, ACTION_MAILPASS, r)

    secret = r.get(get_mailpass_key(req["sn"])).decode("utf-8")
    if not secret:
        current_app.logger.warning("Auth OK but secret not in redis, sn=%s", req["sn"])
        return create_auth_session(req, ACTION_MAILPASS, r)

    current_app.logger.debug("Mailpass server from redis, sn=%s", req["sn"])
    return build_reply_get_mailpass_ok(secret)


def get_auth_session(sn, sid, r):
    """ Get state of client session from Redis. If the session is broken
    or missing, return fail info.
    """
    session_json = r.get(get_session_key(sn, sid))
    if not session_json:  # authentication session open / certificate creation in progress
        current_app.logger.debug("Authentication session not found, sn=%s, sid=%s", sn, sid)
        raise RequestProcessError("Auth session not found. Did you send 'get' request?")

    try:
        session = json.loads(session_json.decode("utf-8"))
        check_session(session)
    except (UnicodeDecodeError, json.decoder.JSONDecodeError, InvalidRedisDataError) as e:
        raise CertAPISystemError("{} for sn={}, sid={}".format(e, sn, sid))

    return session


def store_auth_params(sn, sid, session, queue_name, r, extra_params=()):
    """ This function is being called during processing auth request invoked
        by the client. This function inserts the auth request into the Redis
        queue along with its "action" so that propriate authority (CA, Mailpass)
        cand handle the request.

        The session (not the param) saved in Redis is being updated as well so
        we can detect and forbid any possible duplicate auth request
        in the future.

        Parameters "nonce", "digest", "flags", "auth_type" and extra_params are
        required in the session (the param) dictionary.
    """
    params = ("nonce", "digest", "flags", "auth_type") + extra_params
    request = {i: session[i] for i in params}
    request.update({"sn": sn, "sid": sid})

    pipe = r.pipeline(transaction=True)
    pipe.delete(get_session_key(sn, sid))
    pipe.setex(get_session_key(sn, sid),
               current_app.config["REDIS_SESSION_TIMEOUT"],
               json.dumps(session))
    pipe.lpush(queue_name, json.dumps(request))
    pipe.execute()


def process_req_auth(req, action, r):
    """ Parameters "sn", "sid", "digest" and "auth_type" are
        required in the req dictionary.
    """
    current_app.logger.debug("Processing AUTH request, sn=%s, sid=%s", req["sn"], req["sid"])

    session = get_auth_session(req["sn"], req["sid"], r)

    current_app.logger.debug("Authentication session found open for sn=%s, sid=%s", req["sn"], req["sid"])

    if session["action"] != action:
        current_app.logger.debug("Action does not match, sn=%s, sid=%s", req["sn"], req["sid"])
        raise RequestProcessError("Action does not match the original one")

    if session["auth_type"] != req["auth_type"]:
        current_app.logger.debug("Authentication type does not match, sn=%s, sid=%s", req["sn"], req["sid"])
        raise RequestProcessError("Auth type does not match the original one")

    if session["digest"]:  # already authenticated
        current_app.logger.debug("Digest already saved for sn=%s, sid=%s", req["sn"], req["sid"])
        raise RequestProcessError("Digest already saved")

    # store authentication parameters & tell the client to ask for result later
    current_app.logger.debug("Saving digest for sn=%s, sid=%s", req["sn"], req["sid"])
    session["digest"] = req["digest"]
    if action == "certs":
        store_auth_params(req["sn"], req["sid"], session, QUEUE_NAME_CERTS, r,
                          CERTS_EXTRA_PARAMS)
    elif action == "mailpass":
        store_auth_params(req["sn"], req["sid"], session, QUEUE_NAME_MAILPASS, r)
    else:
        raise CertAPISystemError("Unknown action {}".format(action))

    return build_reply_auth_accepted()


def process_request(req, r, action):
    try:
        check_request(req, action)

        if req["type"] == "get":
            if action == "certs":
                req["csr_str"] = req["csr"]  # stupid different naming in req and internals
                return process_req_get_cert(req, r)

            elif action == "mailpass":
                return process_req_get_mailpass(req, r)

            raise CertAPISystemError("Unknown action {}".format(action))  # should not be raised here

        elif req["type"] == "auth":
            return process_req_auth(req, action, r)

        raise CertAPISystemError("Invalid request type {}".format(action))  # should not be raised here

    except RequestProcessError as e:
        return build_reply("fail", str(e))

    except RequestConsistencyError as e:
        return build_reply("error", str(e))

    except CertAPISystemError as e:
        current_app.logger.error(str(e))
        return build_reply("error", "Sentinel error. Please, restart the process")
