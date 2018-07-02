#!/usr/bin/env python
import json
import os
import random

from cryptography.hazmat.backends import default_backend
from cryptography import x509

from certapi import app

DELAY_GET_SESSION_EXISTS = 10
DELAY_AUTH = 10
DELAY_AUTH_AGAIN = 10

AVAIL_REQUEST_TYPES = {"get_cert", "auth"}
AVAIL_AUTH_TYPES = {"atsha204"}
AVAIL_FLAGS = {"renew"}

MAX_SID = 10000000000


def param_auth_type_ok(auth_type):
    return auth_type in AVAIL_AUTH_TYPES


def param_flags_ok(flags):
    for flag in flags:
        if flag not in AVAIL_FLAGS:
            return False
    return True


def param_type_ok(req_type):
    return req_type in AVAIL_REQUEST_TYPES


def get_nonce():
    return os.urandom(32).hex()


def get_session_key(sn, sid):
    return "session:{}:{}".format(sn, sid)


def get_auth_state_key(sn, sid):
    return "auth_state:{}:{}".format(sn, sid)


def get_cert_key(sn):
    return "certificate:{}".format(sn)


def generate_nonce(sn, sid, csr_str, flags, r):
    """ Certificate with matching private key not found in redis
    """
    app.logger.debug("Starting authentication for sn=%s", sn)
    sid = random.randint(1, MAX_SID)
    nonce = get_nonce()
    session = {
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


def process_req_get(sn, sid, csr_str, flags, r):
    app.logger.debug("Processing GET request, sn=%s, sid=%s", sn, sid)
    if "renew" in flags:  # when renew is flagged we ignore cert in redis
        return generate_nonce(sn, sid, csr_str, flags, r)
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
                # the problem might be with CA or data in Redis, nevetheless we
                # have to inform the client that something bad happened
                app.logger.error(e)
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
            return generate_nonce(sn, sid, csr_str, flags, r)
    else:
        if authenticated:
            app.logger.warning("Auth OK but certificate not in redis, sn=%s", sn)
        else:
            app.logger.debug("Certificate not in redis, sn=%s", sn)
        return generate_nonce(sn, sid, csr_str, flags, r)


def process_req_auth(sn, sid, digest, auth_type, r):
    app.logger.debug("Processing AUTH request, sn=%s, sid=%s", sn, sid)

    session = r.get(get_session_key(sn, sid))
    if session is not None:  # authentication session open / certificate creation in progress
        app.logger.debug("Authentication session found open for sn=%s, sid=%s", sn, sid)
        session_json = json.loads(session.decode("utf-8"))

        if session_json["digest"]:  # certificate creation in progress
            if session_json["digest"] == digest:
                app.logger.debug("Digest already saved for sn=%s, sid=%s", sn, sid)
                return {
                    "status": "accepted",
                    "delay": DELAY_AUTH_AGAIN,
                }
            else:
                app.logger.debug("Digest does not match the saved one sn=%s, sid=%s", sn, sid)
                return {"status": "fail"}
        else:  # start certificate creation (CA will check the digest first)
            app.logger.debug("Saving digest for sn=%s, sid=%s", sn, sid)
            session_json["digest"] = digest
            pipe = r.pipeline(transaction=True)
            pipe.delete(get_session_key(sn, sid))
            pipe.setex(get_session_key(sn, sid),
                       app.config["REDIS_SESSION_TIMEOUT"],
                       json.dumps(session_json))
            request = {
                "sn": sn,
                "sid": sid,
                "nonce": session_json['nonce'],
                "digest": digest,
                "csr_str": session_json['csr_str'],
                "flags": session_json["flags"],
                "auth_type": auth_type,
            }
            pipe.lpush('csr', json.dumps(request))
            pipe.execute()

        return {
            "status": "accepted",
            "delay": DELAY_AUTH,
        }

    else:
        app.logger.debug("Authentication session not found, sn=%s, sid=%s", sn, sid)
        return {"status": "fail"}


def process_request(req_json, r):
    if not req_json.get("sn"):
        app.logger.info("Incomming connection: sn not present")
        return {"status": "error"}

    try:
        int(req_json.get("sn"), 16)
    except ValueError:
        app.logger.info("Incomming connection: sn bad format")
        return {"status": "error"}

    if req_json.get("sid") is None:
        app.logger.info("Incomming connection: sid not present")
        return {"status": "error"}

    try:
        sid = int(req_json.get("sid"))
        if sid > MAX_SID:
            app.logger.info("Incomming connection: sid too big")
            return {"status": "error"}

    except ValueError:
        app.logger.info("Incomming connection: sid bad format")
        return {"status": "error"}

    if not req_json.get("type") or not param_type_ok(req_json.get("type")):
        app.logger.info("Incomming connection: type not present")
        return {"status": "error"}

    if req_json["type"] == "get_cert":
        if not req_json.get("csr"):
            app.logger.info("Incomming connection: csr not present")
            return {"status": "error"}

        if "flags" not in req_json or not param_flags_ok(req_json["flags"]):
            app.logger.info("Incomming connection: flags not present or currupted")
            return {"status": "error"}

        # renew flag may be sent only before the auth session starts
        if "renew" in req_json["flags"]:
            if int(req_json["sid"]) != 0:
                return {"status": "fail"}

        reply = process_req_get(req_json["sn"],
                                req_json["sid"],
                                req_json["csr"],
                                req_json["flags"],
                                r)
        return reply

    elif req_json["type"] == "auth":
        reply = process_req_auth(req_json["sn"],
                                 req_json["sid"],
                                 req_json["digest"],
                                 req_json["auth_type"],
                                 r)
        return reply
