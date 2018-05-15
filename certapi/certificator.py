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


def get_nonce():
    return os.urandom(32).hex()


def get_new_cert(sn, sid, csr_str, flags, r):
    """ Certificate with matching private key not found in redis
    """
    if r.exists((sn, sid)):  # cert creation in progress
        app.logger.debug("Certificate creation in progress, sn=%s, sid=%s", sn, sid)
        return {
            "status": "wait",
            "delay": DELAY_GET_SESSION_EXISTS
        }
    else:  # authenticate
        app.logger.debug("Starting authentication for sn=%s", sn)
        sid = random.randint(1, 10000000000)
        nonce = get_nonce()
        r.setex((sn, sid), app.config["REDIS_SESSION_TIMEOUT"], {
            "nonce": nonce,
            "digest": "",
            "csr_str": csr_str,
            "flags": flags,
        })
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
        return get_new_cert(sn, sid, csr_str, flags, r)
    if r.exists(sn):  # cert for requested sn is already in redis
        cert_bytes = r.get(sn)
        app.logger.debug("Certificate found in redis, sn=%s", sn)

        # cert and csr public key match
        if key_match(cert_bytes, csr_str.encode("utf-8")):
            app.logger.debug("Certificate restored from redis, sn=%s", sn)
            return {
                "status": "ok",
                "cert": cert_bytes.decode("utf-8")
            }
        else:
            app.logger.debug("Certificate key does not match, sn=%s", sn)
            return get_new_cert(sn, sid, csr_str, flags, r)
    else:
        app.logger.debug("Certificate not in redis, sn=%s", sn)
        return get_new_cert(sn, sid, csr_str, flags, r)


def process_req_auth(sn, sid, digest, auth_type, r):
    app.logger.debug("Processing AUTH request, sn=%s, sid=%s", sn, sid)

    if r.exists((sn, sid)):  # authentication session open / certificate creation in progress
        app.logger.debug("Authentication session found open for sn=%s, sid=%s", sn, sid)
        session_json = json.loads(r.get((sn, sid)).decode("utf-8").replace("'", '"'))

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
            pipe.delete((sn, sid))
            pipe.setex((sn, sid), app.config["REDIS_SESSION_TIMEOUT"], session_json)
            pipe.lpush('csr', {
                "sn": sn,
                "sid": sid,
                "nonce": session_json['nonce'],
                "digest": digest,
                "csr_str": session_json['csr_str'],
                "flags": session_json["flags"],
                "auth_type": auth_type,
            })
            pipe.execute()

        return {
            "status": "accepted",
            "delay": DELAY_AUTH,
        }

    else:
        app.logger.debug("Authentication session not found, sn=%s, sid=%s", sn, sid)
        return {"status": "fail"}
