#!/usr/bin/env python
import os

import redis
from flask import request
from flask import jsonify
from flask import g
import json
from cryptography.hazmat.backends import default_backend
from cryptography import x509
import random

from certapi import app

DELAY_GET_SESSION_EXISTS = 10
DELAY_AUTH = 10
DELAY_AUTH_AGAIN = 10

AVAIL_FLAGS = {"renew"}

app.config.from_envvar('CERT_API_SETTINGS')


def get_redis():
    r = g.get('redis', None)
    if r is None:
        r = g.redis = redis.StrictRedis(host=app.config["REDIS_HOST"],
                                        port=app.config["REDIS_PORT"],
                                        password=app.config["REDIS_PASSWORD"],
                                        db=0)
    return r


def print_debug_json(msg, msg_json):
    app.logger.debug("{}:\n{}".format(
        msg,
        json.dumps(msg_json, indent=2),
    ))


def param_flags_ok(flags):
    for flag in flags:
        if flag not in AVAIL_FLAGS:
            return False
    return True


@app.route("/v1", methods=['POST'])
def process_all():
    # request.data is class bytes
    req_json = request.get_json()  # class dict

    print_debug_json("Incomming connection", req_json)

    if not req_json.get('sn'):
        app.logger.error('sn not present')
        return jsonify({"status": "error"})

    if req_json.get('sid') is None:
        app.logger.error("sid not present")
        return jsonify({"status": "error"})

    if not req_json.get('type'):
        app.logger.error("type not present")
        return jsonify({"status": "error"})

    if req_json['type'] == 'get_cert':

        if not req_json.get('csr'):
            app.logger.error("csr not present")
            return jsonify({"status": "error"})

        if "flags" not in req_json or not param_flags_ok(req_json["flags"]):
            app.logger.error("flags not present or currupted")
            return jsonify({"status": "error"})

        return process_req_get(
            req_json["sn"],
            req_json["sid"],
            req_json["csr"],
            req_json["flags"],
        )
        # TODO kontrola formatu sid, sn, csr

    elif req_json["type"] == "auth":
        return process_req_auth(
            req_json["sn"],
            req_json["sid"],
            req_json["digest"],
        )


def get_nonce():
    return os.urandom(32).hex()


def get_new_cert(sn, sid, csr_str, flags):
    """ Certificate with matching private key not found in redis
    """
    if get_redis().exists((sn, sid)):  # cert creation in progress
        # TODO: v pripade, ze klient ztratil svoji nonce, poslat mu ji znovu?
        app.logger.debug("Certificate creation in progress, sn={}, sid={}".format(sn, sid))
        return jsonify({
            "status": "wait",
            "delay": DELAY_GET_SESSION_EXISTS
        })
    else:  # authenticate
        app.logger.debug("Starting authentication for sn={}".format(sn))
        sid = random.randint(1, 10000000000)
        nonce = get_nonce()
        get_redis().setex((sn, sid), app.config["REDIS_SESSION_TIMEOUT"], {
            "nonce": nonce,
            "digest": "",
            "csr_str": csr_str,
            "flags": flags,
        })
        return jsonify({
            "status": "authenticate",
            "sid": sid,
            "nonce": nonce,
        })


def key_match(cert_bytes, csr_bytes):
    """ Compare public keys of two cryptographic objects and return True if
    they are the same, otherwise return False.
    """
    cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
    csr = x509.load_pem_x509_csr(csr_bytes, default_backend())
    return cert.public_key().public_numbers() == csr.public_key().public_numbers()


def process_req_get(sn, sid, csr_str, flags):
    app.logger.debug("Processing GET request, sn={}, sid={}".format(sn, sid))
    if "renew" in flags:  # when renew is flagged we ignore cert in redis
        return get_new_cert(sn, sid, csr_str, flags)
    if get_redis().exists(sn):  # cert for requested sn is already in redis
        cert_bytes = get_redis().get(sn)
        app.logger.debug("Certificate found in redis, sn={}".format(sn))

        # cert and csr public key match
        if key_match(cert_bytes, csr_str.encode("utf-8")):
            app.logger.info("Certificate restored from redis, sn={}".format(sn))
            return jsonify({
                "status": "ok",
                "cert": cert_bytes.decode("utf-8")
            })
        else:
            app.logger.debug("Certificate key does not match, sn={}".format(sn))
            return get_new_cert(sn, sid, csr_str, flags)
    else:
        app.logger.debug("Certificate not in redis, sn={}".format(sn))
        return get_new_cert(sn, sid, csr_str, flags)


def process_req_auth(sn, sid, digest):
    app.logger.debug("Processing AUTH request, sn={}, sid={}".format(sn, sid))

    if get_redis().exists((sn, sid)):  # authentication session open / certificate creation in progress
        app.logger.debug("Authentication session found open for sn={}, sid={}".format(sn, sid))
        session_json = json.loads(get_redis().get((sn, sid)).decode("utf-8").replace("'", '"'))

        if session_json["digest"]:  # certificate creation in progress
            if session_json["digest"] == digest:
                app.logger.debug("Digest already saved for sn={}, sid={}".format(sn, sid))
                return jsonify({
                    "status": "accepted",
                    "delay": DELAY_AUTH_AGAIN,
                })
            else:
                app.logger.debug("Digest does not match the saved one sn={}, sid={}".format(sn, sid))
                return jsonify({"status": "fail"})
        else:  # start certificate creation (CA will check the digest first)
            app.logger.debug("Saving digest for sn={}, sid={}".format(sn, sid))
            session_json["digest"] = digest
            pipe = get_redis().pipeline(transaction=True)
            pipe.delete((sn, sid))
            pipe.setex((sn, sid), app.config["REDIS_SESSION_TIMEOUT"], session_json)
            pipe.lpush('csr', {
                "sn": sn,
                "sid": sid,
                "nonce": session_json['nonce'],
                "digest": digest,
                "csr_str": session_json['csr_str'],
                "flags": session_json["flags"],
            })
            pipe.execute()

        # do tohohle jsonu zapisuju typy str a int
        # take prida application/json mimetype
        return jsonify({
            "status": "accepted",
            "delay": DELAY_AUTH,
        })

    else:
        app.logger.debug("Authentication session not found, sn={}, sid={}".format(sn, sid))
        return jsonify({"status": "fail"})