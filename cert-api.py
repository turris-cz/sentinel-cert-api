#!/usr/bin/env python
import redis
from flask import Flask
from flask import request
from flask import jsonify
import json
from OpenSSL import crypto
import random

DELAY_GET_SESSION_EXISTS = 10
DELAY_AUTH = 10
DELAY_AUTH_AGAIN = 10
app = Flask(__name__)


def print_debug_json(msg, msg_json):
    app.logger.debug("{}:\n{}".format(
        msg,
        json.dumps(msg_json, indent=2),
    ))


@app.route("/", methods=['POST'])
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

    if not req_json.get("api_version"):
        app.logger.error("api version not present")
        return jsonify({"status": "error"})

    if req_json['type'] == 'get_cert':

        if not req_json.get('csr'):
            app.logger.error("csr not present")
            return jsonify({"status": "error"})

        return process_req_get(
            req_json["sn"],
            req_json["sid"],
            req_json["csr"]
        )
        # TODO kontrola formatu sid, sn, csr

    elif req_json["type"] == "auth":
        return process_req_auth(
            req_json["sn"],
            req_json["sid"],
            req_json["digest"],
        )


def get_nonce():
    # TODO vylepsit
    return str(random.randint(
        1000000000000000000000000000000000000000000000000000000000000000,
        9999999999999999999999999999999999999999999999999999999999999999
    ))


def get_new_cert(sn, sid, csr_str):
    """ Certificate with matching private key not found in redis
    """
    if r.exists((sn, sid)):  # cert creation in progress
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
        r.setnx((sn, sid), {
            "nonce": nonce,
            "digest": "",
            "csr_str": csr_str,
        })
        return jsonify({
            "status": "authenticate",
            "sid": sid,
            "nonce": nonce,
        })


def process_req_get(sn, sid, csr_str):
    app.logger.debug("Processing GET request, sn={}, sid={}".format(sn, sid))
    if r.exists(sn):  # cert for requested sn is already in redis
        cert_str = r.get(sn).decode("utf-8")
        app.logger.debug("Certificate found in redis, sn={}".format(sn))

        cert = crypto.load_certificate(type=crypto.FILETYPE_PEM, buffer=cert_str)
        cert_pubkey_str = crypto.dump_publickey(type=crypto.FILETYPE_PEM, pkey=cert.get_pubkey()).decode("utf-8")

        csr = crypto.load_certificate_request(type=crypto.FILETYPE_PEM, buffer=csr_str)
        csr_pubkey_str = crypto.dump_publickey(type=crypto.FILETYPE_PEM, pkey=csr.get_pubkey()).decode("utf-8")

        # cert and csr public key match
        if (csr_pubkey_str == cert_pubkey_str):
            app.logger.info("Certificate restored from redis, sn={}".format(sn))
            return jsonify({
                "status": "ok",
                "cert": cert_str
            })
        else:
            app.logger.debug("Certificate key does not match, sn={}".format(sn))
            return get_new_cert(sn, sid, csr_str)
    else:
        app.logger.debug("Certificate not in redis, sn={}".format(sn))
        return get_new_cert(sn, sid, csr_str)


def process_req_auth(sn, sid, digest):
    app.logger.debug("Processing AUTH request, sn={}, sid={}".format(sn, sid))

    if r.exists((sn, sid)):  # authentication session open / certificate creation in progress
        app.logger.debug("Authentication session found open for sn={}, sid={}".format(sn, sid))
        session_json = json.loads(r.get((sn, sid)).decode("utf-8").replace("'", '"'))

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
            # lze v redisu atomicky? asi ne...
            r.delete((sn, sid))
            r.setnx((sn, sid), session_json)
            r.lpush('csr', {
                "sn": sn,
                "sid": sid,
                "nonce": session_json['nonce'],
                "digest": digest,
                "csr_str": session_json['csr_str'],
            })

        # do tohohle jsonu zapisuju typy str a int
        # take prida application/json mimetype
        return jsonify({
            "status": "accepted",
            "delay": DELAY_AUTH,
        })

    else:
        app.logger.debug("Authentication session not found, sn={}, sid={}".format(sn, sid))
        return jsonify({"status": "fail"})


if __name__ == "__main__":
    app.config.from_envvar('CERT_API_SETTINGS')
    r = redis.StrictRedis(
        host=app.config["REDIS_HOST"],
        port=app.config["REDIS_PORT"],
        db=0
    )

    app.run(
        host='0.0.0.0',
    )
