#!/usr/bin/env python
import json

import redis
from flask import request
from flask import jsonify
from flask import g

from certapi import app
from certapi import certificator

AVAIL_FLAGS = {"renew"}


AVAIL_REQUEST_TYPES = {"get_cert", "auth"}


def get_redis():
    r = g.get('redis', None)
    if r is None:
        r = g.redis = redis.StrictRedis(host=app.config["REDIS_HOST"],
                                        port=app.config["REDIS_PORT"],
                                        password=app.config["REDIS_PASSWORD"],
                                        db=0)
    return r


def param_flags_ok(flags):
    for flag in flags:
        if flag not in AVAIL_FLAGS:
            return False
    return True


def param_type_ok(req_type):
    return req_type in AVAIL_REQUEST_TYPES


def print_debug_json(msg, msg_json):
    app.logger.debug("{}:\n{}".format(
        msg,
        json.dumps(msg_json, indent=2),
    ))


@app.route("/v1", methods=['POST'])
def process_all():
    # request.data is class bytes
    req_json = request.get_json()  # class dict

    print_debug_json("Incomming connection", req_json)

    if not req_json.get("sn"):
        app.logger.error("sn not present")
        return jsonify({"status": "error"})

    try:
        int(req_json.get("sn"), 16)
    except ValueError:
        app.logger.error("sn bad format")
        return jsonify({"status": "error"})

    if req_json.get("sid") is None:
        app.logger.error("sid not present")
        return jsonify({"status": "error"})

    try:
        int(req_json.get("sid"))
    except ValueError:
        app.logger.error("sid bad format")
        return jsonify({"status": "error"})

    if not req_json.get("type") or not param_type_ok(req_json.get("type")):
        app.logger.error("type not present")
        return jsonify({"status": "error"})

    if req_json['type'] == 'get_cert':
        if not req_json.get('csr'):
            app.logger.error("csr not present")
            return jsonify({"status": "error"})

        if "flags" not in req_json or not param_flags_ok(req_json["flags"]):
            app.logger.error("flags not present or currupted")
            return jsonify({"status": "error"})

        reply = certificator.process_req_get(req_json["sn"],
                                             req_json["sid"],
                                             req_json["csr"],
                                             req_json["flags"],
                                             get_redis())
        return jsonify(reply)

    elif req_json["type"] == "auth":
        reply = certificator.process_req_auth(req_json["sn"],
                                              req_json["sid"],
                                              req_json["digest"],
                                              get_redis())
        return jsonify(reply)
