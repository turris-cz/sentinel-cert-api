#!/usr/bin/env python
import json

import redis
from flask import request
from flask import jsonify
from flask import g

from certapi import app
from certapi import certificator


def get_redis():
    r = g.get('redis', None)
    if r is None:
        r = g.redis = redis.StrictRedis(host=app.config["REDIS_HOST"],
                                        port=app.config["REDIS_PORT"],
                                        password=app.config["REDIS_PASSWORD"],
                                        db=0)
    return r


def log_debug_json(msg, msg_json):
    app.logger.debug("%s:\n%s", msg, json.dumps(msg_json, indent=2))


@app.route("/v1", methods=['POST'])
def request_view():
    # request.data is class bytes
    req_json = request.get_json()  # class dict
    log_debug_json("Incomming connection", req_json)
    reply = certificator.process_request(req_json, get_redis())
    log_debug_json("Reply", reply)
    return jsonify(reply)
