import json

import redis

from flask import Blueprint
from flask import request
from flask import jsonify
from flask import g
from flask import current_app
from flask import redirect, url_for

from .authentication import process_request


apiv1 = Blueprint("apiv1", __name__)


def get_redis():
    r = g.get('redis', None)
    if r is None:
        r = g.redis = redis.StrictRedis(host=current_app.config["REDIS_HOST"],
                                        port=current_app.config["REDIS_PORT"],
                                        password=current_app.config["REDIS_PASSWORD"],
                                        db=0)
    return r


def log_debug_json(msg, msg_json):
    current_app.logger.debug("%s:\n%s", msg, json.dumps(msg_json, indent=2))


@apiv1.route("certs", methods=['POST'])
@apiv1.route("", methods=['POST'])
def certs_view():
    # request.data is class bytes
    req_json = request.get_json()  # class dict
    log_debug_json("Incomming connection", req_json)
    reply = process_request(req_json, get_redis(), "certs")
    log_debug_json("Reply", reply)
    return jsonify(reply)


@apiv1.route("", methods=['GET'])
def redirect_humans():
    return redirect(url_for("pages.home"))
