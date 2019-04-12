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


def _get_redis_instance(config_namespace):
    config = current_app.config.get_namespace(config_namespace)
    r = redis.StrictRedis(host=config.get("host"),
                          port=config.get("port"),
                          password=config.get("password"))
    return r


def get_certs_redis():
    if "redis_certs" not in g:
        g.redis_certs = _get_redis_instance("REDIS_CERTS_")
    return g.redis_certs


def get_mailpass_redis():
    if "redis_mailpass" not in g:
        g.redis_mailpass = _get_redis_instance("REDIS_MAILPASS_")
    return g.redis_mailpass


def log_debug_json(msg, msg_json):
    current_app.logger.debug("%s:\n%s", msg, json.dumps(msg_json, indent=2))


@apiv1.route("certs", methods=['POST'])
@apiv1.route("", methods=['POST'])
def certs_view():
    # request.data is class bytes
    req_json = request.get_json()  # class dict
    log_debug_json("Incomming connection", req_json)
    reply = process_request(req_json, get_certs_redis(), "certs")
    log_debug_json("Reply", reply)
    return jsonify(reply)


@apiv1.route("mailpass", methods=['POST'])
def mailpass_view():
    # request.data is class bytes
    req_json = request.get_json()  # class dict
    log_debug_json("Incomming connection", req_json)
    reply = process_request(req_json, get_mailpass_redis(), "mailpass")
    log_debug_json("Reply", reply)
    return jsonify(reply)


@apiv1.route("", methods=['GET'])
def redirect_humans():
    return redirect(url_for("pages.home"))
