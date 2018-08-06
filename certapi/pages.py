from flask import Blueprint


pages = Blueprint("pages", __name__)


@pages.route("/")
def home():
    return "Turris:Sentinel"
