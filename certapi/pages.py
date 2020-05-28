from flask import render_template
from flask import Blueprint

pages = Blueprint("pages", __name__)


@pages.route("/")
def home():
    return render_template("index.html")
