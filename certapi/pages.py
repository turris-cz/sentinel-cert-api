from flask import Blueprint


pages = Blueprint("pages", __name__)


@pages.route("/")
def home():
    return """<html>
    <head>
        <title>Turris:Sentinel</title>
    </head>
    <body>
        <h1>Turris:Sentinel</h1>
        <p>
            This is frontend of Turris:Sentinel authentication API.
        </p>
        <p>
            The page is intended for robots and there is no human-readable content.
            If you need more informations, see details about project Turris.
        </p>
    </body>
</html>
"""
