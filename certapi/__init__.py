from logging.config import dictConfig

from flask import Flask


def setup_logging():
    dictConfig({
        "version": 1,
        "root": {
            "level": "INFO",
        },
    })


def create_app(additional_config=None):
    app = Flask(__name__, instance_relative_config=True)

    app.config.from_object("certapi.default_settings")
    app.config.from_pyfile("local.cfg", silent=True)
    app.config.from_envvar("FLASK_APP_SETTINGS", silent=True)
    if additional_config:
        app.config.from_mapping(additional_config)

    setup_logging()

    from .pages import pages
    from .apiv1 import apiv1
    app.register_blueprint(pages)
    app.register_blueprint(apiv1, url_prefix="/v1")

    return app
