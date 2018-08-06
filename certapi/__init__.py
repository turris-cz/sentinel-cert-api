from flask import Flask

app = Flask(__name__, instance_relative_config=True)

app.config.from_object("certapi.default_settings")
app.config.from_pyfile("local.cfg", silent=True)
app.config.from_envvar("FLASK_APP_SETTINGS", silent=True)

from certapi.views import apiv1
app.register_blueprint(apiv1, url_prefix="/v1")
