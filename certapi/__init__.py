from flask import Flask
app = Flask(__name__)
app.config.from_pyfile("default.cfg")
app.config.from_envvar("CERT_API_SETTINGS", silent=True)

import certapi.views
