from flask import Flask
app = Flask(__name__)
app.config.from_envvar('CERT_API_SETTINGS')

import certapi.views
