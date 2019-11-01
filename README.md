# Certapi

[![pipeline status](https://gitlab.labs.nic.cz/turris/sentinel/cert-api/badges/master/pipeline.svg)](https://gitlab.labs.nic.cz/turris/sentinel/cert-api/commits/master)
[![coverage report](https://gitlab.labs.nic.cz/turris/sentinel/cert-api/badges/master/coverage.svg)](https://gitlab.labs.nic.cz/turris/sentinel/cert-api/commits/master)

Flask application providing HTTP API for Turris:Sentinel authentication backend.


## Development usage

- Prepare python virtual environment and install `certapi` package (Consider
  using `-e` option: `pip install -e .`)
- Create `.env` file with local environment variables (see `.env.example`)
- Set the configuration in `instance/local.cfg`
    - Example configuration can be found in `instance/local.cfg.example`
    - The default configuration can be found in `certapi/default_settings.py`
- Run the application using `flask run` (Use wsgi server for production!)
