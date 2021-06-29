from flask import Flask
from flask_bootstrap import Bootstrap
from logging.config import dictConfig

# Default initial logging instantiated before the Flask app reads
# configuration details.
dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})


def create_app(test_config=None):
    app = Flask(__name__)

    app.config.from_envvar('PYSTEPUPIDP_SETTINGS')

    # Configure logging using the configuration from the configuration file.
    dictConfig(app.config['LOGGING'])

    from . import healthcheck
    app.register_blueprint(healthcheck.bp)

    from . import saml
    app.register_blueprint(saml.bp)

    from . import token
    app.register_blueprint(token.bp)

    Bootstrap(app)

    return app
