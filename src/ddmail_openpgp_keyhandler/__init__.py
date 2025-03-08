import os
import toml
import sys
from flask import Flask


def create_app(config_file = None, test_config = None):
    """Create and configure an instance of the Flask application ddmail_openpgp_keyhandler."""
    app = Flask(__name__, instance_relative_config=True)

    # Parse toml config file.
    toml_config = None
    with open(config_file, 'r') as f:
        toml_config = toml.load(f)

    # Set app configurations from toml config file.
    mode=os.environ.get('MODE')
    if mode == "PRODUCTION":
        app.config["SECRET_KEY"] = toml_config["PRODUCTION"]["SECRET_KEY"]
        app.config["PASSWORD_HASH"] = toml_config["PRODUCTION"]["PASSWORD_HASH"]
        app.config["GNUPG_HOME"] = toml_config["PRODUCTION"]["GNUPG_HOME"]
    elif mode == "TESTING":
        app.config["SECRET_KEY"] = toml_config["TESTING"]["SECRET_KEY"]
        app.config["PASSWORD_HASH"] = toml_config["TESTING"]["PASSWORD_HASH"]
        app.config["GNUPG_HOME"] = toml_config["TESTING"]["GNUPG_HOME"]
    elif mode == "DEVELOPMENT":
        app.config["SECRET_KEY"] = toml_config["DEVELOPMENT"]["SECRET_KEY"]
        app.config["PASSWORD_HASH"] = toml_config["DEVELOPMENT"]["PASSWORD_HASH"]
        app.config["GNUPG_HOME"] = toml_config["DEVELOPMENT"]["GNUPG_HOME"]
    else:
        print("Error: you need to set env variabel MODE to PRODUCTION/TESTING/DEVELOPMENT")
        sys.exit(1)
    
    app.secret_key = app.config["SECRET_KEY"]

    # Ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # Apply the blueprints to the app
    from ddmail_openpgp_keyhandler import application
    app.register_blueprint(application.bp)

    return app 
