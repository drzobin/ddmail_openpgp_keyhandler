import os
from flask import Flask


def create_app(test_config=None):
    """Create and configure an instance of the Flask application dmcp_keyhandler."""
    app = Flask(__name__, instance_relative_config=True)

    # Set app configurations from configuration file config.py
    mode=os.environ.get('MODE')
    if mode == "PRODUCTION":
        app.config.from_object("config.Prod")
    elif mode == "TESTING":
        app.config.from_object("config.Test")
    elif mode == "DEVELOPMENT":
        app.config.from_object("config.Dev")
    else:
        print("Error: you need to set env variabel MODE to PRODUCTION/TESTING/DEVELOPMENT")
        exit(1)
    
    app.secret_key = app.config["SECRET_KEY"]

    # Ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # Apply the blueprints to the app
    from openpgp_keyhandler import application
    app.register_blueprint(application.bp)

    return app 
