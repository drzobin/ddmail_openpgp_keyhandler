from flask import Blueprint, current_app, request
from argon2 import PasswordHasher
import os
import time
import subprocess
import logging
import gnupg

from openpgp_keyhandler.validators import is_domain_allowed, is_password_allowed, is_email_allowed

bp = Blueprint("application", __name__, url_prefix="/")

# Configure logging.
logging.basicConfig(filename="/var/log/ddmail_openpgp_keyhandler.log", format='%(asctime)s: %(levelname)s: %(message)s', level=logging.ERROR)

@bp.route("/hash_data", methods=["POST"])
def hash_data():
    if request.method == 'POST':
        ph = PasswordHasher()

        data = request.form.get('data')

        # Validate password.
        if is_password_allowed(data) != True:
            logging.error("hash_data() validation of data failed")
            return "error: validation of data failed"

        data_hash = ph.hash(data)

        return data_hash

@bp.route("/upload_public_key", methods=["POST"])
def upload_public_key():
    if request.method == 'POST':
        ph = PasswordHasher()

        # Get post form data.
        public_key = request.form.get('public_key')
        password = request.form.get('password')

        # Validate public_key.
        if is_public_key_allowed(public_key) != True:
            logging.error("upload_public_key() public key validation failed")
            return "error: public key validation failed"

        # Validate password.
        if is_password_allowed(password) != True:
            logging.error("upload_public_key() password validation failed")
            return "error: password validation failed"

        # Check if password is correct.
        try:
            if ph.verify(current_app.config["PASSWORD_HASH"], password) != True:
                time.sleep(1)
                logging.error("upload_public_key() wrong password")
                return "error: wrong password"
        except:
            time.sleep(1)
            logging.error("upload_public_key() wrong password")
            return "error: wrong password"
        time.sleep(1)

        # Upload public key.
        gpg = gnupg.GPG(gnupghome=current_app.config["GNUPG_HOME"])
        import_result = gpg.import_keys(public_key)

        # Check if 1 key has been imported.
        if import_result.count != 1:
            logging.error("upload_public_key() import_result.count is not 1")
            return "error: failed to upload public key"

        # Set trustlevel of imported key.
        gpg.trust_keys(import_result.fingerprints, "TRUST_ULTIMATE")

        logging.debug("upload_public_key() imported public key with fingerprint: " + import_result.fingerprints)
        return "fingerprint: " + import_result.fingerprints

@bp.route("/remove_public_key", methods=["POST"])
def remove_public_key():
    if request.method == 'POST':
        ph = PasswordHasher()

        # Get post form data.
        fingerprint = request.form.get('fingerprint')
        password = request.form.get('password')

        # Validate fingerprint.
        if is_fingerprint_allowed(email) != True:
            logging.error("remove_public_key() fingerprint validation failed")
            return "error: fingerprint validation failed"

        # Validate password.
        if is_password_allowed(password) != True:
            logging.error("remove_public_key() password validation failed")
            return "error: password validation failed"

        # Check if password is correct.
        try:
            if ph.verify(current_app.config["PASSWORD_HASH"], password) != True:
                time.sleep(1)
                logging.error("change_password_on_key() wrong password")
                return "error: wrong password"
        except:
            time.sleep(1)
            logging.error("change_password_on_key() wrong password")
            return "error: wrong password"
        time.sleep(1)

        # Remove public key.
        gpg = gnupg.GPG(gnupghome=current_app.config["GNUPG_HOME"])
        import_result = gpg.import_keys(public_key)

        logging.debug("remove_public_key() done")
        return "done"
