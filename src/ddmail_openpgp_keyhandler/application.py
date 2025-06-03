import os
import time
import subprocess
import string
import secrets
import shutil
import gnupg
from flask import Blueprint, current_app, request
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import ddmail_validators.validators as validators


bp = Blueprint("application", __name__, url_prefix="/")

@bp.route("/get_fingerprint", methods=["POST"])
def get_fingerprint():
    if request.method == 'POST':
        ph = PasswordHasher()

        # Get post form data.
        public_key = request.form.get('public_key')
        password = request.form.get('password')

        # Check if input from form is None.
        if password == None:
            current_app.logger.error("password is None")
            return "error: password is none"

        if public_key == None:
            current_app.logger.error("public_key is None")
            return "error: public_key is none"

        # Remove whitespace character.
        public_key = public_key.strip()
        password = password.strip()

        # Validate password.
        if validators.is_password_allowed(password) != True:
            current_app.logger.error("password validation failed")
            return "error: password validation failed"

        # Validate public_key.
        if validators.is_openpgp_public_key_allowed(public_key) != True:
            current_app.logger.error("public key validation failed")
            return "error: public key validation failed"

        # Check if password is correct.
        try:
            if ph.verify(current_app.config["PASSWORD_HASH"], password) != True:
                current_app.logger.error("wrong password")
                return "error: wrong password"
        except VerifyMismatchError:
            current_app.logger.error("wrong password")
            return "error: wrong password"

        # Generate a random string.
        alphabet = string.ascii_letters + string.digits
        random = ''.join(secrets.choice(alphabet) for i in range(24))

        # Set vars to be used for gnupg gpg object.
        tmp_folder = current_app.config["TMP_FOLDER"]
        gpg_binary_path = current_app.config["GPG_BINARY_PATH"]
        gnupghome_path = tmp_folder + "/" + random
        keyring_path = gnupghome_path + "/" + random

        # Check that tmp_folder exist.
        if not os.path.isdir(tmp_folder) == True:
            current_app.logger.error("tmp_folder do not exist")
            return "error: failed to get fingerprint from public key beacuse tmp_folder do not exist"

        # Create gnupghome_path folder.
        if not os.path.exists(gnupghome_path):
            os.makedirs(gnupghome_path)

        # Create gnupg gpg object.
        gpg = gnupg.GPG(gnupghome=gnupghome_path, keyring=keyring_path, gpgbinary=gpg_binary_path)

        # Upload public key.
        import_result = gpg.import_keys(public_key)

        # Check if 1 key has been imported.
        if import_result.count != 1:
            current_app.logger.error("import_result.count is not 1")
            shutil.rmtree(gnupghome_path)
            return "error: failed to get fingerprint from public key"

        # Check that fingerprint from importe_result is not None.
        if import_result.fingerprints[0] == None:
            current_app.logger.error("import_result.fingerprints[0] is None")
            shutil.rmtree(gnupghome_path)
            return "error: import_result.fingerprints is None"

        # Validate fingerprint from importe_result.
        if validators.is_openpgp_key_fingerprint_allowed(import_result.fingerprints[0]) != True:
            current_app.logger.error("import_result.fingerprints[0] validation failed")
            shutil.rmtree(gnupghome_path)
            return "error: import_result.fingerprints validation failed"

        # Get imported public keys data from keyring.
        public_keys =  gpg.list_keys()

        fingerprint_from_keyring = None

        # Find imported public key data in keyring.
        for key in public_keys:
            if key["fingerprint"] == import_result.fingerprints[0]:
                # Get fingerprint from keystore.
                fingerprint_from_keyring = key["fingerprint"]

                # Check public key trust level.
                if key["trust"] != "u":
                    current_app.logger.error("failed to set trust level of key " + str(import_result.fingerprints[0]) + " for keyring " + str(keyring))
                    shutil.rmtree(gnupghome_path)
                    return "error: failed to set trust level of key"

        # Check that imported public key fingerprint exist in keyring.
        if fingerprint_from_keyring == None:
            current_app.logger.error("failed to find key " + str(import_result.fingerprints[0])  +" in keyring " + str(keyring))
            shutil.rmtree(gnupghome_path)
            return "error: failed to find key"

        # Remove temp gnupghome folder.
        shutil.rmtree(gnupghome_path)

        current_app.logger.debug("imported public key with fingerprint: " + import_result.fingerprints[0])
        return "done fingerprint: " + import_result.fingerprints[0]
