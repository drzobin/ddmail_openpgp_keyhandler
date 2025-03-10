import os
import time
import subprocess
import logging
import gnupg
from flask import Blueprint, current_app, request
from argon2 import PasswordHasher
import ddmail_validators.validators as validators

bp = Blueprint("application", __name__, url_prefix="/")

# Configure logging.
logging.basicConfig(filename="/var/log/ddmail_openpgp_keyhandler.log", format='%(asctime)s: %(levelname)s: %(message)s', level=logging.ERROR)

@bp.route("/upload_public_key", methods=["POST"])
def upload_public_key():
    if request.method == 'POST':
        ph = PasswordHasher()

        # Get post form data.
        public_key = request.form.get('public_key')
        keyring = request.form.get('keyring')
        password = request.form.get('password')

        # Check if input from form is None.
        if password == None:
            logging.error("remove_public_key() password is None")
            return "error: password is none"

        if public_key == None:
            logging.error("remove_public_key() public_key is None")
            return "error: public_key is none"

        if keyring == None:
            logging.error("remove_public_key() keyring is None")
            return "error: keyring is none"

        # Remove whitespace character.
        public_key = public_key.strip()
        keyring = keyring.strip()
        password = password.strip()
        
        # Validate password.
        if validators.is_password_allowed(password) != True:
            logging.error("upload_public_key() password validation failed")
            return "error: password validation failed"

        # Validate public_key.
        if validators.is_openpgp_public_key_allowed(public_key) != True:
            logging.error("upload_public_key() public key validation failed")
            return "error: public key validation failed"

        # Validate keyring.
        if validators.is_openpgp_keyring_allowed(keyring) != True:
            logging.error("upload_public_key() keyring validation failed")
            return "error: keyring validation failed"

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

        # Create gnupg gpg object.
        gnuhome_path = current_app.config["GNUPG_HOME"]
        keyring_path = current_app.config["GNUPG_HOME"] + "/" + keyring
        gpg = gnupg.GPG(gnupghome=gnuhome_path, keyring=keyring_path, gpgbinary="/usr/bin/gpg")

        # Upload public key.
        import_result = gpg.import_keys(public_key)

        # Check if 1 key has been imported.
        if import_result.count != 1:
            logging.error("upload_public_key() import_result.count is not 1")
            return "error: failed to upload public key"

        # Check that fingerprint from importe_result is not None.
        if import_result.fingerprints[0] == None:
            logging.error("remove_public_key() import_result.fingerprints[0] is None")
            return "error: import_result.fingerprints[0] is None"

        # Validate fingerprint from importe_result.
        if validators.is_fingerprint_allowed(import_result.fingerprints[0]) != True:
            logging.error("remove_public_key() import_result.fingerprints[0] validation failed")
            return "error: import_result.fingerprints[0] validation failed"

        # Set trustlevel of imported public key.
        gpg.trust_keys(import_result.fingerprints[0], "TRUST_ULTIMATE")

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
                    logging.error("upload_public_key() failed to set trust level of key " + str(import_result.fingerprint[0]) + " for keyring " + str(keyring))
                    return "upload_public_key() failed to set trust level of key " + str(import_result.fingerprint[0]) + " for keyring " + str(keyring)

        # Check that imported public key fingerprint exist in keyring.
        if fingerprint_from_keyring == None:
            logging.error("upload_public_key() failed to find key " + str(import_result.fingerprint[0])  +" in keyring " + str(keyring))
            return "error: failed to find key " + str(import_result.fingerprint[0]) + " in keyring " + str(keyring)

        logging.debug("upload_public_key() imported public key with fingerprint: " + import_result.fingerprints[0])
        return "done fingerprint: " + import_result.fingerprints[0]

@bp.route("/remove_public_key", methods=["POST"])
def remove_public_key():
    if request.method == 'POST':
        ph = PasswordHasher()

        # Get post form data.
        fingerprint = request.form.get('fingerprint')
        keyring = request.form.get('keyring')
        password = request.form.get('password')

        # Check if input from form is None.
        if fingerprint == None:
            logging.error("remove_public_key() fingerprint is None")
            return "error: fingerprint is none"

        if keyring == None:
            logging.error("remove_public_key() keyring is None")
            return "error: keyring is none"

        if password == None:
            logging.error("remove_public_key() password is None")
            return "error: password is none"

        # Remove whitespace character.
        fingerprint = fingerprint.strip()
        keyring = keyring.strip()
        password = password.strip()

        # Validate fingerprint.
        if validators.is_openpgp_key_fingerprint_allowed(fingerprint) != True:
            logging.error("remove_public_key() fingerprint validation failed")
            return "error: fingerprint validation failed"

        # Validate keyring.
        if validators.is_openpgp_keyring_allowed(keyring) != True:
            logging.error("upload_public_key() keyring validation failed")
            return "error: keyring validation failed"

        # Validate password.
        if validators.is_password_allowed(password) != True:
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

        # Create gnupg gpg object.
        gnuhome_path = current_app.config["GNUPG_HOME"]
        keyring_path = current_app.config["GNUPG_HOME"] + "/" + keyring
        gpg = gnupg.GPG(gnupghome=gnuhome_path, keyring=keyring_path, gpgbinary="/usr/bin/gpg")

        # Get public keys data from keyring.
        public_keys =  gpg.list_keys()
        
        fingerprint_fom_keyring = None

        # Find public key fingerprint in keyring.
        for key in public_keys:
            if key["fingerprint"] == fingerprint:
                # Get fingerprint from keystore.
                fingerprint_from_keyring = key["fingerprint"]

        # Check that public key fingerprint exist in keyring.
        if fingerprint_from_keyring == None:
            logging.error("remove_public_key() failed to find key " + str(fingerprint)  +" in keyring " + str(keyring))
            return "error: failed to find key " + str(fingerprint) + " in keyring " + str(keyring)

        # Delete public key.
        delete_result = gpg.delete_keys(fingerprint)

        if str(delete_result) != "ok":
            logging.error("remove_public_key() remove_result is not ok")
            return "error: failed to remove public key"

        # Get public keys data from keyring.
        public_keys =  gpg.list_keys()

        fingerprint_from_keyring = None

        # Find public key fingerprint in keyring.
        for key in public_keys:
            if key["fingerprint"] == fingerprint:
                # Get fingerprint from keystore.
                fingerprint_from_keyring = key["fingerprint"]

        # Check that public key fingerprint do not exist anymore in keyring.
        if fingerprint_from_keyring != None:
            logging.error("remove_public_key() failed key " + str(fingerprint)  +" is still in keyring " + str(keyring))
            return "error: failed key " + str(fingerprint) + " is still in keyring " + str(keyring)

        logging.debug("remove_public_key() done")
        return "done"
