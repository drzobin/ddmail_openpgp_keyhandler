import os
import time
import subprocess
import gnupg
from flask import Blueprint, current_app, request
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import ddmail_validators.validators as validators


bp = Blueprint("application", __name__, url_prefix="/")

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
            current_app.logger.error("password is None")
            return "error: password is none"

        if public_key == None:
            current_app.logger.error("public_key is None")
            return "error: public_key is none"

        if keyring == None:
            current_app.logger.error("keyring is None")
            return "error: keyring is none"

        # Remove whitespace character.
        public_key = public_key.strip()
        keyring = keyring.strip()
        password = password.strip()
        
        # Validate password.
        if validators.is_password_allowed(password) != True:
            current_app.logger.error("password validation failed")
            return "error: password validation failed"

        # Validate public_key.
        if validators.is_openpgp_public_key_allowed(public_key) != True:
            current_app.logger.error("public key validation failed")
            return "error: public key validation failed"

        # Validate keyring.
        if validators.is_openpgp_keyring_allowed(keyring) != True:
            current_app.logger.error("keyring validation failed")
            return "error: keyring validation failed"

        # Check if password is correct.
        try:
            if ph.verify(current_app.config["PASSWORD_HASH"], password) != True:
                current_app.logger.error("wrong password")
                return "error: wrong password"
        except VerifyMismatchError:
            current_app.logger.error("wrong password")
            return "error: wrong password"

        # Create gnupg gpg object.
        gnuhome_path = current_app.config["GNUPG_HOME"]
        keyring_path = current_app.config["GNUPG_HOME"] + "/" + keyring
        gpg = gnupg.GPG(gnupghome=gnuhome_path, keyring=keyring_path, gpgbinary="/usr/bin/gpg")

        # Upload public key.
        import_result = gpg.import_keys(public_key)

        # Check if 1 key has been imported.
        if import_result.count != 1:
            current_app.logger.error("import_result.count is not 1")
            return "error: failed to upload public key"

        # Check that fingerprint from importe_result is not None.
        if import_result.fingerprints[0] == None:
            current_app.logger.error("import_result.fingerprints[0] is None")
            return "error: import_result.fingerprints is None"

        # Validate fingerprint from importe_result.
        if validators.is_openpgp_key_fingerprint_allowed(import_result.fingerprints[0]) != True:
            current_app.logger.error("import_result.fingerprints[0] validation failed")
            return "error: import_result.fingerprints validation failed"

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
                    current_app.logger.error("failed to set trust level of key " + str(import_result.fingerprint[0]) + " for keyring " + str(keyring))
                    return "error: failed to set trust level of key"

        # Check that imported public key fingerprint exist in keyring.
        if fingerprint_from_keyring == None:
            current_app.logger.error("failed to find key " + str(import_result.fingerprint[0])  +" in keyring " + str(keyring))
            return "error: failed to find key"

        current_app.logger.debug("imported public key with fingerprint: " + import_result.fingerprints[0])
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
            current_app.logger.error("fingerprint is None")
            return "error: fingerprint is none"

        if keyring == None:
            current_app.logger.error("keyring is None")
            return "error: keyring is none"

        if password == None:
            current_app.logger.error("password is None")
            return "error: password is none"

        # Remove whitespace character.
        fingerprint = fingerprint.strip()
        keyring = keyring.strip()
        password = password.strip()
        
        # Validate password.
        if validators.is_password_allowed(password) != True:
            current_app.logger.error("password validation failed")
            return "error: password validation failed"

        # Validate fingerprint.
        if validators.is_openpgp_key_fingerprint_allowed(fingerprint) != True:
            current_app.logger.error("fingerprint validation failed")
            return "error: fingerprint validation failed"

        # Validate keyring.
        if validators.is_openpgp_keyring_allowed(keyring) != True:
            current_app.logger.error("keyring validation failed")
            return "error: keyring validation failed"

        # Check if password is correct.
        try:
            if ph.verify(current_app.config["PASSWORD_HASH"], password) != True:
                current_app.logger.error("wrong password")
                return "error: wrong password"
        except VerifyMismatchError:
            current_app.logger.error("wrong password")
            return "error: wrong password"

        gnuhome_path = current_app.config["GNUPG_HOME"]
        keyring_path = current_app.config["GNUPG_HOME"] + "/" + keyring
        
        # Check if keyring excist on disc.
        if os.path.isfile(keyring_path) is not True:
            current_app.logger.error("can not find keyring file")
            return "error: can not find keyring file"
        
        # Create gnupg gpg object.
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
            current_app.logger.error("failed to find key " + str(fingerprint)  +" in keyring " + str(keyring))
            return "error: failed to find key"

        # Delete public key.
        delete_result = gpg.delete_keys(fingerprint)

        if str(delete_result) != "ok":
            current_app.logger.error("remove_result is not ok")
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
            current_app.logger.error("failed key " + str(fingerprint)  +" is still in keyring " + str(keyring))
            return "error: key is still in keyring"

        current_app.logger.debug("done")
        return "done"
