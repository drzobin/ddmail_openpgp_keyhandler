import os
import secrets
import shutil
import string

import ddmail_validators.validators as validators
import gnupg
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import Blueprint, Response, current_app, make_response, request

bp = Blueprint("application", __name__, url_prefix="/")


@bp.route("/get_fingerprint", methods=["POST"])
def get_fingerprint() -> Response:
    """
    Extracts the fingerprint from a PGP public key after validation.

    This function processes a POST request containing a PGP public key and a password.
    It validates the inputs, verifies the password against a stored hash, and then
    extracts the fingerprint from the provided public key using GnuPG.

    Returns:
        str: A success message with the extracted fingerprint if successful,
             or an error message describing the issue encountered.

    Request Form Parameters:
        public_key (str): The PGP public key to extract the fingerprint from
        password (str): The password for authentication

    Error Responses:
        "error: password is none": If the password parameter is missing
        "error: public_key is none": If the public_key parameter is missing
        "error: password validation failed": If the password doesn't meet validation requirements
        "error: public key validation failed": If the public key format is invalid
        "error: wrong password": If the provided password doesn't match the stored hash
        "error: failed to get fingerprint from public key beacuse tmp_folder do not exist": If the temporary folder doesn't exist
        "error: failed to get fingerprint from public key": If the key import process fails
        "error: import_result.fingerprints is None": If no fingerprint was extracted
        "error: import_result.fingerprints validation failed": If the extracted fingerprint is invalid
        "error: failed to find key": If the imported key can't be found in the keyring

    Success Response:
        "done fingerprint: [FINGERPRINT]": Returns the extracted fingerprint
    """
    if request.method != 'POST':
        return make_response("Method not allowed", 405)

    ph = PasswordHasher()

    # Get post form data.
    public_key = request.form.get('public_key')
    password = request.form.get('password')

    # Check if input from form is None.
    if password is None:
        current_app.logger.error("password is None")
        return make_response("error: password is none", 200)

    if public_key is None:
        current_app.logger.error("public_key is None")
        return make_response("error: public_key is none", 200)

    # Remove whitespace character.
    public_key = public_key.strip()
    password = password.strip()

    # Validate password.
    if not validators.is_password_allowed(password):
        current_app.logger.error("password validation failed")
        return make_response("error: password validation failed", 200)

    # Validate public_key.
    if not validators.is_openpgp_public_key_allowed(public_key):
        current_app.logger.error("public key validation failed")
        return make_response("error: public key validation failed", 200)

    # Check if password is correct.
    try:
        if not ph.verify(current_app.config["PASSWORD_HASH"], password):
            current_app.logger.error("wrong password")
            return make_response("error: wrong password", 200)
    except VerifyMismatchError:
        current_app.logger.error("wrong password")
        return make_response("error: wrong password", 200)

    # Generate a random string.
    alphabet = string.ascii_letters + string.digits
    random = ''.join(secrets.choice(alphabet) for i in range(24))

    # Set vars to be used for gnupg gpg object.
    tmp_folder = current_app.config["TMP_FOLDER"]
    gpg_binary_path = current_app.config["GPG_BINARY_PATH"]
    gnupghome_path = tmp_folder + "/" + random
    keyring_path = gnupghome_path + "/" + random

    # Log vars used to create gnupg gpg object.
    current_app.logger.debug("tmp_folder set to " + tmp_folder)
    current_app.logger.debug("gpg_binary_path set to " + gpg_binary_path)
    current_app.logger.debug("gnupghome_path set to " + gnupghome_path)
    current_app.logger.debug("keyring_path set to " + keyring_path)

    # Check that tmp_folder exist.
    if not os.path.isdir(tmp_folder):
        current_app.logger.error("tmp_folder do not exist")
        return make_response("error: failed to get fingerprint from public key because tmp_folder do not exist", 200)

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
        return make_response("error: failed to get fingerprint from public key", 200)

    # Check that fingerprint from importe_result is not None.
    if import_result.fingerprints[0] is None:
        current_app.logger.error("import_result.fingerprints[0] is None")
        shutil.rmtree(gnupghome_path)
        return make_response("error: import_result.fingerprints is None", 200)

    # Validate fingerprint from importe_result.
    if not validators.is_openpgp_key_fingerprint_allowed(import_result.fingerprints[0]):
        current_app.logger.error("import_result.fingerprints[0] validation failed")
        shutil.rmtree(gnupghome_path)
        return make_response("error: import_result.fingerprints validation failed", 200)

    # Get imported public keys data from keyring.
    public_keys =  gpg.list_keys()

    fingerprint_from_keyring = None

    # Find imported public key data in keyring.
    for key in public_keys:
        if key["fingerprint"] == import_result.fingerprints[0]:
            # Get fingerprint from keystore.
            fingerprint_from_keyring = key["fingerprint"]

    # Check that imported public key fingerprint exist in keyring.
    if fingerprint_from_keyring is None:
        current_app.logger.error("failed to find key " + str(import_result.fingerprints[0])  +" in keyring " + str(keyring_path))
        shutil.rmtree(gnupghome_path)
        return make_response("error: failed to find key", 200)

    # Remove temp gnupghome folder.
    shutil.rmtree(gnupghome_path)

    current_app.logger.info("imported public key with fingerprint: " + import_result.fingerprints[0])
    return make_response("done fingerprint: " + import_result.fingerprints[0], 200)

@bp.route("/encrypt_data", methods=["POST"])
def encrypt_data() -> Response:
    """
    Encrypt data using the provided OpenPGP public key.

    This function processes a POST request containing a PGP public key, cleartext data and a application password.
    It validates the inputs, verifies the password against a stored hash, and then encrypts the cleartext data with the provided OpenPGP public key
    and returns the encrypted data.

    Returns:
        str: A success message with the encrypted data in ascii-armored format.

    Request Form Parameters:
        public_key (str): The PGP public key to extract the fingerprint from
        password (str): The application password for authentication
        cleartext_data (str): The cleartext data to encrypt

    Error Responses:
        "error: password is none": If the password parameter is missing
        "error: public_key is none": If the public_key parameter is missing
        "error: cleartext_data is none": If the cleartext_data parameter is missing
        "error: password validation failed": If the password doesn't meet validation requirements
        "error: public key validation failed": If the public key format is invalid
        "error: cleartext_data validation failed": If the cleartext_data length exceeds 8096 characters
        "error: wrong password": If the provided password doesn't match the stored hash
        "error: failed to get fingerprint from public key beacuse tmp_folder do not exist": If the temporary folder doesn't exist
        "error: failed to get fingerprint from public key": If the key import process fails
        "error: import_result.fingerprints is None": If no fingerprint was extracted
        "error: import_result.fingerprints validation failed": If the extracted fingerprint is invalid
        "error: failed to find key": If the imported key can't be found in the keyring
        "error: failed to encrypt data": If the encryption process fails

    Success Response:
        "done encrypted data:[ENCRYPTED DATA]": Returns the encrypted data in ascii-armored format.
    """
    if request.method != 'POST':
        return make_response("Method not allowed", 405)

    ph = PasswordHasher()

    # Get post form data.
    public_key = request.form.get('public_key')
    password = request.form.get('password')
    cleartext_data = request.form.get('cleartext_data')

    # Check if input from form is None.
    if password is None:
        current_app.logger.error("password is None")
        return make_response("error: password is none", 200)

    if public_key is None:
        current_app.logger.error("public_key is None")
        return make_response("error: public_key is none", 200)

    if cleartext_data is None:
        current_app.logger.error("cleartext_data is None")
        return make_response("error: cleartext_data is none", 200)

    # Remove whitespace character.
    public_key = public_key.strip()
    password = password.strip()
    cleartext_data = cleartext_data.strip()

    # Validate password.
    if not validators.is_password_allowed(password):
        current_app.logger.error("password validation failed")
        return make_response("error: password validation failed", 200)

    # Validate public_key.
    if not validators.is_openpgp_public_key_allowed(public_key):
        current_app.logger.error("public key validation failed")
        return make_response("error: public key validation failed", 200)

    # Validate cleartext_data length.
    if len(cleartext_data) > 8096:
        current_app.logger.error("cleartext_data length validation failed length " + str(len(cleartext_data)))
        return make_response("error: cleartext_data validation failed", 200)

    # Check if password is correct.
    try:
        if not ph.verify(current_app.config["PASSWORD_HASH"], password):
            current_app.logger.error("wrong password")
            return make_response("error: wrong password", 200)
    except VerifyMismatchError:
        current_app.logger.error("wrong password")
        return make_response("error: wrong password", 200)

    # Generate a random string.
    alphabet = string.ascii_letters + string.digits
    random = ''.join(secrets.choice(alphabet) for i in range(24))

    # Set vars to be used for gnupg gpg object.
    tmp_folder = current_app.config["TMP_FOLDER"]
    gpg_binary_path = current_app.config["GPG_BINARY_PATH"]
    gnupghome_path = tmp_folder + "/" + random
    keyring_path = gnupghome_path + "/" + random

    # Log vars used to create gnupg gpg object.
    current_app.logger.debug("tmp_folder set to " + tmp_folder)
    current_app.logger.debug("gpg_binary_path set to " + gpg_binary_path)
    current_app.logger.debug("gnupghome_path set to " + gnupghome_path)
    current_app.logger.debug("keyring_path set to " + keyring_path)

    # Check that tmp_folder exist.
    if not os.path.isdir(tmp_folder):
        current_app.logger.error("tmp_folder do not exist")
        return make_response("error: failed to get fingerprint from public key because tmp_folder do not exist", 200)

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
        return make_response("error: failed to get fingerprint from public key", 200)

    # Check that fingerprint from importe_result is not None.
    if import_result.fingerprints[0] is None:
        current_app.logger.error("import_result.fingerprints[0] is None")
        shutil.rmtree(gnupghome_path)
        return make_response("error: import_result.fingerprints is None", 200)

    # Validate fingerprint from importe_result.
    if not validators.is_openpgp_key_fingerprint_allowed(import_result.fingerprints[0]):
        current_app.logger.error("import_result.fingerprints[0] validation failed")
        shutil.rmtree(gnupghome_path)
        return make_response("error: import_result.fingerprints validation failed", 200)

    # Get imported public keys data from keyring.
    public_keys =  gpg.list_keys()

    fingerprint_from_keyring = None

    # Find imported public key data in keyring.
    for key in public_keys:
        if key["fingerprint"] == import_result.fingerprints[0]:
            # Get fingerprint from keystore.
            fingerprint_from_keyring = key["fingerprint"]

    # Check that imported public key fingerprint exist in keyring.
    if fingerprint_from_keyring is None:
        current_app.logger.error("failed to find key " + str(import_result.fingerprints[0])  +" in keyring " + str(keyring_path))
        shutil.rmtree(gnupghome_path)
        return make_response("error: failed to find key", 200)

    # Encrypt cleartext data with imported public key.
    encrypted = gpg.encrypt(cleartext_data, str(import_result.fingerprints[0]), always_trust=True)

    # Check that encryption was successful.
    if not encrypted.ok:
        current_app.logger.error("failed to encrypt data with fingerprint " + str(import_result.fingerprints[0]) +" encrypted.status " + str(encrypted.status))
        shutil.rmtree(gnupghome_path)
        return make_response("error: failed to encrypt data", 200)

    # Convert encrypted data to string.
    encrypted_data = str(encrypted)

    # Remove temp gnupghome folder.
    shutil.rmtree(gnupghome_path)

    current_app.logger.info("encrypted data with public key fingerprint: " + import_result.fingerprints[0])
    return make_response("done encrypted_data:" + str(encrypted_data), 200)
