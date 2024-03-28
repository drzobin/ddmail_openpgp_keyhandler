import re

# Validate password. Passwords will be base64 encoded. Only allow the following chars: A-Z, a-z, 0-9 and +/=
def is_password_allowed(password):
    pattern = re.compile(r"[a-zA-Z0-9\+\/\=]")

    for char in password:
        if not re.match(pattern, char):
            return False

    return True

# Validate openpgp public key. Only allow the following chars: A-Z, a-z, 0-9 and +/=
def is_public_key_allowed(public_key):

    # Check start and end of string.
    if public_key.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----") != True:
        return False
    if public_key.endswith("-----END PGP PUBLIC KEY BLOCK-----") != True:
        return False

    public_key = public_key.replace("-----BEGIN PGP PUBLIC KEY BLOCK-----", "", 1)
    public_key = public_key.replace("-----END PGP PUBLIC KEY BLOCK-----", "", 1)

    # Only allow A-Z ,a-z, 0-9 and +/=
    pattern = re.compile(r"[a-zA-Z0-9\+\/\=]")
    for char in public_key:
        if not re.match(pattern, char):
            return False

    return True

# Validate openpgp public key fingerprint string. Only allow the following chars: A-Z, 0-9
def is_fingerprint_allowed(fingerprint):
    # Fingerprint string should be 40 char.
    allowed_len = 40
    if len(fingerprint) != allowed_len:
        return False

    # Only allow A-Z, 0-9
    pattern = re.compile(r"[A-Z0-9]")
    for char in fingerprint:
        if not re.match(pattern, char):
            return False

    return True
