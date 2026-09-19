
def test_get_fingerprint_password_validation_failure(client,password):
    """Test password validation failure

    This test verifies that the application rejects requests with an incorrect password format.
    It sends a request with a clearly invalid password and expects to receive a validation
    error response from the server.
    """
    response = client.post("/get_fingerprint", data={"public_key":"nopublickey","password":"wrong password"})
    assert response.status_code == 200
    assert b"error: password validation failed" in response.data

def test_get_fingerprint_invalid_pubkey(client,password):
    """Test public key validation failure

    This test verifies that the application properly validates the public key parameter
    and rejects requests containing invalid public key formats. The endpoint should
    return a specific error message indicating the public key validation failed.
    """
    response = client.post("/get_fingerprint", data={"public_key":"no public key","password":"A"*24})
    assert response.status_code == 200
    assert b"error: public key validation failed" in response.data

def test_get_fingerprint_malformed_pgp_block(client,password):
    """Test handling of malformed PGP block

    This test ensures the application correctly identifies and rejects PGP blocks
    that appear to have the right format markers but contain invalid content between
    the BEGIN and END markers. The validation should fail with an appropriate error.
    """
    fake_pubkey = "-----BEGIN PGP PUBLIC KEY BLOCK-----aB1+!=-----END PGP PUBLIC KEY BLOCK-----"

    response = client.post("/get_fingerprint", data={"public_key":fake_pubkey,"password":password})
    assert response.status_code == 200
    assert b"error: public key validation failed" in response.data

def test_get_fingerprint_wrong_password(client,password):
    """Test using wrong password with valid format

    This test checks that the application rejects requests that have a password
    with the correct format but incorrect value. The response should contain
    a specific error message indicating the password is wrong.
    """
    fake_pubkey = "-----BEGIN PGP PUBLIC KEY BLOCK-----aB1+/=-----END PGP PUBLIC KEY BLOCK-----"

    response = client.post("/get_fingerprint", data={"public_key":fake_pubkey,"password":"A"*24})
    assert response.status_code == 200
    assert b"error: wrong password" in response.data

def test_get_fingerprint_working(client,password):
    """Test successful fingerprint extraction

    This test verifies that the application correctly processes a valid public key
    and returns the fingerprint when all parameters are correct. It uses a real
    PGP public key and the correct password to ensure the happy path works.
    """
    real_pubkey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZdUJSxYJKwYBBAHaRw8BAQdAQh/tvYt/2A6Fo/TMuWsWb23V1HLoEekHmnzd\nh4QgEy60FmdlbmVyYWxAY3Jldy5kZG1haWwuc2WIkwQTFgoAOxYhBL4dF5XUzKUM\n+RzHcJmypiemZ3O6BQJl1QlLAhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheA\nAAoJEJmypiemZ3O6KJ4BAIUt8x3tWg/h+MhxyASMA6F2D0b6mTEBRudOKhI52Q3q\nAQDozvDYivlMAWr+pDmT4FOhfesvSfJrLOYJt176wIqMD7g4BGXVCUsSCisGAQQB\nl1UBBQEBB0DSgnpR6/JCkNXsR1EJureDB5Be1foI5A/xvJ7EzjA+LwMBCAeIeAQY\nFgoAIBYhBL4dF5XUzKUM+RzHcJmypiemZ3O6BQJl1QlLAhsMAAoJEJmypiemZ3O6\nkR0BAPBdn3BLdZMPAlkS9PUZYScNyZ6vsUQZCLQHnGVGkPFIAP0X0niayPcSAOti\nvTF7UzVX18zXr0zUFWU2JBTyct88AA==\n=kpN6\n-----END PGP PUBLIC KEY BLOCK-----"

    response = client.post("/get_fingerprint", data={"public_key":real_pubkey,"password":password})
    assert response.status_code == 200
    assert b"done" in response.data

def test_get_fingerprint_missing_password(client):
    """Test handling of missing password parameter

    This test verifies that the application properly handles cases where the password
    parameter is completely omitted from the request. The endpoint should detect
    the missing parameter and return an appropriate error message.
    """
    response = client.post("/get_fingerprint", data={"public_key": "some key"})
    assert response.status_code == 200
    assert b"error: password is none" in response.data

def test_get_fingerprint_missing_public_key(client, password):
    """Test handling of missing public_key parameter

    This test verifies that the application properly handles cases where the public_key
    parameter is completely omitted from the request. The endpoint should detect
    the missing parameter and return an appropriate error message.
    """
    response = client.post("/get_fingerprint", data={"password": password})
    assert response.status_code == 200
    assert b"error: public_key is none" in response.data

def test_get_fingerprint_empty_password(client):
    """Test handling of empty password parameter

    This test ensures the application correctly validates requests where the password
    parameter is present but empty. The validation should fail and return an appropriate
    error message about password validation.
    """
    response = client.post("/get_fingerprint", data={"public_key": "some key", "password": ""})
    assert response.status_code == 200
    assert b"error: password validation failed" in response.data

def test_get_fingerprint_empty_public_key(client, password):
    """Test handling of empty public_key parameter

    This test ensures the application correctly validates requests where the public_key
    parameter is present but empty. The validation should fail and return an appropriate
    error message about public key validation.
    """
    response = client.post("/get_fingerprint", data={"public_key": "", "password": password})
    assert response.status_code == 200
    assert b"error: public key validation failed" in response.data

def test_get_fingerprint_whitespace_trimming(client, password, monkeypatch):
    """Test whitespace trimming from input parameters

    This test verifies that the application properly trims leading and trailing
    whitespace from input parameters before validation. It uses a mocked validator
    to ensure the whitespace-trimmed inputs are correctly processed.
    """
    real_pubkey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZdUJSxYJKwYBBAHaRw8BAQdAQh/tvYt/2A6Fo/TMuWsWb23V1HLoEekHmnzd\nh4QgEy60FmdlbmVyYWxAY3Jldy5kZG1haWwuc2WIkwQTFgoAOxYhBL4dF5XUzKUM\n+RzHcJmypiemZ3O6BQJl1QlLAhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheA\nAAoJEJmypiemZ3O6KJ4BAIUt8x3tWg/h+MhxyASMA6F2D0b6mTEBRudOKhI52Q3q\nAQDozvDYivlMAWr+pDmT4FOhfesvSfJrLOYJt176wIqMD7g4BGXVCUsSCisGAQQB\nl1UBBQEBB0DSgnpR6/JCkNXsR1EJureDB5Be1foI5A/xvJ7EzjA+LwMBCAeIeAQY\nFgoAIBYhBL4dF5XUzKUM+RzHcJmypiemZ3O6BQJl1QlLAhsMAAoJEJmypiemZ3O6\nkR0BAPBdn3BLdZMPAlkS9PUZYScNyZ6vsUQZCLQHnGVGkPFIAP0X0niayPcSAOti\nvTF7UzVX18zXr0zUFWU2JBTyct88AA==\n=kpN6\n-----END PGP PUBLIC KEY BLOCK-----"

    # Mock validators to focus on whitespace handling
    import ddmail_validators.validators as validators
    original_validators = validators.is_openpgp_public_key_allowed

    def mock_validator(key):
        # Verify the key doesn't have leading/trailing whitespace
        assert key == key.strip()
        return original_validators(key)

    monkeypatch.setattr(validators, "is_openpgp_public_key_allowed", mock_validator)

    # Test with whitespace before and after the key
    response = client.post("/get_fingerprint", data={
        "public_key": f"  \n{real_pubkey}\t  ",
        "password": f" {password} "
    })

    assert response.status_code == 200
    assert b"done fingerprint:" in response.data

def test_get_fingerprint_gpg_binary_error(client, password, monkeypatch):
    """Test handling of GPG binary errors

    This test verifies that the application properly handles errors that might occur
    when interacting with the GPG binary. It mocks the GPG import_keys method to
    simulate a failed import and checks that an appropriate error is returned.
    """
    real_pubkey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZdUJSxYJKwYBBAHaRw8BAQdAQh/tvYt/2A6Fo/TMuWsWb23V1HLoEekHmnzd\nh4QgEy60FmdlbmVyYWxAY3Jldy5kZG1haWwuc2WIkwQTFgoAOxYhBL4dF5XUzKUM\n+RzHcJmypiemZ3O6BQJl1QlLAhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheA\nAAoJEJmypiemZ3O6KJ4BAIUt8x3tWg/h+MhxyASMA6F2D0b6mTEBRudOKhI52Q3q\nAQDozvDYivlMAWr+pDmT4FOhfesvSfJrLOYJt176wIqMD7g4BGXVCUsSCisGAQQB\nl1UBBQEBB0DSgnpR6/JCkNXsR1EJureDB5Be1foI5A/xvJ7EzjA+LwMBCAeIeAQY\nFgoAIBYhBL4dF5XUzKUM+RzHcJmypiemZ3O6BQJl1QlLAhsMAAoJEJmypiemZ3O6\nkR0BAPBdn3BLdZMPAlkS9PUZYScNyZ6vsUQZCLQHnGVGkPFIAP0X0niayPcSAOti\nvTF7UzVX18zXr0zUFWU2JBTyct88AA==\n=kpN6\n-----END PGP PUBLIC KEY BLOCK-----"

    # Set invalid GPG binary path in app config
    def mock_import_keys(*args, **kwargs):
        class ImportResult:
            count = 0
        return ImportResult()

    monkeypatch.setattr("gnupg.GPG.import_keys", mock_import_keys)

    response = client.post("/get_fingerprint", data={"public_key": real_pubkey, "password": password})
    assert response.status_code == 200
    assert b"error: failed to get fingerprint from public key" in response.data

def test_get_fingerprint_none_fingerprint(client, password, monkeypatch):
    """Test handling of None fingerprints

    This test verifies that the application correctly handles cases where GPG returns
    a None value for the fingerprint. It mocks the GPG import_keys method to return
    a None fingerprint and checks that an appropriate error is returned.
    """
    real_pubkey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZdUJSxYJKwYBBAHaRw8BAQdAQh/tvYt/2A6Fo/TMuWsWb23V1HLoEekHmnzd\nh4QgEy60FmdlbmVyYWxAY3Jldy5kZG1haWwuc2WIkwQTFgoAOxYhBL4dF5XUzKUM\n+RzHcJmypiemZ3O6BQJl1QlLAhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheA\nAAoJEJmypiemZ3O6KJ4BAIUt8x3tWg/h+MhxyASMA6F2D0b6mTEBRudOKhI52Q3q\nAQDozvDYivlMAWr+pDmT4FOhfesvSfJrLOYJt176wIqMD7g4BGXVCUsSCisGAQQB\nl1UBBQEBB0DSgnpR6/JCkNXsR1EJureDB5Be1foI5A/xvJ7EzjA+LwMBCAeIeAQY\nFgoAIBYhBL4dF5XUzKUM+RzHcJmypiemZ3O6BQJl1QlLAhsMAAoJEJmypiemZ3O6\nkR0BAPBdn3BLdZMPAlkS9PUZYScNyZ6vsUQZCLQHnGVGkPFIAP0X0niayPcSAOti\nvTF7UzVX18zXr0zUFWU2JBTyct88AA==\n=kpN6\n-----END PGP PUBLIC KEY BLOCK-----"

    # Mock import_keys to return None fingerprint
    def mock_import_keys(*args, **kwargs):
        class ImportResult:
            count = 1
            fingerprints = [None]
        return ImportResult()

    monkeypatch.setattr("gnupg.GPG.import_keys", mock_import_keys)

    response = client.post("/get_fingerprint", data={"public_key": real_pubkey, "password": password})
    assert response.status_code == 200
    assert b"error: import_result.fingerprints is None" in response.data

def test_get_fingerprint_invalid_fingerprint(client, password, monkeypatch):
    """Test handling of invalid fingerprints

    This test verifies that the application properly validates fingerprints
    returned by GPG. It mocks the GPG import_keys method to return an invalid
    fingerprint and the validator to reject it, then checks for the appropriate error.
    """
    real_pubkey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZdUJSxYJKwYBBAHaRw8BAQdAQh/tvYt/2A6Fo/TMuWsWb23V1HLoEekHmnzd\nh4QgEy60FmdlbmVyYWxAY3Jldy5kZG1haWwuc2WIkwQTFgoAOxYhBL4dF5XUzKUM\n+RzHcJmypiemZ3O6BQJl1QlLAhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheA\nAAoJEJmypiemZ3O6KJ4BAIUt8x3tWg/h+MhxyASMA6F2D0b6mTEBRudOKhI52Q3q\nAQDozvDYivlMAWr+pDmT4FOhfesvSfJrLOYJt176wIqMD7g4BGXVCUsSCisGAQQB\nl1UBBQEBB0DSgnpR6/JCkNXsR1EJureDB5Be1foI5A/xvJ7EzjA+LwMBCAeIeAQY\nFgoAIBYhBL4dF5XUzKUM+RzHcJmypiemZ3O6BQJl1QlLAhsMAAoJEJmypiemZ3O6\nkR0BAPBdn3BLdZMPAlkS9PUZYScNyZ6vsUQZCLQHnGVGkPFIAP0X0niayPcSAOti\nvTF7UzVX18zXr0zUFWU2JBTyct88AA==\n=kpN6\n-----END PGP PUBLIC KEY BLOCK-----"

    # Mock import_keys to return invalid fingerprint
    def mock_import_keys(*args, **kwargs):
        class ImportResult:
            count = 1
            fingerprints = ["invalid_fingerprint"]
        return ImportResult()

    # Mock validator to reject the fingerprint
    import ddmail_validators.validators as validators
    def mock_validator(fingerprint):
        return False

    monkeypatch.setattr("gnupg.GPG.import_keys", mock_import_keys)
    monkeypatch.setattr(validators, "is_openpgp_key_fingerprint_allowed", mock_validator)

    response = client.post("/get_fingerprint", data={"public_key": real_pubkey, "password": password})
    assert response.status_code == 200
    assert b"error: import_result.fingerprints validation failed" in response.data

def test_get_fingerprint_missing_key_in_keyring(client, password, monkeypatch):
    """Test handling of missing keys in keyring

    This test verifies that the application correctly handles the case where a key
    is successfully imported but cannot be found in the keyring. It mocks import_keys
    to succeed but list_keys to return empty results, then checks for the appropriate error.
    """
    real_pubkey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZdUJSxYJKwYBBAHaRw8BAQdAQh/tvYt/2A6Fo/TMuWsWb23V1HLoEekHmnzd\nh4QgEy60FmdlbmVyYWxAY3Jldy5kZG1haWwuc2WIkwQTFgoAOxYhBL4dF5XUzKUM\n+RzHcJmypiemZ3O6BQJl1QlLAhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheA\nAAoJEJmypiemZ3O6KJ4BAIUt8x3tWg/h+MhxyASMA6F2D0b6mTEBRudOKhI52Q3q\nAQDozvDYivlMAWr+pDmT4FOhfesvSfJrLOYJt176wIqMD7g4BGXVCUsSCisGAQQB\nl1UBBQEBB0DSgnpR6/JCkNXsR1EJureDB5Be1foI5A/xvJ7EzjA+LwMBCAeIeAQY\nFgoAIBYhBL4dF5XUzKUM+RzHcJmypiemZ3O6BQJl1QlLAhsMAAoJEJmypiemZ3O6\nkR0BAPBdn3BLdZMPAlkS9PUZYScNyZ6vsUQZCLQHnGVGkPFIAP0X0niayPcSAOti\nvTF7UzVX18zXr0zUFWU2JBTyct88AA==\n=kpN6\n-----END PGP PUBLIC KEY BLOCK-----"

    valid_fingerprint = "BE1D1795D4CCA50CF91CC77099B2A627A66773BA"

    # Mock import_keys to return valid fingerprint but list_keys returns empty
    def mock_import_keys(*args, **kwargs):
        class ImportResult:
            count = 1
            fingerprints = [valid_fingerprint]
        return ImportResult()

    def mock_list_keys(*args, **kwargs):
        # Return empty list or list with different fingerprint
        return []

    # Mock validator to accept the fingerprint
    import ddmail_validators.validators as validators
    def mock_fingerprint_validator(fingerprint):
        return True

    monkeypatch.setattr("gnupg.GPG.import_keys", mock_import_keys)
    monkeypatch.setattr("gnupg.GPG.list_keys", mock_list_keys)
    monkeypatch.setattr(validators, "is_openpgp_key_fingerprint_allowed", mock_fingerprint_validator)

    response = client.post("/get_fingerprint", data={"public_key": real_pubkey, "password": password})
    assert response.status_code == 200
    assert b"error: failed to find key" in response.data

def test_get_fingerprint_non_post_request(client):
    """Test handling of non-POST requests

    This test verifies that the application properly handles HTTP methods other than POST.
    The endpoint should reject GET requests with an appropriate error status code
    since it only accepts POST requests for security reasons.
    """
    response = client.get("/get_fingerprint")
    # The route only processes POST requests, so this should return a 405 Method Not Allowed
    # or some other error response
    assert response.status_code != 200


def test_encrypt_data_password_validation_failure(client,password):
    """Test password validation failure for encrypt_data

    This test verifies that the application rejects requests with an incorrect password format
    when calling encrypt_data. It sends a request with a clearly invalid password and expects
    to receive a validation error response from the server.
    """
    response = client.post("/encrypt_data", data={"public_key":"nopublickey","password":"wrong password","cleartext_data":"test"})
    assert response.status_code == 200
    assert b"error: password validation failed" in response.data


def test_encrypt_data_invalid_pubkey(client,password):
    """Test public key validation failure for encrypt_data

    This test verifies that the application properly validates the public key parameter
    and rejects requests containing invalid public key formats when calling encrypt_data.
    The endpoint should return a specific error message indicating the public key validation failed.
    """
    response = client.post("/encrypt_data", data={"public_key":"no public key","password":"A"*24,"cleartext_data":"test"})
    assert response.status_code == 200
    assert b"error: public key validation failed" in response.data


def test_encrypt_data_malformed_pgp_block(client,password):
    """Test handling of malformed PGP block for encrypt_data

    This test ensures the application correctly identifies and rejects PGP blocks
    that appear to have the right format markers but contain invalid content between
    the BEGIN and END markers when calling encrypt_data. The validation should fail with an appropriate error.
    """
    fake_pubkey = "-----BEGIN PGP PUBLIC KEY BLOCK-----aB1+!=-----END PGP PUBLIC KEY BLOCK-----"

    response = client.post("/encrypt_data", data={"public_key":fake_pubkey,"password":password,"cleartext_data":"test"})
    assert response.status_code == 200
    assert b"error: public key validation failed" in response.data


def test_encrypt_data_wrong_password(client,password):
    """Test using wrong password with valid format for encrypt_data

    This test checks that the application rejects requests that have a password
    with the correct format but incorrect value when calling encrypt_data.
    The response should contain a specific error message indicating the password is wrong.
    """
    fake_pubkey = "-----BEGIN PGP PUBLIC KEY BLOCK-----aB1+/=-----END PGP PUBLIC KEY BLOCK-----"

    response = client.post("/encrypt_data", data={"public_key":fake_pubkey,"password":"A"*24,"cleartext_data":"test"})
    assert response.status_code == 200
    assert b"error: wrong password" in response.data


def test_encrypt_data_missing_password(client):
    """Test handling of missing password parameter for encrypt_data

    This test verifies that the application properly handles cases where the password
    parameter is completely omitted from the request when calling encrypt_data.
    The endpoint should detect the missing parameter and return an appropriate error message.
    """
    response = client.post("/encrypt_data", data={"public_key": "some key", "cleartext_data": "test"})
    assert response.status_code == 200
    assert b"error: password is none" in response.data


def test_encrypt_data_missing_public_key(client, password):
    """Test handling of missing public_key parameter for encrypt_data

    This test verifies that the application properly handles cases where the public_key
    parameter is completely omitted from the request when calling encrypt_data.
    The endpoint should detect the missing parameter and return an appropriate error message.
    """
    response = client.post("/encrypt_data", data={"password": password, "cleartext_data": "test"})
    assert response.status_code == 200
    assert b"error: public_key is none" in response.data


def test_encrypt_data_missing_cleartext_data(client, password):
    """Test handling of missing cleartext_data parameter for encrypt_data

    This test verifies that the application properly handles cases where the cleartext_data
    parameter is completely omitted from the request when calling encrypt_data.
    The endpoint should detect the missing parameter and return an appropriate error message.
    """
    response = client.post("/encrypt_data", data={"public_key": "some key", "password": password})
    assert response.status_code == 200
    assert b"error: cleartext_data is none" in response.data


def test_encrypt_data_empty_password(client):
    """Test handling of empty password parameter for encrypt_data

    This test ensures the application correctly validates requests where the password
    parameter is present but empty when calling encrypt_data.
    The validation should fail and return an appropriate error message about password validation.
    """
    response = client.post("/encrypt_data", data={"public_key": "some key", "password": "", "cleartext_data": "test"})
    assert response.status_code == 200
    assert b"error: password validation failed" in response.data


def test_encrypt_data_empty_public_key(client, password):
    """Test handling of empty public_key parameter for encrypt_data

    This test ensures the application correctly validates requests where the public_key
    parameter is present but empty when calling encrypt_data.
    The validation should fail and return an appropriate error message about public key validation.
    """
    response = client.post("/encrypt_data", data={"public_key": "", "password": password, "cleartext_data": "test"})
    assert response.status_code == 200
    assert b"error: public key validation failed" in response.data


def test_encrypt_data_empty_cleartext_data(client, password):
    """Test handling of empty cleartext_data parameter for encrypt_data

    This test ensures the application correctly validates requests where the cleartext_data
    parameter is present but empty when calling encrypt_data.
    The validation should pass as empty string is valid for cleartext_data (length 0 <= 8096).
    """
    # Use an invalid public key to trigger validation error after cleartext_data passes validation
    response = client.post("/encrypt_data", data={"public_key": "invalid", "password": password, "cleartext_data": ""})
    assert response.status_code == 200
    # Empty cleartext_data should pass validation (length 0 <= 8096)
    # but public key validation should fail
    assert b"error: public key validation failed" in response.data


def test_encrypt_data_cleartext_too_long(client, password):
    """Test handling of cleartext_data that exceeds maximum length for encrypt_data

    This test ensures the application correctly validates requests where the cleartext_data
    parameter exceeds the maximum allowed length (8096 characters) when calling encrypt_data.
    The validation should fail and return an appropriate error message.
    """
    fake_pubkey = "-----BEGIN PGP PUBLIC KEY BLOCK-----aB1+/=-----END PGP PUBLIC KEY BLOCK-----"
    long_cleartext = "A" * 8097  # Exceeds the 8096 character limit
    response = client.post("/encrypt_data", data={"public_key": fake_pubkey, "password": password, "cleartext_data": long_cleartext})
    assert response.status_code == 200
    assert b"error: cleartext_data validation failed" in response.data


def test_encrypt_data_working(client,password):
    """Test successful data encryption for encrypt_data

    This test verifies that the application correctly processes a valid public key,
    password, and cleartext data, and returns encrypted data when all parameters are correct.
    It uses a real PGP public key and the correct password to ensure the happy path works.
    """
    real_pubkey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZdUJSxYJKwYBBAHaRw8BAQdAQh/tvYt/2A6Fo/TMuWsWb23V1HLoEekHmnzd\nh4QgEy60FmdlbmVyYWxAY3Jldy5kZG1haWwuc2WIkwQTFgoAOxYhBL4dF5XUzKUM\n+RzHcJmypiemZ3O6BQJl1QlLAhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheA\nAAoJEJmypiemZ3O6KJ4BAIUt8x3tWg/h+MhxyASMA6F2D0b6mTEBRudOKhI52Q3q\nAQDozvDYivlMAWr+pDmT4FOhfesvSfJrLOYJt176wIqMD7g4BGXVCUsSCisGAQQB\nl1UBBQEBB0DSgnpR6/JCkNXsR1EJureDB5Be1foI5A/xvJ7EzjA+LwMBCAeIeAQY\nFgoAIBYhBL4dF5XUzKUM+RzHcJmypiemZ3O6BQJl1QlLAhsMAAoJEJmypiemZ3O6\nkR0BAPBdn3BLdZMPAlkS9PUZYScNyZ6vsUQZCLQHnGVGkPFIAP0X0niayPcSAOti\nvTF7UzVX18zXr0zUFWU2JBTyct88AA==\n=kpN6\n-----END PGP PUBLIC KEY BLOCK-----"

    response = client.post("/encrypt_data", data={"public_key":real_pubkey,"password":password,"cleartext_data":"test data"})
    assert response.status_code == 200
    assert b"done encrypted_data:" in response.data


def test_encrypt_data_whitespace_trimming(client, password, monkeypatch):
    """Test whitespace trimming from input parameters for encrypt_data

    This test verifies that the application properly trims leading and trailing
    whitespace from input parameters before validation when calling encrypt_data.
    It uses a mocked validator to ensure the whitespace-trimmed inputs are correctly processed.
    """
    real_pubkey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZdUJSxYJKwYBBAHaRw8BAQdAQh/tvYt/2A6Fo/TMuWsWb23V1HLoEekHmnzd\nh4QgEy60FmdlbmVyYWxAY3Jldy5kZG1haWwuc2WIkwQTFgoAOxYhBL4dF5XUzKUM\n+RzHcJmypiemZ3O6BQJl1QlLAhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheA\nAAoJEJmypiemZ3O6KJ4BAIUt8x3tWg/h+MhxyASMA6F2D0b6mTEBRudOKhI52Q3q\nAQDozvDYivlMAWr+pDmT4FOhfesvSfJrLOYJt176wIqMD7g4BGXVCUsSCisGAQQB\nl1UBBQEBB0DSgnpR6/JCkNXsR1EJureDB5Be1foI5A/xvJ7EzjA+LwMBCAeIeAQY\nFgoAIBYhBL4dF5XUzKUM+RzHcJmypiemZ3O6BQJl1QlLAhsMAAoJEJmypiemZ3O6\nkR0BAPBdn3BLdZMPAlkS9PUZYScNyZ6vsUQZCLQHnGVGkPFIAP0X0niayPcSAOti\nvTF7UzVX18zXr0zUFWU2JBTyct88AA==\n=kpN6\n-----END PGP PUBLIC KEY BLOCK-----"

    # Mock validators to focus on whitespace handling
    import ddmail_validators.validators as validators
    original_validators = validators.is_openpgp_public_key_allowed

    def mock_validator(key):
        # Verify the key doesn't have leading/trailing whitespace
        assert key == key.strip()
        return original_validators(key)

    monkeypatch.setattr(validators, "is_openpgp_public_key_allowed", mock_validator)

    # Test with whitespace before and after the parameters
    response = client.post("/encrypt_data", data={
        "public_key": f"  \n{real_pubkey}\t  ",
        "password": f" {password} ",
        "cleartext_data": "  test data  "
    })

    assert response.status_code == 200
    assert b"done encrypted_data:" in response.data


def test_encrypt_data_gpg_binary_error(client, password, monkeypatch):
    """Test handling of GPG binary errors for encrypt_data

    This test verifies that the application properly handles errors that might occur
    when interacting with the GPG binary during encryption. It mocks the GPG import_keys method
    to simulate a failed import and checks that an appropriate error is returned.
    """
    real_pubkey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZdUJSxYJKwYBBAHaRw8BAQdAQh/tvYt/2A6Fo/TMuWsWb23V1HLoEekHmnzd\nh4QgEy60FmdlbmVyYWxAY3Jldy5kZG1haWwuc2WIkwQTFgoAOxYhBL4dF5XUzKUM\n+RzHcJmypiemZ3O6BQJl1QlLAhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheA\nAAoJEJmypiemZ3O6KJ4BAIUt8x3tWg/h+MhxyASMA6F2D0b6mTEBRudOKhI52Q3q\nAQDozvDYivlMAWr+pDmT4FOhfesvSfJrLOYJt176wIqMD7g4BGXVCUsSCisGAQQB\nl1UBBQEBB0DSgnpR6/JCkNXsR1EJureDB5Be1foI5A/xvJ7EzjA+LwMBCAeIeAQY\nFgoAIBYhBL4dF5XUzKUM+RzHcJmypiemZ3O6BQJl1QlLAhsMAAoJEJmypiemZ3O6\nkR0BAPBdn3BLdZMPAlkS9PUZYScNyZ6vsUQZCLQHnGVGkPFIAP0X0niayPcSAOti\nvTF7UzVX18zXr0zUFWU2JBTyct88AA==\n=kpN6\n-----END PGP PUBLIC KEY BLOCK-----"

    # Mock import_keys to return count 0 (failed import)
    def mock_import_keys(*args, **kwargs):
        class ImportResult:
            count = 0
        return ImportResult()

    monkeypatch.setattr("gnupg.GPG.import_keys", mock_import_keys)

    response = client.post("/encrypt_data", data={"public_key": real_pubkey, "password": password, "cleartext_data": "test"})
    assert response.status_code == 200
    assert b"error: failed to get fingerprint from public key" in response.data


def test_encrypt_data_none_fingerprint(client, password, monkeypatch):
    """Test handling of None fingerprints for encrypt_data

    This test verifies that the application correctly handles cases where GPG returns
    a None value for the fingerprint during encryption. It mocks the GPG import_keys method
    to return a None fingerprint and checks that an appropriate error is returned.
    """
    real_pubkey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZdUJSxYJKwYBBAHaRw8BAQdAQh/tvYt/2A6Fo/TMuWsWb23V1HLoEekHmnzd\nh4QgEy60FmdlbmVyYWxAY3Jldy5kZG1haWwuc2WIkwQTFgoAOxYhBL4dF5XUzKUM\n+RzHcJmypiemZ3O6BQJl1QlLAhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheA\nAAoJEJmypiemZ3O6KJ4BAIUt8x3tWg/h+MhxyASMA6F2D0b6mTEBRudOKhI52Q3q\nAQDozvDYivlMAWr+pDmT4FOhfesvSfJrLOYJt176wIqMD7g4BGXVCUsSCisGAQQB\nl1UBBQEBB0DSgnpR6/JCkNXsR1EJureDB5Be1foI5A/xvJ7EzjA+LwMBCAeIeAQY\nFgoAIBYhBL4dF5XUzKUM+RzHcJmypiemZ3O6BQJl1QlLAhsMAAoJEJmypiemZ3O6\nkR0BAPBdn3BLdZMPAlkS9PUZYScNyZ6vsUQZCLQHnGVGkPFIAP0X0niayPcSAOti\nvTF7UzVX18zXr0zUFWU2JBTyct88AA==\n=kpN6\n-----END PGP PUBLIC KEY BLOCK-----"

    # Mock import_keys to return None fingerprint
    def mock_import_keys(*args, **kwargs):
        class ImportResult:
            count = 1
            fingerprints = [None]
        return ImportResult()

    monkeypatch.setattr("gnupg.GPG.import_keys", mock_import_keys)

    response = client.post("/encrypt_data", data={"public_key": real_pubkey, "password": password, "cleartext_data": "test"})
    assert response.status_code == 200
    assert b"error: import_result.fingerprints is None" in response.data


def test_encrypt_data_invalid_fingerprint(client, password, monkeypatch):
    """Test handling of invalid fingerprints for encrypt_data

    This test verifies that the application properly validates fingerprints
    returned by GPG during encryption. It mocks the GPG import_keys method to return an invalid
    fingerprint and the validator to reject it, then checks for the appropriate error.
    """
    real_pubkey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZdUJSxYJKwYBBAHaRw8BAQdAQh/tvYt/2A6Fo/TMuWsWb23V1HLoEekHmnzd\nh4QgEy60FmdlbmVyYWxAY3Jldy5kZG1haWwuc2WIkwQTFgoAOxYhBL4dF5XUzKUM\n+RzHcJmypiemZ3O6BQJl1QlLAhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheA\nAAoJEJmypiemZ3O6KJ4BAIUt8x3tWg/h+MhxyASMA6F2D0b6mTEBRudOKhI52Q3q\nAQDozvDYivlMAWr+pDmT4FOhfesvSfJrLOYJt176wIqMD7g4BGXVCUsSCisGAQQB\nl1UBBQEBB0DSgnpR6/JCkNXsR1EJureDB5Be1foI5A/xvJ7EzjA+LwMBCAeIeAQY\nFgoAIBYhBL4dF5XUzKUM+RzHcJmypiemZ3O6BQJl1QlLAhsMAAoJEJmypiemZ3O6\nkR0BAPBdn3BLdZMPAlkS9PUZYScNyZ6vsUQZCLQHnGVGkPFIAP0X0niayPcSAOti\nvTF7UzVX18zXr0zUFWU2JBTyct88AA==\n=kpN6\n-----END PGP PUBLIC KEY BLOCK-----"

    # Mock import_keys to return invalid fingerprint
    def mock_import_keys(*args, **kwargs):
        class ImportResult:
            count = 1
            fingerprints = ["invalid_fingerprint"]
        return ImportResult()

    # Mock validator to reject the fingerprint
    import ddmail_validators.validators as validators
    def mock_validator(fingerprint):
        return False

    monkeypatch.setattr("gnupg.GPG.import_keys", mock_import_keys)
    monkeypatch.setattr(validators, "is_openpgp_key_fingerprint_allowed", mock_validator)

    response = client.post("/encrypt_data", data={"public_key": real_pubkey, "password": password, "cleartext_data": "test"})
    assert response.status_code == 200
    assert b"error: import_result.fingerprints validation failed" in response.data


def test_encrypt_data_missing_key_in_keyring(client, password, monkeypatch):
    """Test handling of missing keys in keyring for encrypt_data

    This test verifies that the application correctly handles the case where a key
    is successfully imported but cannot be found in the keyring during encryption.
    It mocks import_keys to succeed but list_keys to return empty results, then checks for the appropriate error.
    """
    real_pubkey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZdUJSxYJKwYBBAHaRw8BAQdAQh/tvYt/2A6Fo/TMuWsWb23V1HLoEekHmnzd\nh4QgEy60FmdlbmVyYWxAY3Jldy5kZG1haWwuc2WIkwQTFgoAOxYhBL4dF5XUzKUM\n+RzHcJmypiemZ3O6BQJl1QlLAhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheA\nAAoJEJmypiemZ3O6KJ4BAIUt8x3tWg/h+MhxyASMA6F2D0b6mTEBRudOKhI52Q3q\nAQDozvDYivlMAWr+pDmT4FOhfesvSfJrLOYJt176wIqMD7g4BGXVCUsSCisGAQQB\nl1UBBQEBB0DSgnpR6/JCkNXsR1EJureDB5Be1foI5A/xvJ7EzjA+LwMBCAeIeAQY\nFgoAIBYhBL4dF5XUzKUM+RzHcJmypiemZ3O6BQJl1QlLAhsMAAoJEJmypiemZ3O6\nkR0BAPBdn3BLdZMPAlkS9PUZYScNyZ6vsUQZCLQHnGVGkPFIAP0X0niayPcSAOti\nvTF7UzVX18zXr0zUFWU2JBTyct88AA==\n=kpN6\n-----END PGP PUBLIC KEY BLOCK-----"

    valid_fingerprint = "BE1D1795D4CCA50CF91CC77099B2A627A66773BA"

    # Mock import_keys to return valid fingerprint but list_keys returns empty
    def mock_import_keys(*args, **kwargs):
        class ImportResult:
            count = 1
            fingerprints = [valid_fingerprint]
        return ImportResult()

    def mock_list_keys(*args, **kwargs):
        # Return empty list or list with different fingerprint
        return []

    # Mock validator to accept the fingerprint
    import ddmail_validators.validators as validators
    def mock_fingerprint_validator(fingerprint):
        return True

    monkeypatch.setattr("gnupg.GPG.import_keys", mock_import_keys)
    monkeypatch.setattr("gnupg.GPG.list_keys", mock_list_keys)
    monkeypatch.setattr(validators, "is_openpgp_key_fingerprint_allowed", mock_fingerprint_validator)

    response = client.post("/encrypt_data", data={"public_key": real_pubkey, "password": password, "cleartext_data": "test"})
    assert response.status_code == 200
    assert b"error: failed to find key" in response.data


def test_encrypt_data_encryption_failure(client, password, monkeypatch):
    """Test handling of encryption failure for encrypt_data

    This test verifies that the application correctly handles cases where the encryption
    process fails. It mocks the GPG encrypt method to return a failed result and checks
    that an appropriate error is returned.
    """
    real_pubkey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZdUJSxYJKwYBBAHaRw8BAQdAQh/tvYt/2A6Fo/TMuWsWb23V1HLoEekHmnzd\nh4QgEy60FmdlbmVyYWxAY3Jldy5kZG1haWwuc2WIkwQTFgoAOxYhBL4dF5XUzKUM\n+RzHcJmypiemZ3O6BQJl1QlLAhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheA\nAAoJEJmypiemZ3O6KJ4BAIUt8x3tWg/h+MhxyASMA6F2D0b6mTEBRudOKhI52Q3q\nAQDozvDYivlMAWr+pDmT4FOhfesvSfJrLOYJt176wIqMD7g4BGXVCUsSCisGAQQB\nl1UBBQEBB0DSgnpR6/JCkNXsR1EJureDB5Be1foI5A/xvJ7EzjA+LwMBCAeIeAQY\nFgoAIBYhBL4dF5XUzKUM+RzHcJmypiemZ3O6BQJl1QlLAhsMAAoJEJmypiemZ3O6\nkR0BAPBdn3BLdZMPAlkS9PUZYScNyZ6vsUQZCLQHnGVGkPFIAP0X0niayPcSAOti\nvTF7UzVX18zXr0zUFWU2JBTyct88AA==\n=kpN6\n-----END PGP PUBLIC KEY BLOCK-----"

    valid_fingerprint = "BE1D1795D4CCA50CF91CC77099B2A627A66773BA"

    # Mock import_keys to return valid fingerprint
    def mock_import_keys(*args, **kwargs):
        class ImportResult:
            count = 1
            fingerprints = [valid_fingerprint]
        return ImportResult()

    def mock_list_keys(*args, **kwargs):
        # Return list with the valid fingerprint
        return [{"fingerprint": valid_fingerprint}]

    # Mock encrypt to return failed result
    def mock_encrypt(*args, **kwargs):
        class EncryptResult:
            ok = False
            status = "encryption failed"
        return EncryptResult()

    # Mock validator to accept the fingerprint
    import ddmail_validators.validators as validators
    def mock_fingerprint_validator(fingerprint):
        return True

    monkeypatch.setattr("gnupg.GPG.import_keys", mock_import_keys)
    monkeypatch.setattr("gnupg.GPG.list_keys", mock_list_keys)
    monkeypatch.setattr("gnupg.GPG.encrypt", mock_encrypt)
    monkeypatch.setattr(validators, "is_openpgp_key_fingerprint_allowed", mock_fingerprint_validator)

    response = client.post("/encrypt_data", data={"public_key": real_pubkey, "password": password, "cleartext_data": "test"})
    assert response.status_code == 200
    assert b"error: failed to encrypt data" in response.data


def test_encrypt_data_non_post_request(client):
    """Test handling of non-POST requests for encrypt_data

    This test verifies that the application properly handles HTTP methods other than POST
    for the encrypt_data endpoint. The endpoint should reject GET requests with an appropriate
    error status code since it only accepts POST requests for security reasons.
    """
    response = client.get("/encrypt_data")
    # The route only processes POST requests, so this should return a 405 Method Not Allowed
    # or some other error response
    assert response.status_code != 200
