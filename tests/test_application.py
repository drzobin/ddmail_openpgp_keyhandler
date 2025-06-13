def test_get_fingerprint_password_validation_failure(client,password):
    """Test password validation failure"""
    response = client.post("/get_fingerprint", data={"public_key":"nopublickey","password":"wrong password"})
    assert response.status_code == 200
    assert b"error: password validation failed" in response.data

def test_get_fingerprint_invalid_pubkey(client,password):
    """Test public key validation failure"""
    response = client.post("/get_fingerprint", data={"public_key":"no public key","password":"A"*24})
    assert response.status_code == 200
    assert b"error: public key validation failed" in response.data

def test_get_fingerprint_malformed_pgp_block(client,password):
    """Test malformed PGP block"""
    fake_pubkey = "-----BEGIN PGP PUBLIC KEY BLOCK-----aB1+!=-----END PGP PUBLIC KEY BLOCK-----"

    response = client.post("/get_fingerprint", data={"public_key":fake_pubkey,"password":password})
    assert response.status_code == 200
    assert b"error: public key validation failed" in response.data

def test_get_fingerprint_wrong_password(client,password):
    """Test wrong password"""
    fake_pubkey = "-----BEGIN PGP PUBLIC KEY BLOCK-----aB1+/=-----END PGP PUBLIC KEY BLOCK-----"

    response = client.post("/get_fingerprint", data={"public_key":fake_pubkey,"password":"A"*24})
    assert response.status_code == 200
    assert b"error: wrong password" in response.data

def test_get_fingerprint_working(client,password):
    """Test working fingerprint"""
    real_pubkey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZdUJSxYJKwYBBAHaRw8BAQdAQh/tvYt/2A6Fo/TMuWsWb23V1HLoEekHmnzd\nh4QgEy60FmdlbmVyYWxAY3Jldy5kZG1haWwuc2WIkwQTFgoAOxYhBL4dF5XUzKUM\n+RzHcJmypiemZ3O6BQJl1QlLAhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheA\nAAoJEJmypiemZ3O6KJ4BAIUt8x3tWg/h+MhxyASMA6F2D0b6mTEBRudOKhI52Q3q\nAQDozvDYivlMAWr+pDmT4FOhfesvSfJrLOYJt176wIqMD7g4BGXVCUsSCisGAQQB\nl1UBBQEBB0DSgnpR6/JCkNXsR1EJureDB5Be1foI5A/xvJ7EzjA+LwMBCAeIeAQY\nFgoAIBYhBL4dF5XUzKUM+RzHcJmypiemZ3O6BQJl1QlLAhsMAAoJEJmypiemZ3O6\nkR0BAPBdn3BLdZMPAlkS9PUZYScNyZ6vsUQZCLQHnGVGkPFIAP0X0niayPcSAOti\nvTF7UzVX18zXr0zUFWU2JBTyct88AA==\n=kpN6\n-----END PGP PUBLIC KEY BLOCK-----"

    response = client.post("/get_fingerprint", data={"public_key":real_pubkey,"password":password})
    assert response.status_code == 200
    assert b"done" in response.data

def test_get_fingerprint_missing_password(client):
    """Test when password parameter is missing"""
    response = client.post("/get_fingerprint", data={"public_key": "some key"})
    assert response.status_code == 200
    assert b"error: password is none" in response.data

def test_get_fingerprint_missing_public_key(client, password):
    """Test when public_key parameter is missing"""
    response = client.post("/get_fingerprint", data={"password": password})
    assert response.status_code == 200
    assert b"error: public_key is none" in response.data

def test_get_fingerprint_empty_password(client):
    """Test with empty password"""
    response = client.post("/get_fingerprint", data={"public_key": "some key", "password": ""})
    assert response.status_code == 200
    assert b"error: password validation failed" in response.data

def test_get_fingerprint_empty_public_key(client, password):
    """Test with empty public key"""
    response = client.post("/get_fingerprint", data={"public_key": "", "password": password})
    assert response.status_code == 200
    assert b"error: public key validation failed" in response.data

def test_get_fingerprint_whitespace_trimming(client, password, monkeypatch):
    """Test if whitespace is properly trimmed from inputs"""
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
    """Test handling of GPG binary errors"""
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
    """Test handling of None fingerprints"""
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
    """Test handling of invalid fingerprints"""
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
    """Test handling of key not found in keyring"""
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
    """Test handling of non-POST request"""
    response = client.get("/get_fingerprint")
    # The route only processes POST requests, so this should return a 405 Method Not Allowed
    # or some other error response
    assert response.status_code != 200
