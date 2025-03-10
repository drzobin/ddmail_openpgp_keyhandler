from flask import current_app
import pytest
import os

def test_upload_public_key(client,password):
    fake_pubkey = "-----BEGIN PGP PUBLIC KEY BLOCK-----aB1+/=-----END PGP PUBLIC KEY BLOCK-----"
    real_pubkey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZdUJSxYJKwYBBAHaRw8BAQdAQh/tvYt/2A6Fo/TMuWsWb23V1HLoEekHmnzd\nh4QgEy60FmdlbmVyYWxAY3Jldy5kZG1haWwuc2WIkwQTFgoAOxYhBL4dF5XUzKUM\n+RzHcJmypiemZ3O6BQJl1QlLAhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheA\nAAoJEJmypiemZ3O6KJ4BAIUt8x3tWg/h+MhxyASMA6F2D0b6mTEBRudOKhI52Q3q\nAQDozvDYivlMAWr+pDmT4FOhfesvSfJrLOYJt176wIqMD7g4BGXVCUsSCisGAQQB\nl1UBBQEBB0DSgnpR6/JCkNXsR1EJureDB5Be1foI5A/xvJ7EzjA+LwMBCAeIeAQY\nFgoAIBYhBL4dF5XUzKUM+RzHcJmypiemZ3O6BQJl1QlLAhsMAAoJEJmypiemZ3O6\nkR0BAPBdn3BLdZMPAlkS9PUZYScNyZ6vsUQZCLQHnGVGkPFIAP0X0niayPcSAOti\nvTF7UzVX18zXr0zUFWU2JBTyct88AA==\n=kpN6\n-----END PGP PUBLIC KEY BLOCK-----"

    response = client.post("/upload_public_key", data={"public_key":"nopublickey","keyring":"nokeyring","password":"wrong password"})
    assert response.status_code == 200
    assert b"error: password validation failed" in response.data


    response = client.post("/upload_public_key", data={"public_key":"no public key","keyring":"nokeyring","password":"wrongpassword"})
    assert response.status_code == 200
    assert b"error: public key validation failed" in response.data


    response = client.post("/upload_public_key", data={"public_key":fake_pubkey,"keyring":"no keyring","password":"wrongpassword"})
    assert response.status_code == 200
    assert b"error: keyring validation failed" in response.data


    response = client.post("/upload_public_key", data={"public_key":fake_pubkey,"keyring":"MYKEYRINGTEST","password":"wrongpassword"})
    assert response.status_code == 200
    assert b"error: wrong password" in response.data
    

    response = client.post("/upload_public_key", data={"public_key":real_pubkey,"keyring":"MYKEYRINGTEST","password":password})
    assert response.status_code == 200
    assert b"done" in response.data

def test_remove_public_key(client, password):
    fingerprint = "BE1D1795D4CCA50CF91CC77099B2A627A66773BA"

    response = client.post("/remove_public_key", data={"fingerprint":"nofingerprint","keyring":"nokeyring","password":"wrong password"})
    assert response.status_code == 200
    assert b"error: password validation failed" in response.data
    
    response = client.post("/remove_public_key", data={"fingerprint":"nofingerprint","keyring":"nokeyring","password":"wrongpassword"})
    assert response.status_code == 200
    assert b"error: fingerprint validation failed" in response.data
    
    response = client.post("/remove_public_key", data={"fingerprint":fingerprint,"keyring":"nokeyring","password":"wrongpassword"})
    assert response.status_code == 200
    assert b"error: keyring validation failed" in response.data
    
    response = client.post("/remove_public_key", data={"fingerprint":fingerprint,"keyring":"MYKEYRINGTEST","password":"wrongpassword"})
    assert response.status_code == 200
    assert b"error: wrong password" in response.data
    
    response = client.post("/remove_public_key", data={"fingerprint":fingerprint,"keyring":"MYNOKEYRINGTEST","password":password})
    assert response.status_code == 200
    assert b"error: can not find keyring file" in response.data
    
    response = client.post("/remove_public_key", data={"fingerprint":fingerprint,"keyring":"MYKEYRINGTEST","password":password})
    assert response.status_code == 200
    assert b"done" in response.data
