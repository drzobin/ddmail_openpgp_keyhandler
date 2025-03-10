from flask import current_app
import pytest
import os

def test_upload_public_key(client,password):
    fake_pubkey = "-----BEGIN PGP PUBLIC KEY BLOCK-----aB1+/=-----END PGP PUBLIC KEY BLOCK-----"


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
    

    response = client.post("/upload_public_key", data={"public_key":fake_pubkey,"keyring":"MYKEYRINGTEST","password":password})
    assert response.status_code == 200
    assert b"error: wrong password" in response.data
