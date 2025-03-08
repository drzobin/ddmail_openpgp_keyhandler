from flask import current_app
from openpgp_keyhandler.validators import is_password_allowed
import pytest
import os

def test_is_password_allowed():
    assert is_password_allowed("aA8/+=") == True
    assert is_password_allowed("aA8/+=\\") == False
    assert is_password_allowed("aA8/+=\\vfgg") == False
    assert is_password_allowed("aAx\"fds") == False
    assert is_password_allowed("a-b3") == False
    assert is_password_allowed("a--b3") == False
    assert is_password_allowed("a<b3") == False
    assert is_password_allowed("a>b5") == False
    assert is_password_allowed("a>>6") == False
