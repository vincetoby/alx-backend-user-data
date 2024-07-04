#!/usr/bin/env python3
"""
module that Encrypts passwords
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """ it Returns a salted, hashed password, which is a byte string """
    encoded_p = password.encode()
    hashed = bcrypt.hashpw(encoded_p, bcrypt.gensalt())

    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ this Validates the provided password matches the hashed password """
    valid = False
    encoded_p = password.encode()
    if bcrypt.checkpw(encoded_p, hashed_password):
        valid = True
    return valid
