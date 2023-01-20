"""Example crypto implementation: ECDSA with deterministic-rfc6979 and SHA256.

Copyright 2021 Google LLC.
SPDX-License-Identifier: Apache-2.0
"""

import hashlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class Signer:
    def __init__(self, secret_key):
        self.secret_key = secret_key
        self.public_key = self.secret_key.public_key()

    @classmethod
    def create(self):
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        with open("private.key", 'wb') as pem_out:
            pem_out.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        return Signer(private_key)

    def sign(self, message: bytes) -> bytes:
        """Returns the signature of `message`."""
        artifact_signature = self.secret_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return artifact_signature

    def keyid(self) -> str:
        """Returns a fingerprint of the public key."""
        return Verifier(self.public_key).keyid()


class Verifier:
    def __init__(self, public_key):
        self.public_key = public_key

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Returns true if `message` was signed by `signature`."""
        try:
            self.public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except:
            return False

    def keyid(self) -> str:
        """Returns a fingerprint of the public key."""
        key_pem = self.public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return hashlib.sha256(key_pem).hexdigest()
