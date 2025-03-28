#!/usr/bin/env python3
import json
import base64
import sys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


# Create JWT header and payload
header = {"alg": "RS256", "typ": "JWT"}
header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
payload_b64 = b64url_encode(sys.argv[1].encode("utf-8"))
signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")

# Load the private key
private_key_pem = None
with open("keypair.pem", "rb") as key_file:
    private_key_pem = key_file.read()

private_key = serialization.load_pem_private_key(
    private_key_pem,
    password=None,
)

# Sign the input and encode the input
signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
signature_b64 = b64url_encode(signature)

# Construct the JWT
jwt_token = f"{header_b64}.{payload_b64}.{signature_b64}"
print("Signed JWT:\n", jwt_token)
