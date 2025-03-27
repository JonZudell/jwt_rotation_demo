import base64
import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend


# Utility to decode base64url
def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


# Decode JWT
jwt_token = sys.argv[1]
header_b64, payload_b64, signature_b64 = jwt_token.split(".")
signing_input = f"{header_b64}.{payload_b64}".encode()
signature = b64url_decode(signature_b64)
# Load Public Key
public_key_pem = None
with open("publickey.crt", "rb") as key_file:
    public_key_pem = key_file.read()
public_key = serialization.load_pem_public_key(
    public_key_pem, backend=default_backend()
)

# Verify the signature
try:
    public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    print("✅ JWT signature is valid.")
except InvalidSignature:
    print("❌ JWT signature is invalid.")
    sys.exit(1)
