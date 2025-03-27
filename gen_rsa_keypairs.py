from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate private key (2048-bit RSA)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Export private key in PEM format
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,  # PKCS#1
    encryption_algorithm=serialization.NoEncryption(),
)

# Export public key in PEM format
public_key = private_key.public_key()
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

# Print PEM keys
with open("./keypair.pem", "wb") as key_file:
    key_file.write(private_pem)

with open("./publickey.crt", "wb") as public_key:
    public_key.write(public_pem)
