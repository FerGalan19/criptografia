import os
from cryptography.fernet import Fernet
key = Fernet.generate_key()
f = Fernet(key)
token = f.encrypt(b"A really secret message. Not for prying eyes.")
token

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
salt = os.urandom(16)
print(salt)
# derive
kdf = Scrypt(
    salt=salt,
    length=32,
    n=2**14,
    r=8,
    p=1,
    )
key = kdf.derive(b"my great password")
# verify
kdf = Scrypt(
    salt=salt,
    length=32,
    n=2**14,
    r=8,
    p=1,
    )
kdf.verify(b"my great password", key)
