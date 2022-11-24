import os
import pandas as pd
import base64
import time

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import csv
import re
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

from cryptography.hazmat.primitives import serialization
variable_contraseña = b"toeorkfk"
pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(variable_contraseña)
 )
pem_private.splitlines()[0]
print(pem_private)

f = open('pem_private.txt','wb')
f.write(pem_private)
f.close()

with open('pem_private.txt', 'rb') as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password = variable_contraseña,)

public_key = private_key.public_key()
pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
 )

pem_public.splitlines()[0]
print(pem_public)

f = open('pem_public.txt','wb')
f.write(pem_public)
f.close()

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
message = b"A message I want to sign"
signature = private_key.sign(
     message,
     padding.PSS(
         mgf=padding.MGF1(hashes.SHA256()),
         salt_length=padding.PSS.MAX_LENGTH
     ),
     hashes.SHA256()
 )
print(signature)

public_key = private_key.public_key()
public_key.verify(
     signature,
     message,
     padding.PSS(
         mgf=padding.MGF1(hashes.SHA256()),
         salt_length=padding.PSS.MAX_LENGTH
     ),
     hashes.SHA256()
 )
print(public_key.verify(signature, message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
     hashes.SHA256()))

