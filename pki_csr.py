from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import os
import pandas as pd
import base64
import time
import csv
import re

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key

variable_contraseña = b"rf"

def obtener_clave_privada():

    with open("pem_private.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password = variable_contraseña,)

    return private_key

clave_privada= obtener_clave_privada()
# Generate a CSR
csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
     # Provide various details about who we are.
     x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
     x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"MADRID"),
     x509.NameAttribute(NameOID.LOCALITY_NAME, u"LEGANES"),
     x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"BANCO"),
     x509.NameAttribute(NameOID.COMMON_NAME, u"PKICSR"),
 ])).sign(clave_privada, hashes.SHA256())

# Write our CSR out to disk.
with open("pki_csr.pem", "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))