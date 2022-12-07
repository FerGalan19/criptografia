from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

"""Programa para generar CertificateSigningRequestBuilder, pem"""

variable_contraseña = b"rf"

def obtener_clave_privada():

    with open("pems/pem_private.pem", "rb") as key_file:
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
with open("pems/pki_csr.pem", "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))