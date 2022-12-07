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
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography import x509

# *************** PARTE 2: FIRMA DIGITAL Y CERTIFICADOS ***************

variable_contraseña = b"rf"
"""contraseña openssl = bancossl"""


def generar_claves():
    """Generamos clave privada"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048, )

    """Serializamos la clave privada y la guardamos en un pem"""
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(variable_contraseña)
    )
    pem_private.splitlines()[0]

    f = open('pems/pem_private.pem', 'wb')
    f.write(pem_private)
    f.close()

    """Generamos la clave pública de la clave privada"""
    public_key = private_key().public_key()

    """Serializamos la clave pública y la guardamos en un pem"""
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pem_public.splitlines()[0]

    f = open('pems/pem_public.pem', 'wb')
    f.write(pem_public)
    f.close()


def obtener_clave_privada():
    """Desearilazamos la clave privada"""
    with open("pems/pem_private.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=variable_contraseña, )

    return private_key


def obtener_clave_pública():
    """Desearilazamos la clave pública"""
    with open("pems/pem_public.pem", "rb") as key_public_file:
        public_key = load_pem_public_key(key_public_file.read())

    return public_key


def firma(mensaje_str):
    """Firmamos con clave privada"""
    mensaje_b = bytes(mensaje_str, 'utf-8')
    signature = obtener_clave_privada().sign(
        mensaje_b,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    f = open('firma_mensaje/signature.sig', 'w')
    f.write(str(signature.hex()))
    f.close()
    return signature.hex()


def verificar_firma(signature, mensaje_str):
    """Verificamos firma con clave pública de A"""
    try:
        with open('openssl/A/entidad_firmante_cert.pem') as certificado_A:
            cert_A = x509.load_pem_x509_certificate(certificado_A.read().encode('utf-8'))

        encoded_signature = bytes.fromhex(signature)
        encoded_message = mensaje_str.encode('utf-8')
        public_key = cert_A.public_key()
        public_key.verify(
            encoded_signature,
            encoded_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        print("Firma verificada correctamente")
        return True

    except:
        print("Firma NO verificada correctamente")
        return False


def verificación_certificado():
    """Verificamos ambos certificados con clave pública de AC1 """
    try:
        with open('openssl/A/entidad_firmante_cert.pem') as certificado_A:
            cert_A = x509.load_pem_x509_certificate(certificado_A.read().encode('utf-8'))

        with open('openssl/AC1/ac1cert.pem') as certificado_AC1:
            cert_AC1 = x509.load_pem_x509_certificate(certificado_AC1.read().encode('utf-8'))

        clave_pública_certificar = cert_AC1.public_key()

        clave_pública_certificar.verify(
            cert_A.signature,
            cert_A.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert_A.signature_hash_algorithm,
        )

        clave_pública_certificar.verify(
            cert_AC1.signature,
            cert_AC1.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert_AC1.signature_hash_algorithm,
        )
        print("Certificados verificados correctamente")
        return True

    except:
        print("Certificados NO verificados correctamente")
        return False


# *************** PARTE 1 ***************

class PBKDF2:

    # ***************** CRIPTOGRAFÍA *****************
    def __init__(self, salt):
        self.pbk = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16,
            salt=salt,
            iterations=480000, )

    def derive(self, string):
        encoded_string = string.encode('utf-8')
        return (self.pbk.derive(encoded_string)).hex()

    def verify(self, string, derived_key):
        encoded_string = string.encode('utf-8')
        encoded_key = bytes.fromhex(derived_key)
        try:
            self.pbk.verify(encoded_string, encoded_key)
            return True
        except:
            return False


def crear_usuario(usuario, contraseña, saldo):
    # Cifrado contraseña
    salt = os.urandom(32)
    kdf = PBKDF2(salt)
    resumen_contraseña = kdf.derive(contraseña)

    # Ciframos el saldo
    salt_saldo = os.urandom(16)
    kdf_saldo = PBKDF2(salt_saldo)
    resumen = kdf_saldo.derive(contraseña)

    saldo_cifrado = cifrar_saldo(saldo, resumen)

    writer.writerows([{'Usuario': usuario, 'Contraseña': resumen_contraseña,
                       'Saldo': saldo_cifrado, 'Salt': salt.hex(), 'Salt saldo': salt_saldo.hex()}])


def validar_contraseña(contraseña, key, salt):
    salt = bytes.fromhex(salt)
    kdf = PBKDF2(salt)
    if kdf.verify(contraseña, key):
        return True
    else:
        return False


def eliminar_usuario_duplicado():
    df = pd.read_csv("data.csv", sep=",", header=None)
    # print(df)
    resultado = df.drop_duplicates(0, keep="last")
    # print(resultado)
    resultado.to_csv("data.csv", sep=",", header=None, index=False)


# ***************** CIFRADO DEL SALDO *****************

def cifrar_saldo(saldo, resumen):
    key = base64.urlsafe_b64encode(resumen.encode())
    encryptor = Fernet(key)
    str_saldo = str(saldo)
    token = encryptor.encrypt(str_saldo.encode())  # Hemos cambiado el nombre de la variable para que se entienda mejor

    return token.decode()


def descrifrar_saldo(token, resumen):
    key = base64.urlsafe_b64encode(resumen.encode())
    decryptor = Fernet(key)
    saldo = decryptor.decrypt(token.encode())
    return saldo


def cambiar_saldo(saldo_nuevo, saldo, usuario):
    # Abrimos csv para la lectura (data.csv)
    csvfile_reader = open("data.csv", 'r')
    reader = csv.reader(csvfile_reader)
    # Abrimos csv para la escritura (data.csv)
    csvfile_writer = open('data.csv', 'a+')
    csv.DictWriter(csvfile_writer, fieldnames=fieldnames)
    # Recorremos el csv linea a linea
    for row in reader:
        # print(row[0])
        if row[0] == usuario:
            row[2] = row[2].replace(str(saldo), str(saldo_nuevo))
            csv.writer(csvfile_writer).writerow(row)

    eliminar_usuario_duplicado()


# ***************** OPERACIONES CON SALDO *****************

def depositar(saldo_usuario, contraseña, salt_saldo):
    # Función depositar para que el usuario pueda ingresar dinero a su cuenta
    print('Usted eligió Depositar')
    cantidad = float(input('¿Cuánto desea depositar?: '))
    if cantidad <= 0:
        print('Usted está intentando depositar una cantidad menor o igual a cero')
    else:
        # Desciframos el saldo
        salt_saldo = bytes.fromhex(salt_saldo)
        kdf_saldo = PBKDF2(salt_saldo)
        resumen = kdf_saldo.derive(contraseña)

        saldo_descifrado = descrifrar_saldo(saldo_usuario, resumen)

        saldo = float(saldo_descifrado) + cantidad

        # Ciframos el saldo nuevo

        saldo_cifrado = cifrar_saldo(saldo, resumen)

        cambiar_saldo(saldo_cifrado, saldo_usuario, lista_usuarios[posicion])
        # print(f'Su nuevo saldo es: {lista_saldos[posicion]}')
    return saldo


def retirar(saldo_usuario, contraseña, salt_saldo):
    # Función retirar para que el usuario pueda retirar dinero a su cuenta
    print('Usted eligió Retirar')
    cantidad = float(input('¿Cuánto desea retirar?: '))
    if cantidad <= 0:
        print('Usted está intentando depositar una cantidad menor o igual a cero')
    else:
        # Desciframos el saldo
        salt_saldo = bytes.fromhex(salt_saldo)
        kdf_saldo = PBKDF2(salt_saldo)
        resumen = kdf_saldo.derive(contraseña)
        saldo_descifrado = descrifrar_saldo(saldo_usuario, resumen)

        saldo = float(saldo_descifrado) - cantidad

        # Ciframos el saldo nuevo
        saldo_cifrado = cifrar_saldo(saldo, resumen)
        # print("Saldo cifrado: ", saldo_cifrado)

        cambiar_saldo(saldo_cifrado, saldo_usuario, lista_usuarios[posicion])
        # print(f'Su nuevo saldo es: {lista_saldos[posicion]}')
    return saldo


def consultar_saldo(saldo_usuario, contraseña, salt_saldo):
    # Función consultar para que el usuario pueda consultar dinero a su cuenta
    print('Usted eligió consultar saldo')
    salt_saldo = bytes.fromhex(salt_saldo)
    kdf_saldo = PBKDF2(salt_saldo)
    resumen = kdf_saldo.derive(contraseña)

    saldo_descifrado = descrifrar_saldo(saldo_usuario, resumen)
    cantidad = 0
    saldo = float(saldo_descifrado) - cantidad

    # Ciframos el saldo nuevo
    saldo_cifrado = cifrar_saldo(saldo, resumen)

    cambiar_saldo(saldo_cifrado, saldo_usuario, lista_usuarios[posicion])
    # print(f'Su nuevo saldo es: {lista_saldos[posicion]}')
    return saldo


# ***************** APLICACIÓN BANCO *****************

usuario = input("Nombre Usuario: ")
contraseña = input("Contraseña Usuario: ")
dict = {'Usuario': usuario, 'Contraseña': contraseña}

# Abrimos csv para la lectura y escritura, y poder sobreescrbir cobre el csv (data.csv)
csvfile_writer = open('data.csv', 'a+')
fieldnames = ['Usuario', 'Contraseña', "Saldo", "Salt", "Salt saldo"]
writer = csv.DictWriter(csvfile_writer, fieldnames=fieldnames)

csvfile_reader = open('data.csv', 'r')
reader = csv.reader(csvfile_reader)
lista_usuarios = []
lista_contraseñas = []
lista_saldos = []
lista_salt = []
lista_salt_saldo = []

# Añadimos las distintas filas del csv, para conocer las posiciones de cada dato
for row in reader:
    lista_usuarios.append(row[0])
    lista_contraseñas.append(row[1])
    lista_saldos.append(row[2])
    lista_salt.append(row[3])
    lista_salt_saldo.append(row[4])

encontrado = False
contraseña_encontrada = False
hora = time.strftime("%H:%M:%S")
fecha = time.strftime("%d/%m/%y")
# Si la contraseña se introduce mas de tres veces mal, se elimina al usuario
contador_contraseña = 0

# Comprobacción para saber si el usuario esta registrado
if usuario in lista_usuarios:
    posicion = lista_usuarios.index(usuario)
    while contraseña_encontrada is False and contador_contraseña < 3:
        # Usuario esta registrado
        if validar_contraseña(contraseña, lista_contraseñas[posicion], lista_salt[posicion]):
            print("Usuario ya registrado")
            contraseña_encontrada = True
            encontrado = True
            saldo_usuario = lista_saldos[posicion]
            salt_saldo = lista_salt_saldo[posicion]
            print("La fecha en la que usted ha iniciado sesión es el " + fecha + " a las " + hora)
            mensaje_str = ("La fecha en la que usted ha iniciado sesión es el " + str(fecha) + " a las " + str(hora))

            """Firmamos el mensaje y guardamos la firma y el mensaje"""

            mensaje_firmado = firma(mensaje_str)
            f = open('firma_mensaje/mensaje.txt', 'w')
            f.write(mensaje_str)
            f.close()

            """Operación a realizar"""

            print("Que operación quieres realizar: ")
            print(
                "1 - Depositar | 2 - Retirar | 3 - Consultar Saldo | 4 - Verificación firma | 5 - Verificación certificados | 6 - Cerrar sesión")
            operación = int(input('¿Qué desea hacer?: '))

            if operación == 1:
                saldo = (depositar(saldo_usuario, contraseña, salt_saldo))
                print(saldo)
                print("Bienvenido " + usuario + " su saldo es de " + str(saldo))

            if operación == 2:
                saldo = (retirar(saldo_usuario, contraseña, salt_saldo))
                print(saldo)
                print("Bienvenido " + usuario + " su saldo es de " + str(saldo))

            if operación == 3:
                saldo = (consultar_saldo(saldo_usuario, contraseña, salt_saldo))
                print(saldo)
                print("Bienvenido " + usuario + " su saldo es de " + str(saldo))

            if operación == 4:
                # Verificación de firma
                verificar_firma(mensaje_firmado, mensaje_str)

            if operación == 5:
                # Verificación certificados
                verificación_certificado()

            if operación == 6:
                print("Sesión cerrada")
                exit()

        else:
            # Usuario ya registrado, contraseña incorrecta
            print("Usuario ya registrado, pero contraseña incorrecta")
            contraseña = input("Introduce de nuevo la contraseña: ")
            contraseña_encontrada = False
            contador_contraseña += 1
            if contador_contraseña == 3:
                df = pd.read_csv("data.csv", sep=",", header=None)
                resultado = df.iloc[:-1]
                resultado.to_csv("data.csv", sep=",", header=None, index=False)
                print("Usuario bloqueado, por favor contacte con el banco para restablecer la cuenta")

else:
    # Usuario no esta registrado
    usuario_nuevo_encontrado = False
    print("Usuario no encontrado, por favor registrate")
    usuario_nuevo = input("Nombre nuevo de usuario: ")
    contraseña_nueva = input("Introduce nueva contraseña usuario: ")
    pat = re.compile(r"^(?=\w*\d)(?=\w*[A-Z])(?=\w*[a-z])\S{8,16}$")
    # Comprobacción que el usuario no se encuentre ya registrado, y contraseña con regex correcta
    while usuario_nuevo_encontrado is False:
        if usuario_nuevo in lista_usuarios:
            print("Nombre de usuario ya registrada, introduce otro nuevo porfavor")
            usuario_nuevo = input("Nombre nuevo de usuario: ")
        elif re.fullmatch(pat, contraseña_nueva) is None:
            print("Contraseña no válida, porfavor introduce una que debe tener entre 8 y 16 caracteres, "
                  "al menos un dígito, una minúscula y una mayúscula")
            contraseña_nueva = input("Introduce nueva contraseña usuario: ")
        else:
            # Asignamos 2000 como saldo base
            crear_usuario(usuario_nuevo, contraseña_nueva, 2000)
            usuario_nuevo_encontrado = True
    encontrado = False

    print("Bienvenido " + usuario_nuevo + " su saldo es de " + str(2000))
    print("La fecha en la que usted se ha registrado es el " + fecha + " a las " + hora)
    mensaje_str = ("La fecha en la que usted se ha registrado es el " + str(fecha) + " a las " + str(hora))

    """Firmamos el mensaje y guardamos la firma y el mensaje"""

    mensaje_firmado = firma(mensaje_str)
    f = open('firma_mensaje/mensaje.txt', 'w')
    f.write(mensaje_str)
    f.close()

    # Verificación de firma
    verificar_firma(mensaje_firmado, mensaje_str)

    # Verificación certificados
    verificación_certificado()

# Elimina usuarios duplicados al añadir usuario

df = pd.read_csv("data.csv", sep=",", header=None)
resultado = df.drop_duplicates(0, keep="last")
resultado.to_csv("data.csv", sep=",", header=None, index=False)
