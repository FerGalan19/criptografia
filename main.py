import os
import pandas as pd
import base64
import time


from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import csv
import re


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


# ***************** CIFRADO DEL SALDO *****************

def cifrar_saldo(saldo, resumen):
    key = base64.urlsafe_b64encode(resumen.encode())
    encryptor = Fernet(key)
    str_saldo = str(saldo)
    token = encryptor.encrypt(str_saldo.encode())           # Hemos cambiado el nombre de la variable para que se entienda mejor

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
        print("Saldo cifrado: ", saldo_cifrado)

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
"""
*********************Para conocer los datos sin cifrar
print(lista_usuarios)
print(lista_contraseñas)
print(lista_saldos)
print(lista_salt)
print(lista_salt_saldo)
"""

encontrado = False
contraseña_encontrada = False
hora = time.strftime("%H:%M:%S")
fecha = time.strftime("%d/%m/%y")

# Comprobacción para saber si el usuario esta registrado
if usuario in lista_usuarios:
    posicion = lista_usuarios.index(usuario)
    while contraseña_encontrada is False:
        # Usuario esta registrado
        if validar_contraseña(contraseña, lista_contraseñas[posicion], lista_salt[posicion]):
            print("Usuario ya registrado")
            contraseña_encontrada = True
            encontrado = True
            saldo_usuario = lista_saldos[posicion]
            salt_saldo = lista_salt_saldo[posicion]
            print("La fecha en la que usted se ha registrado es el " + fecha + " a las " + hora)
            print("Que operación quieres realizar: ")
            print('1 - Depositar | 2 - Retirar | 3 - Consultar Saldo | 4 - Salir')
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
        else:
            # Usuario ya registrado, contraseña incorrecta
            print("Usuario ya registrado, pero contraseña incorrecta")
            contraseña = input("Introduce de nuevo la contraseña: ")
            contraseña_encontrada = False

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

# Elimina usuarios duplicados al añadir usuario

df = pd.read_csv("data.csv", sep=",", header=None)
# print(df)
resultado = df.drop_duplicates(0, keep="last")
# print(resultado)
resultado.to_csv("data.csv", sep=",", header=None, index=False)
