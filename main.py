import os
import pandas as pd
import base64

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import csv

class PBKDF2:
    def __init__(self, salt):
        self.pbk = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16,
            salt=salt,
            iterations=480000,)        # Recomendación de iteraciones Django Julio de 2022

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
    salt = os.urandom(16)
    kdf = PBKDF2(salt)
    resumen_contraseña = kdf.derive(contraseña)

    # Cifraframos el saldo
    salt_saldo = os.urandom(16)
    kdf_saldo = PBKDF2(salt_saldo)
    resumen = kdf_saldo.derive(contraseña)

    saldo_cifrado = cifrar_saldo(saldo, resumen)

    writer.writerows([{'Usuario': usuario, 'Contraseña': resumen_contraseña,
                              'Saldo': saldo_cifrado,'Salt': salt.hex(),'Salt saldo': salt_saldo.hex()}])

def validar_contraseña(contraseña, key, salt):
    salt = bytes.fromhex(salt)
    kdf = PBKDF2(salt)
    if kdf.verify(contraseña, key ):
        return True
    else:
        return False

# ***************** CIFRADO DEL SALDO *****************

def cifrar_saldo(saldo,resumen):
    key = base64.urlsafe_b64encode(resumen.encode())
    encryptor = Fernet(key)
    str_saldo = str(saldo)
    hash = encryptor.encrypt(str_saldo.encode())

    return hash.decode()

def descrifrar_saldo(hash, resumen):
    key = base64.urlsafe_b64encode(resumen.encode())
    decryptor = Fernet(key)
    saldo = decryptor.decrypt(hash.encode())
    return saldo

def cambiar_saldo(saldo_nuevo,saldo, usuario):

    csvfile_reader = open("countries.csv", 'r')
    reader = csv.reader(csvfile_reader)


    csvfile_writer = open('countries.csv', 'a+')
    csv.DictWriter(csvfile_writer, fieldnames=fieldnames)

    for row in reader:
        #print(row[0])
        if row[0] == usuario:
            row[2] = row[2].replace(str(saldo), str(saldo_nuevo))
            csv.writer(csvfile_writer).writerow(row)

def depositar(saldo_usuario,contraseña, salt_saldo):

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
      #print(f'Su nuevo saldo es: {lista_saldos[posicion]}')
  print(saldo)

def retirar(saldo_usuario, contraseña, salt_saldo):
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

        cambiar_saldo(saldo_cifrado, saldo_usuario, lista_usuarios[posicion])
        #print(f'Su nuevo saldo es: {lista_saldos[posicion]}')
    print(saldo)



# Dictionary that we want to add as a new row
usuario = input("Nombre Usuario: ")
contraseña = input("Contraseña Usuario: ")
dict = {'Usuario': usuario, 'Contraseña': contraseña}

csvfile_writer = open('countries.csv', 'a+')
fieldnames = ['Usuario', 'Contraseña', "Saldo", "Salt", "Salt saldo"]
writer = csv.DictWriter(csvfile_writer, fieldnames=fieldnames)

csvfile_reader = open('countries.csv', 'r')
reader = csv.reader(csvfile_reader)
lista_usuarios = []
lista_contraseñas = []
lista_saldos = []
lista_salt = []
lista_salt_saldo = []

for row in reader:
    lista_usuarios.append(row[0])
    lista_contraseñas.append(row[1])
    lista_saldos.append(row[2])
    lista_salt.append(row[3])
    lista_salt_saldo.append(row[4])

""""
print(lista_usuarios)
print(lista_contraseñas)
print(lista_saldos)
print(lista_salt)
"""

encontrado = False
contraseña_encontrada = False

if usuario in lista_usuarios:
        posicion = lista_usuarios.index(usuario)
        #print(posicion)
        while contraseña_encontrada is False:
         if validar_contraseña(contraseña, lista_contraseñas[posicion], lista_salt[posicion]):
            print("Usuario ya registrado")
            contraseña_encontrada = True
            encontrado = True
            saldo_usuario = lista_saldos[posicion]
            salt_saldo = lista_salt_saldo[posicion]
            print("Que operación quieres realizar: ")
            print('1 - Depositar | 2 - Retirar | 3 - Salir')
            operación = int(input('¿Qué desea hacer?: '))

            if operación == 1:
                depositar(saldo_usuario, contraseña, salt_saldo)

            if operación == 2:
                retirar(saldo_usuario, contraseña, salt_saldo)
         else:

            print("Usuario ya registrado, pero contraseña incorrecta")
            contraseña = input("Introduce de nuevo la contraseña: ")

            contraseña_encontrada = False
else:
        usuario_nuevo_encontrado = False
        print("Usuario no encontrado, por favor registrate")
        usuario_nuevo = input("Nombre nuevo de usuario: ")
        contraseña_nueva = input("Introduce nueva contraseña usuario: ")
        while usuario_nuevo_encontrado is False:
            if usuario_nuevo in lista_usuarios:
                 print("Nombre de usuario ya registrada, introduce otro nuevo porfavor")
                 usuario_nuevo = input("Nombre nuevo de usuario: ")
                 usuario_nuevo_encontrado = False
            else:
                crear_usuario(usuario_nuevo, contraseña_nueva, 2000)
                usuario_nuevo_encontrado = True
        encontrado = False

if encontrado is False:
    print("Bienvenido " + usuario_nuevo + " su saldo es de ")

else:
    print("Bienvenido " + usuario + " su saldo es de ")


#Elimina usuarios duplicados al añadir usuario

df = pd.read_csv("countries.csv", sep=",", header=None)
#print(df)
resultado = df.drop_duplicates(0, keep="last")
#print(resultado)

resultado.to_csv("countries.csv", sep=",", header=None, index=False)


