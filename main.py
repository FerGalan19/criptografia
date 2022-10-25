from csv import DictWriter
import cryptography
import os

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import csv
# list of column names

def depositar(saldo_anterior):
  cantidad = int(input('¿Cuánto desea depositar?: '))
  if cantidad <= 0:
    print('Usted está intentando depositar una cantidad menor o igual a cero')
  else:
    global saldo
    saldo = saldo_anterior + float(cantidad)
    print(f'Su nuevo saldo es: {saldo}')
  return saldo

def retirar(saldo_anterior):
  cantidad = int(input('¿Cuánto desea retirar?: '))
  global saldo
  if cantidad > saldo or cantidad <= 0:
    print('Ha ocurrido un error, cantidad no suficiente, vuelve a intriducir una cantidad')
    retirar()
  else:
    saldo = saldo_anterior - float(cantidad)
    print(f'Su nuevo saldo es: {saldo}')
  return saldo


class PBKDF2:
    def __init__(self, salt):
        self.pbk = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000, )

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
    salt = os.urandom(16)
    kdf = PBKDF2(salt)
    resumen_contraseña = kdf.derive(contraseña)
    writer.writerows([{'Usuario': usuario, 'Contraseña': resumen_contraseña,
                              "Saldo": saldo,"Salt": salt.hex()}])

def validar_contraseña(contraseña, key, salt):
    salt = bytes.fromhex(salt)
    kdf = PBKDF2(salt)
    kdf = PBKDF2(salt)

    if kdf.verify(contraseña, key ):
        return True
    else:
        return False

def cambiar_saldo(saldo_nuevo,saldo, usuario, contraseñas, salt):

    csvfile_reader = open("countries.csv", 'r')
    reader = csv.reader(csvfile_reader)

    csvfile_writer = open('countries.csv', 'a+')
    fieldnames = ['Usuario', 'Contraseña', "Saldo", "Salt"]
    writer = csv.DictWriter(csvfile_writer, fieldnames=fieldnames)

    for row in reader:
        print(row[0])
        if row[0] == usuario:
            row[2] = row[2].replace(str(saldo), str(saldo_nuevo))
            csv.writer(csvfile_writer).writerow(row)


# Dictionary that we want to add as a new row
usuario = input("Nombre Usuario: ")
contraseña = input("Contraseña Usuario: ")
dict = {'Usuario': usuario, 'Contraseña': contraseña}

csvfile_writer = open('countries.csv', 'a+')
fieldnames = ['Usuario', 'Contraseña', "Saldo", "Salt"]
writer = csv.DictWriter(csvfile_writer, fieldnames=fieldnames)

csvfile_reader = open('countries.csv', 'r')
reader = csv.reader(csvfile_reader)
lista_usuarios = []
lista_contraseñas = []
lista_saldos = []
lista_salt = []

for row in reader:
    lista_usuarios.append(row[0])
    lista_contraseñas.append(row[1])
    lista_saldos.append(row[2])
    lista_salt.append(row[3])

print(lista_usuarios)
print(lista_contraseñas)
print(lista_saldos)
print(lista_salt)


encontrado = False
contraseña_encontrada = False

if usuario in lista_usuarios:
        posicion = lista_usuarios.index(usuario)
        print(posicion)
        while contraseña_encontrada is False:       # contraseña == lista_contraseñas[posicion]
         if validar_contraseña(contraseña, lista_contraseñas[posicion], lista_salt[posicion]):
            #print(contraseña)
            #print(lista_contraseñas[posicion])
            print("Usuario ya registrado")
            contraseña_encontrada = True
            encontrado = True
            saldo_usuario = lista_saldos[posicion]
            print("Que operación quieres realizar: ")
            print('1 - Depositar | 2 - Retirar | 3 - Salir')
            operación = int(input('¿Qué desea hacer?: '))
            if operación == 1:
                print('Usted eligió Depositar')
                cantidad = float(input('¿Cuánto desea depositar?: '))
                if cantidad <= 0:
                    print('Usted está intentando depositar una cantidad menor o igual a cero')
                else:
                    saldo = float(saldo_usuario) + cantidad
                    cambiar_saldo(saldo, saldo_usuario, lista_usuarios[posicion], lista_contraseñas[posicion], lista_salt[posicion])
                    print(f'Su nuevo saldo es: {lista_saldos[posicion]}')
                print(saldo)
         else:
            print("Usuario ya registrado, pero contraseña incorrecta")
            contraseña = input("Introduce de nuevo la contraseña: ")
            #print(contraseña)
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































"""
def login():
  user = input('Escriba su nombre de usuario: ')
  password = input('Escriba su contraseña: ')
  if usuarios[0] == user and contraseñas[0] == password:
    print(f'Bienvenido {usuarios} su saldo es: {float(saldo)}')
    opciones()
  else:
    print('Usuario o contraseña inválido')
    login()

def opciones():
  print('1 - Depositar | 2 - Retirar | 3 - Salir')
  operación = int(input('¿Qué desea hacer?: '))
  if operación == 1:
    print('Usted eligió Depositar')
    depositar(saldo)
  elif operación == 2:
    print('Usted eligió Retirar')
    retirar(saldo)
  elif operación == 3:
    print('Usted eligió Salir - Hasta luego!')
  else:
    print('Ha ocurrido un error')


def depositar(saldo_anterior):
  cantidad = int(input('¿Cuánto desea depositar?: '))
  if cantidad <= 0:
    print('Usted está intentando depositar una cantidad menor o igual a cero')
  else:
    global saldo
    saldo = saldo_anterior + float(cantidad)
    print(f'Su nuevo saldo es: {saldo}')
    repetir()

def retirar(saldo_anterior):
  cantidad = int(input('¿Cuánto desea retirar?: '))
  global saldo
  if cantidad > saldo or cantidad <= 0:
    print('Ha ocurrido un error, cantidad no suficiente, vuelve a intriducir una cantidad')
    retirar()
  else:
    saldo = saldo_anterior - float(cantidad)
    print(f'Su nuevo saldo es: {saldo}')
    repetir()

def repetir():
  pregunta = input('¿Desea hacer otra operación?: ')
  while pregunta == 'si':
    return opciones()
  return login()

login()

"""

