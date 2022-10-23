from csv import DictWriter
import csv

# list of column names

# Dictionary that we want to add as a new row
usuario = input("Nombre Usuario: ")
dict = {'Usuario': usuario, 'Contraseña': input("Contraseña Usuario: ")}

csvfile_writer = open('countries.csv', 'a+')
fieldnames = ['Usuario', 'Contraseña', "Saldo"]
writer = csv.DictWriter(csvfile_writer, fieldnames=fieldnames)

csvfile_reader = open('countries.csv', 'r')
reader = csv.reader(csvfile_reader)
lista = []
for row in reader:
    lista.append(row[0])

print(lista)

encontrado = False

if dict['Usuario'] in lista:
        print("Usuario ya registrado")
        encontrado = True
else:
        print("Usuario no encontrado, por favor registrate")
        usuario_nuevo = input("Nombre Usuario: ")
        dict1 = writer.writerows([{'Usuario': usuario_nuevo,
                           'Contraseña': input("Introduce nueva contraseña usuario: "), "Saldo":2000}])
        encontrado = False

if encontrado is False:
    print(usuario_nuevo)

else:
    print(usuario)

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
