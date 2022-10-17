import time
from bank_system import function

Function = function.Function()

class Main(object):
    def run(self):
        while True:
            print("Saltando a la interfaz principal, por favor espere", end="")
            for i in range(5):
                print(".", end="", flush=True)
                time.sleep(0.4)
            print("")
            self.UI()
            number = input("Ingrese el número de función que desea seleccionar:")
            if number not in ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'q']:
                print("¡Ingrese el código correcto!")
            if number == "0":
                Function.create_user()
            elif number == "1":
                Function.query()
            elif number == "2":
                Function.deposit()
            elif number == "3":
                Function.withdrawal()
            elif number == "4":
                Function.change_password()
            elif number == "q":
                print("Saliendo del sistema, por favor espere", end=" ")
                for i in range(6):
                    print(".", end=" ", flush=True)
                    time.sleep(0.5)
                break

    def UI(self):
        print("*****************************************************")
        print("** Bienvenido a - Col china - China Merchants Bank **")
        print("** Consulta de apertura de cuenta (0) (1) **")
        print("** Depósito (2) Retiro (3) **")
        print("** Cambiar contraseña (5) **")
        print("** Salir (q) **")
        print("*****************************************************")

if __name__ == "__main__":
    Main().run()