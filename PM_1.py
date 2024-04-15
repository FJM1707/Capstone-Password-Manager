import os
import json
import getpass
import random
import getpass

class PasswordManager:
    def __init__(self, storage_file):
        self.storage_file = storage_file
        if not os.path.exists(storage_file):
            with open(storage_file, 'w') as f:
                json.dump({}, f)

    def add_password(self, service, username, password):
        with open(self.storage_file, 'r') as f:
            data = json.load(f)
        data[service] = {'username': username, 'password': password}
        with open(self.storage_file, 'w') as f:
            json.dump(data, f)
            
    def get_password(self, service):
        with open(self.storage_file, 'r') as f:
            data = json.load(f)
        if service in data:
            return data[service]['password']
        else:
            return None

    def change_password(self, service, new_password):
        with open(self.storage_file, 'r') as f:
            data = json.load(f)
        if service in data:
            data[service]['password'] = new_password
            with open(self.storage_file, 'w') as f:
                json.dump(data, f)

    def remove_password(self, service):
        with open(self.storage_file, 'r') as f:
            data = json.load(f)
        if service in data:
            del data[service]
            with open(self.storage_file, 'w') as f:
                json.dump(data, f)

    def list_services(self):
        with open(self.storage_file, 'r') as f:
            data = json.load(f)
        return list(data.keys())

    def login(self, service):
        password = self.get_password(service)
        if password is None:
            print(f"No password found for {service}")
            return False
        else:
            print(f"Logging into {service}...")
            username = input("Enter your username: ")
            entered_password = getpass.getpass("Enter your password: ")
            if entered_password == password:
                print("Login successful!")
                return True
            else:
                print("Incorrect password")
                return False
    def generate_passwords(self, service):
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@!$1234567890'

        number = input('Amount of passwords to generate: ')
        number = int(number)

        length = input('Your password length: ')
        length = int(length)

        print('\nHere are your strong passwords: ')

        generated_passwords = []

        for pwd in range(number):
            passwords = ''
            for c in range(length):
                passwords += random.choice(chars)
            print(passwords)
            generated_passwords.append(passwords)

    def logout(self, service):
        self.remove_password(service)

def main():
    storage_file = 'passwords.json'
    password_manager = PasswordManager(storage_file)
    while True:
        print("\nPassword Manager")
        print("1. Add password")
        print("2. Get password")
        print("3. Change password")
        print("4. Remove password")
        print("5. List services")
        print("6. Login")
        print("7. Generate a Complex Password")
        print("8. Exit")
        choice = int(input("Enter your choice: "))
        if choice == 1:
            service = input("Enter service name: ")
            username = input("Enter username: ")
            password = getpass.getpass("Enter password: ")
            password_manager.add_password(service, username, password)
        elif choice == 2:
            service = input("Enter service name: ")
            password = password_manager.get_password(service)
            if password is None:
                print("No password found")
            else:
                print("Password:", password)
        elif choice == 3:
            service = input("Enter service name: ")
            new_password = getpass.getpass("Enter new password: ")
            password_manager.change_password(service, new_password)
        elif choice == 4:
            service = input("Enter service name: ")
            password_manager.remove_password(service)
        elif choice == 5:
            services = password_manager.list_services()
            print("Services:")
            for service in services:
                print(service)
        elif choice == 6:
            service = input("Enter service name: ")
            if password_manager.login(service):
                print("Logged in")
            else:
                print("Login failed")
        elif choice == 7:
            print("Recommendation for a complex password to be at least 8 or more characters with a special character(s)!")
            
            chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@!$#%^&*()~?+=-_1234567890'

            number = 1
    
            length = input('Your password length: ')
            length = int(length)

            print('\nHere is your strong password (If not satisfed run again!): ')

            generated_passwords = []

            for pwd in range(number):
                passwords = ''
                for c in range(length):
                    passwords += random.choice(chars)
            print(passwords)
            generated_passwords.append(passwords)
        elif choice == 8:
            print("Press Any Key to End")
            exit(0)
        else:
            print("Enter Either '0' or '1' or '2' ")
main()
