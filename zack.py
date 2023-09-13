import os
from Crypto import Random
from Crypto.Cipher import AES
import time

class Encryptor:
    def __init__(self, key):
        self.key = key

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message, key, key_size=256):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def encrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            plaintext = fo.read()
        enc = self.encrypt(plaintext, self.key)
        with open(file_name + ".enc", 'wb') as fo:
            fo.write(enc)
        os.remove(file_name)

    def decrypt(self, ciphertext, key):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, file_name, password):
        try:
            with open(file_name, 'rb') as fo:
                ciphertext = fo.read()
            dec = self.decrypt(ciphertext, self.key)
            with open(file_name[:-4], 'wb') as fo:
                fo.write(dec)
        except FileNotFoundError:
            print(f"File not found: {file_name}")

    def getAllFiles(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        dirs = []
        for dirName, subdirList, fileList in os.walk(dir_path):
            for fname in fileList:
                if (fname != 'zack.py' and not fname.endswith(".enc")):
                    dirs.append(os.path.join(dirName, fname))
        return dirs

    def encrypt_all_files(self):
        dirs = self.getAllFiles()
        for file_name in dirs:
            self.encrypt_file(file_name)

    def decrypt_all_files(self):
        dirs = self.getAllFiles()
        for file_name in dirs:
            self.decrypt_file(file_name)

# Corrected file paths using raw strings for Windows:
key = os.urandom(32)  # Generate a random 256-bit AES key
enc = Encryptor(key)
clear = lambda: os.system('cls')

# Use raw strings for file paths to avoid escaping issues
encrypted_file_path = r'C:\Users\MALCOM1\PycharmProjects\pythonProject\data.txt.enc'

# Check if the encrypted file exists before attempting decryption
if os.path.isfile(encrypted_file_path):
    while True:
        password = str(input("Enter password: "))
        enc.decrypt_file(encrypted_file_path, password)
        decrypted_file_path = encrypted_file_path[:-4]  # Remove ".enc" extension
        if os.path.isfile(decrypted_file_path):
            print("Decryption successful.")
            break
        else:
            print("Incorrect password. Try again.")
else:
    while True:
        clear()
        password = str(input("Setting up stuff. Enter a password that will be used for decryption: "))
        repassword = str(input("Confirm password: "))
        if password == repassword:
            break
        else:
            print("Passwords Mismatched!")

    # Create 'data.txt.enc' file and encrypt it with the setup password
    with open(r'C:\Users\MALCOM1\PycharmProjects\pythonProject\data.txt', "w+") as f:
        f.write(password)

    enc.encrypt_file(r'C:\Users\MALCOM1\PycharmProjects\pythonProject\data.txt')

    print("Setup completed. Please restart the program.")
    time.sleep(5)

# Added option for decryption in the main code
while True:
    clear()
    choice = int(input(
        "1. Press '1' to encrypt file.\n2. Press '2' to decrypt file.\n3. Press '3' to Encrypt all files in the directory.\n4. Press '4' to decrypt all files in the directory.\n5. Press '5' to exit.\n"))
    clear()
    if choice == 1:
        enc.encrypt_file(str(input("Enter name of file to encrypt: ")))
    elif choice == 2:
        enc.decrypt_file(str(input("Enter name of file to decrypt: ")), str(input("Enter decryption password: ")))
    elif choice == 3:
        enc.encrypt_all_files()
    elif choice == 4:
        enc.decrypt_all_files()
    elif choice == 5:
        exit()
    else:
        print("Please select a valid option!")