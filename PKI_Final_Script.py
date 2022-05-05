from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import json
import os
def encrypt(message,passPhrase):
    message_len = len(message)
    message = pad(message,block_size=AES.block_size)
    iv = Random.new().read(AES.block_size)
    salt = Random.new().read(16)
    message = pad(message_len.to_bytes(2, byteorder='big'),block_size=AES.block_size) + message
    AESkey = PBKDF2(passPhrase, salt, 32, count=1000000, hmac_hash_module=SHA512)
    cipher = AES.new(AESkey, AES.MODE_CBC, iv)
    return salt + iv + cipher.encrypt(message)

def decrypt(ciphertext,passPhrase):
    salt = ciphertext[:16]
    iv = ciphertext[16:16+ AES.block_size]
    AESkey = PBKDF2(passPhrase, salt, 32, count=1000000, hmac_hash_module=SHA512)
    cipher = AES.new(AESkey, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[16+AES.block_size:])
    size_of_file = plaintext[:AES.block_size]
    size_of_file = int.from_bytes(unpad(size_of_file,block_size=AES.block_size),"big")
    plaintext = plaintext[AES.block_size:AES.block_size+size_of_file]
    return plaintext

def encrypt_file(file_name):
    passPhrase = input("Enter a password: ")
    with open(file_name, 'rb') as fo:
        plaintext = fo.read()
    enc = encrypt(plaintext, passPhrase)
    with open(file_name + ".enc", 'wb') as fo:
        fo.write(enc)

def decrypt_file(file_name):
    passPhrase = input("Enter a password: ")
    with open(file_name, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt(ciphertext, passPhrase)
    with open(file_name[:-4]+".decrypted", 'wb') as fo:
        fo.write(dec)

if __name__ == "__main__":
    while True:  
        print("\nWelcome to the Python Script to do the following:\n")
        print("1. Encrypt a file with AES-256-CBC ")
        print("2. Decrypt a file with AES-256-CBC ")
        print("3. Generate RSA keys")
        print("4. Create a CA")
        print("5. Generate a CSR")
        print("6. Sign the CSR for a server")
        print("7. To exit\n")
        UserOption = int(input("Enter your choice : "))
        if(UserOption == 1):
            inputFileName = input("\nEnter the file to encrypt : ")
            if(os.path.isfile(inputFileName)):
                encrypt_file(inputFileName)
            else:
                print("\nThe file does not exist")
        elif(UserOption == 2):
            inputFileName = input("\nEnter the file to decrypt : ")
            if(os.path.isfile(inputFileName)):
                decrypt_file(inputFileName)
            else:
                print("\nThe file does not exists")
        elif(UserOption == 3):
            
        elif(UserOption == 4):

        elif(UserOption == 5):
        
        elif(UserOption == 6):

        elif(UserOption == 7):
            print("See you again!")
            exit()
        else:
            print("Wrong Input")
        
        #elif(UserOption == 3):
