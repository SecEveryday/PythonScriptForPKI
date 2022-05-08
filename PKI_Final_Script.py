from venv import create
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import json
import os
from datetime import datetime
from datetime import timedelta
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
def create_keys():
    input_size = int(input("Enter the the key Size [Default : 2048] : ") or "2048")
    fileName = input("\nYour Public Key will be : <name>.pub \nYour Private key will be : <name>.priv\nProvide a name : " )
    key = RSA.generate(input_size)
    with open(fileName + ".priv","wb") as f:
        f.write(key.exportKey('PEM'))
    with open(fileName + ".pub","wb") as f:
        f.write((key.publickey()).exportKey('PEM'))
    return fileName + '.priv'
def sign_certificate_request(csr_cert, ca_cert, private_ca_key):
    cert = x509.CertificateBuilder().subject_name(
        csr_cert.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr_cert.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=10)
    ).sign(private_ca_key, hashes.SHA256())
    return cert
def create_CSR():
    priv_key = ''
    keyPresent = input('Do you have a Private key already? [N]: ') or 'Y' 
    if(keyPresent != 'Y'):
        fileName = create_keys()
        priv_key = load_pem_private_key((open(fileName,'rb')).read(), password=None)
    else:
        fileName = input("Enter the file with your Private Key : ")
        if(os.path.isfile(fileName)):
            priv_key = load_pem_private_key((open(fileName,'rb')).read(), password=None)
        else:
            print("Private Key file does not exist")
            return
    commanName = input("Enter the common name : ")
    if(commanName != ''):
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([

        x509.NameAttribute(NameOID.COMMON_NAME, commanName),

        ])).sign(priv_key,hashes.SHA256())
        CSR_key = {'csr': csr , 'key' : priv_key}
        return CSR_key
    else:
        print("Comman name empty")
        return
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
            create_keys()
        elif(UserOption == 4):
            ca = create_CSR()
            cert = sign_certificate_request(ca["csr"],ca["csr"],ca["key"])
            CaCertName = input("Enter the certificate name [ca-cert.pem] : ") or "ca-cert.pem"
            with open(CaCertName, "wb") as f:
                f.write(cert.public_bytes(Encoding.PEM))
        # elif(UserOption == 4):
        elif(UserOption == 5):
            csr = create_CSR()
            csrName = input("Please enter the name for your csr [cert.csr] : ") or "cert.csr"
            with open(csrName, "wb") as f:
                f.write(csr["csr"].public_bytes(Encoding.PEM))
        elif(UserOption == 6):
            CA_name = input("Enter the Certificate authoritie's cert file : ")
            if(os.path.isfile(CA_name)):
                with open(CA_name,"rb") as f:
                    ca_cert = x509.load_pem_x509_certificate(f.read())
            else: 
                print("File not found")
                continue
            csr_name = input("Enter the CSR for your cert : ")
            if(os.path.isfile(csr_name)):
                with open(csr_name,'rb') as f:
                    cert_csr = x509.load_pem_x509_csr(f.read())
            else:
                print("File not found")
                continue
            priv_key_file = input("Enter the file containing priv KEY of CA :")
            if(os.path.isfile(priv_key_file)):
                with open(priv_key_file,"rb") as f:
                    priv_key = load_pem_private_key(f.read(),password=None)
            else:
                print("File not found")
                continue
            cert = sign_certificate_request(cert_csr,ca_cert,priv_key)
            CaCertName = input("Enter the certificate name [cert.pem] : ") or "cert.pem"
            with open(CaCertName, "wb") as f:
                f.write(cert.public_bytes(Encoding.PEM))
        elif(UserOption == 7):
            print("See you again!")
            exit()
        else:
            print("Wrong Input")
