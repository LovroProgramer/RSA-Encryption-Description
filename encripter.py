#!/usr/bin/env python3
import os 
import argparse
import getpass
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

praser = argparse.ArgumentParser(description='Simple RSA encryption tool.')
praser.add_argument('-e', '--encrypt', type=str, help='Encrypt text, place the file location as an argument of the file you want to encrypt')
praser.add_argument('-d', '--decrypt', type=str, help='Decrypt text, place the file location as an argument of the file you want to decrypt')
praser.add_argument('-gk', '--generate-key', action='store_true', help='Generate a new pair of keys')
praser.add_argument('-pub', '--public-key', type=str, help='Path to the public key file for encryption.')
praser.add_argument('-prk', '--private-key', type=str, help='Path to the private key file for encryption.')
praser.add_argument('-p', '--password', type=str, help='Password for the private key')

args = praser.parse_args()


def generateRSA():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    # Serijalizacija privatnog ključa u PEM format
    password = getpass.getpass('Enter the password for the private key, PLEASE DO NOT FORGET YOUR PASSWORD:')
    password2 = getpass.getpass('Please re-enter the password for confirmation:')
    while password != password2:
        print("Passwords do not match. Please try again.")
        password = getpass.getpass('Enter the password for the private key, PLEASE DO NOT FORGET YOUR PASSWORD:')
        password2 = getpass.getpass('Please re-enter the password for confirmation:')

    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(bytes(password, 'utf-8'))
    )
    # Izvoz javnog ključa iz privatnog ključa i serijalizacija u PEM format
    pem_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    
    return pem_private_key, pem_public_key


def encryptRSA_TXT(path, public_key_path):
    try:
        with open(public_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())
    except Exception as e:
        print(f"Error loading public key: {e}")
        return
    
    try:
        with open(path, 'r') as file:
            message = file.read().encode('utf-8')
    except Exception as e:
        print(f"Error reading text file: {e}")
        return
    
    try:
        encrypted = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        print(f"Error encrypting message: {e}")
        return
    
    encrypted_file_path = path + ".encrypted"
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)
    print(f"Encrypted text saved to {encrypted_file_path}")


def decryptRSA_TXT(path, private_key_path, password):
    try:
        # Učitavanje privatnog ključa
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password.encode('utf-8')  # Pretvaranje lozinke u bytes
            )
    except Exception as e:
        print(f"Error loading private key: {e}")
        return
    
    try:
        # Učitavanje enkriptirane datoteke
        with open(path, 'rb') as encrypted_file:
            encrypted_message = encrypted_file.read()
    except Exception as e:
        print(f"Error reading encrypted file: {e}")
        return
    
    try:
        # Dekripcija poruke
        decrypted_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        print(f"Error decrypting message: {e}")
        return
    
    # Spremanje dekriptiranog teksta
    decrypted_file_path = os.path.splitext(path)[0] + "_decrypted.txt"
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_message)
    print(f"Decrypted text saved to {decrypted_file_path}")
 

if args.generate_key:
    private_key, public_key = generateRSA()
    print('RSA Private Key created')
    print('RSA Public Key created')
    print('Private Key: Saved at location', os.getcwd() + '/private.pem')
    print('Public Key: Saved at location', os.getcwd() + '/public.pem')
    with open("private.pem", "wb") as prv_file:
        prv_file.write(private_key)
    with open("public.pem", "wb") as pub_file:
        pub_file.write(public_key)

if args.encrypt:
    if not args.public_key:
        print("You need to specify -pub to provide the public key location!")
    else:
        encryptRSA_TXT(args.encrypt, args.public_key)

if args.decrypt:
    if args.decrypt and args.password:
        if args.private_key:
            decryptRSA_TXT(args.decrypt, args.private_key, args.password)
        else:
            print("-pk parrametar not provided")
    else:
        print("""You need to specify 3 parrametars: 
              -d to provide the encrypted file location
              -p for the private key password.
              -prk for private key location""")
