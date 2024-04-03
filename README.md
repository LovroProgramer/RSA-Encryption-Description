# RSA Encryption/Decryption Tool

## Description
This simple RSA encryption and decryption tool is built with Python. It allows users to generate RSA public/private key pairs, encrypt messages using the public key, and decrypt them using the private key. Designed for educational purposes and straightforward use, this tool demonstrates the basics of cryptographic operations in Python.

## Features
- Generate RSA public and private key pairs with a high level of encryption strength.
- Encrypt text files using the RSA public key.
- Decrypt text files using the RSA private key.
- Command-line interface for easy operation.

## Installation
To set up this tool, follow these steps:

1. Clone this repository to your local machine.

$ git clone https://github.com/LovroProgramer/RSA-Encryption-Description.git

2. Navigate to the project directory.

$ cd RSA-Encryption-Description

3. Install the required packages.

$ pip install -r requirements.txt



## Usage
Below are the commands to use the RSA Encryption/Decryption Tool.

### Generate Keys
To generate a new RSA key pair:

$ ./encripter.py --generate-key


To encrypt a text file named `exemple.txt` using a public key:

$ ./encripter.py --encrypt exemple.txt --public-key path/to/publicKey.pem

### Decrypt a Message
To decrypt an encrypted file named `exemple.txt.encrypted` using a private key:

$ ./encripter.py --decrypt exemple.txt.encrypted --private-key path/to/privateKey.pem --password YOUR_PRIVATE_KEY_PASSWORD







## Contributing
Contributions to enhance the functionality or efficiency of this tool are welcome. 

