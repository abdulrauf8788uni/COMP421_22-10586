
import base64
import rsa
import os

"""
Abdul Rauf
22-10585
"""

def generateKeys():
    (publicKey, privateKey) = rsa.newkeys(1024, True, 8)
    with open('keys/publicKey.pem', 'wb') as p:
        p.write(publicKey.save_pkcs1('PEM'))
    with open('keys/privateKey.pem', 'wb') as p:
        p.write(privateKey.save_pkcs1('PEM'))


def loadKeys():
    with open('keys/publicKey.pem', 'rb') as p:
        publicKey = rsa.PublicKey.load_pkcs1(p.read())
    with open('keys/privateKey.pem', 'rb') as p:
        privateKey = rsa.PrivateKey.load_pkcs1(p.read())
    return privateKey, publicKey

def encrypt(message, key):
    return rsa.encrypt(message.encode('ascii'), key)

def decrypt(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except:
        return False


def main(publicKey, privateKey):
    """ Main Function loop """

    selection = input ("""
Select one option:
    1. Encrypt Text
    2. Decrypt Text
    3. Exit
    Enter Your Choice: """)
    
    if selection == "1":
        # Cypher text
        text = input("Enter Normal text: ")
        ciphertext = base64.b64encode(encrypt(text, publicKey))
        print(f"Encrypted text is with base64 encoding is:\n\n{ciphertext.decode()}")

    elif selection == "2":
        # Decrypt Text
        ciphertext = base64.b64decode(input("Enter Encrypted text in base64 encoding: ").strip())
        text = decrypt(ciphertext, privateKey)
        if text:
            print(f"\nNormal Text is: {text}")
        else:
            print("\nUnable to Decrypt the given Encryped text.")

    elif selection == "3":
        # Print thankyou for using service
        print("\nThank you for using RSA encrypyion and Decryption service. ")
        return False
    else:
        # Print enter valid input 
        print("Please enter a valid option. ")

    return True

if __name__ == "__main__":
    print("\nWelcome to RSA encrypyion and Decryption service")
    
    try:
        privateKey, publicKey = loadKeys()
    except:
        print("Generating public and private keys.... ")
        os.mkdir("keys")
        generateKeys()
        privateKey, publicKey = loadKeys()

    cont = True
    while cont:
        cont = main(publicKey, privateKey)