# Universidad del Valle de Guatemala
# Cifrado de información 2020 2
# Grupo 7
# Implementation RSA-w-library.py

import rsa
## Python-RSA homepage --> https://stuvel.eu/software/rsa/
## Python-RSA documenyation --> https://stuvel.eu/python-rsa-doc/
## Python-RSA installation --> "pip install rsa"

##  First we generate the pair of keys thanks to the RSA library, this step is very easy.
##  We are given the option to choose big we want the keys to be.
##  Here is the table:
##  Keysize(bits)     single process     eightprocess
##  128               0.01 sec.          0.01 sec
##  256               0.03 sec.          0.02 sec
##  384               0.09 sec.          0.04 sec
##  512               0.11 sec.          0.07 sec
##  1024              0.79 sec.          0.30 sec
##  2028              6.55 sec.          1.60 sec
##  3072              23.4 sec.          7.14 sec
##  4096              72.0 sec.          24.4 sec

menu = ''' RSA PUBLIC-KEY CRYPTOSYSTEM 

    1. RSA without signing and verification
    2. RSA with signing and verification

    Enter the option you want to do: 

'''

option = input(menu)
option = int(option)

if option == 1: 
    ## 1. Bob generates a keypair, and gives the public key to Alice. 
    ## This is done such that Alice knows for sure that the key is really Bob’s 
    ## (for example by handing over a USB stick that contains the key).
    (pk, sk) = rsa.newkeys(512)
    print('PUBLIC KEY -> ' + str(pk) + '\n')
    print('SECRET KEY -> ' + str(sk) + '\n')

    ## 2. Alice writes a message, and encodes it in UTF-8. The RSA module only 
    ## operates on bytes, and not on strings, so this step is necessary.
    message = input('Enter the message you want to encrypt: ')
    message = message.encode('utf8')

    ## 3. Alice encrypts the message using Bob’s public key, and sends the encrypted message.
    crypto = rsa.encrypt(message, pk)
    print('\nEncypted message --> ' + str(crypto))

    ## 4. Bob receives the message, and decrypts it with his private key.
    message = rsa.decrypt(crypto, sk)
    print('\nMessage after being decrypted --> ' + message.decode('utf8'))

elif option == 2:

    ##  It is the same as wihtout signing and verification. We just add a couple of steps
    ##  to sign the message when we encrypt it and to validate it when we decrypt it

    ## 1. Bob generates a keypair, and gives the public key to Alice. 
    ## This is done such that Alice knows for sure that the key is really Bob’s 
    ## (for example by handing over a USB stick that contains the key).
    (pk, sk) = rsa.newkeys(512)
    print('PUBLIC KEY -> ' + str(pk) + '\n')
    print('SECRET KEY -> ' + str(sk) + '\n')

    ## 2. Alice writes a message, and encodes it in UTF-8. The RSA module only 
    ## operates on bytes, and not on strings, so this step is necessary.
    message = input('Enter the message you want to encrypt: ')
    message = message.encode('utf8')

    ##  we add the signature to the message
    hash = rsa.compute_hash(message, 'SHA-1')
    signature = rsa.sign_hash(hash, sk, 'SHA-1')
    print('\nSignature -> ' + str(signature))

    ## 3. Alice encrypts the message using Bob’s public key, and sends the encrypted message.
    crypto = rsa.encrypt(message, pk)
    print('\nEncypted message --> ' + str(crypto))

    wants_to_modify = input('\nWant to modify the message? (yes or no)  ')
    wants_to_modify = wants_to_modify.lower()

    if wants_to_modify == 'yes':
        ## let's an attacker got the message and he decides to change it
        message = input('\nModify the message: ')
        message = message.encode('utf8')

        crypto = rsa.encrypt(message, pk)

    ## 4. Bob receives the message, and decrypts it with his private key.
    ##  we add a step to validate the signature of the message

    #   This code shows the validation failed while trying to validate it
    message = rsa.decrypt(crypto, sk)
    validate = rsa.verify(message, signature, sk)
    if validate:
        print('\nMessage was not modified!')
        print(message)
    else:
        print('\nMessage was modified!')
    