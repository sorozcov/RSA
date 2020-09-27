# Universidad del Valle de Guatemala
# Cifrado de información 2020 2
# Grupo 7
# Implementation RSA.py

import random
from sympy import mod_inverse
from Crypto.Util.number import bytes_to_long ,long_to_bytes
import binascii
# First Alice and Bob will communicate thru RSA
# STEPS FOR RSA
# 1. Generate two big random prime number p and q
# 2. Calculate n = p*q
# 3. Use Euler Function φ of φ(n)=(p-1)(q-1) size
# Euler function gives all numbers between 1 and n with no common factors with n, it means are coprimes with n.
# 4. Pick a number e between 1 and φ(n) and also e is coprime with φ(n) and n
# 5. Calculate d knowing that e*d===1 mod φ(n)
# e is the public key (n,e)
# d is the private key (n,d)

# Now each message we parse it as a number and then we can encrypt/decrypt

# encrypt  c=m^{e}mod{n}
# decrypt  m=c^{d}mod{n}

def isPrime(number):
    if(number==1):
        return False
    if(number==2):
        return True
    for i in range(2,number):
        if(number%i==0):
            return False
    return True

def factors(number):
    if(number==1):
        return [1]
    if(number==2):
        return [1,2]
    factors=[1,number]
    for i in range(2,number):
        if(number%i==0):
            factors.append(i)
    return factors

# minium common multiple
def mcm(number1,number2):
    return number1*number2/mcd(number1,number2)

# greatest common divisor
def mcd(number1,number2):
    minNum = min(number1,number2)
    if(number1<1 or number2<1):
        return 0 #Error
    for i in range(minNum,2,-1):
        if(number1%i==0 and number2%i==0):
            return i
    return 1

def mcdFactors(number1,number2):
    factors1 = factors(number1)
    factors2 = factors(number2)
    commonDivisors = [value for value in factors1 if value in factors2]
    if(len(commonDivisors)>1):
        return max(commonDivisors)
    return 1

def isCoprime(number1,number2):
    if(mcd(number1,number2)==1):
        return True
    return False

def generateRandomPrimeNumber(a=100,b=999):
    n = random.randint(a, b)
    while not isPrime(n):
        n = random.randint(a, b)
    return n

def generatePandQ(a=100,b=999):
    #Generate p and q
    p=generateRandomPrimeNumber(a,b)
    q=generateRandomPrimeNumber(a,b)
    while(p==q):
        q=generateRandomPrimeNumber(a,b)
    print("P will be",p)
    print("Q will be",q)
    n=p*q
    print("N will be",n)
    return p,q,n

def eulerFunction(p,q):
    phi=(p-1)*(q-1)
    print("Phi will be",phi)
    return phi


def calculateEandD(p,q):
    n=p*q
    phi=eulerFunction(p,q)
    #Calculate e
    e=random.randint(1,phi)
    #Now we calculate d
    # e*d = 1 mod phi
    d=modInverse(e,phi)
    while(not (isCoprime(e,n) and isCoprime(e,phi)) or d==False):
        e=random.randint(1,phi)
        d=modInverse(e,phi)

    print("e will be",e)
    print("d will be",d)
    return e,d

def modInverse(e,n):
    try:
        d=mod_inverse(e,n)
        return d
    except:
        return False


#RSA Object
class RSA(object):
    #generate our own RSA
    def __init__(self,a=100,b=999,p=None, q=None,assumeNumbers=False,byChar=False):
        if(p==None or q==None):
            p,q,n = generatePandQ(a,b)
        else:
            n=p*q
        e,d = calculateEandD(p,q)
        self.p=p
        self.q=q
        self.n=n
        self.e=e
        self.d=d
        self.publicKey=(e,n)
        self.privateKey=(d,n)
        self.assumeNumbers = assumeNumbers
        self.byChar = byChar

    # encrypt  c=m^{e}mod{n}

    def encrypt(self,message):
        if(self.assumeNumbers):
            m=int(message)
            c = pow(m,self.e,self.n)
            return c
        else:
            if(self.byChar):
                finalEncrypt=""
                for char in message:
                    m = ord(char)
                    c = pow(m,self.e,self.n)
                    finalEncrypt+= chr(c)
                return finalEncrypt
            else:
                m=message.encode('latin-1')
                m=bytes_to_long(m)
            
                c = pow(m,self.e,self.n)
                cipher = long_to_bytes(c)
                return cipher.decode('latin-1')
            

    # decrypt  m=c^{d}mod{n}
    def decrypt(self,cipher):
       
        if(self.assumeNumbers):
            c=int(cipher)
            m = pow(c,self.d,self.n)
            return m
        else:
            if(self.byChar):
                finalDecrypted=""
                for char in cipher:
                    c=ord(char)
                    m = pow(c,self.d,self.n)
                    finalDecrypted+= chr(m)
                return finalDecrypted
            else:
                c=cipher.encode('latin-1')
                c=bytes_to_long(c)
                m = pow(c,self.d,self.n)
                message = long_to_bytes(m)
                return message.decode('latin-1')



        


        
def mainExample():
    print("Welcome to our own RSA implementation example")
    print("This an example of use: ")
    rsa= RSA(assumeNumbers=False,byChar=True)
    message="My Secret Message"
    print("Message to encrypt: ",message)
    e=rsa.encrypt(message)
    d=rsa.decrypt(e)
    print("Encryption: ",e)
    print("Decryption: ",d)

mainExample()

