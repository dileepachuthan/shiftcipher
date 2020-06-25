# implementing shiftcipher idea in cryptography using python and printing the frequency of letters

#Encryption
from collections import Counter
def getplaintext():
    print("Enter your Plaintext ")
    return input()
def encrypt(plaintext,shift): 
    rslt = "" 
    for i in range(len(plaintext)): 
        char = plaintext[i] 
        if (char.islower()):
            rslt += chr((ord(char) + shift-97) % 26 + 97) 
        else:
            rslt += chr((ord(char) + shift-65) % 26 + 65)     
            
    return rslt
plaintext=getplaintext()
shift = 4    
print ("Ciphertext is " + encrypt(plaintext,shift))    
test_str = encrypt(plaintext,shift)
res = Counter(test_str)
print("Frequency of characters :"+str(res)) 
#Decryption
def getciphertext():
    print("Enter your ciphertext ")
    return input()
def decrypt(ciphertext,shift): 
    rslt = "" 
    for i in range(len(ciphertext)): 
        char = ciphertext[i] 
        if (char.islower()):
            rslt += chr((ord(char) + shift-97) % 26 + 97)
        else:
            rslt += chr((ord(char) + shift-65) % 26 + 65) 
    return rslt
ciphertext=getciphertext()
shift = -4    
print ("Plaintext is " + decrypt(ciphertext,shift))
test_str = decrypt(ciphertext,shift)
res = Counter(test_str)
print("Frequency of characters :"+str(res))
