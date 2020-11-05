from vignere import VignereCipher
from reverse import ReverseCipherDecrypt
from multiplicative import MultiplicativeCipher
from caesar import CaesarCipherDecrypt
from otp import OTP
from transposition import TranspositionCipher
from substitution import SubstitutionCipher

import os
list_dir = os.listdir("../website/data/")
print(list_dir[0][:-4])

key = []
decrypted_message = ''

for file in list_dir:
    if file == 'key.txt':
        f = open("../website/data/" + file)
        key = f.read()
        f.close()

for file in list_dir:
    algo = file[:-4]

    f = open("../website/data/"+file)
    encrypted_message = f.read()
    f.close()

    if algo == 'vignere':
        f = open("../website/data/"+file)
        encrypted_message = f.read()
        f.close()
        vignere = VignereCipher(' ', key)
        decrypted_message = vignere.decrypt(encrypted_message)
        print("Decrypted Message: {}".format(decrypted_message))
        os.remove("../website/data/"+file)
    
    if algo == 'reverse':
        f = open("../website/data/"+file)
        encrypted_message = f.read()
        f.close()
        reverse = ReverseCipherDecrypt(encrypted_message)
        decrypted_message = reverse.decrypt()
        print("Decrypted Message: {}".format(decrypted_message))
        os.remove("../website/data/"+file)

    if algo == 'multiplicative':
        f = open("../website/data/"+file)
        encrypted_message = f.read()
        f.close()
        multiplicative = MultiplicativeCipher(" ")
        decrypted_message = multiplicative.decrypt(encrypted_message)
        print("Decrypted Message: {}".format(decrypted_message))
        os.remove("../website/data/"+file)
    
    if algo == 'caesar':
        f = open("../website/data/"+file)
        encrypted_message = f.read()
        f.close()
        caesar = CaesarCipherDecrypt(encrypted_message)
        decrypted_message = caesar.decrypt(5)
        print("Decrypted Message: {}".format(decrypted_message))
        os.remove("../website/data/"+file)

    if algo == 'otp':
        f = open("../website/data/"+file)
        encrypted_message = f.read()
        f.close()
        otp = OTP(" ")
        key = key[1:-1].split(', ')
        for x in range(len(key)):
            key[x] = int(key[x])
        decrypted_message = otp.decrypt(encrypted_message, key)
        print("Decrypted Message: {}".format(decrypted_message))
        os.remove("../website/data/"+file)

    if algo == 'substitution':
        f = open("../website/data/"+file)
        encrypted_message = f.read()
        f.close()
        key = key[1:-1].split(', ')
        for x in range(len(key)):
            key[x] = int(key[x])
        substitution = SubstitutionCipher('', key)
        decrypted_message = substitution.decrypt(encrypted_message)
        print("Decrypted Message: {}".format(decrypted_message))
        os.remove("../website/data/"+file)
    
    if algo == 'transposition':
        
        transposition = TranspositionCipher()
        decrypted_message = transposition.decrypt(eval(key), encrypted_message)
        print("Decrypted Message: {}".format(decrypted_message))
        os.remove("../website/data/"+file)


